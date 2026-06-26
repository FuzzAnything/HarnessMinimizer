"""Unit tests for stack trace extraction, normalization, and periodic iteration logic.

These tests exercise the pure-logic parts of the stack trace validation feature
without running the full reduction pipeline or compiling any code.
"""
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harnessreducer.reducer_runner import (
    MEMORY_ADDRESS_PATTERN,
    STACK_FRAME_PATTERN,
    LLVMFuzzerTestOneInput_PATTERN,
    extract_crash_pattern_from_output,
    extract_stack_trace,
    normalize_crash_signature,
    get_stack_trace_file,
    get_stack_trace_counter_file,
    get_stack_trace_backup_file,
    reset_stack_trace_state,
    stack_trace_tester_args,
    validate_stack_trace,
    configure_work_dir,
)

# Import the crash_tester helpers (they are in a standalone script, so we
# add the project root to sys.path and import the relevant functions).
import sys

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# crash_tester.py is a script, not a package — we import specific functions.
# We exec it in a controlled namespace to avoid its argparse main().
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "crash_tester", str(_PROJECT_ROOT / "tests" / "crash_tester.py")
)
_ct_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ct_module)

ct_extract_stack_trace = _ct_module.extract_stack_trace
ct_effective_iteration = _ct_module._effective_iteration
ct_read_counter = _ct_module._read_counter
ct_write_counter = _ct_module._write_counter
ct_check_stack_trace = _ct_module._check_stack_trace
SMALL_HARNESS_LINE_THRESHOLD = _ct_module.SMALL_HARNESS_LINE_THRESHOLD
TINY_HARNESS_LINE_THRESHOLD = _ct_module.TINY_HARNESS_LINE_THRESHOLD
SMALL_HARNESS_ITERATION = _ct_module.SMALL_HARNESS_ITERATION
TINY_HARNESS_ITERATION = _ct_module.TINY_HARNESS_ITERATION


# --- Sample ASan output for testing ---
SAMPLE_ASAN_OUTPUT = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000034 at pc 0x5ea4dfe78fe6 bp 0x7ffc1234 sp 0x7ffc5678
READ of size 4 at 0x602000000034 thread T0
    #0 0x5ea4dfe78fe6 in av1_one_pass_cbr_svc_start_layer /root/src/libaom/av1/encoder/svc_layercontext.c:444:18
    #1 0x5ea4dfc2cfe3 in av1_get_compressed_data /root/src/libaom/av1/encoder/encoder.c:5342:5
    #2 0x5ea4dfb42f7f in encoder_encode /root/src/libaom/av1/av1_cx_iface.c:3639:20
    #3 0x5ea4dfb36563 in aom_codec_encode /root/src/libaom/aom/src/aom_encoder.c:191:11
    #4 0x5ea4dfb34b11 in LLVMFuzzerTestOneInput /root/FuzzAgent/output/libaom/crash_002/reduced_poc.cpp:33:3
    #5 0x5ea4dfa2f68f in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/root/FuzzAgent/output/libaom/crash_002/fuzzer+0x46068f)
SUMMARY: AddressSanitizer: heap-buffer-overflow /root/src/libaom/av1/encoder/svc_layercontext.c:444:18 in av1_one_pass_cbr_svc_start_layer
"""

SAMPLE_ASAN_OUTPUT_TWO_TRACES = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000034
    #0 0xaaa1 in crash_func /src/crash.c:10:3
    #1 0xbbb2 in caller_func /src/caller.c:20:5
    #2 0xccc3 in LLVMFuzzerTestOneInput /src/harness.cpp:5:1
0x602000000034 is located 0 bytes to the right of 4-byte region [0x602000000030,0x602000000034)
allocated by thread T0 here:
    #0 0xddd0 in malloc /src/asan_malloc.cc:100
    #1 0xeee1 in alloc_func /src/alloc.c:30:7
    #2 0xfff2 in LLVMFuzzerTestOneInput /src/harness.cpp:3:1
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/crash.c:10:3 in crash_func
"""

SAMPLE_UBSAN_OUTPUT = """\
/root/src/foo.c:42:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x1234 in buggy_func /root/src/foo.c:42:5
    #1 0x5678 in LLVMFuzzerTestOneInput /root/harness.cpp:10:3
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /root/src/foo.c:42:5
"""

SAMPLE_ASAN_OUTPUT_WITH_HELPER = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000034
    #0 0xaaa1 in crash_func /src/lib.c:10:3
    #1 0xbbb2 in caller_func /src/caller.c:20:5
    #2 0xccc3 in helper_func /tmp/case/custom_harness.cpp:40:7
    #3 0xddd4 in LLVMFuzzerTestOneInput /tmp/case/custom_harness.cpp:80:1
    #4 0xeee5 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/tmp/fuzzer+0x123)
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/lib.c:10:3 in crash_func
"""


class TestStackFramePattern(unittest.TestCase):
    """Test the STACK_FRAME_PATTERN and LLVMFuzzerTestOneInput_PATTERN regexes."""

    def test_matches_standard_frame(self):
        line = "    #0 0x5ea4dfe78fe6 in av1_one_pass_cbr_svc_start_layer /root/src/file.c:444:18"
        self.assertIsNotNone(STACK_FRAME_PATTERN.match(line))

    def test_matches_mangled_frame(self):
        line = "    #5 0x5ea4dfa2f68f in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/path/fuzzer+0x46068f)"
        self.assertIsNotNone(STACK_FRAME_PATTERN.match(line))

    def test_no_match_non_frame(self):
        line = "SUMMARY: AddressSanitizer: heap-buffer-overflow"
        self.assertIsNone(STACK_FRAME_PATTERN.match(line))

    def test_no_match_error_line(self):
        line = "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000034"
        self.assertIsNone(STACK_FRAME_PATTERN.match(line))

    def test_llvmfuzzer_entrypoint(self):
        line = "    #4 0x5ea4dfb34b11 in LLVMFuzzerTestOneInput /root/harness.cpp:33:3"
        self.assertIsNotNone(LLVMFuzzerTestOneInput_PATTERN.search(line))


class TestExtractStackTrace(unittest.TestCase):
    """Test extract_stack_trace() from reducer_runner.py."""

    def test_extracts_first_trace_truncated(self):
        result = extract_stack_trace(SAMPLE_ASAN_OUTPUT)
        self.assertIsNotNone(result)
        lines = result.strip().splitlines()
        self.assertEqual(len(lines), 4)  # #0 through #3
        self.assertIn("av1_one_pass_cbr_svc_start_layer", lines[0])
        self.assertIn("aom_codec_encode", lines[3])
        self.assertNotIn("LLVMFuzzerTestOneInput", result)
        self.assertNotIn("fuzzer::Fuzzer::ExecuteCallback", result)

    def test_only_first_trace_with_two_traces(self):
        result = extract_stack_trace(SAMPLE_ASAN_OUTPUT_TWO_TRACES)
        self.assertIsNotNone(result)
        lines = result.strip().splitlines()
        self.assertEqual(len(lines), 2)  # #0, #1 from first trace only
        self.assertIn("crash_func", lines[0])
        self.assertIn("caller_func", lines[1])
        self.assertNotIn("malloc", result)
        self.assertNotIn("alloc_func", result)

    def test_no_stack_trace_returns_none(self):
        output = "SUMMARY: AddressSanitizer: heap-buffer-overflow\nsome other text"
        result = extract_stack_trace(output)
        self.assertIsNone(result)

    def test_ubsan_trace(self):
        result = extract_stack_trace(SAMPLE_UBSAN_OUTPUT)
        self.assertIsNotNone(result)
        lines = result.strip().splitlines()
        self.assertEqual(len(lines), 1)  # #0 only, #1 is LLVMFuzzerTestOneInput
        self.assertIn("buggy_func", lines[0])

    def test_truncates_at_first_harness_frame_when_path_is_known(self):
        result = extract_stack_trace(
            SAMPLE_ASAN_OUTPUT_WITH_HELPER,
            harness_path="/tmp/case/custom_harness.cpp",
        )
        self.assertIsNotNone(result)
        lines = result.strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("crash_func", lines[0])
        self.assertIn("caller_func", lines[1])
        self.assertNotIn("helper_func", result)
        self.assertNotIn("LLVMFuzzerTestOneInput", result)

    def test_crash_tester_same_logic(self):
        """The crash_tester.py copy of extract_stack_trace should produce the same result."""
        result_runner = extract_stack_trace(
            SAMPLE_ASAN_OUTPUT_WITH_HELPER,
            harness_path="/tmp/case/custom_harness.cpp",
        )
        result_tester = ct_extract_stack_trace(
            SAMPLE_ASAN_OUTPUT_WITH_HELPER,
            harness_path="/tmp/case/custom_harness.cpp",
        )
        self.assertEqual(result_runner, result_tester)


class TestNormalizeCrashSignature(unittest.TestCase):
    """Test normalize_crash_signature() for stack trace use."""

    def test_replaces_hex_addresses(self):
        sig = "    #0 0x5ea4dfe78fe6 in func /root/file.c:444:18"
        result = normalize_crash_signature(sig, escape=True)
        self.assertNotIn("5ea4dfe78fe6", result)
        self.assertIn("0x[0-9a-fA-F]+", result)
        # The rest should be escaped
        self.assertIn(r"\#", result)  # # is escaped
        self.assertIn(r"/root", result)

    def test_escape_false_keeps_text(self):
        sig = "SUMMARY: AddressSanitizer: heap-buffer-overflow at 0xdeadbeef"
        result = normalize_crash_signature(sig, escape=False)
        self.assertIn("0x[0-9a-fA-F]+", result)
        self.assertNotIn(r"\:", result)  # colons not escaped in non-escape mode
        self.assertIn("heap-buffer-overflow", result)

    def test_normalized_pattern_matches_shifted_address(self):
        """A pattern normalized from one run should match output with different addresses."""
        original = "    #0 0x5ea4dfe78fe6 in func /root/file.c:444:18"
        pattern = normalize_crash_signature(original, escape=True)
        shifted = "    #0 0xAAAAAAA fe78fe6 in func /root/file.c:444:18"
        # The shifted address format should still match because we only check
        # that the address wildcard matches 0x followed by hex digits.
        different_run = "    #0 0xdeadbeef1234 in func /root/file.c:444:18"
        self.assertIsNotNone(re.search(pattern, different_run))


class TestEffectiveIteration(unittest.TestCase):
    """Test the adaptive iteration logic in crash_tester.py."""

    def test_large_file_uses_base(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cpp", delete=False) as f:
            f.write("\n".join(["int x;"] * 100))
            f.flush()
            result = ct_effective_iteration(100, f.name)
            self.assertEqual(result, 100)
        os.unlink(f.name)

    def test_small_file_uses_small_iteration(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cpp", delete=False) as f:
            f.write("\n".join(["int x;"] * 60))  # between 50 and 75
            f.flush()
            result = ct_effective_iteration(100, f.name)
            self.assertEqual(result, SMALL_HARNESS_ITERATION)
        os.unlink(f.name)

    def test_tiny_file_uses_tiny_iteration(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cpp", delete=False) as f:
            f.write("\n".join(["int x;"] * 30))  # below 50
            f.flush()
            result = ct_effective_iteration(100, f.name)
            self.assertEqual(result, TINY_HARNESS_ITERATION)
        os.unlink(f.name)

    def test_missing_file_uses_base(self):
        result = ct_effective_iteration(100, "/nonexistent/file.cpp")
        self.assertEqual(result, 100)


class TestCounterFile(unittest.TestCase):
    """Test counter file read/write helpers from crash_tester.py."""

    def test_read_counter_missing_file(self):
        self.assertEqual(ct_read_counter("/nonexistent/counter.txt"), 0)

    def test_read_write_roundtrip(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("42")
            f.flush()
            self.assertEqual(ct_read_counter(f.name), 42)
            ct_write_counter(f.name, 43)
            self.assertEqual(ct_read_counter(f.name), 43)
        os.unlink(f.name)

    def test_read_counter_invalid_content(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("not_a_number")
            f.flush()
            self.assertEqual(ct_read_counter(f.name), 0)
        os.unlink(f.name)


class TestCheckStackTrace(unittest.TestCase):
    """Test the _check_stack_trace helper from crash_tester.py."""

    def test_matching_trace_passes(self):
        # Build a stored pattern from the sample output
        raw_trace = extract_stack_trace(SAMPLE_ASAN_OUTPUT)
        pattern = normalize_crash_signature(raw_trace, escape=True)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pattern", delete=False) as f:
            f.write(pattern)
            f.flush()
            trace_file = f.name
        backup_file = tempfile.mktemp(suffix=".cpp")

        # Create a real source file so shutil.copy2 can back it up
        source_file = tempfile.mktemp(suffix=".cpp")
        Path(source_file).write_text("int main() {}", encoding="utf-8")

        try:
            result = ct_check_stack_trace(
                SAMPLE_ASAN_OUTPUT, trace_file, source_file, backup_file
            )
            self.assertTrue(result)
        finally:
            os.unlink(trace_file)
            os.unlink(source_file)
            if os.path.exists(backup_file):
                os.unlink(backup_file)

    def test_non_matching_trace_fails(self):
        # Store a pattern from one crash, test against different output
        raw_trace = extract_stack_trace(SAMPLE_ASAN_OUTPUT)
        pattern = normalize_crash_signature(raw_trace, escape=True)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pattern", delete=False) as f:
            f.write(pattern)
            f.flush()
            trace_file = f.name
        backup_file = tempfile.mktemp(suffix=".cpp")

        different_output = """\
    #0 0x1111 in different_func /other/file.c:1:1
    #1 0x2222 in other_caller /other/file.c:2:2
    #2 0x3333 in LLVMFuzzerTestOneInput /other/harness.cpp:5:1
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""
        try:
            result = ct_check_stack_trace(
                different_output, trace_file, "/fake/source.cpp", backup_file
            )
            self.assertFalse(result)
        finally:
            os.unlink(trace_file)
            if os.path.exists(backup_file):
                os.unlink(backup_file)

    def test_empty_pattern_passes(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pattern", delete=False) as f:
            f.write("")
            f.flush()
            trace_file = f.name
        try:
            result = ct_check_stack_trace(
                "some output", trace_file, "/fake/source.cpp", None
            )
            self.assertTrue(result)
        finally:
            os.unlink(trace_file)

    def test_no_trace_in_output_fails(self):
        raw_trace = extract_stack_trace(SAMPLE_ASAN_OUTPUT)
        pattern = normalize_crash_signature(raw_trace, escape=True)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pattern", delete=False) as f:
            f.write(pattern)
            f.flush()
            trace_file = f.name
        try:
            result = ct_check_stack_trace(
                "No stack trace here, just SUMMARY line", trace_file, "/fake/source.cpp", None
            )
            self.assertFalse(result)
        finally:
            os.unlink(trace_file)

    def test_backup_saved_on_match(self):
        raw_trace = extract_stack_trace(SAMPLE_ASAN_OUTPUT)
        pattern = normalize_crash_signature(raw_trace, escape=True)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pattern", delete=False) as f:
            f.write(pattern)
            f.flush()
            trace_file = f.name

        # Create a fake source file to back up
        source_file = tempfile.mktemp(suffix=".cpp")
        with open(source_file, "w") as f:
            f.write("int main() {}")
        backup_file = tempfile.mktemp(suffix=".backup.cpp")

        try:
            result = ct_check_stack_trace(
                SAMPLE_ASAN_OUTPUT, trace_file, source_file, backup_file
            )
            self.assertTrue(result)
            self.assertTrue(os.path.exists(backup_file))
            self.assertEqual(
                Path(backup_file).read_text(), "int main() {}"
            )
        finally:
            os.unlink(trace_file)
            os.unlink(source_file)
            if os.path.exists(backup_file):
                os.unlink(backup_file)


class TestStackTraceTesterArgs(unittest.TestCase):
    """Test stack_trace_tester_args() from reducer_runner.py."""

    def test_no_iteration_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            result = stack_trace_tester_args(None)
            self.assertEqual(result, [])

    def test_with_iteration_includes_all_args(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            # Create the stack trace file so it's detected
            trace_file = get_stack_trace_file()
            Path(trace_file).write_text("pattern", encoding="utf-8")

            result = stack_trace_tester_args(100)
            self.assertIn("--stack-trace-file", result)
            self.assertIn("--iteration", result)
            self.assertIn("100", result)
            self.assertIn("--counter-file", result)
            self.assertIn("--backup-file", result)

    def test_missing_trace_file_omits_trace_arg(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            # Don't create the stack trace file
            result = stack_trace_tester_args(100)
            self.assertNotIn("--stack-trace-file", result)
            self.assertIn("--iteration", result)
            self.assertIn("100", result)


class TestStackTraceStateManagement(unittest.TestCase):
    def test_reset_stack_trace_state_removes_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            Path(get_stack_trace_file()).write_text("pattern", encoding="utf-8")
            Path(get_stack_trace_counter_file()).write_text("3", encoding="utf-8")
            Path(get_stack_trace_backup_file()).write_text("int main() {}", encoding="utf-8")

            reset_stack_trace_state()

            self.assertFalse(os.path.exists(get_stack_trace_file()))
            self.assertFalse(os.path.exists(get_stack_trace_counter_file()))
            self.assertFalse(os.path.exists(get_stack_trace_backup_file()))

    @patch("harnessreducer.reducer_runner.run_command")
    def test_extract_crash_pattern_without_trace_clears_stale_pattern(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            trace_file = get_stack_trace_file()
            Path(trace_file).write_text("stale-pattern", encoding="utf-8")
            mock_run.return_value.returncode = 77
            mock_run.return_value.stdout = "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
            mock_run.return_value.stderr = ""

            pattern = extract_crash_pattern_from_output(None, harness_path="harness.cpp")

            self.assertEqual(pattern, "SUMMARY: AddressSanitizer: heap-buffer-overflow")
            self.assertFalse(os.path.exists(trace_file))


class TestValidateStackTraceInvocation(unittest.TestCase):
    @patch("harnessreducer.reducer_runner.run_command")
    def test_validate_stack_trace_passes_separate_cli_args(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            Path(get_stack_trace_file()).write_text("pattern", encoding="utf-8")
            mock_run.return_value.returncode = 77
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""

            ok = validate_stack_trace(
                "candidate.cpp",
                "AddressSanitizer",
                "seed.bin",
                "-O2",
                "-lm",
                fdp_trace_file="/tmp/fdp.log",
            )

            self.assertTrue(ok)
            cmd = mock_run.call_args.args[0]
            self.assertIn("--compile-flags=-O2", cmd)
            self.assertIn("--link-flags=-lm", cmd)
            self.assertIn("--symbolize", cmd)
            self.assertIn("--stack-trace-file", cmd)
            broken_arg = "--compile-flags=-O2--link-flags=-lm--symbolize"
            self.assertNotIn(broken_arg, cmd)


if __name__ == "__main__":
    unittest.main()

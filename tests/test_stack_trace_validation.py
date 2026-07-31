"""Unit tests for stack trace extraction, normalization, and validation logic.

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
    DynamicCrashSite,
    MEMORY_ADDRESS_PATTERN,
    STACK_FRAME_PATTERN,
    LLVMFuzzerTestOneInput_PATTERN,
    count_first_stack_trace_frames,
    dynamic_crash_site_tester_args,
    extract_crash_pattern_from_output,
    extract_first_dynamic_library_crash_site,
    extract_first_sanitizer_stack_trace,
    extract_stack_trace,
    extract_symbolized_crash_location,
    get_crash_pattern_file,
    get_dynamic_crash_site_file,
    get_dynamic_reference_crash_site,
    get_normal_reference_stack_depth,
    get_reference_crash_pattern_symbolize_0,
    get_reference_crash_pattern_symbolize_1,
    get_symbolized_crash_location_file,
    get_symbolized_reference_crash_location_pattern,
    get_symbolized_reference_stack_depth,
    has_static_target_libraries,
    infer_target_dynamic_library_hints,
    normalize_crash_signature,
    get_stack_trace_file,
    reset_stack_trace_state,
    set_dynamic_reference_crash_site,
    set_symbolized_reference_crash_location_pattern,
    set_normal_reference_stack_depth,
    set_symbolized_reference_stack_depth,
    stack_depth_tester_args,
    symbolized_crash_location_tester_args,
    validate_symbolized_crash_pattern_depth_location,
    validate_crash_pattern_and_stack_trace,
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
ct_check_stack_trace = _ct_module._check_stack_trace
ct_check_crash_location_pattern = _ct_module._check_crash_location_pattern
ct_check_crash_location = _ct_module._check_crash_location
ct_check_dynamic_crash_site = _ct_module._check_dynamic_crash_site
ct_stack_depth_is_advisory = _ct_module._stack_depth_is_advisory
ct_compile_error_mentions_uninitialized = _ct_module.compile_error_mentions_uninitialized


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

SAMPLE_ASAN_OUTPUT_UNSYMBOLIZED = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000034
    #0 0xaaa1  (/tmp/poc.out+0x111)
    #1 0xbbb2  (/tmp/poc.out+0x222)
    #2 0xccc3  (/tmp/poc.out+0x333)

allocated by thread T0 here:
    #0 0xddd4  (/tmp/poc.out+0x444)
SUMMARY: AddressSanitizer: heap-buffer-overflow (/tmp/poc.out+0x111)
"""

SAMPLE_DYNAMIC_LIBRARY_OUTPUT = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1111  (/lib/x86_64-linux-gnu/libc.so.6+0x9eb2c)
    #1 0x2222  (/tmp/build/lib/libtarget.so+0xbeaf0)
    #2 0x3333  (/tmp/harness+0x123)

allocated by thread T0 here:
    #0 0x4444  (/tmp/build/lib/libtarget.so+0x999)
SUMMARY: AddressSanitizer: heap-buffer-overflow (/tmp/build/lib/libtarget.so+0xbeaf0)
"""

SAMPLE_DYNAMIC_LIBRARY_FIRST_TRACE_OUTPUT = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1111  (/tmp/build/lib/libaom.so+0x201cf25)
    #1 0x2222  (/tmp/harness+0x123)

allocated by thread T0 here:
    #0 0x3333  (/tmp/build/lib/libaom.so+0x13ce1c3)
SUMMARY: AddressSanitizer: heap-buffer-overflow (/tmp/build/lib/libaom.so+0x201cf25)
"""


class TestStackFramePattern(unittest.TestCase):
    """Test the STACK_FRAME_PATTERN and LLVMFuzzerTestOneInput_PATTERN regexes."""

    def setUp(self):
        set_normal_reference_stack_depth(None)
        set_symbolized_reference_stack_depth(None)

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

    def test_extract_first_sanitizer_stack_trace_supports_unsymbolized_output(self):
        self.assertEqual(
            extract_first_sanitizer_stack_trace(SAMPLE_ASAN_OUTPUT_UNSYMBOLIZED),
            "    #0 0xaaa1  (/tmp/poc.out+0x111)\n"
            "    #1 0xbbb2  (/tmp/poc.out+0x222)\n"
            "    #2 0xccc3  (/tmp/poc.out+0x333)",
        )

    def test_count_first_stack_trace_frames_supports_unsymbolized_output(self):
        self.assertEqual(
            count_first_stack_trace_frames(SAMPLE_ASAN_OUTPUT_UNSYMBOLIZED),
            3,
        )

    def test_extract_symbolized_crash_location_uses_first_pre_harness_source_location(self):
        self.assertEqual(
            extract_symbolized_crash_location(
                SAMPLE_ASAN_OUTPUT_WITH_HELPER,
                harness_path="/tmp/case/custom_harness.cpp",
            ),
            "/src/lib.c:10:3",
        )

    def test_extract_symbolized_crash_location_skips_abort_wrapper_frames(self):
        output = """\
==12345==ERROR: AddressSanitizer: ABRT
    #0 0xaaa in __pthread_kill_implementation nptl/pthread_kill.c:44:76
    #1 0xbbb in __pthread_kill_internal nptl/pthread_kill.c:78:10
    #2 0xccc in pthread_kill nptl/pthread_kill.c:89:10
    #3 0xddd in raise signal/../sysdeps/posix/raise.c:26:13
    #4 0xeee in abort stdlib/abort.c:79:7
    #5 0xfff in pcapint_filter_with_aux_data /root/src/libpcap/bpf_filter.c:112:4
    #6 0x111 in LLVMFuzzerTestOneInput /tmp/harness.cpp:19:3
SUMMARY: AddressSanitizer: ABRT
"""
        self.assertEqual(
            extract_symbolized_crash_location(output, harness_path="/tmp/harness.cpp"),
            "/root/src/libpcap/bpf_filter.c:112:4",
        )

    def test_extract_symbolized_crash_location_skips_sanitizer_wrapper_frames(self):
        output = """\
==12345==ERROR: AddressSanitizer: negative-size-param: (size=-4)
    #0 0xaaa in __asan_memset /root/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:31:3
    #1 0xbbb in _lou_backTranslate /root/src/liblouis/liblouis/lou_backTranslateString.c:257:23
    #2 0xccc in lou_backTranslate /root/src/liblouis/liblouis/lou_backTranslateString.c:179:9
    #3 0xddd in LLVMFuzzerTestOneInput /tmp/harness.cpp:42:3
SUMMARY: AddressSanitizer: negative-size-param
"""
        self.assertEqual(
            extract_symbolized_crash_location(output, harness_path="/tmp/harness.cpp"),
            "/root/src/liblouis/liblouis/lou_backTranslateString.c:257:23",
        )

    def test_extract_symbolized_crash_location_returns_none_without_source_location(self):
        self.assertIsNone(
            extract_symbolized_crash_location(SAMPLE_ASAN_OUTPUT_UNSYMBOLIZED)
        )


class TestDynamicCrashSiteExtraction(unittest.TestCase):
    def setUp(self):
        set_dynamic_reference_crash_site(None)

    def test_extracts_first_target_library_offset_from_first_trace_only(self):
        site = extract_first_dynamic_library_crash_site(
            SAMPLE_DYNAMIC_LIBRARY_FIRST_TRACE_OUTPUT,
            "-laom",
        )

        self.assertIsNotNone(site)
        self.assertEqual(site.library_name, "libaom.so")
        self.assertEqual(site.offset, "0x201cf25")

    def test_uses_crash_output_when_link_flags_have_no_library_directory(self):
        site = extract_first_dynamic_library_crash_site(
            SAMPLE_DYNAMIC_LIBRARY_OUTPUT,
            "-ltarget -lpthread",
        )

        self.assertIsNotNone(site)
        self.assertEqual(site.library_path, "/tmp/build/lib/libtarget.so")
        self.assertEqual(site.offset, "0xbeaf0")

    def test_expected_library_offset_search_uses_same_first_trace(self):
        site = extract_first_dynamic_library_crash_site(
            SAMPLE_DYNAMIC_LIBRARY_OUTPUT,
            expected_library="/other/location/libtarget.so.1",
        )

        self.assertIsNotNone(site)
        self.assertEqual(site.library_name, "libtarget.so")
        self.assertEqual(site.offset, "0xbeaf0")

    def test_expected_library_match_does_not_query_filesystem(self):
        with patch("pathlib.Path.exists", side_effect=AssertionError("no fs")):
            with patch("pathlib.Path.resolve", side_effect=AssertionError("no fs")):
                site = extract_first_dynamic_library_crash_site(
                    SAMPLE_DYNAMIC_LIBRARY_OUTPUT,
                    expected_library="/tmp/build/lib/libtarget.so",
                )

        self.assertIsNotNone(site)
        self.assertEqual(site.offset, "0xbeaf0")

    def test_static_target_does_not_enable_unresolved_dependency_fallback(self):
        site = extract_first_dynamic_library_crash_site(
            SAMPLE_DYNAMIC_LIBRARY_OUTPUT,
            "/tmp/build/lib/libtarget.a -ldependency",
        )

        self.assertIsNone(site)

    def test_static_target_detection_handles_explicit_archive_and_bstatic(self):
        self.assertTrue(has_static_target_libraries("/tmp/build/lib/libtarget.a -lm"))
        self.assertTrue(
            has_static_target_libraries("-Wl,-Bstatic -ltarget -Wl,-Bdynamic")
        )

    def test_static_target_detection_prefers_shared_for_plain_l_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lib_dir = Path(tmpdir)
            (lib_dir / "libtarget.so").write_text("", encoding="utf-8")
            (lib_dir / "libtarget.a").write_text("", encoding="utf-8")

            self.assertFalse(has_static_target_libraries(f"-L{lib_dir} -ltarget"))

    def test_dynamic_hints_keep_unresolved_l_names_without_static_targets(self):
        hints = infer_target_dynamic_library_hints("-ltarget -ldependency")

        self.assertIn("libtarget.so", hints.exact_names)
        self.assertTrue(hints.allow_output_fallback)


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

        try:
            result = ct_check_stack_trace(
                SAMPLE_ASAN_OUTPUT, trace_file, "/tmp/source.cpp"
            )
            self.assertTrue(result)
        finally:
            os.unlink(trace_file)


    def test_non_matching_trace_fails(self):
        # Store a pattern from one crash, test against different output
        raw_trace = extract_stack_trace(SAMPLE_ASAN_OUTPUT)
        pattern = normalize_crash_signature(raw_trace, escape=True)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pattern", delete=False) as f:
            f.write(pattern)
            f.flush()
            trace_file = f.name
        different_output = """\
    #0 0x1111 in different_func /other/file.c:1:1
    #1 0x2222 in other_caller /other/file.c:2:2
    #2 0x3333 in LLVMFuzzerTestOneInput /other/harness.cpp:5:1
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""
        try:
            result = ct_check_stack_trace(
                different_output, trace_file, "/fake/source.cpp"
            )
            self.assertFalse(result)
        finally:
            os.unlink(trace_file)

    def test_dynamic_offset_check_passes_and_fails(self):
        self.assertTrue(
            ct_check_dynamic_crash_site(
                SAMPLE_DYNAMIC_LIBRARY_OUTPUT,
                "/tmp/build/lib/libtarget.so",
                "0xbeaf0",
            )
        )
        self.assertFalse(
            ct_check_dynamic_crash_site(
                SAMPLE_DYNAMIC_LIBRARY_OUTPUT,
                "/tmp/build/lib/libtarget.so",
                "0x999",
            )
        )

    def test_crash_location_check_passes_and_fails(self):
        pattern = normalize_crash_signature("/src/lib.c:10:3", escape=True)
        self.assertTrue(
            ct_check_crash_location_pattern(
                SAMPLE_ASAN_OUTPUT_WITH_HELPER,
                pattern,
                "/tmp/case/custom_harness.cpp",
            )
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pattern", delete=False) as f:
            f.write(pattern)
            f.flush()
            location_file = f.name

        try:
            self.assertTrue(
                ct_check_crash_location(
                    SAMPLE_ASAN_OUTPUT_WITH_HELPER,
                    location_file,
                    "/tmp/case/custom_harness.cpp",
                )
            )
            self.assertFalse(
                ct_check_crash_location(
                    SAMPLE_ASAN_OUTPUT,
                    location_file,
                    "/tmp/case/custom_harness.cpp",
                )
            )
        finally:
            os.unlink(location_file)


class TestCrashTesterCompileDiagnostics(unittest.TestCase):
    def test_compile_error_mentions_uninitialized_detects_warning_error(self):
        self.assertTrue(
            ct_compile_error_mentions_uninitialized(
                "error: variable 'mode' is uninitialized when used here [-Wuninitialized]"
            )
        )

    def test_compile_error_mentions_uninitialized_ignores_other_errors(self):
        self.assertFalse(
            ct_compile_error_mentions_uninitialized(
                "error: use of undeclared identifier 'foo'"
            )
        )

    def test_empty_pattern_passes(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pattern", delete=False) as f:
            f.write("")
            f.flush()
            trace_file = f.name
        try:
            result = ct_check_stack_trace(
                "some output", trace_file, "/fake/source.cpp"
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
                "No stack trace here, just SUMMARY line", trace_file, "/fake/source.cpp"
            )
            self.assertFalse(result)
        finally:
            os.unlink(trace_file)

    @patch("harnessreducer.reducer_runner.run_command")
    def test_extract_crash_pattern_records_reference_stack_depth(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            mock_run.side_effect = [
                type("Proc", (), {"returncode": 77, "stdout": SAMPLE_DYNAMIC_LIBRARY_OUTPUT, "stderr": ""})(),
                type("Proc", (), {"returncode": 77, "stdout": SAMPLE_ASAN_OUTPUT, "stderr": ""})(),
            ]

            extract_crash_pattern_from_output(
                None,
                harness_path="harness.cpp",
                link_flags="-ltarget -lpthread",
            )

            self.assertEqual(get_normal_reference_stack_depth(), 3)
            self.assertEqual(get_symbolized_reference_stack_depth(), 6)
            self.assertEqual(
                get_reference_crash_pattern_symbolize_0(),
                "SUMMARY: AddressSanitizer: heap-buffer-overflow",
            )
            self.assertEqual(
                get_reference_crash_pattern_symbolize_1(),
                "SUMMARY: AddressSanitizer: heap-buffer-overflow",
            )
            self.assertTrue(os.path.exists(get_crash_pattern_file(symbolized=False)))
            self.assertTrue(os.path.exists(get_crash_pattern_file(symbolized=True)))
            self.assertEqual(stack_depth_tester_args(symbolized=False), ["--stack-depth", "3"])
            self.assertEqual(stack_depth_tester_args(symbolized=True), ["--stack-depth", "6"])
            self.assertEqual(
                dynamic_crash_site_tester_args(),
                [
                    "--dynamic-crash-site-library",
                    "/tmp/build/lib/libtarget.so",
                    "--dynamic-crash-site-offset",
                    "0xbeaf0",
                ],
            )

    @patch("harnessreducer.reducer_runner.run_command")
    def test_extract_crash_pattern_records_distinct_symbolized_pattern(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            fast_output = "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
            symbolized_output = (
                "/root/src/opencv/modules/imgproc/src/drawing.cpp:1142:13: "
                "runtime error: left shift of negative value -1\n"
                "    #0 0xaaa in cv::line /root/src/opencv/modules/imgproc/src/drawing.cpp:1142:13\n"
                "    #1 0xbbb in LLVMFuzzerTestOneInput /tmp/harness.cpp:10:3\n"
            )
            mock_run.side_effect = [
                type("Proc", (), {"returncode": 77, "stdout": fast_output, "stderr": ""})(),
                type("Proc", (), {"returncode": 77, "stdout": symbolized_output, "stderr": ""})(),
            ]

            pattern = extract_crash_pattern_from_output(
                None,
                harness_path="harness.cpp",
            )

            self.assertEqual(pattern, "SUMMARY: AddressSanitizer: heap-buffer-overflow")
            self.assertEqual(
                get_reference_crash_pattern_symbolize_0(),
                "SUMMARY: AddressSanitizer: heap-buffer-overflow",
            )
            self.assertEqual(
                get_reference_crash_pattern_symbolize_1(),
                r"/root/src/opencv/modules/imgproc/src/drawing\.cpp:1142:13:\ runtime\ error:\ left\ shift\ of\ negative\ value\ \-1",
            )

    @patch("harnessreducer.reducer_runner.run_command")
    def test_extract_crash_pattern_records_symbolized_crash_location_when_requested(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            mock_run.side_effect = [
                type("Proc", (), {"returncode": 77, "stdout": SAMPLE_DYNAMIC_LIBRARY_OUTPUT, "stderr": ""})(),
                type("Proc", (), {"returncode": 77, "stdout": SAMPLE_ASAN_OUTPUT_WITH_HELPER, "stderr": ""})(),
            ]

            extract_crash_pattern_from_output(
                None,
                harness_path="/tmp/case/custom_harness.cpp",
                link_flags="-ltarget -lpthread",
                record_symbolized_crash_location=True,
            )

            expected_pattern = normalize_crash_signature("/src/lib.c:10:3", escape=True)
            self.assertEqual(
                get_symbolized_reference_crash_location_pattern(),
                expected_pattern,
            )
            self.assertEqual(
                Path(get_symbolized_crash_location_file()).read_text(encoding="utf-8").strip(),
                expected_pattern,
            )
            self.assertEqual(
                symbolized_crash_location_tester_args(),
                ["--crash-location-pattern", expected_pattern],
            )

    @patch("harnessreducer.reducer_runner.run_command")
    def test_extract_crash_pattern_does_not_record_crash_location_by_default(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            Path(get_symbolized_crash_location_file()).write_text(
                "stale-location", encoding="utf-8"
            )
            set_symbolized_reference_crash_location_pattern("stale-location")
            mock_run.side_effect = [
                type("Proc", (), {"returncode": 77, "stdout": SAMPLE_DYNAMIC_LIBRARY_OUTPUT, "stderr": ""})(),
                type("Proc", (), {"returncode": 77, "stdout": SAMPLE_ASAN_OUTPUT_WITH_HELPER, "stderr": ""})(),
            ]

            extract_crash_pattern_from_output(
                None,
                harness_path="/tmp/case/custom_harness.cpp",
                link_flags="-ltarget -lpthread",
            )

            self.assertIsNone(get_symbolized_reference_crash_location_pattern())
            self.assertFalse(os.path.exists(get_symbolized_crash_location_file()))


class TestStackTraceStateManagement(unittest.TestCase):
    def test_reset_stack_trace_state_removes_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            Path(get_stack_trace_file()).write_text("pattern", encoding="utf-8")
            Path(get_crash_pattern_file(symbolized=False)).write_text(
                "fast-pattern", encoding="utf-8"
            )
            Path(get_crash_pattern_file(symbolized=True)).write_text(
                "symbolized-pattern", encoding="utf-8"
            )
            Path(get_dynamic_crash_site_file()).write_text("{}", encoding="utf-8")
            Path(get_symbolized_crash_location_file()).write_text(
                "location-pattern", encoding="utf-8"
            )
            set_dynamic_reference_crash_site(
                DynamicCrashSite(
                    library_path="/tmp/libtarget.so",
                    library_name="libtarget.so",
                    offset="0x123",
                )
            )
            set_symbolized_reference_crash_location_pattern("location-pattern")

            reset_stack_trace_state()

            self.assertFalse(os.path.exists(get_stack_trace_file()))
            self.assertFalse(os.path.exists(get_crash_pattern_file(symbolized=False)))
            self.assertFalse(os.path.exists(get_crash_pattern_file(symbolized=True)))
            self.assertFalse(os.path.exists(get_dynamic_crash_site_file()))
            self.assertFalse(os.path.exists(get_symbolized_crash_location_file()))
            self.assertIsNone(get_reference_crash_pattern_symbolize_0())
            self.assertIsNone(get_reference_crash_pattern_symbolize_1())
            self.assertIsNone(get_dynamic_reference_crash_site())
            self.assertIsNone(get_symbolized_reference_crash_location_pattern())

    @patch("harnessreducer.reducer_runner.run_command")
    def test_extract_crash_pattern_without_trace_clears_stale_pattern(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            trace_file = get_stack_trace_file()
            Path(trace_file).write_text("stale-pattern", encoding="utf-8")
            dynamic_file = get_dynamic_crash_site_file()
            Path(dynamic_file).write_text("stale-dynamic-site", encoding="utf-8")
            mock_run.side_effect = [
                type("Proc", (), {"returncode": 77, "stdout": "SUMMARY: AddressSanitizer: heap-buffer-overflow\n", "stderr": ""})(),
                type("Proc", (), {"returncode": 77, "stdout": "SUMMARY: AddressSanitizer: heap-buffer-overflow\n", "stderr": ""})(),
            ]

            pattern = extract_crash_pattern_from_output(None, harness_path="harness.cpp")

            self.assertEqual(pattern, "SUMMARY: AddressSanitizer: heap-buffer-overflow")
            self.assertFalse(os.path.exists(trace_file))
            self.assertFalse(os.path.exists(dynamic_file))
            self.assertTrue(os.path.exists(get_crash_pattern_file(symbolized=False)))
            self.assertTrue(os.path.exists(get_crash_pattern_file(symbolized=True)))


class TestValidateStackTraceInvocation(unittest.TestCase):
    def test_fast_stack_depth_is_strict_without_dynamic_crash_site_anchor(self):
        args = type(
            "Args",
            (),
            {
                "dynamic_crash_site_library": None,
                "dynamic_crash_site_offset": None,
            },
        )()
        self.assertFalse(ct_stack_depth_is_advisory(args, use_symbolize=False))

    def test_fast_stack_depth_stays_advisory_with_dynamic_crash_site_anchor(self):
        args = type(
            "Args",
            (),
            {
                "dynamic_crash_site_library": "/tmp/build/lib/libtarget.so",
                "dynamic_crash_site_offset": "0xbeaf0",
            },
        )()
        self.assertTrue(ct_stack_depth_is_advisory(args, use_symbolize=False))

    def test_symbolized_stack_depth_stays_advisory(self):
        args = type(
            "Args",
            (),
            {
                "dynamic_crash_site_library": None,
                "dynamic_crash_site_offset": None,
            },
        )()
        self.assertTrue(ct_stack_depth_is_advisory(args, use_symbolize=True))

    @patch("harnessreducer.reducer_runner.run_command")
    def test_validate_stack_trace_passes_separate_cli_args(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            set_symbolized_reference_stack_depth(6)
            expected_pattern = normalize_crash_signature("/src/lib.c:10:3", escape=True)
            set_symbolized_reference_crash_location_pattern(expected_pattern)
            set_dynamic_reference_crash_site(
                DynamicCrashSite(
                    library_path="/tmp/build/lib/libtarget.so",
                    library_name="libtarget.so",
                    offset="0xbeaf0",
                )
            )
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
            self.assertIn("--stack-depth", cmd)
            self.assertNotIn("--dynamic-crash-site-library", cmd)
            self.assertNotIn("--dynamic-crash-site-offset", cmd)
            broken_arg = "--compile-flags=-O2--link-flags=-lm--symbolize"
            self.assertNotIn(broken_arg, cmd)

    @patch("harnessreducer.reducer_runner.run_command")
    def test_validate_symbolized_crash_location_oracle_passes_expected_args(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            set_symbolized_reference_stack_depth(6)
            expected_pattern = normalize_crash_signature("/src/lib.c:10:3", escape=True)
            set_symbolized_reference_crash_location_pattern(expected_pattern)
            set_dynamic_reference_crash_site(
                DynamicCrashSite(
                    library_path="/tmp/build/lib/libtarget.so",
                    library_name="libtarget.so",
                    offset="0xbeaf0",
                )
            )
            mock_run.return_value.returncode = 77
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""

            ok = validate_symbolized_crash_pattern_depth_location(
                "candidate.cpp",
                "AddressSanitizer",
                "seed.bin",
                "-O2",
                "-lm",
                fdp_trace_file="/tmp/fdp.log",
            )

            self.assertTrue(ok)
            cmd = mock_run.call_args.args[0]
            self.assertIn("--symbolize", cmd)
            self.assertIn("--stack-depth", cmd)
            self.assertIn("6", cmd)
            self.assertIn("--crash-location-pattern", cmd)
            self.assertIn(expected_pattern, cmd)
            self.assertIn("--fdp-trace", cmd)
            self.assertNotIn("--crash-location-file", cmd)
            self.assertNotIn("--stack-trace-file", cmd)
            self.assertNotIn("--dynamic-crash-site-library", cmd)
            self.assertNotIn("--dynamic-crash-site-offset", cmd)

    @patch("harnessreducer.reducer_runner.run_command")
    def test_validate_stack_trace_without_stored_pattern_still_runs(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            set_symbolized_reference_stack_depth(6)
            set_dynamic_reference_crash_site(None)
            mock_run.return_value.returncode = 77
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""

            ok = validate_stack_trace(
                "candidate.cpp",
                "AddressSanitizer",
                "seed.bin",
                "-O2",
                "-lm",
            )

            self.assertTrue(ok)
            cmd = mock_run.call_args.args[0]
            self.assertIn("--symbolize", cmd)
            self.assertIn("--stack-depth", cmd)
            self.assertNotIn("--stack-trace-file", cmd)

    @patch("harnessreducer.reducer_runner.run_command")
    def test_validate_stack_trace_writes_failure_log_when_requested(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            set_symbolized_reference_stack_depth(6)
            set_dynamic_reference_crash_site(None)
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = "oops stdout\n"
            mock_run.return_value.stderr = "oops stderr\n"
            log_path = Path(tmpdir) / "validation.log"

            ok = validate_stack_trace(
                "candidate.cpp",
                "AddressSanitizer",
                "seed.bin",
                "-O2",
                "-lm",
                validation_log_path=str(log_path),
            )

            self.assertFalse(ok)
            log_text = log_path.read_text(encoding="utf-8")
            self.assertIn("returncode: 1", log_text)
            self.assertIn("oops stdout", log_text)
            self.assertIn("oops stderr", log_text)

    @patch("harnessreducer.reducer_runner.run_command")
    def test_validate_stack_trace_can_skip_symbolized_crash_pattern(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            set_symbolized_reference_stack_depth(6)
            mock_run.return_value.returncode = 77
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""

            ok = validate_stack_trace(
                "candidate.cpp",
                None,
                "seed.bin",
                "-O2",
                "-lm",
                require_crash_pattern=False,
            )

            self.assertTrue(ok)
            cmd = mock_run.call_args.args[0]
            self.assertIn("--symbolize", cmd)
            self.assertIn("--skip-crash-pattern", cmd)
            self.assertIn(".*", cmd)

    @patch("harnessreducer.reducer_runner.run_command")
    def test_validate_crash_pattern_and_stack_trace_decouples_patterns(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            set_normal_reference_stack_depth(3)
            set_symbolized_reference_stack_depth(6)
            mock_run.return_value.returncode = 77
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""

            ok = validate_crash_pattern_and_stack_trace(
                "candidate.cpp",
                "FastPattern",
                None,
                "seed.bin",
                "-O2",
                "-lm",
                fdp_trace_file="/tmp/fdp.log",
            )

            self.assertTrue(ok)
            self.assertEqual(mock_run.call_count, 2)
            fast_cmd = mock_run.call_args_list[0].args[0]
            symbolized_cmd = mock_run.call_args_list[1].args[0]
            self.assertIn("FastPattern", fast_cmd)
            self.assertNotIn("--symbolize", fast_cmd)
            self.assertIn("--symbolize", symbolized_cmd)
            self.assertIn("--skip-crash-pattern", symbolized_cmd)
            self.assertIn(".*", symbolized_cmd)


if __name__ == "__main__":
    unittest.main()

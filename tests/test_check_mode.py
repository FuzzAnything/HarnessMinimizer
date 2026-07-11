import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harnessreducer.check_mode import (
    CheckReference,
    append_candidate_stack_trace,
    count_stack_trace_frames,
    extract_first_entire_stack_trace,
    get_check_candidate_stack_traces_file,
    get_check_reference_file,
    get_check_statistics_file,
    initialize_check_statistics_file,
    read_check_statistics,
    load_check_reference,
    reset_check_state,
    record_check_statistics,
    run_treereducer_with_check,
    write_check_reference,
)
from harnessreducer import reducer_runner
from harnessreducer.reducer_runner import configure_work_dir

SAMPLE_OUTPUT = """\
=================================================================
==1953==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x76923a00faf4
    #0 0x5ef838c11ae5 in av1_one_pass_cbr_svc_start_layer /root/src/libaom/av1/encoder/svc_layercontext.c:447:18
    #1 0x5ef8386dec7e in av1_get_compressed_data /root/src/libaom/av1/encoder/encoder.c:5338:5
    #2 0x5ef838494e3f in encoder_encode /root/src/libaom/av1/av1_cx_iface.c:3639:20
    #3 0x5ef83846b79c in aom_codec_encode /root/src/libaom/aom/src/aom_encoder.c:191:11
    #4 0x5ef83845b6b0 in LLVMFuzzerTestOneInput /tmp/harness.cpp:240:9
    #5 0x5ef83835270f in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/tmp/harness+0xa8d70f)
    #6 0x5ef83833a213 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/tmp/harness+0xa75213)

allocated by thread T0 here:
    #0 0x5ef838412098 in malloc (/tmp/harness+0xb4d098)
    #1 0x5ef838476ae3 in aom_memalign /root/src/libaom/aom_mem/aom_mem.c:59:22
"""


class TestCheckModeHelpers(unittest.TestCase):
    def setUp(self):
        reducer_runner.TREEDUCER_DIR = None
        reducer_runner._IS_USER_WORK_DIR = False

    def test_extract_first_entire_stack_trace_keeps_full_first_trace(self):
        trace = extract_first_entire_stack_trace(SAMPLE_OUTPUT)
        self.assertIsNotNone(trace)
        lines = trace.splitlines()
        self.assertEqual(len(lines), 7)
        self.assertIn("LLVMFuzzerTestOneInput", trace)
        self.assertIn("fuzzer::RunOneTest", trace)
        self.assertNotIn("malloc", trace)

    def test_count_stack_trace_frames_counts_frame_lines_directly(self):
        trace = extract_first_entire_stack_trace(SAMPLE_OUTPUT)
        self.assertEqual(count_stack_trace_frames(trace), 7)

    def test_check_statistics_roundtrip_and_ratio(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            path = initialize_check_statistics_file()
            record_check_statistics(path, level_same=True, stack_same=False)
            record_check_statistics(path, level_same=True, stack_same=True)
            record_check_statistics(path, level_same=False, stack_same=False)
            stats = read_check_statistics(path)
            self.assertEqual(stats.level_same, 2)
            self.assertEqual(stats.stack_same, 1)
            self.assertAlmostEqual(stats.ratio, 0.5)

    def test_write_check_reference_includes_frame_count(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            reference = CheckReference(
                crash_pattern="AddressSanitizer",
                full_stack_trace="#0 ...\n#1 ...",
                full_stack_trace_pattern="\\#0.*\\#1.*",
                frame_count=2,
            )
            path = write_check_reference(reference)
            text = Path(path).read_text(encoding="utf-8")
            self.assertIn('"frame_count": 2', text)
            self.assertIn('"crash_pattern": "AddressSanitizer"', text)

    def test_append_candidate_stack_trace_writes_log_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            log_path = get_check_candidate_stack_traces_file()
            append_candidate_stack_trace(
                log_path,
                source_path="/tmp/candidate.cpp",
                crash_pattern_matched=True,
                frame_count=2,
                level_same=True,
                stack_same=False,
                full_stack_trace="#0 in foo\n#1 in bar\n#2 in harness",
                compare_stack_trace="#0 in foo\n#1 in bar",
                candidate_code="int main() { return 0; }\n",
            )
            text = Path(log_path).read_text(encoding="utf-8")
            self.assertIn("source: /tmp/candidate.cpp", text)
            self.assertIn("crash_pattern_matched: True", text)
            self.assertIn("frame_count: 2", text)
            self.assertIn("#0 in foo", text)
            self.assertIn("compare_stack_trace:", text)
            self.assertIn("compile_failed: False", text)
            self.assertIn("uninitialized_compile_error: False", text)
            self.assertIn("candidate_code:", text)
            self.assertIn("int main() { return 0; }", text)

    def test_append_candidate_stack_trace_writes_compile_failure_details(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            log_path = get_check_candidate_stack_traces_file()
            append_candidate_stack_trace(
                log_path,
                source_path="/tmp/candidate.cpp",
                crash_pattern_matched=False,
                frame_count=0,
                level_same=False,
                stack_same=False,
                full_stack_trace=None,
                compare_stack_trace=None,
                compile_failed=True,
                uninitialized_compile_error=True,
                compile_error="variable 'x' is uninitialized when used here [-Wuninitialized]",
            )
            text = Path(log_path).read_text(encoding="utf-8")
            self.assertIn("compile_failed: True", text)
            self.assertIn("uninitialized_compile_error: True", text)
            self.assertIn("compile_error:", text)
            self.assertIn("[-Wuninitialized]", text)

    def test_reset_check_state_removes_stack_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            log_path = Path(get_check_candidate_stack_traces_file())
            log_path.write_text("data", encoding="utf-8")
            reset_check_state()
            self.assertFalse(log_path.exists())

    @patch("harnessreducer.check_mode.os.path.exists", return_value=True)
    @patch("harnessreducer.check_mode.subprocess.run")
    def test_run_treereducer_with_check_skips_last_interesting_file_by_default(
        self,
        mock_run,
        _mock_exists,
    ):
        mock_run.return_value = type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            write_check_reference(
                CheckReference(
                    crash_pattern="AddressSanitizer",
                    full_stack_trace="#0 ...",
                    full_stack_trace_pattern="\\#0.*",
                    frame_count=1,
                )
            )
            initialize_check_statistics_file()

            out = run_treereducer_with_check(
                harness_path="/tmp/in.cpp",
                fdp_trace_file="/tmp/trace.log",
                crash_pattern="AddressSanitizer",
                compile_flags="-std=c++17",
                link_flags="-lm",
                crash_input="seed.bin",
            )

            self.assertTrue(out.endswith("reduced_harness.cpp"))
            cmd = mock_run.call_args.args[0]
            self.assertIn("--check-reference-file", cmd)
            self.assertIn(get_check_reference_file(), cmd)
            self.assertIn("--check-statistics-file", cmd)
            self.assertIn("--split", cmd)
            self.assertNotIn("--last-interesting-file", cmd)

    @patch("harnessreducer.check_mode.run_amortized_reference_candidate")
    @patch("harnessreducer.check_mode.start_amortized_runner")
    @patch("harnessreducer.check_mode.os.path.exists", return_value=True)
    @patch("harnessreducer.check_mode.subprocess.run")
    def test_check_mode_uses_amortized_runner_reference(
        self,
        mock_run,
        _mock_exists,
        mock_start_runner,
        mock_reference,
    ):
        mock_run.return_value = type(
            "Proc", (), {"returncode": 0, "stdout": "", "stderr": ""}
        )()
        mock_start_runner.return_value = nullcontext(
            SimpleNamespace(socket_path="/tmp/fahm-check.sock")
        )
        mock_reference.return_value = SAMPLE_OUTPUT

        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            write_check_reference(
                CheckReference(
                    crash_pattern="AddressSanitizer",
                    full_stack_trace="#0 old",
                    full_stack_trace_pattern="old",
                    frame_count=1,
                )
            )
            (Path(tmpdir) / "stack_trace.pattern").write_text(
                "target", encoding="utf-8"
            )

            run_treereducer_with_check(
                harness_path="/tmp/in.cpp",
                fdp_trace_file="/tmp/trace.log",
                crash_pattern="AddressSanitizer",
                compile_flags=None,
                link_flags="/tmp/libtarget.so",
                crash_input="seed.bin",
                amortize_link=True,
            )

            cmd = mock_run.call_args.args[0]
            self.assertIn("--amortized-runner-socket", cmd)
            self.assertIn("/tmp/fahm-check.sock", cmd)
            self.assertEqual(load_check_reference().frame_count, 7)

    @patch("harnessreducer.check_mode.os.path.exists", return_value=True)
    @patch("harnessreducer.check_mode.subprocess.run")
    def test_run_treereducer_with_check_passes_last_interesting_file_when_enabled(
        self,
        mock_run,
        _mock_exists,
    ):
        mock_run.return_value = type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            write_check_reference(
                CheckReference(
                    crash_pattern="AddressSanitizer",
                    full_stack_trace="#0 ...",
                    full_stack_trace_pattern="\\#0.*",
                    frame_count=1,
                )
            )
            initialize_check_statistics_file()

            run_treereducer_with_check(
                harness_path="/tmp/in.cpp",
                fdp_trace_file="/tmp/trace.log",
                crash_pattern="AddressSanitizer",
                compile_flags="-std=c++17",
                link_flags="-lm",
                crash_input="seed.bin",
                snapshot=True,
            )

            cmd = mock_run.call_args.args[0]
            self.assertIn("--last-interesting-file", cmd)
            self.assertIn(reducer_runner.get_last_interesting_file(), cmd)

import tempfile
import unittest
from pathlib import Path

from harnessreducer.check_mode import (
    CheckReference,
    append_candidate_stack_trace,
    count_stack_trace_frames,
    extract_first_entire_stack_trace,
    get_check_candidate_stack_traces_file,
    initialize_check_statistics_file,
    read_check_statistics,
    reset_check_state,
    record_check_statistics,
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
            )
            text = Path(log_path).read_text(encoding="utf-8")
            self.assertIn("source: /tmp/candidate.cpp", text)
            self.assertIn("crash_pattern_matched: True", text)
            self.assertIn("frame_count: 2", text)
            self.assertIn("#0 in foo", text)
            self.assertIn("compare_stack_trace:", text)

    def test_reset_check_state_removes_stack_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            configure_work_dir(tmpdir)
            log_path = Path(get_check_candidate_stack_traces_file())
            log_path.write_text("data", encoding="utf-8")
            reset_check_state()
            self.assertFalse(log_path.exists())

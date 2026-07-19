import importlib.util
import re
import unittest
from pathlib import Path
from types import SimpleNamespace


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "check_tester_module",
    str(_PROJECT_ROOT / "tests" / "check_tester.py"),
)
_check_tester = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_check_tester)

evaluate_check_candidate = _check_tester._evaluate_check_candidate


SAMPLE_SYMBOLIZED_LOG = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1111 in crash_func /src/lib.c:10:3
    #1 0x2222 in caller_func /src/caller.c:20:5
    #2 0x3333 in LLVMFuzzerTestOneInput /tmp/harness.cpp:30:1
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/lib.c:10:3 in crash_func
"""

SAMPLE_SYMBOLIZED_LOG_DIFFERENT_PREFIX = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0xaaaa in other_func /src/other.c:10:3
    #1 0xbbbb in caller_func /src/caller.c:20:5
    #2 0xcccc in LLVMFuzzerTestOneInput /tmp/harness.cpp:30:1
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/lib.c:10:3 in crash_func
"""

SAMPLE_DYNAMIC_LOG = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1111  (/tmp/build/lib/libtarget.so+0xbeaf0)
    #1 0x2222  (/tmp/harness+0x123)
SUMMARY: AddressSanitizer: heap-buffer-overflow (/tmp/build/lib/libtarget.so+0xbeaf0)
"""


class TestCheckTesterEvaluation(unittest.TestCase):
    def test_execution_env_can_disable_symbolization(self):
        env = _check_tester._execution_env(
            SimpleNamespace(link_flags=None, fdp_trace="/tmp/fdp-trace.log"),
            symbolize=False,
        )

        self.assertIn("symbolize=0", env["ASAN_OPTIONS"])
        self.assertIn("symbolize=0", env["UBSAN_OPTIONS"])
        self.assertEqual(env["FDP_TRACE_PATH"], "/tmp/fdp-trace.log")

    def test_level_same_is_false_when_frame_count_differs(self):
        result = evaluate_check_candidate(
            run_returncode=77,
            run_log=SAMPLE_SYMBOLIZED_LOG,
            crash_pattern=re.escape("SUMMARY: AddressSanitizer: heap-buffer-overflow"),
            stored_compare_pattern=(
                r"\s+#0 0x[0-9a-fA-F]+ in crash_func /src/lib\.c:10:3\n"
                r"\s+#1 0x[0-9a-fA-F]+ in caller_func /src/caller\.c:20:5"
            ),
            reference_frame_count=4,
            candidate_source="/tmp/harness.cpp",
        )

        crash_pattern_matched, _, level_same, stack_same, _, _ = result
        self.assertTrue(crash_pattern_matched)
        self.assertFalse(level_same)
        self.assertFalse(stack_same)

    def test_stack_same_is_diagnostic_only(self):
        result = evaluate_check_candidate(
            run_returncode=77,
            run_log=SAMPLE_SYMBOLIZED_LOG_DIFFERENT_PREFIX,
            crash_pattern=re.escape("SUMMARY: AddressSanitizer: heap-buffer-overflow"),
            stored_compare_pattern=(
                r"\s+#0 0x[0-9a-fA-F]+ in crash_func /src/lib\.c:10:3\n"
                r"\s+#1 0x[0-9a-fA-F]+ in caller_func /src/caller\.c:20:5"
            ),
            reference_frame_count=3,
            candidate_source="/tmp/harness.cpp",
        )

        crash_pattern_matched, _, level_same, stack_same, _, _ = result
        self.assertTrue(crash_pattern_matched)
        self.assertTrue(level_same)
        self.assertFalse(stack_same)

    def test_dynamic_offset_mismatch_makes_candidate_not_interesting(self):
        result = evaluate_check_candidate(
            run_returncode=77,
            run_log=SAMPLE_DYNAMIC_LOG,
            crash_pattern=re.escape("SUMMARY: AddressSanitizer: heap-buffer-overflow"),
            stored_compare_pattern="",
            reference_frame_count=2,
            candidate_source="/tmp/harness.cpp",
            dynamic_crash_site_library="/tmp/build/lib/libtarget.so",
            dynamic_crash_site_offset="0x999",
        )

        crash_pattern_matched, _, level_same, stack_same, _, _ = result
        self.assertTrue(crash_pattern_matched)
        self.assertFalse(level_same)
        self.assertFalse(stack_same)

    def test_dynamic_offset_can_use_symbolize_0_log(self):
        result = evaluate_check_candidate(
            run_returncode=77,
            run_log=SAMPLE_SYMBOLIZED_LOG,
            crash_pattern=re.escape("SUMMARY: AddressSanitizer: heap-buffer-overflow"),
            stored_compare_pattern="",
            reference_frame_count=3,
            candidate_source="/tmp/harness.cpp",
            dynamic_crash_site_library="/tmp/build/lib/libtarget.so",
            dynamic_crash_site_offset="0xbeaf0",
            dynamic_crash_site_log=SAMPLE_DYNAMIC_LOG,
        )

        crash_pattern_matched, _, level_same, stack_same, _, _ = result
        self.assertTrue(crash_pattern_matched)
        self.assertTrue(level_same)
        self.assertFalse(stack_same)


if __name__ == "__main__":
    unittest.main()

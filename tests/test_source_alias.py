"""Crash matching for identical headers reached through different build roots."""

import argparse
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest

from harnessminimizer.crash_evidence import EvidenceResult
from harnessminimizer.reducer_runner import _extract_crash_signature_from_output
from harnessminimizer.source_alias import matches_crash_location, matches_crash_pattern


_SPEC = importlib.util.spec_from_file_location(
    "crash_tester_source_alias", Path(__file__).with_name("crash_tester.py"),
)
_TESTER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_TESTER)


class SourceAliasTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.reference = root / "installed" / "include" / "flatbuffers" / "buffer.h"
        self.candidate = root / "checkout" / "include" / "flatbuffers" / "buffer.h"
        for path in (self.reference, self.candidate):
            path.parent.mkdir(parents=True)
            path.write_text("\n" * 113 + "return *value;\n", encoding="utf-8")
        self.message = (
            "runtime error: load of misaligned address 0x1234 for type "
            "'const double', which requires 8 byte alignment"
        )
        self.reference_report = f"{self.reference}:114:25: {self.message}"
        self.candidate_report = f"{self.candidate}:114:25: {self.message.replace('0x1234', '0x5678')}"
        self.pattern = _extract_crash_signature_from_output(self.reference_report)
        self.location_pattern = re.escape(f"{self.reference}:114:25")

    def test_identical_headers_match_both_crash_and_location(self):
        self.assertTrue(matches_crash_pattern(self.pattern, self.candidate_report))
        self.assertTrue(matches_crash_location(self.location_pattern, f"{self.candidate}:114:25"))

    def test_summary_only_report_uses_the_same_file_check(self):
        reference = f"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior {self.reference}:114:25"
        candidate = f"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior {self.candidate}:114:25"
        pattern = _extract_crash_signature_from_output(reference)
        self.assertTrue(matches_crash_pattern(pattern, candidate))
        self.candidate.write_text("different source\n", encoding="utf-8")
        self.assertFalse(matches_crash_pattern(pattern, candidate))

    def test_different_file_or_unavailable_reference_is_rejected(self):
        self.candidate.write_text("\n" * 113 + "return *other;\n", encoding="utf-8")
        self.assertFalse(matches_crash_pattern(self.pattern, self.candidate_report))
        self.assertFalse(matches_crash_location(self.location_pattern, f"{self.candidate}:114:25"))
        self.candidate.write_bytes(self.reference.read_bytes())
        self.reference.unlink()
        self.assertFalse(matches_crash_pattern(self.pattern, self.candidate_report))

    def test_same_basename_different_location_or_error_is_rejected(self):
        for report in (
            self.candidate_report.replace(":114:25:", ":115:25:"),
            self.candidate_report.replace(":114:25:", ":114:26:"),
            self.candidate_report.replace("misaligned", "out-of-bounds"),
            self.candidate_report.replace("const double", "const long"),
        ):
            with self.subTest(report=report):
                self.assertFalse(matches_crash_pattern(self.pattern, report))
        self.assertFalse(matches_crash_location(self.location_pattern, f"{self.candidate}:115:25"))

    def test_a_non_sanitizer_line_cannot_supply_a_crash_alias(self):
        line = self.candidate_report.replace("runtime error:", "ordinary log:")
        self.assertFalse(matches_crash_pattern(self.pattern, line))

    def test_candidate_oracle_accepts_verified_alias_only(self):
        report = (
            self.candidate_report + "\n"
            f"    #0 0xaaa in flatbuffers::Read {self.candidate}:114:25\n"
            "    #1 0xbbb in LLVMFuzzerTestOneInput /tmp/harness.cpp:20:3\n"
        )
        args = argparse.Namespace(
            symbolize=True, debug_log=None, skip_crash_pattern=False,
            crash_pattern=self.pattern, link_flags="", dynamic_crash_site_library=None,
            dynamic_crash_site_offset=None, crash_location_pattern=self.location_pattern,
            crash_location_file=None, source="/tmp/harness.cpp", stack_depth=None,
            stack_trace_file=None,
        )
        result, _ = _TESTER._evaluate_candidate_crash(args, 77, report)
        self.assertEqual(result, EvidenceResult.MATCH)

        self.candidate.write_text("different source\n", encoding="utf-8")
        result, _ = _TESTER._evaluate_candidate_crash(args, 77, report)
        self.assertEqual(result, EvidenceResult.MISMATCH)


if __name__ == "__main__":
    unittest.main()

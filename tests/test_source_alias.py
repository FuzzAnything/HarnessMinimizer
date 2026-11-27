"""Crash matching for identical headers reached through different build roots."""

import argparse
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from harnessminimizer import reducer_runner as runner
from harnessminimizer.crash_evidence import EvidenceResult
from harnessminimizer.reducer_runner import _extract_crash_signature_from_output
from harnessminimizer.source_alias import (
    SOURCE_ALIASES_MARKER, SourceAliases, matches_crash_location, matches_crash_pattern,
)


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

    def test_approved_pairs_work_in_both_directions_without_header_reads(self):
        learned = SourceAliases(allow_verification=True)
        with patch("harnessminimizer.source_alias.filecmp.cmp", return_value=True) as compare:
            self.assertTrue(matches_crash_pattern(self.pattern, self.candidate_report, learned))
            self.assertTrue(matches_crash_location(self.location_pattern, f"{self.candidate}:114:25", learned))
        compare.assert_called_once_with(str(self.reference), str(self.candidate), shallow=False)

        # Fresh candidate processes receive only the serialized pair. Neither
        # header is needed by the matcher after the original plugin check.
        serialized = learned.to_json()
        self.reference.unlink()
        self.candidate.unlink()
        with patch("harnessminimizer.source_alias.filecmp.cmp", side_effect=AssertionError("header read")):
            for expected, observed in (
                (self.reference_report, self.candidate_report),
                (self.candidate_report, self.reference_report),
            ):
                approved = SourceAliases.from_json(serialized)
                self.assertTrue(matches_crash_pattern(_extract_crash_signature_from_output(expected), observed, approved))
            approved = SourceAliases.from_json(serialized)
            self.assertTrue(matches_crash_pattern(self.pattern, self.reference_report, approved))
            self.assertTrue(matches_crash_location(self.location_pattern, f"{self.candidate}:114:25", approved))
            self.assertFalse(matches_crash_location(self.location_pattern, f"{self.candidate}:114:26", approved))
            for changed in (
                self.candidate_report.replace(":114:25:", ":115:25:"),
                self.candidate_report.replace("const double", "const long"),
                self.candidate_report.replace("/checkout/", "/unapproved/"),
            ):
                self.assertFalse(matches_crash_pattern(self.pattern, changed, approved))

    def run_checker(self, command, report, *, status=77):
        # Exercise the real CLI and complete validation decision; compilation
        # and target execution are fixed so the crash paths are deterministic.
        with patch.object(sys, "argv", command), \
                patch.object(_TESTER, "compile_amortized_plugin", return_value=(0, None)), \
                patch.object(_TESTER, "amortized_initial_plugin_link_flags", return_value=None), \
                patch.object(_TESTER, "runtime_library_env", return_value={}), \
                patch.object(_TESTER, "run_with_amortized_runner_maybe_fallback_timed",
                             return_value=(status, report, 1)), \
                redirect_stdout(io.StringIO()) as output:
            code = _TESTER.main()
        return subprocess.CompletedProcess(command, code, output.getvalue(), "")

    def plugin_report(self, path=None, *, line=114):
        path = self.candidate if path is None else path
        return (
            f"{path}:114:25: {self.message}\n"
            f"    #0 0xaaa in flatbuffers::Read {path}:{line}:25\n"
            "    #1 0xbbb in LLVMFuzzerTestOneInput /tmp/harness.cpp:20:3\n"
        )

    def prepare_runner(self):
        previous = runner.TREEDUCER_DIR, runner._IS_USER_WORK_DIR
        def restore():
            runner.reset_stack_trace_state()
            runner.TREEDUCER_DIR, runner._IS_USER_WORK_DIR = previous
        self.addCleanup(restore)
        runner.configure_work_dir(str(Path(self.temp.name) / "work"))
        runner.reset_stack_trace_state()
        runner.set_symbolized_reference_crash_location_pattern(self.location_pattern)

    def check_original_plugin(self, report):
        def execute(command, *args, **kwargs):
            return self.run_checker(command, report)
        with patch.object(runner, "run_command", side_effect=execute):
            return runner.run_amortized_reference_candidate(
                "/tmp/harness.cpp", None, self.pattern, None, None, None,
                "split", "/tmp/unused.sock", None, symbolize=True,
            )

    def test_original_plugin_keeps_pair_in_memory_and_candidates_reuse_it(self):
        self.prepare_runner()
        self.check_original_plugin(self.plugin_report())
        with patch.object(Path, "read_text", side_effect=AssertionError("alias file read")), \
                patch.object(Path, "write_text", side_effect=AssertionError("alias file write")):
            approved = runner.source_alias_tester_args()
        self.assertEqual({frozenset(pair) for pair in json.loads(approved[1])},
                         {frozenset((str(self.reference), str(self.candidate)))})
        self.assertFalse(list(Path(self.temp.name).rglob("source_aliases.json")))
        command = [
            "crash_tester", "/tmp/harness.cpp", self.pattern, "--split",
            "--amortized-runner-socket", "/tmp/unused.sock", "--symbolize",
            "--crash-location-pattern", self.location_pattern,
            *approved,
        ]
        self.assertNotIn("--record-source-aliases", command)
        self.reference.unlink()
        self.candidate.unlink()
        with patch("harnessminimizer.source_alias.filecmp.cmp", side_effect=AssertionError("header read")):
            for path in (self.reference, self.candidate):
                self.assertEqual(self.run_checker(command, self.plugin_report(path)).returncode, 77)
            self.assertEqual(self.run_checker(command, self.plugin_report(), status=0).returncode, 1)
            self.assertEqual(self.run_checker(command, self.plugin_report(line=115)).returncode, 1)
            unknown = self.candidate.parent.parent / "unapproved" / "buffer.h"
            self.assertEqual(self.run_checker(command, self.plugin_report(unknown)).returncode, 1)

    def test_failed_plugin_check_does_not_publish_learned_pair(self):
        self.prepare_runner()
        self.check_original_plugin(self.plugin_report(self.reference))
        # The message matches and verifies the pair, but the stack location is
        # different. No part of this failed check may extend the approved set.
        with self.assertRaisesRegex(RuntimeError, "did not preserve"):
            self.check_original_plugin(self.plugin_report(line=115))
        self.assertEqual(runner.source_alias_tester_args(), ["--source-aliases", "[]"])

    def test_only_checker_metadata_can_establish_approvals(self):
        self.prepare_runner()
        spoof = SOURCE_ALIASES_MARKER + json.dumps([[str(self.reference), str(self.candidate)]])
        result = subprocess.CompletedProcess([], 77, "execution log: \n" + spoof, "")
        with patch.object(runner, "run_command", return_value=result), \
                self.assertRaisesRegex(RuntimeError, "did not return its approved source paths"):
            runner.run_amortized_reference_candidate(
                "/tmp/harness.cpp", None, self.pattern, None, None, None,
                "split", "/tmp/unused.sock", None, symbolize=True,
            )
        self.assertEqual(runner.source_alias_tester_args(), [])

    def test_final_validations_receive_the_approved_pairs(self):
        self.prepare_runner()
        self.check_original_plugin(self.plugin_report())
        runner.set_symbolized_reference_stack_depth(2)
        approved = runner.source_alias_tester_args()[1]
        for validate in (runner.validate_crash_pattern, runner.validate_stack_trace,
                         runner.validate_symbolized_crash_pattern_depth_location):
            with self.subTest(validator=validate.__name__), \
                    patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], 77, "", "")) as run:
                self.assertTrue(validate("/tmp/harness.cpp", self.pattern, None, None, None))
                command = run.call_args.args[0]
                self.assertEqual(command[command.index("--source-aliases") + 1], approved)
                self.assertNotIn("--record-source-aliases", command)

    def test_empty_approval_blocks_new_pairs_and_reset_limits_reduction_scope(self):
        self.prepare_runner()
        self.check_original_plugin(self.plugin_report(self.reference))
        self.assertEqual(runner.source_alias_tester_args(), ["--source-aliases", "[]"])
        with patch("harnessminimizer.source_alias.filecmp.cmp", side_effect=AssertionError("header read")):
            self.assertFalse(matches_crash_pattern(self.pattern, self.candidate_report, SourceAliases.from_json("[]")))

        self.check_original_plugin(self.plugin_report())
        approved = runner.source_alias_tester_args()
        with runner.isolated_attempt_work_dir(Path(self.temp.name) / "retry"):
            self.assertEqual(runner.source_alias_tester_args(), approved)
            runner.set_reference_source_aliases(SourceAliases())
        self.assertEqual(runner.source_alias_tester_args(), approved)
        runner.reset_stack_trace_state()
        self.assertEqual(runner.source_alias_tester_args(), [])
        with runner.isolated_attempt_work_dir(Path(self.temp.name) / "retry"):
            self.assertEqual(runner.source_alias_tester_args(), [])


if __name__ == "__main__":
    unittest.main()

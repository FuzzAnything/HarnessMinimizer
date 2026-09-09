"""Deterministic missing-report recovery without relying on intermittent crashes."""

from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from harnessreducer import reducer_runner as runner
from tests import crash_tester as tester


PATTERN = "SUMMARY: AddressSanitizer: stack-overflow"
MATCH_PATTERN = r"(?:SUMMARY|ERROR):\s*AddressSanitizer:\s*stack\-overflow(?![\w-])"
EMPTY = "AddressSanitizer:DEADLYSIGNAL\n    <empty stack>\n" + PATTERN
FAST = "    #0 0xabcd (/tmp/libtarget.so+0x123)\n    #1 0xbeef (/tmp/poc.out+0x789)\n" + PATTERN
SYMBOLIZED = "    #0 0xabcd in target /src/target.c:42:3\n    #1 0xbeef in LLVMFuzzerTestOneInput /tmp/harness.cpp:9:1\n" + PATTERN
LOCATION = r"/src/target\.c:42:3"


class TestCandidateEvidenceRetry(unittest.TestCase):
    def run_candidate(self, outputs, *, symbolize=False, mode="direct", extra=(), profile=False):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            source = root / "candidate.cpp"
            source.write_text("candidate source\n")
            obj = root / "candidate.o"
            stats, snapshot, events = (root / name for name in ("stats", "last.cpp", "profile.jsonl"))
            argv = ["crash_tester", str(source), MATCH_PATTERN, "--crash-input", "seed.bin",
                    "--fdp-trace", "trace.log", "--exec-timeout-ms", "1000",
                    "--statistics-file", str(stats), "--last-interesting-file", str(snapshot),
                    "--print-exec-time-ms"]
            if symbolize:
                argv += ["--symbolize", "--crash-location-pattern", LOCATION]
            else:
                argv += ["--dynamic-crash-site-library", "/tmp/libtarget.so",
                         "--dynamic-crash-site-offset", "0x123"]
            argv += ["--split", "--amortized-runner-socket", "runner.sock"] if mode == "amortized" else ["--" + mode]
            if profile:
                argv += ["--profile-file", str(events)]
            argv += list(extra)
            built_args = []

            def build(args, output_path, *unused):
                built_args.append(args)
                obj.write_text("compiled object")
                return 0, str(obj)

            builders = [stack.enter_context(patch.object(tester, name, side_effect=build)) for name in
                        ("compile_direct", "compile_split", "compile_with_pch", "compile_amortized_plugin")]
            stack.enter_context(patch.object(tester, "amortized_initial_plugin_link_flags", return_value=None))
            stack.enter_context(patch.object(tester, "_enable_amortized_fallback_first"))
            fallback = stack.enter_context(patch.object(tester, "link_amortized_plugin", return_value=0))
            stack.enter_context(patch.object(sys, "argv", argv))
            stack.enter_context(patch.dict(os.environ, {"HARNESSREDUCER_TMPDIR": tmp}))
            stack.enter_context(patch.object(tester, "runtime_library_env", return_value={}))
            ticks = [0]
            stack.enter_context(patch.object(tester.time, "perf_counter_ns", side_effect=lambda: ticks[0]))
            observations = iter(outputs)

            def execute(*args, **kwargs):
                self.assertIsNone(built_args[0]._profile_oracle_started_ns)
                ticks[0] += 1_000_000
                if mode != "amortized":
                    self.assertEqual(kwargs["exec_timeout_ms"], 1000)
                    self.assertEqual(kwargs["env"]["FDP_TRACE_PATH"], "trace.log")
                return next(observations)

            execute_name = "run_with_amortized_runner_timed" if mode == "amortized" else "run_executable"
            execution = stack.enter_context(patch.object(tester, execute_name, side_effect=execute))
            evaluate = tester._evaluate_candidate_crash

            def parse(*args):
                ticks[0] += 100
                return evaluate(*args)

            stack.enter_context(patch.object(tester, "_evaluate_candidate_crash", side_effect=parse))
            output = io.StringIO()
            with redirect_stdout(output):
                result = tester.main()
            self.assertEqual(sum(mock.call_count for mock in builders), 1)
            self.assertFalse(obj.exists())
            self.assertEqual(list(root.glob("poc_*.out")), [])
            self.assertIn("total: 1\n", stats.read_text())
            self.assertEqual(snapshot.exists(), result == 77)
            if result == 77:
                self.assertEqual(snapshot.read_text(), source.read_text())
            if profile:
                records = [json.loads(line) for line in events.read_text().splitlines()]
                self.assertEqual(len(records), 1)
                durations = records[0]["durations_ns"]
                self.assertEqual(durations["execute_ns"], 1_000_000 * execution.call_count)
                self.assertEqual(durations["oracle_ns"], 100 * len(outputs))
                self.assertEqual(records[0]["result_code"], result)
            return result, execution.call_count, output.getvalue(), fallback.call_count

    def test_recovery_builds_once_in_every_mode_and_preserves_profile(self):
        for mode in ("direct", "split", "pch", "amortized"):
            for symbolize in (False, True):
                with self.subTest(mode=mode, symbolize=symbolize):
                    good = SYMBOLIZED if symbolize else FAST
                    result, attempts, log, _ = self.run_candidate(
                        [(77, EMPTY, 7), (77, good, 8)], mode=mode, symbolize=symbolize, profile=True,
                    )
                    self.assertEqual((result, attempts), (77, 2))
                    self.assertIn("attempt 1/3; retrying", log)
                    self.assertIn("HARNESSREDUCER_EXEC_TIME_MS=8", log)

    def test_stable_path_executes_once(self):
        for symbolize, good in ((False, FAST), (True, SYMBOLIZED)):
            with self.subTest(symbolize=symbolize):
                result, attempts, log, _ = self.run_candidate([(77, good, 7)], symbolize=symbolize, profile=True)
                self.assertEqual((result, attempts), (77, 1))
                self.assertNotIn("retrying", log)

    def test_candidate_recovery_allows_error_summary_transition(self):
        for mode in ("direct", "amortized"):
            for symbolize, complete in ((False, FAST), (True, SYMBOLIZED)):
                for first_prefix, next_prefix in (("ERROR", "SUMMARY"), ("SUMMARY", "ERROR")):
                    with self.subTest(mode=mode, symbolize=symbolize, first_prefix=first_prefix):
                        result, attempts, _, _ = self.run_candidate(
                            [(77, EMPTY.replace("SUMMARY", first_prefix), 7),
                             (77, complete.replace("SUMMARY", next_prefix), 8)],
                            symbolize=symbolize, mode=mode, profile=True,
                        )
                        self.assertEqual((result, attempts), (77, 2))

    def test_exhaustion_is_bounded(self):
        for symbolize in (False, True):
            with self.subTest(symbolize=symbolize):
                result, attempts, log, _ = self.run_candidate([(77, EMPTY, 7)] * 3, symbolize=symbolize, profile=True)
                self.assertEqual((result, attempts), (1, 3))
                self.assertIn("attempts exhausted", log)

    def test_mismatches_never_retry(self):
        for status, report, symbolize in (
            (0, EMPTY, False), (124, EMPTY, False), (125, EMPTY, False),
            (77, "different crash", False), (77, FAST.replace("+0x123", "+0x456"), False),
            (77, SYMBOLIZED.replace("42:3", "43:3"), True),
        ):
            with self.subTest(status=status, report=report):
                result, attempts, _, _ = self.run_candidate([(status, report, 7)], symbolize=symbolize)
                self.assertEqual((result, attempts), (1, 1))

    def test_mismatch_after_missing_stops_without_third_attempt(self):
        result, attempts, _, _ = self.run_candidate([(77, EMPTY, 7), (77, FAST.replace("+0x123", "+0x456"), 8)])
        self.assertEqual((result, attempts), (1, 2))

    def test_present_mismatch_takes_precedence_over_missing_anchor(self):
        # A location exists and differs, while the required dynamic-library frame is absent.
        result, attempts, _, _ = self.run_candidate(
            [(77, SYMBOLIZED.replace("42:3", "43:3"), 7)],
            extra=["--crash-location-pattern", LOCATION],
        )
        self.assertEqual((result, attempts), (1, 1))

    def test_optional_and_advisory_checks_do_not_retry(self):
        result, attempts, _, _ = self.run_candidate(
            [(77, EMPTY, 7)], symbolize=True,
            extra=["--crash-location-pattern", "", "--stack-depth", "20"],
        )
        self.assertEqual((result, attempts), (77, 1))

    def test_explicit_pattern_bypass_still_recovers_location(self):
        result, attempts, _, _ = self.run_candidate(
            [(77, "<empty stack>", 7), (77, SYMBOLIZED, 8)], symbolize=True,
            extra=["--skip-crash-pattern"],
        )
        self.assertEqual((result, attempts), (77, 2))

    def test_existing_oom_retry_remains_bounded(self):
        outputs = [(71, "ERROR: libFuzzer: out-of-memory", 5), (77, EMPTY, 7)] * 3
        result, attempts, _, _ = self.run_candidate(outputs, extra=["--retry-oom-without-rss-limit"])
        self.assertEqual((result, attempts), (1, 6))

    def test_amortized_fallback_relinks_once_across_evidence_retries(self):
        result, attempts, _, links = self.run_candidate(
            [(125, "dlopen candidate failed: undefined symbol: target", 5), (77, EMPTY, 7), (77, FAST, 8)],
            mode="amortized", extra=["--amortized-plugin-fallback-link-flags=-ltarget"],
        )
        self.assertEqual((result, attempts, links), (77, 3, 1))


class TestReferenceEvidenceRetry(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(patch.stopall)
        patch.object(runner, "TREEDUCER_DIR", self.temp.name).start()
        runner.reset_stack_trace_state()
        self.addCleanup(runner.reset_stack_trace_state)

    def capture(self, outputs, *, link_flags="/tmp/libtarget.so", required=True):
        procs = [subprocess.CompletedProcess([], status, output, "") for status, output in outputs]
        with patch.object(runner, "run_command", side_effect=procs) as execution:
            pattern = runner.extract_crash_pattern_from_output(
                "seed.bin", harness_path="/tmp/harness.cpp", link_flags=link_flags,
                record_symbolized_crash_location=required,
            )
        self.assertEqual(execution.call_count, len(outputs))
        for call in execution.call_args_list:
            self.assertEqual(call.args[0], [str(Path(self.temp.name) / "poc.out"), "seed.bin"])
        return pattern

    def test_recovers_both_modes_and_records_complete_observations(self):
        self.assertEqual(self.capture([(77, EMPTY), (77, FAST), (77, EMPTY), (77, SYMBOLIZED)]), MATCH_PATTERN)
        self.assertEqual(runner.get_dynamic_reference_crash_site().offset, "0x123")
        self.assertEqual(runner.get_normal_reference_stack_depth(), 2)
        self.assertEqual(runner.get_symbolized_reference_stack_depth(), 2)
        self.assertEqual(runner.get_symbolized_reference_crash_location_pattern(), LOCATION)
        self.assertIn("target", Path(runner.get_stack_trace_file()).read_text())

    def test_reference_recovery_allows_error_summary_transition(self):
        for first_prefix, next_prefix in (("ERROR", "SUMMARY"), ("SUMMARY", "ERROR")):
            with self.subTest(first_prefix=first_prefix):
                self.assertEqual(self.capture([
                    (77, EMPTY.replace("SUMMARY", first_prefix)),
                    (77, FAST.replace("SUMMARY", next_prefix)),
                    (77, EMPTY.replace("SUMMARY", first_prefix)),
                    (77, SYMBOLIZED.replace("SUMMARY", next_prefix)),
                ]), MATCH_PATTERN)
                self.assertEqual(runner.get_reference_crash_pattern_symbolize_0(), MATCH_PATTERN)
                self.assertEqual(runner.get_reference_crash_pattern_symbolize_1(), MATCH_PATTERN)

    def test_static_only_skips_dynamic_retries(self):
        for flags in (None, "-lpthread -lm", "/tmp/libtarget.a -lpthread", "-Wl,-Bstatic -ltarget"):
            with self.subTest(flags=flags):
                self.capture([(77, EMPTY), (77, SYMBOLIZED)], link_flags=flags)
                self.assertIsNone(runner.get_dynamic_reference_crash_site())

    def test_optional_exhaustion_retains_existing_fallback(self):
        self.capture([(77, EMPTY)] * 10, required=False)
        self.assertIsNone(runner.get_dynamic_reference_crash_site())
        self.assertIsNone(runner.get_symbolized_reference_crash_location_pattern())
        self.assertFalse(Path(runner.get_stack_trace_file()).exists())
        for mode in (0, 1):
            self.assertIn(EMPTY, (Path(self.temp.name) / f"crash_reference.symbolize{mode}.failure.log").read_text())

    def test_required_location_exhaustion_fails(self):
        with self.assertRaisesRegex(ValueError, "No symbolized crash location"):
            self.capture([(77, FAST)] + [(77, EMPTY)] * 5)

    def test_pattern_change_stops_reference_retry_in_each_mode(self):
        for prefix in ([], [(77, FAST)]):
            with self.subTest(symbolize=bool(prefix)):
                with self.assertRaisesRegex(ValueError, "Crash pattern changed"):
                    self.capture(prefix + [(77, EMPTY), (77, SYMBOLIZED.replace("stack-overflow", "heap-buffer-overflow"))])

    def test_harness_crash_on_retry_is_rejected(self):
        with self.assertRaises(runner.HarnessCrashDetected):
            self.capture([(77, FAST), (77, EMPTY), (77, SYMBOLIZED.replace("/src/target.c", "/tmp/harness.cpp"))])

    def test_noncrashing_reference_retains_existing_handling(self):
        self.assertIsNone(self.capture([(0, "no crash")]))
        self.assertEqual(self.capture([(77, FAST), (0, "no crash")]), MATCH_PATTERN)


if __name__ == "__main__":
    unittest.main()

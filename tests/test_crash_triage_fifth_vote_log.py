"""Test the fixed fifth-vote CSV using mocked LLM replies and temporary files."""

from concurrent.futures import ProcessPoolExecutor
from contextlib import redirect_stdout
import csv
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import crash_triage_new as triage


def append_case_in_worker(path: str, benchmark_name: str) -> None:
    # Every worker uses the same fixed-path setting, isolated from real results.
    triage.FIFTH_VOTE_CSV_PATH = Path(path)
    triage.append_fifth_vote_case(benchmark_name, "treereduce", 2, 2)


class CrashTriageFifthVoteLogTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.log_path = self.root / "fixed" / "fifth-vote-cases.csv"
        self.enterContext(patch.object(triage, "FIFTH_VOTE_CSV_PATH", self.log_path))
        self.enterContext(patch.object(triage, "TRIAGE_REPETITIONS", 4))
        self.enterContext(patch.object(triage, "PRINT_STACK_TRACE", False))
        self.enterContext(redirect_stdout(io.StringIO()))

    def read_cases(self):
        with self.log_path.open(newline="") as handle:
            return list(csv.DictReader(handle))

    def request_votes(self):
        return triage.send_stack_trace_to_llm(
            "harness source", None, "stack trace",
            benchmark_name="sqlite-7", tool="treereduce",
        )

    def test_case_is_recorded_before_requesting_the_fifth_vote(self):
        replies = iter(["library-bug", "harness-bug"] * 2 + ["library-bug"])
        calls = 0

        def reply(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 5:
                self.assertEqual(self.read_cases(), [{
                    "dir": "sqlite-7", "tool": "treereduce",
                    "library_votes": "2", "harness_votes": "2",
                }])
            else:
                self.assertFalse(self.log_path.exists())
            return next(replies)

        with patch.object(triage, "post_chat_completion", side_effect=reply):
            self.assertEqual(self.request_votes(), "library-bug")
        self.assertEqual(calls, 5)
        self.assertEqual(len(self.read_cases()), 1)

    def test_early_stop_does_not_create_the_extra_csv(self):
        with patch.object(triage, "post_chat_completion", return_value="harness-bug") as request:
            self.assertEqual(self.request_votes(), "harness-bug")
        self.assertEqual(request.call_count, 3)
        self.assertFalse(self.log_path.exists())

    def test_case_remains_recorded_when_the_deciding_vote_fails(self):
        for last_reply in (triage.TriageError("request failed"), "Unable to decide."):
            with self.subTest(last_reply=last_reply), patch.object(
                triage, "post_chat_completion",
                side_effect=["library-bug", "harness-bug"] * 2 + [last_reply],
            ):
                with self.assertRaises(triage.TriageError):
                    self.request_votes()
        self.assertEqual(len(self.read_cases()), 2)
        self.assertTrue(all(row["dir"] == "sqlite-7" for row in self.read_cases()))

    def test_main_records_case_and_tool_independently_of_results_csv(self):
        benchmark = self.root / "example-case"
        benchmark.mkdir()
        (benchmark / "harness.cpp").write_text("// example harness\n")
        (benchmark / "crash-input").write_bytes(b"crash")
        reduced = benchmark / "harnessreducer-perf-comparison-treereduce-test/optimized/jobs-1/reduced.cpp"
        reduced.parent.mkdir(parents=True)
        reduced.write_text("// reduced harness\n")
        results_path = self.root / "custom-results.csv"

        for tool in ("none", "treereduce"):
            with (
                self.subTest(tool=tool),
                patch.object(triage, "compile_harness"),
                patch.object(triage, "run_harness_for_stack_trace", return_value="stack trace"),
                patch.object(triage, "post_chat_completion", side_effect=[
                    "library-bug", "harness-bug", "library-bug", "harness-bug", "library-bug",
                ]),
            ):
                self.assertEqual(triage.main([
                    "--dir", str(benchmark), "--tool", tool, "--csv", str(results_path),
                ]), 0)
        self.assertEqual(self.read_cases(), [
            {"dir": "example-case", "tool": tool, "library_votes": "2", "harness_votes": "2"}
            for tool in ("none", "treereduce")
        ])
        with results_path.open(newline="") as handle:
            self.assertEqual(list(csv.reader(handle)), [
                ["dir", "tool", "triage result"],
                ["example-case", "none", "library-bug"],
                ["example-case", "treereduce", "library-bug"],
            ])

    def test_parallel_processes_preserve_all_rows_and_one_header(self):
        with ProcessPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(append_case_in_worker, str(self.log_path), f"case-{index}")
                for index in range(24)
            ]
            for future in futures:
                future.result(timeout=15)
        with self.log_path.open(newline="") as handle:
            rows = list(csv.reader(handle))
        header = ["dir", "tool", "library_votes", "harness_votes"]
        self.assertEqual(rows[0], header)
        self.assertEqual(rows.count(header), 1)
        self.assertEqual(len(rows), 25)
        self.assertEqual(
            {tuple(row) for row in rows[1:]},
            {(f"case-{index}", "treereduce", "2", "2") for index in range(24)},
        )


if __name__ == "__main__":
    unittest.main()

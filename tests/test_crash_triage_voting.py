"""Check early majority stopping and tie resolution without making API calls."""

from contextlib import redirect_stdout
import io
import itertools
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import crash_triage_new as triage


class CrashTriageVotingTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(triage, "TRIAGE_REPETITIONS", 4))
        self.enterContext(patch.object(triage, "PRINT_STACK_TRACE", False))
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.object(
            triage, "FIFTH_VOTE_CSV_PATH", Path(directory) / "fifth-vote-cases.csv"
        ))
        self.output = io.StringIO()
        self.enterContext(redirect_stdout(self.output))

    def request_votes(self):
        return triage.send_stack_trace_to_llm(
            "harness source", None, "stack trace",
            benchmark_name="test-case", tool="none",
            llm_timeout_seconds=3600, reasoning_effort="max",
        )

    def test_stops_at_three_matching_votes_for_every_five_vote_sequence(self):
        verdicts = ("library-bug", "harness-bug")
        for responses in itertools.product(verdicts, repeat=5):
            with self.subTest(responses=responses):
                if len(set(responses[:3])) == 1:
                    expected_calls = 3
                elif responses[:4].count("library-bug") == 2:
                    expected_calls = 5
                else:
                    expected_calls = 4
                with (
                    patch.object(triage, "post_chat_completion", side_effect=responses) as request,
                    patch.object(triage, "append_fifth_vote_case") as record,
                ):
                    result = self.request_votes()
                # Stopping early must preserve the full five-vote majority.
                self.assertEqual(result, max(verdicts, key=responses.count))
                self.assertEqual(request.call_count, expected_calls)
                if expected_calls == 5:
                    record.assert_called_once_with("test-case", "none", 2, 2)
                else:
                    record.assert_not_called()
                for call in request.call_args_list:
                    self.assertEqual(call, request.call_args_list[0])
                self.assertEqual(request.call_args.kwargs, {
                    "timeout_seconds": 3600, "reasoning_effort": "max",
                })

    def test_deciding_vote_failure_does_not_default_to_harness_bug(self):
        responses = ["library-bug", "harness-bug"] * 2 + [triage.TriageError("request failed")]
        with patch.object(triage, "post_chat_completion", side_effect=responses) as request:
            with self.assertRaisesRegex(triage.TriageError, "request failed"):
                self.request_votes()
        self.assertEqual(request.call_count, 5)
        self.assertIn("tied 2-2; requesting deciding vote 5", self.output.getvalue())

    def test_unparseable_deciding_vote_is_not_counted(self):
        responses = ["library-bug", "harness-bug"] * 2 + ["Unable to decide."]
        with patch.object(triage, "post_chat_completion", side_effect=responses) as request:
            with self.assertRaisesRegex(triage.TriageError, "Could not parse LLM triage result"):
                self.request_votes()
        self.assertEqual(request.call_count, 5)

    def test_odd_repetition_setting_needs_no_extra_vote(self):
        responses = ["library-bug", "harness-bug", "library-bug"]
        with (
            patch.object(triage, "TRIAGE_REPETITIONS", 3),
            patch.object(triage, "post_chat_completion", side_effect=responses) as request,
        ):
            self.assertEqual(self.request_votes(), "library-bug")
        self.assertEqual(request.call_count, 3)

    def test_majority_vote_rejects_an_unresolved_tie(self):
        with self.assertRaisesRegex(triage.TriageError, "votes are tied"):
            triage.majority_vote(["library-bug", "harness-bug"] * 2)


if __name__ == "__main__":
    unittest.main()

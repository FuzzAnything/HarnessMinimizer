"""Check minimum vote counts and tie resolution without making API calls."""

from contextlib import redirect_stdout
import io
import itertools
import unittest
from unittest.mock import patch

import crash_triage_new as triage


class CrashTriageVotingTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(triage, "TRIAGE_REPETITIONS", 4))
        self.enterContext(patch.object(triage, "PRINT_STACK_TRACE", False))
        self.output = io.StringIO()
        self.enterContext(redirect_stdout(self.output))

    def request_votes(self):
        return triage.send_stack_trace_to_llm(
            "harness source", None, "stack trace",
            llm_timeout_seconds=3600, reasoning_effort="max",
        )

    def test_all_four_vote_outcomes_request_a_fifth_only_when_tied(self):
        verdicts = ("library-bug", "harness-bug")
        for initial in itertools.product(verdicts, repeat=4):
            tied = initial.count("library-bug") == 2
            for deciding in verdicts if tied else (None,):
                with self.subTest(initial=initial, deciding=deciding):
                    responses = list(initial)
                    if tied:
                        responses.append(deciding)
                    with patch.object(triage, "post_chat_completion", side_effect=responses) as request:
                        result = self.request_votes()
                    expected = deciding if tied else max(verdicts, key=initial.count)
                    self.assertEqual(result, expected)
                    self.assertEqual(request.call_count, 5 if tied else 4)
                    # The deciding vote uses the same evidence and model settings.
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

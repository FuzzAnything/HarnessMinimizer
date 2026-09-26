"""Check bounded HKU retries and vote preservation without provider calls."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest.mock import patch
import urllib.error

import crash_triage_new_hku as triage
from tests.test_crash_triage_streaming import Response, event


def answer(verdict):
    return Response(event({"content": verdict}, "stop"))


class CrashTriageHKURetryTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.errors = io.StringIO()
        self.enterContext(redirect_stdout(self.output))
        self.enterContext(redirect_stderr(self.errors))
        self.enterContext(patch.object(
            triage, "llm_configuration",
            return_value=("https://unused.invalid/v1", "GLM-5.3", "test-key"),
        ))
        self.send = self.enterContext(patch.object(triage.urllib.request, "urlopen"))
        self.sleep = self.enterContext(patch.object(triage.time, "sleep"))
        self.record = self.enterContext(patch.object(triage, "append_fifth_vote_case"))
        self.enterContext(patch.object(triage, "PRINT_STACK_TRACE", False))

    def request_votes(self):
        return triage.send_stack_trace_to_llm(
            "harness", None, "stack trace", benchmark_name="test-case",
            tool="treereduce", reasoning_effort="high",
        )

    def test_empty_stream_retries_with_the_same_request_settings(self):
        for ending in (event(finish_reason="stop"), b"data: [DONE]\n\n"):
            with self.subTest(ending=ending):
                self.send.reset_mock()
                self.sleep.reset_mock()
                self.send.side_effect = [
                    Response(event({"reasoning_content": "library-bug", "content": " \n"}) + ending),
                    answer("harness-bug"),
                ]
                result = triage.post_chat_completion(
                    [{"role": "user", "content": "triage"}],
                    reasoning_effort="high", timeout_seconds=3600,
                )
                self.assertEqual(result, "harness-bug")
                self.assertEqual(self.send.call_count, 2)
                requests = [call.args[0].data for call in self.send.call_args_list]
                self.assertEqual(requests[0], requests[1])
                self.assertEqual(json.loads(requests[1])["reasoning_effort"], "high")
                for call in self.send.call_args_list:
                    self.assertEqual(call.kwargs["timeout"], 3600)
                self.sleep.assert_called_once_with(2)
                self.assertIn("no final answer text", self.errors.getvalue())

    def test_empty_json_answer_is_also_retried(self):
        for content in (None, "", " \n"):
            with self.subTest(content=content):
                self.send.reset_mock()
                body = json.dumps({"choices": [{
                    "message": {"content": content, "reasoning_content": "harness-bug"},
                    "finish_reason": "stop",
                }]}).encode()
                self.send.side_effect = [
                    Response(body, "application/json"), answer("library-bug"),
                ]
                self.assertEqual(triage.post_chat_completion([]), "library-bug")
                self.assertEqual(self.send.call_count, 2)

    def test_empty_answers_stop_after_ten_retries(self):
        self.assertEqual(triage.LLM_RETRIES, 10)
        self.send.side_effect = lambda *args, **kwargs: answer("")
        with self.assertRaisesRegex(
            triage.TriageError, r"after 11 attempt\(s\).*no final answer text",
        ):
            triage.post_chat_completion([])
        self.assertEqual(self.send.call_count, 11)
        self.assertEqual(self.sleep.call_count, 10)
        self.assertTrue(all(0 < call.args[0] <= 10 for call in self.sleep.call_args_list))
        self.assertIn("LLM attempt 11/11 failed", self.errors.getvalue())

    def test_last_allowed_retry_can_succeed(self):
        self.send.side_effect = [answer("") for _ in range(10)] + [answer("library-bug")]
        self.assertEqual(triage.post_chat_completion([]), "library-bug")
        self.assertEqual(self.send.call_count, 11)
        self.assertEqual(self.sleep.call_count, 10)

    def test_successful_votes_survive_a_retry_and_still_stop_early(self):
        self.send.side_effect = (
            [answer("library-bug") for _ in range(2)]
            + [answer("")]
            + [answer("library-bug") for _ in range(4)]
        )
        with patch.object(triage, "TRIAGE_REPETITIONS", 10):
            self.assertEqual(self.request_votes(), "library-bug")
        self.assertEqual(self.send.call_count, 7)
        self.assertEqual(self.output.getvalue().count("Requesting triage vote"), 6)
        self.assertIn("after 6 triages; stopping", self.output.getvalue())
        self.record.assert_not_called()

    def test_deciding_vote_retries_without_repeating_votes_or_audit_record(self):
        self.send.side_effect = (
            [answer(verdict) for verdict in ("library-bug", "harness-bug") * 5]
            + [answer(""), answer("harness-bug")]
        )
        with patch.object(triage, "TRIAGE_REPETITIONS", 10):
            self.assertEqual(self.request_votes(), "harness-bug")
        self.assertEqual(self.send.call_count, 12)
        self.record.assert_called_once_with("test-case", "treereduce", 5, 5)
        self.assertEqual(self.output.getvalue().count("requesting deciding vote 11"), 1)

    def test_token_limit_remains_an_error_instead_of_a_verdict(self):
        self.send.side_effect = [Response(event({"content": "library-bug"}, "length"))]
        with self.assertRaisesRegex(triage.TriageError, "finish_reason='length'"):
            triage.post_chat_completion([])
        self.assertEqual(self.send.call_count, 1)
        self.sleep.assert_not_called()

    def test_permanent_http_error_is_not_retried(self):
        self.send.side_effect = urllib.error.HTTPError(
            "https://unused.invalid", 401, "Unauthorized", {}, io.BytesIO(b"bad credentials"),
        )
        with self.assertRaisesRegex(triage.TriageError, "after 1 attempt.*HTTP 401"):
            triage.post_chat_completion([])
        self.assertEqual(self.send.call_count, 1)
        self.sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()

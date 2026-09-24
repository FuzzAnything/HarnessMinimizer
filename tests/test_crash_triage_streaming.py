"""Exercise LLM transport without provider requests or harness execution."""

from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error

import crash_triage_new as triage


def event(delta=None, finish_reason=None):
    return (
        "data: "
        + json.dumps({"choices": [{"delta": delta or {}, "finish_reason": finish_reason}]})
        + "\n\n"
    ).encode()


class Response(io.BytesIO):
    def __init__(self, body, content_type="text/event-stream"):
        super().__init__(body)
        self.headers = Message()
        self.headers["Content-Type"] = content_type


class CrashTriageStreamingTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.errors = io.StringIO()
        self.enterContext(redirect_stdout(self.output))
        self.enterContext(redirect_stderr(self.errors))
        self.enterContext(patch.object(
            triage, "llm_configuration",
            return_value=("https://unused.invalid/v4", "glm-5.3", "test-key"),
        ))

    def test_stream_keeps_max_effort_and_uses_only_final_answer(self):
        body = (
            b": heartbeat\r\n\r\n"
            + event({"reasoning_content": "Could this be harness-bug?"})
            + b'data: {"choices": [\r\ndata: {"delta": {"content": "library-"}}]}\r\n\r\n'
            + event({"content": "bug"}, "stop")
            + b"data: [DONE]\n\n"
        )
        with patch.object(triage.urllib.request, "urlopen", return_value=Response(body)) as send:
            result = triage.post_chat_completion(
                [{"role": "user", "content": "triage"}],
                timeout_seconds=1800, reasoning_effort="max",
            )
        self.assertEqual(result, "library-bug")
        payload = json.loads(send.call_args.args[0].data)
        self.assertTrue(payload["stream"])
        self.assertEqual(payload["reasoning_effort"], "max")
        self.assertEqual(send.call_args.kwargs["timeout"], 1800)
        self.assertIn("reasoning characters", self.output.getvalue())
        self.assertNotIn("Could this be harness-bug?", self.output.getvalue())

    def test_disconnection_discards_partial_verdict_before_retry(self):
        responses = [
            Response(event({"content": "library-bug"})),
            Response(event({"content": "harness-bug"}, "stop")),
        ]
        with (
            patch.object(triage.urllib.request, "urlopen", side_effect=responses) as send,
            patch.object(triage.time, "sleep"),
        ):
            self.assertEqual(triage.post_chat_completion([]), "harness-bug")
        self.assertEqual(send.call_count, 2)
        self.assertIn("discarding the partial answer", self.errors.getvalue())

    def test_missing_final_answer_or_token_limit_is_not_a_verdict(self):
        for body, error in [
            (event({"reasoning_content": "library-bug"}) + b"data: [DONE]\n\n", "no final answer"),
            (event({"content": "library-bug"}, "length"), "finish_reason='length'"),
        ]:
            with self.subTest(error=error), patch.object(
                triage.urllib.request, "urlopen", return_value=Response(body)
            ) as send:
                with self.assertRaisesRegex(triage.TriageError, error):
                    triage.post_chat_completion([])
                self.assertEqual(send.call_count, 1)

    def test_provider_stream_error_is_reported(self):
        body = b'data: {"error": {"code": "provider_timeout", "message": "generation timed out"}}\n\n'
        with patch.object(triage.urllib.request, "urlopen", return_value=Response(body)):
            with self.assertRaisesRegex(triage.TriageError, "provider_timeout"):
                triage.post_chat_completion([])

    def test_nonstreaming_gateway_response_is_supported(self):
        body = json.dumps({"choices": [{
            "message": {"content": "library-bug", "reasoning_content": "harness-bug?"},
            "finish_reason": "stop",
        }]}).encode()
        with patch.object(
            triage.urllib.request, "urlopen",
            return_value=Response(body, "application/json; charset=utf-8"),
        ):
            self.assertEqual(triage.post_chat_completion([]), "library-bug")

    def test_timeout_retry_preserves_effort_and_reports_cause(self):
        with (
            patch.object(triage.urllib.request, "urlopen", side_effect=[
                TimeoutError("timed out"),
                Response(event({"content": "library-bug"}, "stop")),
            ]) as send,
            patch.object(triage.time, "sleep"),
        ):
            self.assertEqual(
                triage.post_chat_completion([], reasoning_effort="max"), "library-bug"
            )
        for call in send.call_args_list:
            self.assertEqual(json.loads(call.args[0].data)["reasoning_effort"], "max")
        self.assertIn("TimeoutError: timed out", self.errors.getvalue())
        self.assertIn("failed after", self.errors.getvalue())

    def test_permanent_http_error_reports_actual_attempt_count(self):
        error = urllib.error.HTTPError(
            "https://unused.invalid", 400, "Bad Request", {}, io.BytesIO(b"bad parameter")
        )
        with patch.object(triage.urllib.request, "urlopen", side_effect=error) as send:
            with self.assertRaisesRegex(triage.TriageError, r"after 1 attempt.*HTTP 400"):
                triage.post_chat_completion([])
        self.assertEqual(send.call_count, 1)

    def test_llm_flags_are_separate_from_harness_timeout(self):
        args = triage.build_parser().parse_args([
            "--dir", "unused", "--timeout", "60",
            "--llm-timeout", "3600", "--llm-reasoning-effort", "max",
        ])
        self.assertEqual((args.timeout, args.llm_timeout, args.llm_reasoning_effort), (60, 3600, "max"))
        with self.assertRaisesRegex(SystemExit, "--llm-timeout must be positive"):
            triage.main(["--dir", "unused", "--llm-timeout", "0"])

    def test_active_chunked_http_stream_can_outlast_network_timeout(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                chunks = [event({"reasoning_content": "thinking"})] * 10
                chunks.append(event({"content": "library-bug"}) + b"data: [DONE]\n\n")
                try:
                    for chunk in chunks:
                        self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                        self.wfile.flush()
                        if chunk is not chunks[-1]:
                            time.sleep(0.15)
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass  # The client can close as soon as it sees [DONE].

            def log_message(self, *args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
            thread.start()
            try:
                with (
                    patch.object(triage, "llm_configuration", return_value=(
                        f"http://127.0.0.1:{server.server_port}", "glm-5.3", "test-key",
                    )),
                    patch.object(triage, "LLM_RETRIES", 1),
                ):
                    started = time.monotonic()
                    result = triage.post_chat_completion([], timeout_seconds=1, reasoning_effort="max")
                    elapsed = time.monotonic() - started
                self.assertEqual(result, "library-bug")
                self.assertGreater(elapsed, 1)
                self.assertEqual(len(requests), 1)
                self.assertEqual(requests[0]["reasoning_effort"], "max")
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

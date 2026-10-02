"""Check per-case reasoning fallback without provider calls or harness runs."""

from contextlib import redirect_stderr, redirect_stdout
import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import crash_triage_new_hku as triage
from tests.test_crash_triage_hku_retries import answer
from tests.test_crash_triage_streaming import Response, event


ROOT = Path(__file__).resolve().parents[1]


class CrashTriageHKUFallbackTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.errors = io.StringIO()
        self.enterContext(redirect_stdout(self.output))
        self.enterContext(redirect_stderr(self.errors))
        self.enterContext(patch.object(triage, "LLM_RETRIES", 1))
        self.enterContext(patch.object(triage, "TRIAGE_REPETITIONS", 4))
        self.enterContext(patch.object(triage, "PRINT_STACK_TRACE", False))
        self.enterContext(patch.object(
            triage, "llm_configuration",
            return_value=("https://unused.invalid/v1", "GLM-5.3-CLI", "test-key"),
        ))
        self.send = self.enterContext(patch.object(triage.urllib.request, "urlopen"))
        self.enterContext(patch.object(triage.time, "sleep"))
        self.record = self.enterContext(patch.object(triage, "append_fifth_vote_case"))

    def request_votes(self, effort="high", benchmark="test-case"):
        return triage.send_stack_trace_to_llm(
            "harness", None, "stack trace", benchmark_name=benchmark,
            tool="treereduce", reasoning_effort=effort,
        )

    def efforts(self):
        return [json.loads(call.args[0].data)["reasoning_effort"] for call in self.send.call_args_list]

    def test_fallback_preserves_votes_persists_for_case_and_resets_for_next_case(self):
        self.send.side_effect = [
            answer("library-bug"), answer(""), answer(""),
            answer("harness-bug"), answer("library-bug"), answer("library-bug"),
            answer("library-bug"), answer("library-bug"), answer("library-bug"),
        ]
        self.assertEqual(self.request_votes(), "library-bug")
        self.assertEqual(self.efforts(), ["high"] * 3 + ["low"] * 3)
        self.assertIn("Keeping 1 completed vote(s)", self.output.getvalue())
        self.assertIn("after 4 triages; stopping", self.output.getvalue())
        self.assertEqual(self.request_votes(benchmark="next-case"), "library-bug")
        self.assertEqual(self.efforts(), ["high"] * 3 + ["low"] * 3 + ["high"] * 3)
        self.assertEqual(self.output.getvalue().count("Reasoning fallback"), 1)
        self.record.assert_not_called()

    def test_success_on_last_high_attempt_does_not_switch_effort(self):
        self.send.side_effect = [answer("")] + [answer("library-bug") for _ in range(3)]
        self.assertEqual(self.request_votes(), "library-bug")
        self.assertEqual(self.efforts(), ["high"] * 4)
        self.assertNotIn("Reasoning fallback", self.output.getvalue())

    def test_low_exhaustion_stops_without_another_fallback(self):
        self.send.side_effect = lambda *args, **kwargs: answer("")
        with self.assertRaisesRegex(triage.LLMRetriesExhausted, "after 2 attempt"):
            self.request_votes()
        self.assertEqual(self.efforts(), ["high", "high", "low", "low"])
        self.assertEqual(self.output.getvalue().count("Reasoning fallback"), 1)

    def test_deciding_vote_can_fall_back_without_repeating_audit_record(self):
        self.send.side_effect = (
            [answer(verdict) for verdict in ("library-bug", "harness-bug") * 2]
            + [answer(""), answer(""), answer("library-bug")]
        )
        self.assertEqual(self.request_votes(), "library-bug")
        self.assertEqual(self.efforts(), ["high"] * 6 + ["low"])
        self.record.assert_called_once_with("test-case", "treereduce", 2, 2)

    def test_other_initial_efforts_do_not_fall_back(self):
        for effort in ("low", "medium", "max"):
            with self.subTest(effort=effort):
                self.send.reset_mock()
                self.send.side_effect = lambda *args, **kwargs: answer("")
                with self.assertRaises(triage.LLMRetriesExhausted):
                    self.request_votes(effort=effort)
                self.assertEqual(self.efforts(), [effort] * 2)
        self.assertNotIn("Reasoning fallback", self.output.getvalue())

    def test_permanent_http_error_on_last_attempt_does_not_trigger_fallback(self):
        self.send.side_effect = [answer(""), urllib.error.HTTPError(
            "https://unused.invalid", 401, "Unauthorized", {}, io.BytesIO(b"bad credentials"),
        )]
        with self.assertRaisesRegex(triage.TriageError, "HTTP 401") as error:
            self.request_votes()
        self.assertNotIsInstance(error.exception, triage.LLMRetriesExhausted)
        self.assertEqual(self.efforts(), ["high", "high"])

    def test_token_limit_does_not_trigger_fallback(self):
        self.send.side_effect = [Response(event({"content": "library-bug"}, "length"))]
        with self.assertRaisesRegex(triage.TriageError, "finish_reason='length'"):
            self.request_votes()
        self.assertEqual(self.efforts(), ["high"])

    def test_standalone_main_preserves_requested_csv_path(self):
        self.send.side_effect = [answer(""), answer("")] + [answer("library-bug") for _ in range(3)]
        with tempfile.TemporaryDirectory() as directory:
            benchmark = Path(directory) / "case"
            benchmark.mkdir()
            (benchmark / "harness.cpp").write_text("harness")
            (benchmark / "crash-input").write_bytes(b"input")
            csv_path = Path(directory) / "results-high.csv"
            with (
                patch.object(triage, "build_compile_command", return_value=["unused-compiler"]),
                patch.object(triage, "compile_harness"),
                patch.object(triage, "run_harness_for_stack_trace", return_value="stack trace"),
            ):
                result = triage.main([
                    "--dir", str(benchmark), "--tool", "none",
                    "--csv", str(csv_path), "--llm-reasoning-effort", "high",
                ])
            self.assertEqual(result, 0, self.errors.getvalue())
            with csv_path.open(newline="") as handle:
                self.assertEqual(list(csv.reader(handle)), [
                    ["dir", "tool", "triage result"], ["case", "none", "library-bug"],
                ])
            self.assertEqual(list(Path(directory).glob("*.csv")), [csv_path])
        self.assertEqual(self.efforts(), ["high"] * 2 + ["low"] * 3)


class CrashTriageHKUFallbackLauncherTests(unittest.TestCase):
    def test_launcher_keeps_initial_effort_in_csv_and_log_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "run_crash_triage_parallel_hku.sh"
            shutil.copyfile(ROOT / launcher.name, launcher)
            (root / "harness_bug_cases.tsv").write_text(
                "benchmark\tcompile_flags\tlink_flags\ncase\t-I$(pwd)/include\t-lunused\n"
            )
            worker = f'''
import json
from pathlib import Path
import sys
from unittest.mock import patch
sys.path.insert(0, {str(ROOT)!r})
import crash_triage_new_hku as triage
from tests.test_crash_triage_hku_retries import answer
args = triage.build_parser().parse_args()
assert args.llm_reasoning_effort == "high"
efforts = []
def send(request, **kwargs):
    effort = json.loads(request.data)["reasoning_effort"]
    efforts.append(effort)
    return answer("" if effort == "high" else "library-bug")
with (
    patch.object(triage, "LLM_RETRIES", 1),
    patch.object(triage, "TRIAGE_REPETITIONS", 4),
    patch.object(triage, "PRINT_STACK_TRACE", False),
    patch.object(triage, "llm_configuration", return_value=("https://unused.invalid", "GLM-5.3-CLI", "test-key")),
    patch.object(triage.urllib.request, "urlopen", side_effect=send),
    patch.object(triage.time, "sleep"),
):
    verdict = triage.send_stack_trace_to_llm("harness", None, "stack", benchmark_name=args.dir, tool=args.tool, reasoning_effort=args.llm_reasoning_effort)
    triage.append_csv_row(Path(args.csv), args.dir, args.tool, verdict)
assert efforts == ["high", "high", "low", "low", "low"], efforts
'''
            (root / "crash_triage_new_hku.py").write_text(worker)
            env = {key: value for key, value in os.environ.items() if not key.startswith("HR_TRIAGE_")}
            result = subprocess.run(
                ["bash", str(launcher), "2"], env=env,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Reasoning effort: high", result.stdout)
            self.assertEqual(
                [path.name for path in root.glob("*.csv")], ["crash_triage_results_new_hku_5.3high.csv"]
            )
            log_root = root / "triage-logs-hku-high"
            logs = list(log_root.glob("*/*.log"))
            self.assertTrue(logs)
            with (root / "crash_triage_results_new_hku_5.3high.csv").open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(logs), len(rows))
            for log in logs:
                self.assertIn("high -> low", log.read_text())
            self.assertFalse(list(root.rglob("*low*")))


if __name__ == "__main__":
    unittest.main()

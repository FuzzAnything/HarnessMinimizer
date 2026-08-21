import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from tests import crash_tester


class TestCrashTesterStatistics(unittest.TestCase):
    def test_compile_with_pch_uses_amortized_pch_compile_flags(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pch_path = Path(tmpdir) / "harness_prefix.pch"
            source_path = Path(tmpdir) / "candidate.cpp"
            pch_path.write_text("", encoding="utf-8")
            source_path.write_text("int main() { return 0; }\n", encoding="utf-8")

            args = Namespace(
                pch_path=str(pch_path),
                pch_amortized_link=True,
                fdp_trace=None,
                compile_flags="-I/tmp/include",
                link_flags="-lm",
                source=str(source_path),
            )

            compile_proc = type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            link_proc = type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()

            with patch(
                "tests.crash_tester.subprocess.run",
                side_effect=[compile_proc, link_proc],
            ) as mock_run:
                status, object_path = crash_tester.compile_with_pch(
                    args,
                    str(Path(tmpdir) / "candidate.out"),
                )

            self.assertEqual(status, 0)
            self.assertIsNotNone(object_path)
            compile_cmd = mock_run.call_args_list[0].args[0]
            self.assertIn("-include-pch", compile_cmd)
            self.assertIn(str(pch_path), compile_cmd)
            self.assertIn("-fPIC", compile_cmd)
            self.assertIn("-fsanitize=address,undefined", compile_cmd)
            self.assertNotIn("-fsanitize=address,fuzzer,undefined", compile_cmd)

    def test_run_standalone_candidate_retries_libfuzzer_oom_without_rss_limit(self):
        args = Namespace(
            exec_timeout_ms=1234,
            retry_oom_without_rss_limit=True,
            _debug_first_execution_return_code=None,
            _debug_oom_retry_attempted=None,
        )

        with patch(
            "tests.crash_tester.run_executable",
            side_effect=[
                (71, "ERROR: libFuzzer: out-of-memory (malloc(42))", 10),
                (77, "SUMMARY: AddressSanitizer: heap-buffer-overflow", 11),
            ],
        ) as mock_run:
            status, run_log, exec_time_ms = crash_tester.run_standalone_candidate(
                args,
                ["/tmp/poc.out", "seed.bin"],
                env={},
            )

        self.assertEqual(status, 77)
        self.assertIn("AddressSanitizer", run_log)
        self.assertEqual(exec_time_ms, 11)
        self.assertEqual(args._debug_first_execution_return_code, 71)
        self.assertTrue(args._debug_oom_retry_attempted)
        self.assertEqual(mock_run.call_count, 2)
        retry_cmd = mock_run.call_args_list[1].args[0]
        self.assertEqual(retry_cmd, ["/tmp/poc.out", "-rss_limit_mb=0", "seed.bin"])

    def test_run_standalone_candidate_does_not_retry_when_disabled(self):
        args = Namespace(
            exec_timeout_ms=1234,
            retry_oom_without_rss_limit=False,
            _debug_first_execution_return_code=None,
            _debug_oom_retry_attempted=None,
        )

        with patch(
            "tests.crash_tester.run_executable",
            return_value=(71, "ERROR: libFuzzer: out-of-memory (malloc(42))", 10),
        ) as mock_run:
            status, _run_log, exec_time_ms = crash_tester.run_standalone_candidate(
                args,
                ["/tmp/poc.out", "seed.bin"],
                env={},
            )

        self.assertEqual(status, 71)
        self.assertEqual(exec_time_ms, 10)
        self.assertEqual(args._debug_first_execution_return_code, 71)
        self.assertFalse(args._debug_oom_retry_attempted)
        mock_run.assert_called_once()

    def test_update_statistics_file_accumulates_counts_and_probabilities(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            stats_path = Path(tmpdir) / "statistics.txt"

            crash_tester._update_statistics_file(str(stats_path), 77)
            crash_tester._update_statistics_file(str(stats_path), 1)
            crash_tester._update_statistics_file(str(stats_path), -1)
            crash_tester._update_statistics_file(str(stats_path), 77)

            text = stats_path.read_text(encoding="utf-8")
            self.assertIn("total: 4", text)
            self.assertIn("count_77: 2", text)
            self.assertIn("count_1: 1", text)
            self.assertIn("count_-1: 1", text)
            self.assertIn("probability_77: 0.500000", text)
            self.assertIn("probability_1: 0.250000", text)
            self.assertIn("probability_-1: 0.250000", text)

    def test_finalize_result_updates_statistics_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            stats_path = Path(tmpdir) / "statistics.txt"
            args = Namespace(statistics_file=str(stats_path))

            result = crash_tester._finalize_result(args, 77)

            self.assertEqual(result, 77)
            self.assertTrue(stats_path.exists())

    def test_update_last_interesting_file_copies_only_when_content_changes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "candidate.cpp"
            snapshot = Path(tmpdir) / "last_interesting.cpp"

            source.write_text("int a = 1;\n", encoding="utf-8")
            crash_tester._update_last_interesting_file(str(source), str(snapshot))
            first_mtime = snapshot.stat().st_mtime_ns

            crash_tester._update_last_interesting_file(str(source), str(snapshot))
            self.assertEqual(snapshot.stat().st_mtime_ns, first_mtime)

            source.write_text("int a = 2;\n", encoding="utf-8")
            crash_tester._update_last_interesting_file(str(source), str(snapshot))
            self.assertEqual(snapshot.read_text(encoding="utf-8"), "int a = 2;\n")

    def test_amortized_fallback_state_uses_countdown_before_fast_probe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            args = Namespace(
                amortized_runner_socket=str(Path(tmpdir) / "runner.sock"),
                amortized_plugin_fallback_link_flags="-ltarget",
            )

            self.assertIsNone(crash_tester.amortized_initial_plugin_link_flags(args))

            crash_tester._enable_amortized_fallback_first(args, probe_interval=2)

            self.assertEqual(
                crash_tester.amortized_initial_plugin_link_flags(args),
                "-ltarget",
            )
            self.assertEqual(
                crash_tester.amortized_initial_plugin_link_flags(args),
                "-ltarget",
            )
            self.assertIsNone(crash_tester.amortized_initial_plugin_link_flags(args))

    def test_amortized_fallback_retry_enables_fallback_first_window(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            args = Namespace(
                amortized_runner_socket=str(Path(tmpdir) / "runner.sock"),
                amortized_plugin_fallback_link_flags="-ltarget",
            )

            with (
                patch(
                    "tests.crash_tester.run_with_amortized_runner",
                    side_effect=[
                        (125, "dlopen candidate failed: candidate.so: undefined symbol: hidden"),
                        (77, "crash"),
                    ],
                ) as run_candidate,
                patch("tests.crash_tester.link_amortized_plugin", return_value=0) as link_plugin,
            ):
                status, run_log = crash_tester.run_with_amortized_runner_maybe_fallback(
                    args,
                    "/tmp/candidate.so",
                    "/tmp/candidate.o",
                )

            self.assertEqual(status, 77)
            self.assertEqual(run_log, "crash")
            self.assertTrue(args._amortized_plugin_fallback_linked)
            link_plugin.assert_called_once_with(
                args,
                "/tmp/candidate.o",
                "/tmp/candidate.so",
                "-ltarget",
            )
            self.assertEqual(run_candidate.call_count, 2)
            self.assertEqual(
                crash_tester.amortized_initial_plugin_link_flags(args),
                "-ltarget",
            )

    def test_amortized_fallback_retry_is_skipped_when_plugin_already_used_fallback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            args = Namespace(
                amortized_runner_socket=str(Path(tmpdir) / "runner.sock"),
                amortized_plugin_fallback_link_flags="-ltarget",
                _amortized_plugin_fallback_linked=True,
            )

            with (
                patch(
                    "tests.crash_tester.run_with_amortized_runner",
                    return_value=(
                        125,
                        "dlopen candidate failed: candidate.so: undefined symbol: hidden",
                    ),
                ) as run_candidate,
                patch("tests.crash_tester.link_amortized_plugin", return_value=0) as link_plugin,
            ):
                status, run_log = crash_tester.run_with_amortized_runner_maybe_fallback(
                    args,
                    "/tmp/candidate.so",
                    "/tmp/candidate.o",
                )

            self.assertEqual(status, 125)
            self.assertIn("undefined symbol", run_log)
            run_candidate.assert_called_once()
            link_plugin.assert_not_called()


if __name__ == "__main__":
    unittest.main()

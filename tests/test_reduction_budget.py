import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from harnessminimizer import reduction_budget
from harnessminimizer.reduction_budget import CHECKPOINT_START_ENV, run_bounded_reduction
from harnessminimizer.reduction_engines import ReducerInvocation
from tests import crash_tester


class ReductionBudgetTests(unittest.TestCase):
    def test_checkpoint_cutoff_is_shared_with_testers_without_changing_parent_environment(self):
        for budget, cutoff in [(2400, 2260), (600, 460), (240, 100), (30, 100)]:
            with self.subTest(budget=budget), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output, snapshot = root / "reduced.cpp", root / "checkpoint.cpp"
                with patch.dict(os.environ, {CHECKPOINT_START_ENV: "previous-run"}), \
                        patch.object(reduction_budget.time, "monotonic", return_value=100), \
                        patch.object(reduction_budget, "run_supervised") as run:
                    run.return_value = subprocess.CompletedProcess(["reducer"], 0)
                    run_bounded_reduction(["reducer"], str(output), budget, str(snapshot))
                    environment = run.call_args.kwargs["env"]
                    self.assertEqual(float(environment[CHECKPOINT_START_ENV]), cutoff)
                    self.assertEqual(run.call_args.kwargs["timeout"], budget)
                    self.assertEqual(os.environ[CHECKPOINT_START_ENV], "previous-run")
                    self.assertFalse(output.exists())
                    self.assertFalse(snapshot.exists())

    def test_only_early_accepted_candidates_cannot_recover_a_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "accepted.cpp"
            output, snapshot = root / "reduced.cpp", root / "checkpoint.cpp"
            source.write_text("int accepted_before_window;\n")

            def accept_then_stall(command, *, env, timeout, **_kwargs):
                with patch.dict(os.environ, env, clear=True):
                    crash_tester._update_last_interesting_file(str(source), str(snapshot))
                self.assertFalse(snapshot.exists())
                raise subprocess.TimeoutExpired(command, timeout)

            with patch.object(reduction_budget.time, "monotonic", return_value=100), \
                    patch.object(reduction_budget, "run_supervised", side_effect=accept_then_stall):
                with self.assertRaisesRegex(RuntimeError, "without a candidate"):
                    run_bounded_reduction(["reducer"], str(output), 2400, str(snapshot))
            self.assertFalse(output.exists())
            self.assertFalse(snapshot.exists())

    def test_normal_completion_before_checkpoint_window_preserves_reducer_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, snapshot = root / "reduced.cpp", root / "checkpoint.cpp"
            result = run_bounded_reduction(
                [sys.executable, "-c",
                 "import pathlib, sys; pathlib.Path(sys.argv[1]).write_text('int reduced;')",
                 str(output)],
                str(output), 2400, str(snapshot),
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "int reduced;")
            self.assertFalse(snapshot.exists())

    def test_timeout_recovers_candidate_accepted_in_last_four_minutes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "accepted.cpp"
            output, snapshot = root / "reduced.cpp", root / "checkpoint.cpp"

            def accept_then_stall(command, *, env, timeout, **_kwargs):
                with patch.dict(os.environ, env, clear=True):
                    source.write_text("int early_candidate;\n")
                    with patch.object(crash_tester.time, "monotonic", return_value=2259):
                        crash_tester._update_last_interesting_file(str(source), str(snapshot))
                    self.assertFalse(snapshot.exists())
                    source.write_text("int late_candidate;\n")
                    with patch.object(crash_tester.time, "monotonic", return_value=2260):
                        crash_tester._update_last_interesting_file(str(source), str(snapshot))
                raise subprocess.TimeoutExpired(command, timeout)

            with patch.object(reduction_budget.time, "monotonic", return_value=100), \
                    patch.object(reduction_budget, "run_supervised", side_effect=accept_then_stall):
                result = run_bounded_reduction(["reducer"], str(output), 2400, str(snapshot))
            self.assertEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "int late_candidate;\n")

    def test_budget_recovers_atomic_snapshot_and_stops_testers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "reduced.cpp"
            snapshot = root / "checkpoint.cpp"
            script = (
                "import pathlib, subprocess, sys, time; "
                "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
                "pathlib.Path(sys.argv[2]).write_text('int reduced;'); "
                "time.sleep(60)"
            )
            result = run_bounded_reduction(
                [sys.executable, "-c", script, str(root / "child"), str(snapshot)],
                str(output), 1, str(snapshot),
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "int reduced;")
            pid = int((root / "child").read_text())
            process = Path(f"/proc/{pid}/stat")
            self.assertTrue(not process.exists() or process.read_text().split()[2] == "Z")

    def test_stale_candidate_cannot_make_an_empty_timeout_succeed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, snapshot = root / "reduced.cpp", root / "checkpoint.cpp"
            output.write_text("stale")
            snapshot.write_text("stale checkpoint")
            with self.assertRaisesRegex(RuntimeError, "without a candidate"):
                run_bounded_reduction(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    str(output), 0.1, str(snapshot),
                )

    def test_regular_reducer_failure_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_bounded_reduction(
                [sys.executable, "-c", "raise SystemExit(7)"],
                os.path.join(directory, "reduced.cpp"), 1,
                os.path.join(directory, "checkpoint.cpp"),
            )
            self.assertEqual(result.returncode, 7)

    def test_invalid_budgets_fail_before_launch(self):
        for value in [0, -1, float("nan"), float("inf")]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                run_bounded_reduction(["must-not-run"], "unused", value, "unused-snapshot")

    def test_perses_timeout_preserves_cwd_log_environment_and_result_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "input"
            inputs.mkdir()
            output = root / "output" / "candidate.cpp"
            destination = root / "export.cpp"
            checkpoint = root / "checkpoint.cpp"
            script = (
                "import json, os, pathlib, sys, time; "
                "print('perses progress', flush=True); "
                "pathlib.Path('observed.json').write_text(json.dumps(dict(os.environ))); "
                "pathlib.Path(sys.argv[1]).write_text('int verified_candidate;'); "
                "time.sleep(60)"
            )
            invocation = ReducerInvocation(
                [sys.executable, "-c", script, str(checkpoint)], output, destination,
                {"tool": "perses"}, cwd=inputs, log_path=root / "perses.log",
                env={**os.environ, "TEST_TRACE_REFERENCE": "approved-trace"},
            )
            result = run_bounded_reduction(
                invocation.command, str(output), 1, str(checkpoint), invocation=invocation,
            )
            self.assertEqual(result.returncode, 0)
            self.assertFalse(destination.exists())
            invocation.publish_result()
            self.assertEqual(destination.read_text(), "int verified_candidate;")
            self.assertIn("perses progress", invocation.log_path.read_text())
            environment = json.loads((inputs / "observed.json").read_text())
            self.assertEqual(environment["TEST_TRACE_REFERENCE"], "approved-trace")
            self.assertIn(CHECKPOINT_START_ENV, environment)

    def test_perses_initial_output_without_a_late_checkpoint_cannot_recover(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, snapshot = root / "initial.cpp", root / "checkpoint.cpp"
            invocation = ReducerInvocation(
                [sys.executable, "-c",
                 "import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text('initial');time.sleep(60)",
                 str(output)], output, root / "export.cpp", {"tool": "perses"},
                cwd=root, log_path=root / "perses.log",
            )
            with self.assertRaisesRegex(RuntimeError, "without a candidate"):
                run_bounded_reduction(
                    invocation.command, str(output), 0.5, str(snapshot), invocation=invocation,
                )
            self.assertFalse(invocation.destination.exists())

    def test_perses_normal_result_and_failure_keep_their_original_meaning(self):
        for exit_code in (0, 7):
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / "candidate.cpp"
                invocation = ReducerInvocation(
                    [sys.executable, "-c",
                     "import pathlib,sys;print('engine diagnostic');pathlib.Path(sys.argv[1]).write_text('normal');sys.exit(int(sys.argv[2]))",
                     str(output), str(exit_code)], output, root / "export.cpp",
                    {"tool": "perses"}, cwd=root, log_path=root / "perses.log",
                )
                result = run_bounded_reduction(
                    invocation.command, str(output), 2400, str(root / "checkpoint.cpp"),
                    invocation=invocation,
                )
                self.assertEqual(result.returncode, exit_code)
                if exit_code == 0:
                    invocation.publish_result()
                    self.assertEqual(invocation.destination.read_text(), "normal")
                else:
                    self.assertIn("engine diagnostic", result.stdout)
                    self.assertFalse(invocation.destination.exists())

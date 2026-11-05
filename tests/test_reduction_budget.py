import os
from pathlib import Path
import sys
import tempfile
import unittest

from harnessminimizer.reduction_budget import run_bounded_reduction


class ReductionBudgetTests(unittest.TestCase):
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

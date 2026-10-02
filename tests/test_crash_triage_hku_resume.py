"""Check HKU batch resume using temporary CSVs and fake triage workers."""

import csv
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from tests.test_crash_triage_parallel import FAKE_WORKER


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "run_crash_triage_parallel_hku.sh"


class CrashTriageHKUResumeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        shutil.copyfile(LAUNCHER, self.root / LAUNCHER.name)
        (self.root / "crash_triage_new_hku.py").write_text(FAKE_WORKER.format(root=str(ROOT)))
        with (self.root / "harness_bug_cases.tsv").open("w", newline="") as handle:
            writer = csv.writer(handle, delimiter="\t")
            writer.writerow(["benchmark", "compile_flags", "link_flags"])
            for index in range(6):
                writer.writerow([
                    f"case-{index}", "-I$(pwd)/build/sanitizer/include",
                    "-L$(pwd)/build/sanitizer/lib -lsqlite3",
                ])
        self.csv = self.root / "custom results.csv"
        self.env = os.environ | {
            "HR_TRIAGE_CSV": str(self.csv),
            "HR_TRIAGE_LOG_DIR": str(self.root / "logs"),
            "HR_TEST_STATE": str(self.root / "state.json"),
            "HR_TEST_FAIL": "",
        }
        self.all_pairs = {
            (f"case-{index}", tool)
            for index in range(6) for tool in ("none", "treereduce", "cdd", "wdd", "perses")
        }

    def seed_results(self):
        rows = [
            ["case-0", "none", "library-bug"],
            ["case-0", "treereduce", "harness-bug"],
            ["case-1", "none", "harness-bug"],
            ["case-2", "treereduce", "library-bug"],
        ]
        with self.csv.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["dir", "tool", "triage result"])
            writer.writerows(rows)
            writer.writerow(rows[0])  # Duplicate success still counts only once.
            writer.writerow(["case-3", "none", ""])  # Not a completed result.
            writer.writerow(["outside-manifest", "none", "library-bug"])
        return {(row[0], row[1]) for row in rows}

    def run_batch(self, *flags):
        return subprocess.run(
            ["bash", str(self.root / LAUNCHER.name), "3", *flags],
            env=self.env, capture_output=True, text=True, timeout=30,
        )

    def commands(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return [shlex.split(line) for line in result.stdout.splitlines()]

    def pairs(self, commands):
        return {(args[args.index("--dir") + 1], args[args.index("--tool") + 1]) for args in commands}

    def test_resume_runs_only_missing_pairs_and_second_resume_does_nothing(self):
        completed = self.seed_results()
        original = self.csv.read_bytes()
        result = self.run_batch("--resume")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = json.loads((self.root / "state.json").read_text())
        self.assertEqual(len(state["runs"]), 26)
        self.assertEqual({(run["dir"], run["tool"]) for run in state["runs"]}, self.all_pairs - completed)
        self.assertEqual(state["active"], 0)
        self.assertGreater(state["maximum"], 1)
        self.assertLessEqual(state["maximum"], 3)
        for run in state["runs"]:
            self.assertEqual(run["llm_reasoning_effort"], "high")
            self.assertEqual(run["compile_flags"], "-I$(pwd)/build/sanitizer/include")
            self.assertEqual(run["link_flags"], "-L$(pwd)/build/sanitizer/lib -lsqlite3")
        self.assertTrue(self.csv.read_bytes().startswith(original))
        self.assertIn("Skipping 4 completed example/tool pairs; 26 pairs remain", result.stderr)
        with self.csv.open(newline="") as handle:
            rows = list(csv.reader(handle))
        self.assertEqual(rows.count(["dir", "tool", "triage result"]), 1)
        self.assertEqual(len(rows), 34)  # Header, seven original rows, 26 new results.
        self.assertEqual(len(list((self.root / "logs").glob("*.log"))), 26)
        csv_after = self.csv.read_bytes()
        result = self.run_batch("--resume")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("0 pairs remain", result.stderr)
        self.assertEqual(self.csv.read_bytes(), csv_after)
        self.assertEqual(json.loads((self.root / "state.json").read_text()), state)

    def test_resume_preview_preserves_flags_and_writes_nothing(self):
        completed = self.seed_results()
        original = self.csv.read_bytes()
        for flags in (("--resume", "--dry-run"), ("--dry-run", "--resume")):
            with self.subTest(flags=flags):
                commands = self.commands(self.run_batch(*flags))
                self.assertEqual(len(commands), 26)
                self.assertEqual(self.pairs(commands), self.all_pairs - completed)
                for args in commands:
                    self.assertEqual(args[:3], ["python3", "-u", "crash_triage_new_hku.py"])
                    self.assertEqual(args[args.index("--csv") + 1], str(self.csv))
                    self.assertIn("--compile-flags=-I$(pwd)/build/sanitizer/include", args)
                    self.assertIn("--link-flags=-L$(pwd)/build/sanitizer/lib -lsqlite3", args)
                self.assertEqual(self.csv.read_bytes(), original)
                self.assertFalse((self.root / "state.json").exists())
                self.assertFalse((self.root / "logs").exists())

    def test_missing_or_empty_csv_resumes_all_pairs(self):
        for empty_file in (False, True):
            with self.subTest(empty_file=empty_file):
                if empty_file:
                    self.csv.touch()
                commands = self.commands(self.run_batch("--resume", "--dry-run"))
                self.assertEqual(len(commands), 30)
                self.assertEqual(self.pairs(commands), self.all_pairs)
                self.assertEqual(self.csv.exists(), empty_file)

    def test_without_resume_all_pairs_are_still_scheduled(self):
        self.seed_results()
        commands = self.commands(self.run_batch("--dry-run"))
        self.assertEqual(len(commands), 30)
        self.assertEqual(self.pairs(commands), self.all_pairs)

    def test_unexpected_csv_header_stops_before_launching_any_jobs(self):
        self.csv.write_text("wrong,columns\ncase-0,none\n")
        result = self.run_batch("--resume")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot resume: unexpected CSV header", result.stderr)
        self.assertFalse((self.root / "state.json").exists())
        self.assertEqual(self.csv.read_text(), "wrong,columns\ncase-0,none\n")

    def test_failed_pair_remains_pending_while_other_pairs_complete(self):
        self.seed_results()
        self.env["HR_TEST_FAIL"] = "case-1/treereduce"
        result = self.run_batch("--resume")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("case-1 / treereduce (exit 7)", result.stderr)
        commands = self.commands(self.run_batch("--resume", "--dry-run"))
        self.assertEqual(len(commands), 1)
        self.assertEqual(self.pairs(commands), {("case-1", "treereduce")})


if __name__ == "__main__":
    unittest.main()

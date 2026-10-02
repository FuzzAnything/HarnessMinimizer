"""Verify the batch launcher using fake triage workers, without LLM calls."""

import csv
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "run_crash_triage_parallel.sh"

FAKE_WORKER = '''
import fcntl
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, {root!r})
import crash_triage_new as triage

args = triage.build_parser().parse_args()

def record(starting):
    with open(os.environ["HR_TEST_STATE"], "a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        text = handle.read()
        state = json.loads(text) if text else dict(active=0, maximum=0, runs=[])
        state["active"] += 1 if starting else -1
        state["maximum"] = max(state["maximum"], state["active"])
        if starting:
            state["runs"].append(vars(args))
        handle.seek(0)
        handle.truncate()
        json.dump(state, handle)

record(True)
try:
    time.sleep(0.1)
    if os.environ.get("HR_TEST_FAIL") == args.dir + "/" + args.tool:
        print("simulated failure", flush=True)
        sys.exit(7)
    triage.append_csv_row(Path(args.csv), args.dir, args.tool, "library-bug")
finally:
    record(False)
'''


class CrashTriageParallelTests(unittest.TestCase):
    def prepare_batch(self, directory):
        root = Path(directory)
        shutil.copyfile(LAUNCHER, root / LAUNCHER.name)
        (root / "crash_triage_new.py").write_text(FAKE_WORKER.format(root=str(ROOT)))
        with (root / "harness_bug_cases.tsv").open("w", newline="") as handle:
            writer = csv.writer(handle, delimiter="\t")
            writer.writerow(["benchmark", "compile_flags", "link_flags"])
            for index in range(6):
                writer.writerow([
                    f"case-{index}", "-I$(pwd)/build/sanitizer/include",
                    "-L$(pwd)/build/sanitizer/lib -lsqlite3",
                ])
        env = os.environ | {
            "HR_TRIAGE_CSV": str(root / "results.csv"),
            "HR_TRIAGE_LOG_DIR": str(root / "logs"),
            "HR_TEST_STATE": str(root / "state.json"),
            "HR_TEST_FAIL": "",
        }
        return root, env

    def run_batch(self, root, env):
        return subprocess.run(
            ["bash", str(root / LAUNCHER.name), "3"],
            env=env, capture_output=True, text=True, timeout=30,
        )

    def test_parallel_writes_preserve_every_result_and_one_header(self):
        with tempfile.TemporaryDirectory() as directory:
            root, env = self.prepare_batch(directory)
            result = self.run_batch(root, env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            state = json.loads((root / "state.json").read_text())
            self.assertEqual(state["active"], 0)
            self.assertGreater(state["maximum"], 1)
            self.assertLessEqual(state["maximum"], 3)
            self.assertEqual(len(state["runs"]), 6)
            for run in state["runs"]:
                self.assertEqual(run["llm_reasoning_effort"], "high")
                self.assertEqual(run["compile_flags"], "-I$(pwd)/build/sanitizer/include")
                self.assertEqual(run["link_flags"], "-L$(pwd)/build/sanitizer/lib -lsqlite3")
            with (root / "results.csv").open(newline="") as handle:
                rows = list(csv.reader(handle))
            header = ["dir", "tool", "triage result"]
            self.assertEqual(rows[0], header)
            self.assertEqual(rows.count(header), 1)
            self.assertEqual(len(rows), 7)
            self.assertEqual(
                {(row[0], row[1]) for row in rows[1:]},
                {(f"case-{index}", tool) for index in range(6) for tool in ("treereduce",)},
            )
            self.assertEqual(len(list((root / "logs").glob("*.log"))), 6)

    def test_failed_job_keeps_existing_results_and_other_jobs_continue(self):
        with tempfile.TemporaryDirectory() as directory:
            root, env = self.prepare_batch(directory)
            (root / "results.csv").write_text("dir,tool,triage result\nexisting,none,harness-bug\n")
            env["HR_TEST_FAIL"] = "case-0/treereduce"
            result = self.run_batch(root, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("case-0 / treereduce (exit 7)", result.stderr)
            self.assertIn("simulated failure", (root / "logs/treereduce-case-0.log").read_text())
            with (root / "results.csv").open(newline="") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(rows[1], ["existing", "none", "harness-bug"])
            self.assertEqual(len(rows), 7)  # Header, existing row, 5 successes.
            self.assertIn(["case-1", "treereduce", "library-bug"], rows)
            self.assertEqual(len(json.loads((root / "state.json").read_text())["runs"]), 6)

    def test_dry_run_preserves_all_cases_and_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = os.environ | {
                "HR_TRIAGE_CSV": str(root / "results.csv"),
                "HR_TRIAGE_LOG_DIR": str(root / "logs"),
            }
            result = subprocess.run(
                ["bash", str(LAUNCHER), "4", "--dry-run"],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with (ROOT / "harness_bug_cases.tsv").open(newline="") as handle:
                cases = list(csv.DictReader(handle, delimiter="\t"))
            expected = {
                (case["benchmark"], tool, case["compile_flags"], case["link_flags"])
                for case in cases for tool in ("treereduce",)
            }
            actual = []
            for line in result.stdout.splitlines():
                args = shlex.split(line)
                self.assertEqual(args[:3], ["python3", "-u", "crash_triage_new.py"])
                self.assertEqual(args[args.index("--llm-reasoning-effort") + 1], "high")
                self.assertEqual(args[args.index("--csv") + 1], str(root / "results.csv"))
                actual.append((
                    args[args.index("--dir") + 1], args[args.index("--tool") + 1],
                    next(arg.split("=", 1)[1] for arg in args if arg.startswith("--compile-flags=")),
                    next(arg.split("=", 1)[1] for arg in args if arg.startswith("--link-flags=")),
                ))
            self.assertEqual(len(actual), len(expected))
            self.assertEqual(set(actual), expected)
            self.assertFalse((root / "results.csv").exists())
            self.assertFalse((root / "logs").exists())


if __name__ == "__main__":
    unittest.main()

"""Verify deduplication rules, data preservation, and coordination with writers."""

import csv
import fcntl
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import deduplicate_triage_csv as dedup


SCRIPT = Path(dedup.__file__).resolve()
HEADER = ["dir", "tool", "triage result"]


class DeduplicateTriageCSVTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "triage results.csv"

    def write_rows(self, rows, header=HEADER):
        with self.path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)

    def read_rows(self):
        with self.path.open(newline="", encoding="utf-8") as handle:
            return list(csv.reader(handle))

    def test_conflicts_use_tool_policy_even_when_preferred_verdict_is_a_minority(self):
        tools = ("none", "treereduce", "perses", "wdd", "cdd", "new-engine")
        rows = []
        expected = []
        for tool in tools:
            preferred = "library-bug" if tool == "none" else "harness-bug"
            opposite = "harness-bug" if tool == "none" else "library-bug"
            rows.extend([["case-1", tool, opposite]] * 2 + [["case-1", tool, preferred]])
            expected.append(["case-1", tool, preferred])
        self.write_rows(rows)
        original = self.path.read_bytes()
        inode = self.path.stat().st_ino
        before, after, conflicts, backup = dedup.deduplicate_csv_in_place(self.path)
        self.assertEqual((before, after, conflicts), (18, 6, 6))
        self.assertEqual(self.read_rows(), [HEADER, *expected])
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(self.path.stat().st_ino, inode)

    def test_matching_results_keep_first_row_and_preserve_columns_and_order(self):
        header = ["notes", "tool", "triage result", "dir"]
        rows = [
            ["discard conflict", "none", "harness-bug", "a"],
            ["unique", "treereduce", "library-bug", "b"],
            ['first, with "quotes"\nand a newline', "wdd", "library-bug", "c"],
            ["first preferred", "none", "library-bug", "a"],
            ["later preferred", "none", "library-bug", "a"],
            ["later matching", "wdd", "library-bug", "c"],
            ["same dir, different tool", "treereduce", "harness-bug", "a"],
        ]
        self.write_rows(rows, header)
        before, after, conflicts, _ = dedup.deduplicate_csv_in_place(self.path)
        self.assertEqual((before, after, conflicts), (7, 4, 1))
        self.assertEqual(self.read_rows(), [header, *(rows[index] for index in (1, 2, 3, 6))])
        self.assertEqual(dedup.deduplicate_csv_in_place(self.path), (4, 4, 0, None))
        self.assertEqual(len(list(self.root.glob("*.bak-*"))), 1)

    def test_unique_file_is_not_rewritten_or_backed_up(self):
        self.path.write_bytes(b"dir,tool,triage result\ncase,none,harness-bug\n")
        original = self.path.read_bytes()
        modified = self.path.stat().st_mtime_ns
        self.assertEqual(dedup.deduplicate_csv_in_place(self.path), (1, 1, 0, None))
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.path.stat().st_mtime_ns, modified)
        self.assertEqual(list(self.root.glob("*.bak-*")), [])

    def test_invalid_input_is_rejected_without_modifying_it(self):
        for body in (
            b"dir,tool\ncase,none\n",
            b"dir,tool,triage result\ncase,none\n",
            b"dir,tool,triage result\ncase,none,unknown\n",
            b"dir,tool,triage result\n,none,library-bug\n",
            b'dir,tool,triage result\n"unclosed,none,library-bug\n',
        ):
            with self.subTest(body=body):
                self.path.write_bytes(body)
                with self.assertRaises((ValueError, csv.Error)):
                    dedup.deduplicate_csv_in_place(self.path)
                self.assertEqual(self.path.read_bytes(), body)
                self.assertEqual(list(self.root.glob("*.bak-*")), [])

    def test_backup_failure_leaves_original_and_existing_backup_untouched(self):
        self.write_rows([["case", "none", "library-bug"]] * 2)
        original = self.path.read_bytes()
        backup = self.path.with_name(self.path.name + ".bak-existing")
        backup.write_bytes(b"previous backup")
        with patch.object(dedup, "datetime") as clock:
            clock.now.return_value.strftime.return_value = "existing"
            with self.assertRaises(FileExistsError):
                dedup.deduplicate_csv_in_place(self.path)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(backup.read_bytes(), b"previous backup")

    def test_cli_waits_for_writer_and_includes_its_new_result(self):
        self.write_rows([["case", "none", "harness-bug"]])
        with self.path.open("a", newline="") as writer_handle:
            fcntl.flock(writer_handle.fileno(), fcntl.LOCK_EX)
            with subprocess.Popen(
                [sys.executable, str(SCRIPT), str(self.path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ) as process:
                try:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        process.wait(timeout=0.2)
                    csv.writer(writer_handle).writerow(["case", "none", "library-bug"])
                    writer_handle.flush()
                finally:
                    fcntl.flock(writer_handle.fileno(), fcntl.LOCK_UN)
                output, errors = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, errors)
        self.assertIn("Rows: 2 -> 1; removed 1; conflicting pairs resolved: 1", output)
        self.assertEqual(self.read_rows(), [HEADER, ["case", "none", "library-bug"]])


if __name__ == "__main__":
    unittest.main()

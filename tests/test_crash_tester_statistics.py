import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from tests import crash_tester


class TestCrashTesterStatistics(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

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

    def test_finalize_result_skips_statistics_when_iteration_is_set(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            stats_path = Path(tmpdir) / "statistics.txt"
            args = Namespace(statistics_file=str(stats_path), iteration=10)

            result = crash_tester._finalize_result(args, 77)

            self.assertEqual(result, 77)
            self.assertFalse(stats_path.exists())


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from harnessreducer import reducer_runner
from harnessreducer.api import tag_harness_with_fdp_ids


class TestHarnessTagging(unittest.TestCase):
    def setUp(self):
        reducer_runner.TREEDUCER_DIR = None
        reducer_runner._IS_USER_WORK_DIR = False

    def test_work_dir_beside_source_does_not_overwrite_input(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir) / "harness.cpp"
            original = (
                "void f(FuzzedDataProvider &fdp) {\n"
                "  (void)fdp.ConsumeBool();\n"
                "}\n"
            )
            source_path.write_text(original, encoding="utf-8")
            reducer_runner.configure_work_dir(tmpdir)

            tagged_path = Path(
                tag_harness_with_fdp_ids(str(source_path), 100000, "FDP_ID")
            )

            self.assertEqual(source_path.read_text(encoding="utf-8"), original)
            self.assertEqual(tagged_path.name, "harness.tagged.cpp")
            self.assertNotEqual(tagged_path, source_path)
            self.assertIn("FDP_ID:100000", tagged_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

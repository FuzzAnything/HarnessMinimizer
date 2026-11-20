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

            tagged = tag_harness_with_fdp_ids(str(source_path), 100000, "FDP_ID")
            tagged_path = Path(tagged)

            self.assertEqual(source_path.read_text(encoding="utf-8"), original)
            self.assertEqual(tagged_path.name, "harness.tagged.cpp")
            self.assertNotEqual(tagged_path, source_path)
            self.assertEqual(tagged.fdp_callsite_count, 1)
            self.assertIn("FDP_ID:100000", tagged_path.read_text(encoding="utf-8"))

    def test_ambiguous_only_source_preserves_previous_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "sample.cpp"
            original = b"void f(FuzzedDataProvider &fdp) { fdp.ConsumeRandomLengthString(); }\r\n"
            source.write_bytes(original)
            previous = source.with_name("sample.tagged.cpp")
            previous.write_bytes(b"prior output\n")
            reducer_runner.configure_work_dir(tmpdir)
            with self.assertRaisesRegex(ValueError, "none can be tagged"):
                tag_harness_with_fdp_ids(str(source), 100100, "SITE")
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(previous.read_bytes(), b"prior output\n")


if __name__ == "__main__":
    unittest.main()

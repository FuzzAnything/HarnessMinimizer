import os
from pathlib import Path
import tempfile
import unittest

from harnessreducer.safe_files import open_regular_file, replace_regular_file


class RegularFileReplacementTests(unittest.TestCase):
    def test_replacement_preserves_a_newer_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "output"
            path.write_bytes(b"first")
            with open_regular_file(path) as source:
                original = os.fstat(source.fileno())
                replace_regular_file(path, b"second", original)
                self.assertEqual(source.read(), b"first")
                with self.assertRaises(OSError):
                    replace_regular_file(path, b"stale", original)
            self.assertEqual(path.read_bytes(), b"second")
            self.assertEqual(list(path.parent.iterdir()), [path])

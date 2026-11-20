import os
from pathlib import Path
import tempfile
import unittest

import pytest

from harnessreducer.api import ADDITIONAL_HEADERS, _finalize_fallback_harness
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


def test_fallback_rejects_invalid_utf8_before_rewriting(tmp_path):
    path = tmp_path / "source.cpp"
    original = b"// \xff memo\r\nint value;\r\n"
    path.write_bytes(original)
    inode = path.stat().st_ino
    with pytest.raises(UnicodeDecodeError):
        _finalize_fallback_harness(str(path), 100000)
    assert path.read_bytes() == original
    assert path.stat().st_ino == inode


def test_fallback_preserves_crlf_and_is_idempotent(tmp_path):
    path = tmp_path / "source.cpp"
    body = "// café\r\nvoid f() { fdp.ConsumeBool(/*SITE:100100*/ 0); }\r\n"
    path.write_bytes(body.encode("utf-8"))
    _finalize_fallback_harness(str(path), 100000, "SITE")
    expected = "\r\n".join(ADDITIONAL_HEADERS) + "\r\n" + body.replace("/*SITE:100100*/ 0", "")
    assert path.read_bytes() == expected.encode("utf-8")
    inode = path.stat().st_ino
    _finalize_fallback_harness(str(path), 100000, "SITE")
    assert path.stat().st_ino == inode


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink", "parent"])
def test_source_writes_reject_linked_paths(tmp_path, link_kind):
    directory = tmp_path / "sources"
    directory.mkdir()
    source = directory / "source.cpp"
    source.write_bytes(b"int original;\n")
    linked = tmp_path / "linked"
    if link_kind == "parent":
        linked.symlink_to(directory, target_is_directory=True)
        linked = linked / source.name
    elif link_kind == "hardlink":
        linked.hardlink_to(source)
    else:
        linked.symlink_to(source)
    with pytest.raises(OSError):
        _finalize_fallback_harness(str(linked), 100000)
    with pytest.raises(OSError):
        replace_regular_file(linked, b"updated")
    assert source.read_bytes() == b"int original;\n"


def test_creating_output_preserves_a_concurrently_created_file(tmp_path, monkeypatch):
    output = tmp_path / "output"
    link = os.link

    def create_competing_output(*args, **kwargs):
        output.write_bytes(b"newer")
        return link(*args, **kwargs)

    monkeypatch.setattr(os, "link", create_competing_output)
    with pytest.raises(FileExistsError):
        replace_regular_file(output, b"stale")
    assert output.read_bytes() == b"newer"
    assert list(tmp_path.iterdir()) == [output]

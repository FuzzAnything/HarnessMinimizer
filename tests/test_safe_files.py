import os
from pathlib import Path
import tempfile
import unittest

import pytest

from harnessminimizer.api import ADDITIONAL_HEADERS, _finalize_fallback_harness
from harnessminimizer.safe_files import open_regular_file, replace_regular_file


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


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_source_writes_reject_linked_paths(tmp_path, link_kind):
    directory = tmp_path / "sources"
    directory.mkdir()
    source = directory / "source.cpp"
    source.write_bytes(b"int original;\n")
    linked = tmp_path / "linked.cpp"
    if link_kind == "hardlink":
        linked.hardlink_to(source)
    else:
        linked.symlink_to(source)
    with pytest.raises(OSError):
        _finalize_fallback_harness(str(linked), 100000)
    with pytest.raises(OSError):
        replace_regular_file(linked, b"updated")
    assert source.read_bytes() == b"int original;\n"


def test_output_directory_alias_is_supported(tmp_path):
    directory = tmp_path / "outputs"
    directory.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    source = alias / "source.cpp"
    replace_regular_file(source, b"void f() { fdp.ConsumeBool(/*FDP_ID:100000*/ 100000); }\n")
    _finalize_fallback_harness(str(source), 100000)
    assert "fdp.ConsumeBool()" in (directory / "source.cpp").read_text()
    assert alias.is_symlink()


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


def test_checkpoint_skips_identical_content_and_replaces_complete_bytes(tmp_path):
    from tests.crash_tester import _update_last_interesting_file
    source, saved = tmp_path / 'source.cpp', tmp_path / 'saved.cpp'
    source.write_bytes(b'int a;\n')
    _update_last_interesting_file(str(source), str(saved))
    inode = saved.stat().st_ino
    _update_last_interesting_file(str(source), str(saved))
    assert saved.stat().st_ino == inode
    source.write_bytes(b'int b;\n')
    _update_last_interesting_file(str(source), str(saved))
    assert saved.read_bytes() == b'int b;\n'
    assert saved.stat().st_ino != inode


@pytest.mark.parametrize('link_kind', ['symlink', 'hardlink'])
def test_debug_log_and_checkpoint_do_not_overwrite_link_targets(tmp_path, link_kind):
    from harnessminimizer.debug_log import copy_debug_log, open_debug_log
    from harnessminimizer.safe_files import copy_regular_file
    original, linked, accepted = (tmp_path / name for name in ('original', 'linked', 'accepted'))
    original.write_bytes(b'keep this')
    accepted.write_bytes(b'accepted')
    if link_kind == 'symlink':
        linked.symlink_to(original)
    else:
        linked.hardlink_to(original)
    with pytest.raises(OSError):
        with open_debug_log(linked) as handle:
            handle.write('overwrite')
    with pytest.raises(OSError):
        copy_debug_log(accepted, linked)
    with pytest.raises(OSError):
        copy_regular_file(accepted, linked)
    assert original.read_bytes() == b'keep this'

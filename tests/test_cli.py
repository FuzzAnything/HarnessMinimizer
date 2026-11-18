import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harnessreducer.cli import _stage_debug_log, build_parser, main


class TestDebugLogStaging(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.log = self.root / "work" / "reduction_debug.log"
        self.log.parent.mkdir()
        self.log.write_bytes(b"log\n")
        self.output = self.root / "export" / "result.cpp"
        self.copy = self.output.parent / self.log.name
        log_path = patch("harnessreducer.cli.get_debug_log_path", return_value=str(self.log))
        log_path.start()
        self.addCleanup(log_path.stop)

    def test_stages_complete_private_copy_and_preserves_in_place_log(self):
        _stage_debug_log(str(self.output))
        self.assertEqual(self.copy.read_bytes(), self.log.read_bytes())
        self.assertEqual(stat.S_IMODE(self.copy.stat().st_mode), 0o600)
        _stage_debug_log(str(self.log.parent / "result.cpp"))
        self.assertEqual(self.log.read_bytes(), b"log\n")

    def test_rejects_linked_source_or_destination(self):
        self.output.parent.mkdir()
        outside = self.root / "outside"
        outside.write_text("keep")
        for path in (self.copy, self.log):
            for link in (path.symlink_to, path.hardlink_to):
                with self.subTest(path=path, link=link.__name__):
                    path.unlink(missing_ok=True)
                    link(outside)
                    with self.assertRaises(OSError):
                        _stage_debug_log(str(self.output))
                    self.assertEqual(outside.read_text(), "keep")
                    path.unlink()
        self.assertFalse(self.copy.exists())

    def test_failed_copy_preserves_previous_export(self):
        self.output.parent.mkdir()
        self.copy.write_text("previous")
        with patch("harnessreducer.debug_log.shutil.copyfileobj", side_effect=OSError):
            with self.assertRaises(OSError):
                _stage_debug_log(str(self.output))
        self.assertEqual(self.copy.read_text(), "previous")
        self.assertEqual(list(self.output.parent.iterdir()), [self.copy])

    def test_linked_export_ancestor_cannot_redirect_directory_creation(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.output.parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            _stage_debug_log(str(self.output.parent / "nested" / "result.cpp"))
        self.assertEqual(list(outside.iterdir()), [])


class TestCliPhase3Mode(unittest.TestCase):
    def test_split_is_default_phase3_mode(self):
        args = build_parser().parse_args(["harness.cpp", "-o", "reduced.cpp"])
        self.assertEqual(args.phase3_mode, "split")

    def test_explicit_phase3_modes_override_default(self):
        parser = build_parser()
        for option, expected in (
            ("--direct", "direct"),
            ("--single-step", "direct"),
            ("--split", "split"),
            ("--pch", "pch"),
        ):
            with self.subTest(option=option):
                args = parser.parse_args(
                    ["harness.cpp", "-o", "reduced.cpp", option]
                )
                self.assertEqual(args.phase3_mode, expected)

    def test_amortize_link_alone_uses_split(self):
        args = build_parser().parse_args(
            ["harness.cpp", "-o", "reduced.cpp", "--amortize-link"]
        )
        self.assertTrue(args.amortize_link)
        self.assertEqual(args.phase3_mode, "split")

    def test_symbolize_argument_is_available(self):
        args = build_parser().parse_args(
            ["harness.cpp", "-o", "reduced.cpp", "--symbolize"]
        )
        self.assertTrue(args.symbolize)

    def test_debug_argument_is_available(self):
        args = build_parser().parse_args(
            ["harness.cpp", "-o", "reduced.cpp", "--debug"]
        )
        self.assertTrue(args.debug)

    def test_amortize_link_rejects_direct(self):
        with self.assertRaisesRegex(SystemExit, "2"):
            main(
                [
                    "harness.cpp",
                    "-o",
                    "reduced.cpp",
                    "--amortize-link",
                    "--direct",
                ]
            )

    def test_debug_rejects_check_mode(self):
        with self.assertRaisesRegex(SystemExit, "2"):
            main(
                [
                    "harness.cpp",
                    "-o",
                    "reduced.cpp",
                    "--debug",
                    "--check",
                ]
            )


if __name__ == "__main__":
    unittest.main()

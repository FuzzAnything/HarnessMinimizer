import unittest

from harnessreducer.cli import build_parser, main


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

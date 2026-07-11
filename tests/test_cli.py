import unittest

from harnessreducer.cli import build_parser


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


if __name__ == "__main__":
    unittest.main()

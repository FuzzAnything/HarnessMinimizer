import unittest
from unittest.mock import patch

from harnessreducer.api import ReductionResult

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

    def test_initializer_recovery_is_explicitly_opt_in(self):
        parser = build_parser()
        self.assertFalse(parser.parse_args(["h.cpp", "-o", "r.cpp"]).protect_initializers)
        self.assertTrue(parser.parse_args(["h.cpp", "-o", "r.cpp", "--protect-initializers"]).protect_initializers)
        for additional in ("--slice", "--llm"):
            with self.assertRaises(SystemExit):
                main(["h.cpp", "-o", "r.cpp", "--protect-initializers", additional])

    def test_auto_var_init_pattern_is_explicitly_opt_in(self):
        parser = build_parser()
        self.assertFalse(parser.parse_args(["h.cpp", "-o", "r.cpp"]).auto_var_init_pattern)
        self.assertTrue(
            parser.parse_args(
                ["h.cpp", "-o", "r.cpp", "--auto-var-init-pattern"]
            ).auto_var_init_pattern
        )

    def test_unvalidated_result_is_not_copied_or_reported_as_success(self):
        result = ReductionResult("failed.cpp", "tagged.cpp", None, success=False)
        with patch("harnessreducer.cli.reduce_with_config", return_value=result), \
                patch("harnessreducer.cli.shutil.copy2") as copy:
            self.assertEqual(main(["h.cpp", "-o", "result.cpp"]), 1)
            copy.assert_not_called()

    def test_debug_argument_is_available(self):
        args = build_parser().parse_args(
            ["harness.cpp", "-o", "reduced.cpp", "--debug"]
        )
        self.assertTrue(args.debug)

    def test_jobs_and_profile_arguments_are_available(self):
        args = build_parser().parse_args(
            ["harness.cpp", "-o", "reduced.cpp", "--jobs", "8", "--profile"]
        )
        self.assertEqual(args.jobs, 8)
        self.assertTrue(args.profile)

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

    def test_profile_rejects_check_mode(self):
        with self.assertRaisesRegex(SystemExit, "2"):
            main(
                [
                    "harness.cpp",
                    "-o",
                    "reduced.cpp",
                    "--profile",
                    "--check",
                ]
            )

    def test_jobs_rejects_out_of_range_value(self):
        with self.assertRaisesRegex(SystemExit, "2"):
            main(
                [
                    "harness.cpp",
                    "-o",
                    "reduced.cpp",
                    "--jobs",
                    "64",
                ]
            )


if __name__ == "__main__":
    unittest.main()

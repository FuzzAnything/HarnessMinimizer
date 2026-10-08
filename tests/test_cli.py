import unittest
from unittest.mock import patch
import pytest

from harnessreducer.api import ReductionResult

from harnessreducer.cli import build_parser, main


@pytest.mark.parametrize("flags,mode", [
    ([], "split"), (["--direct"], "direct"), (["--single-step"], "direct"),
    (["--split"], "split"), (["--pch"], "pch"),
    (["--pch", "--amortize-link"], "pch"),
])
@pytest.mark.parametrize("symbolization,expected", [
    ([], True), (["--symbolize"], True), (["--no-symbolize"], False),
])
def test_cli_forwards_compilation_mode_and_symbolization(flags, mode, symbolization, expected):
    result = ReductionResult("unused.cpp", "tagged.cpp", None, success=False)
    with patch("harnessreducer.cli.reduce_with_config", return_value=result) as reduce:
        assert main(["h.cpp", "-o", "r.cpp", *flags, *symbolization]) == 1
    config = reduce.call_args.args[0]
    assert config.compilation_mode == mode
    assert config.symbolize is expected
    assert config.amortize_link == ("--amortize-link" in flags)
    assert config.jobs == 60
    assert not config.profile and not config.stable


@pytest.mark.parametrize("flags", [
    ["--symbolize", "--no-symbolize"], ["--no-symbolize", "--symbolize"],
])
def test_conflicting_symbolization_flags_are_rejected(flags):
    with patch("harnessreducer.cli.reduce_with_config") as reduce:
        with pytest.raises(SystemExit) as error:
            main(["h.cpp", "-o", "r.cpp", *flags])
    assert error.value.code == 2
    reduce.assert_not_called()


@pytest.mark.parametrize("success", [True, False])
def test_output_staging_without_profile(tmp_path, success):
    selected = tmp_path / "selected.cpp"
    selected.write_text("int final;\n")
    header = tmp_path / "harness_values.h"
    header.write_text("int value = 7;\n")
    output = tmp_path / "output" / "reduced.cpp"
    result = ReductionResult(
        str(selected), "tagged.cpp", None, success=success,
        generated_headers=(str(header),),
    )
    with patch("harnessreducer.cli.reduce_with_config", return_value=result) as reduce, \
            patch("harnessreducer.cli._stage_profile", side_effect=AssertionError("profiling is disabled")):
        assert main(["h.cpp", "-o", str(output)]) == (0 if success else 1)
    assert reduce.call_args.args[0].profile is False
    assert output.exists() is success
    assert (output.parent / header.name).exists() is success
    if success:
        assert output.read_bytes() == selected.read_bytes()
        assert (output.parent / header.name).read_bytes() == header.read_bytes()
    assert not output.with_suffix(".raw.cpp").exists()
    assert not list(output.parent.glob("candidate_profile*"))
    assert not list(output.parent.glob("reduction_profile*"))


class TestCliCompilationMode(unittest.TestCase):

    def test_split_is_default_compilation_mode(self):
        args = build_parser().parse_args(["harness.cpp", "-o", "reduced.cpp"])
        self.assertEqual(args.compilation_mode, "split")
        self.assertTrue(args.symbolize)
        self.assertFalse(args.amortize_link)

    def test_explicit_compilation_modes_override_default(self):
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
                self.assertEqual(args.compilation_mode, expected)

    def test_amortize_link_alone_uses_split(self):
        args = build_parser().parse_args(
            ["harness.cpp", "-o", "reduced.cpp", "--amortize-link"]
        )
        self.assertTrue(args.amortize_link)
        self.assertEqual(args.compilation_mode, "split")

    def test_symbolize_argument_is_available(self):
        args = build_parser().parse_args(
            ["harness.cpp", "-o", "reduced.cpp", "--symbolize"]
        )
        self.assertTrue(args.symbolize)

    def test_initializer_recovery_is_explicitly_opt_in(self):
        parser = build_parser()
        self.assertFalse(parser.parse_args(["h.cpp", "-o", "r.cpp"]).protect_initializers)
        self.assertTrue(parser.parse_args(["h.cpp", "-o", "r.cpp", "--protect-initializers"]).protect_initializers)
        with self.assertRaises(SystemExit):
            main(["h.cpp", "-o", "r.cpp", "--protect-initializers", "--slice"])

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


@pytest.mark.parametrize("flags", [
    ["--tool", "treereduce"], ["--check"], ["--statistics"],
    ["--capture-raw-output"], ["--no-fdp-replay"], ["--oracle-evaluation", "unused"],
])
def test_removed_options_are_rejected_before_execution(flags):
    with patch("harnessreducer.cli.reduce_with_config") as reduce:
        with pytest.raises(SystemExit) as error:
            main(["h.cpp", "-o", "r.cpp", *flags])
    assert error.value.code == 2
    reduce.assert_not_called()


@pytest.mark.parametrize("success", [True, False])
def test_profile_stages_diagnostics_on_success_and_failure(tmp_path, success):
    from harnessreducer import reducer_runner as runner
    work = tmp_path / "work"
    work.mkdir()
    selected = work / "selected.cpp"
    selected.write_text("int final;")
    artifacts = ("candidate_profile.jsonl", "reduction_profile.json", "reduction_profile.txt")
    for name in artifacts:
        (work / name).write_text("profile data")
    output = tmp_path / "output" / "reduced.cpp"
    result = ReductionResult(str(selected), "tagged.cpp", None, success=success)
    with patch.object(runner, "TREEDUCER_DIR", str(work)), \
            patch("harnessreducer.cli.reduce_with_config", return_value=result) as reduce:
        assert main(["h.cpp", "-o", str(output), "--profile"]) == (0 if success else 1)
    assert reduce.call_args.args[0].profile is True
    assert output.exists() is success
    for name in artifacts:
        assert (output.parent / name).read_text() == "profile data"
    assert not output.with_suffix(".raw.cpp").exists()

import unittest
from pathlib import Path
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
    assert config.tool == "treereduce" and config.jobs == 60
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
@pytest.mark.parametrize("capture_raw", [True, False])
def test_output_staging_without_profile(tmp_path, success, capture_raw):
    selected = tmp_path / "selected.cpp"
    selected.write_text("int final;\n")
    raw = tmp_path / "selected.raw.cpp"
    raw.write_text("int raw;\n")
    output = tmp_path / "output" / "reduced.cpp"
    result = ReductionResult(
        str(selected), "tagged.cpp", None, success=success,
        raw_reduced_harness=str(raw),
    )
    args = ["h.cpp", "-o", str(output)]
    if capture_raw:
        args.append("--capture-raw-output")
    with patch("harnessreducer.cli.reduce_with_config", return_value=result) as reduce, \
            patch("harnessreducer.cli._stage_profile", side_effect=AssertionError("profiling is disabled")):
        assert main(args) == (0 if success else 1)
    config = reduce.call_args.args[0]
    assert config.profile is False
    assert config.capture_raw_output is capture_raw
    assert config.oracle_evaluation is None
    assert config.replay_enabled is True
    assert output.exists() is success
    if success:
        assert output.read_bytes() == selected.read_bytes()
    assert output.with_suffix(".raw.cpp").exists() is capture_raw
    if capture_raw:
        assert output.with_suffix(".raw.cpp").read_bytes() == raw.read_bytes()
    assert not list(output.parent.glob("candidate_profile*"))
    assert not list(output.parent.glob("reduction_profile*"))


@pytest.mark.parametrize("success", [True, False])
def test_profile_stages_selected_raw_output(tmp_path, success):
    selected = tmp_path / "selected.cpp"
    selected.write_text("int final;")
    # This may be a snapshot or the protected recovery attempt; the CLI must
    # use the API's selection instead of guessing work/reduced_harness.cpp.
    raw = tmp_path / "attempt-2" / "snapshot.raw.cpp"
    raw.parent.mkdir()
    raw.write_text('#include "macro.h"\nint x;')
    output = tmp_path / "profiled" / "reduced.cpp"
    result = ReductionResult(str(selected), "tagged.cpp", None, success=success, raw_reduced_harness=str(raw))
    with patch("harnessreducer.cli.reduce_with_config", return_value=result), \
            patch("harnessreducer.cli._stage_profile"):
        assert main(["h.cpp", "-o", str(output), "--profile", "--capture-raw-output"]) == (0 if success else 1)
    if success:
        assert output.read_text() == selected.read_text()
    else:
        assert not output.exists()
    assert output.with_suffix(".raw.cpp").read_bytes() == raw.read_bytes()


def test_profile_never_substitutes_final_output_for_missing_raw(tmp_path):
    selected = tmp_path / "selected.cpp"
    selected.write_text("int final;")
    output = tmp_path / "profiled" / "reduced.cpp"
    result = ReductionResult(str(selected), "tagged.cpp", None,
                             raw_reduced_harness=str(tmp_path / "missing.raw.cpp"))
    with patch("harnessreducer.cli.reduce_with_config", return_value=result), \
            patch("harnessreducer.cli._stage_profile"):
        assert main(["h.cpp", "-o", str(output), "--profile", "--capture-raw-output"]) == 0
    assert not output.with_suffix(".raw.cpp").exists()


class TestCliCompilationMode(unittest.TestCase):
    def test_raw_capture_requires_explicit_opt_in_even_with_profile(self):
        parser = build_parser()
        self.assertFalse(parser.parse_args(["h.cpp", "-o", "r.cpp"]).capture_raw_output)
        self.assertFalse(parser.parse_args(["h.cpp", "-o", "r.cpp", "--profile"]).capture_raw_output)
        self.assertTrue(parser.parse_args(["h.cpp", "-o", "r.cpp", "--capture-raw-output"]).capture_raw_output)

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


def test_profile_alone_does_not_export_raw_artifacts(tmp_path):
    selected = tmp_path / "selected.cpp"
    selected.write_text("int final;")
    raw = tmp_path / "existing.raw.cpp"
    raw.write_text("int old_raw;")
    output = tmp_path / "output/reduced.cpp"
    result = ReductionResult(str(selected), "tagged.cpp", None, raw_reduced_harness=str(raw))
    with patch("harnessreducer.cli.reduce_with_config", return_value=result) as reduce, \
            patch("harnessreducer.cli._stage_profile"), \
            patch("harnessreducer.cli.RawOutputCapture", side_effect=AssertionError("capture must be disabled")):
        assert main(["h.cpp", "-o", str(output), "--profile"]) == 0
    assert reduce.call_args.args[0].capture_raw_output is False
    assert output.read_text() == "int final;"
    assert not output.with_suffix(".raw.cpp").exists()


@pytest.mark.parametrize("success", [True, False])
def test_raw_export_failure_does_not_change_tool_status(tmp_path, capsys, success):
    selected = tmp_path / "selected.cpp"
    selected.write_text("int final;")
    raw = tmp_path / "selected.raw.cpp"
    raw.write_text("int raw;")
    output = tmp_path / "output/reduced.cpp"
    result = ReductionResult(str(selected), "tagged.cpp", None, success=success, raw_reduced_harness=str(raw))
    with patch("harnessreducer.cli.reduce_with_config", return_value=result) as reduce, \
            patch("harnessreducer.cli._stage_profile"), \
            patch.object(Path, "replace", side_effect=OSError("synthetic raw export failure")):
        assert main(["h.cpp", "-o", str(output), "--profile", "--capture-raw-output"]) == (0 if success else 1)
    assert reduce.call_args.args[0].capture_raw_output is True
    assert output.exists() is success
    assert not output.with_suffix(".raw.cpp").exists()
    assert not list(output.parent.glob(".raw-output-*"))
    assert "synthetic raw export failure" in capsys.readouterr().err

"""Treereduce command construction and publication without external reductions."""
import subprocess
from unittest.mock import Mock, patch

import pytest

from harnessminimizer import api
from harnessminimizer.reduction_engines import ReducerInvocation, prepare_reducer_invocation


@pytest.mark.parametrize("stable", [False, True])
@pytest.mark.parametrize("jobs", [1, 63])
def test_treereduce_command_preserves_checker_arguments(tmp_path, stable, jobs):
    source = tmp_path / "quoted ' source.cpp"
    source.write_text("int main() { return 7; }\n")
    output = tmp_path / "reduced.cpp"
    checker = ["checker.py", "@@.cpp", "--compile-flags=-I/path with spaces", "$(literal)"]
    with patch("harnessminimizer.reduction_engines.treereduce_binary", return_value="/tools/treereduce-c"):
        invocation = prepare_reducer_invocation(
           source=str(source), output=str(output), checker_command=checker,
            stable=stable, jobs=jobs,
        )
    expected = ["/tools/treereduce-c", "-j", str(jobs), "-s", str(source), "-o", str(output)]
    expected += ["--stable", "--min-reduction", "1"] if stable else ["--fast"]
    expected += ["--timeout", "300", "--interesting-exit-code", "77", "--", *checker]
    assert invocation.command == expected
    assert invocation.metadata["tool"] == "treereduce"


@pytest.mark.parametrize("jobs", [0, 64])
def test_worker_validation_precedes_source_preparation(tmp_path, jobs):
    with pytest.raises(ValueError, match="between 1 and 63"):
        prepare_reducer_invocation(
            source="missing.cpp", output=str(tmp_path / "reduced.cpp"),
            checker_command=["checker.py", "@@.cpp"], stable=False, jobs=jobs,
        )


def test_invocation_preserves_supervision_and_failure_status(tmp_path):
    output = tmp_path / "reduced.cpp"
    invocation = ReducerInvocation(["treereduce-c"], output, output, {})
    failure = subprocess.CompletedProcess(invocation.command, 1, "failure", "")
    supervisor = Mock(return_value=failure)
    assert invocation.run(supervisor) is failure
    supervisor.assert_called_once_with(
        ["treereduce-c"], stderr=subprocess.STDOUT, text=True,
        check=False, timeout=None, private_tmpdir=True,
    )
    with pytest.raises(RuntimeError, match="expected result"):
        invocation.publish_result()


def test_api_checks_treereduce_before_compiling(tmp_path):
    with patch.object(api, "check_tree_reducer", side_effect=RuntimeError("missing treereduce")) as check, \
            patch.object(api, "check_harness_compilation") as compile:
        with pytest.raises(RuntimeError, match="missing treereduce"):
            api.reduce_with_config(api.ReductionConfig("h.cpp", work_dir=str(tmp_path)))
    check.assert_called_once_with()
    compile.assert_not_called()

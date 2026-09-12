"""Opt-in real-engine checks: HARNESSREDUCER_TEST_PERSES=1 python -m pytest ...

The fixture preserves an ordinary program exit value, so it exercises the
reducer protocol without needing a crashing library or a crash diagnosis.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import pytest

from harnessreducer.reduction_engines import PERSES_COMMIT, check_perses, prepare_reducer_invocation
from harnessreducer.process_supervisor import run_supervised


@pytest.mark.skipif(os.environ.get("HARNESSREDUCER_TEST_PERSES") != "1", reason="opt-in real Perses test")
@pytest.mark.parametrize("tool", ("perses", "wdd", "cdd", "sfc", "vulcan"))
@pytest.mark.parametrize("stable,jobs", ((False, 1), (True, 2)))
def test_presets_reduce_a_compilable_cpp_program(tool, stable, jobs):
    runtime = check_perses()
    if not shutil.which("clang++"):
        raise RuntimeError("These integration tests require clang++")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "harness.cpp"
        original = (
            "int unused_function(int x) { return x + 3; }\n"
            "int saved_value = 7;\n"
            "int main() { int unnecessary = 12; return saved_value; }\n"
        )
        source.write_text(original)
        checker = root / "checker.py"
        checker.write_text(
            "import subprocess,sys\n"
            "from harnessreducer.process_supervisor import run_supervised\n"
            "p=run_supervised(['clang++','-std=c++17',sys.argv[1],'-o','program'], "
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)\n"
            "if p.returncode: sys.exit(255)\n"
            "p=run_supervised(['./program'],timeout=5)\n"
            "sys.exit(77 if p.returncode==7 else 1)\n"
        )
        result_file = root / "reduced.cpp"
        invocation = prepare_reducer_invocation(
            tool=tool, source=str(source), output=str(result_file),
            checker_command=[str(checker), "@@.cpp"], stable=stable, jobs=jobs,
        )

        def bounded_run(command, **kwargs):
            kwargs["timeout"] = 180
            return run_supervised(command, **kwargs)

        result = invocation.run(bounded_run)
        if (
            tool == "vulcan" and runtime.source_commit == PERSES_COMMIT
            and result.returncode != 0
            and "kotlin.NotImplementedError" in (result.stdout or "")
            and "MinimalSparTreeGenerator.preBuildSparTreeNodeRec" in result.stdout
        ):
            # An upstream failure is not a successful integration test. Report
            # only this exact, reproduced limitation as expected; fail on others.
            assert not result_file.exists()
            pytest.xfail("Pinned Perses lacks C++ grammar-label support in Vulcan's MinimalSparTreeGenerator")
        assert result.returncode == 0, result.stdout
        invocation.publish_result()
        reduced = result_file.read_text()
        assert len(re.findall(r"\w+|[^\s\w]", reduced)) < len(re.findall(r"\w+|[^\s\w]", original))
        assert "unused_function" not in reduced
        assert source.read_text() == original
        engine_log = invocation.log_path.read_text()
        for unexpected in ("Latra does not support", "Exception in thread"):
            assert unexpected not in engine_log
        if tool == "sfc":
            assert "sfc_smaller_structure_replacement" in engine_log
        elif tool == "vulcan":
            assert "subtree_replacer" in engine_log
        verdict = run_supervised([sys.executable, str(checker), str(result_file)], cwd=root, timeout=30)
        assert verdict.returncode == 77

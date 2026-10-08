"""Opt-in real reducers with a harmless exit-value oracle, never a benchmark."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from harnessminimizer.initializer_protection import prepare_initializer_protection
from harnessminimizer.process_supervisor import run_supervised
from harnessminimizer.reduction_engines import prepare_reducer_invocation
from harnessminimizer.reducer_runner import _split_source_for_pch


@pytest.mark.skipif(os.environ.get("HARNESSMINIMIZER_TEST_TREEREDUCE") != "1",
                    reason="opt-in harmless real-engine integration")
@pytest.mark.parametrize("mode,jobs", [("split", 1), ("pch", 2)])
def test_real_treereduce_protected_declarations(tmp_path, mode, jobs):
    original = tmp_path / "original.cpp"
    original.write_text(
        "#include <cstddef>\n"
        "struct Point { int x,y; };\n"
        "int main(){ Point p = {3,4}; return p.x+p.y; }\n"
    )
    preparation = prepare_initializer_protection(original, tmp_path / "protection")
    source = preparation.source
    flags = ["-std=c++17", "-O0", "-Werror=uninitialized", "-Werror=return-type"]
    prefix = ""
    if mode == "pch":
        header_text, prefix, body = _split_source_for_pch(source.read_text(), source.parent)
        header = tmp_path / "prefix.h"
        header.write_text(header_text)
        pch = tmp_path / "prefix.pch"
        run_supervised(["clang++", *flags, "-x", "c++-header", str(header), "-o", str(pch)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
        source = tmp_path / "body.cpp"
        source.write_text(body)
        flags += ["-include-pch", str(pch)]
    checker = tmp_path / "checker.py"
    checker.write_text(
        f"#!{sys.executable}\n"
        "import subprocess,sys,tempfile\nfrom pathlib import Path\n"
        "from harnessminimizer.process_supervisor import run_supervised\n"
        "with tempfile.TemporaryDirectory() as build:\n"
        "  obj=str(Path(build)/'candidate.o')\n"
        "  exe=str(Path(build)/'candidate')\n"
        f"  cmd=['clang++', *{flags!r}, '-c',sys.argv[1],'-o',obj]\n"
        "  p=run_supervised(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)\n"
        "  if p.returncode: sys.exit(255)\n"
        "  p=run_supervised(['clang++',obj,'-o',exe],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)\n"
        "  if p.returncode: sys.exit(255)\n"
        "  p=run_supervised([exe],timeout=5)\n"
        "  sys.exit(77 if p.returncode==7 else 1)\n"
    )
    checker.chmod(0o700)
    output = tmp_path / "reduced.cpp"
    invocation = prepare_reducer_invocation(
        source=str(source), output=str(output),
        checker_command=[str(checker), "@@.cpp"], stable=True, jobs=jobs,
    )
    # Keep a finite test deadline without altering reducer options.
    deadline = float(os.environ.get("HARNESSMINIMIZER_TEST_ENGINE_TIMEOUT", "300"))
    def bounded(command, **kwargs):
        return run_supervised(command, **{**kwargs, "timeout": deadline})
    try:
        result = invocation.run(bounded)
    except subprocess.TimeoutExpired:
        # Avoid pytest printing the supervisor's entire environment on failure.
        pytest.fail(f"treereduce/{mode} exceeded the {deadline:g}s test deadline; artifacts: {tmp_path}",
                    pytrace=False)
    assert result.returncode == 0, result.stdout
    invocation.publish_result()
    restored = preparation.restore(prefix + output.read_text())
    assert "HM_KEEP_INIT_" not in restored
    assert "initializer_definitions.h" not in restored
    output.write_text(restored)
    exe = tmp_path / "final"
    run_supervised(["clang++", "-std=c++17", str(output), "-o", str(exe)],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
    assert run_supervised([str(exe)], timeout=5).returncode == 7

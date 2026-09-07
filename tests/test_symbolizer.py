"""Symbolizer isolation must preserve the harness and caller environments."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

import pytest

from harnessreducer import reducer_runner as rr
from harnessreducer import symbolizer
from harnessreducer.process_supervisor import run_supervised


def run(command, **kwargs):
    return run_supervised(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=15, **kwargs)


def fake_symbolizer(directory, label):
    directory.mkdir(parents=True, exist_ok=True)
    program = directory / "llvm-symbolizer"
    program.write_text(
        f"#!{sys.executable}\nimport os,sys,json\n"
        f"print(json.dumps(dict(label={label!r},ld=os.environ.get('LD_LIBRARY_PATH'),"
        "args=sys.argv[1:],pid=os.getpid(),extra=os.environ.get('KEEP_ME'))))\n"
        "sys.exit(23)\n"
    )
    program.chmod(0o755)
    return program


@pytest.mark.parametrize("original_ld", [None, "", "/custom/LLVM libs:/other:$ORIGIN"])
def test_launchers_preserve_separate_selections_and_original_environment(tmp_path, original_ld):
    asan = fake_symbolizer(tmp_path / "asan tools", "asan")
    ubsan = fake_symbolizer(tmp_path / "ubsan tools", "ubsan")
    original = {"ASAN_SYMBOLIZER_PATH": str(asan), "UBSAN_SYMBOLIZER_PATH": str(ubsan),
                "KEEP_ME": "unchanged"}
    if original_ld is not None:
        original["LD_LIBRARY_PATH"] = original_ld
    env = rr.runtime_library_env(f"-L{tmp_path}/target", original)
    nested = rr.runtime_library_env(f"-L{tmp_path}/second", env)
    expected_ld = f"{tmp_path}/second:{tmp_path}/target" + (":" + original_ld if original_ld else "")
    assert nested["LD_LIBRARY_PATH"] == expected_ld
    assert original.get("LD_LIBRARY_PATH") == original_ld
    for kind in ("ASAN", "UBSAN"):
        command = [nested[f"{kind}_SYMBOLIZER_PATH"], "with spaces", "$(false); 'literal'"]
        process = subprocess.Popen(command, env=nested, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 23, stderr
        captured = json.loads(stdout)
        assert captured == dict(label=kind.lower(), ld=original_ld, args=command[1:],
                                pid=process.pid, extra="unchanged")
        # The launcher execs the selected tool; it does not leave a waiting
        # shell process or change argument quoting / exit status.


def test_default_path_selection_survives_changed_working_directory(tmp_path, monkeypatch):
    actual = fake_symbolizer(tmp_path / "tools", "default")
    monkeypatch.chdir(tmp_path)
    env = rr.runtime_library_env("-Ltarget", {"PATH": "tools"})
    monkeypatch.chdir(tmp_path.parent)
    result = run([env["ASAN_SYMBOLIZER_PATH"]], env=env)
    assert result.returncode == 23
    assert json.loads(result.stdout)["label"] == "default"
    assert env["HARNESSREDUCER_REAL_ASAN_SYMBOLIZER"] == str(actual)


@pytest.mark.parametrize("selection", ["", "/missing/llvm-symbolizer", "/usr/bin/addr2line"])
def test_explicit_disabled_missing_and_other_backends_are_not_replaced(selection):
    original = {"ASAN_SYMBOLIZER_PATH": selection, "UBSAN_SYMBOLIZER_PATH": selection}
    env = rr.runtime_library_env("-L/target", original)
    assert env["ASAN_SYMBOLIZER_PATH"] == env["UBSAN_SYMBOLIZER_PATH"] == selection
    assert not any(key.startswith("HARNESSREDUCER_REAL_") for key in env)


def test_fast_path_does_not_prepare_or_probe_symbolizers(monkeypatch):
    def unexpected(*_args, **_kwargs):
        pytest.fail("symbolize=0 must not prepare a symbolizer")
    monkeypatch.setattr(symbolizer, "isolate_symbolizer_environment", unexpected)
    original = {"ASAN_SYMBOLIZER_PATH": "/chosen/llvm-symbolizer", "LD_LIBRARY_PATH": "/original"}
    assert rr.runtime_library_env("-L/target", original, symbolize=False) == {
        **original, "LD_LIBRARY_PATH": "/target:/original",
    }


def test_dynamic_library_collision_is_fixed_without_changing_target_loading(tmp_path):
    """A helper needs the system lib; the harness needs its instrumented twin."""
    system = tmp_path / "system"
    target = tmp_path / "target"
    system.mkdir(); target.mkdir()
    lib_source = tmp_path / "library.cpp"
    lib_source.write_text('extern "C" int value(){return VALUE;}\n')
    for directory, value in ((system, 42), (target, 99)):
        result = run(["clang++", "-shared", "-fPIC", "-Wl,-soname,libhrprobe.so",
                      f"-DVALUE={value}", *(["-fsanitize=address"] if value == 99 else []),
                      str(lib_source), "-o", str(directory / "libhrprobe.so")])
        assert result.returncode == 0, result.stderr
    helper_source = tmp_path / "helper.cpp"
    helper_source.write_text('extern "C" int value();int main(){return value();}\n')
    helper = tmp_path / "llvm-symbolizer"
    result = run(["clang++", str(helper_source), f"-L{system}", "-lhrprobe", "-o", str(helper)])
    assert result.returncode == 0, result.stderr
    base = dict(os.environ, LD_LIBRARY_PATH=str(system), ASAN_SYMBOLIZER_PATH=str(helper))
    clean = run([str(helper)], env=base)
    assert clean.returncode == 42
    polluted = run([str(helper)], env=dict(base, LD_LIBRARY_PATH=f"{target}:{system}"))
    assert polluted.returncode != 42
    assert "__asan_" in polluted.stderr
    env = rr.runtime_library_env(f"-L{target}", base)
    isolated = run([env["ASAN_SYMBOLIZER_PATH"]], env=env)
    assert isolated.returncode == 42, isolated.stderr

    harness = tmp_path / "harness"
    result = run(["clang++", "-fsanitize=address", str(helper_source),
                  f"-L{target}", "-lhrprobe", "-o", str(harness)])
    assert result.returncode == 0, result.stderr
    # The main program still gets the benchmark's library, not the system copy.
    assert run([str(harness)], env=env).returncode == 99


def test_real_crash_checker_retains_symbolized_oracle_and_profile(tmp_path):
    real = shutil.which("llvm-symbolizer")
    assert real is not None, "LLVM symbolizer is required for symbolized validation"
    # This selected symbolizer refuses target LD_LIBRARY_PATH. A real ASan
    # report must pass through the bundled launcher to reach the real LLVM.
    selected = tmp_path / "llvm-symbolizer"
    selected.write_text('#!/bin/sh\ncase "$LD_LIBRARY_PATH" in *hr_target*) exit 90;; esac\n'
                        'exec ' + shlex.quote(real) + ' "$@"\n')
    selected.chmod(0o755)
    lib_dir = tmp_path / "hr_target"
    lib_dir.mkdir()
    source = tmp_path / "target.cpp"
    source.write_text('extern "C" int crash(){volatile int *p=new int[1];int x=p[2];delete[]p;return x;}\n')
    result = run(["clang++", "-shared", "-fPIC", "-fsanitize=address,undefined", "-O0", "-g",
                  str(source), "-o", str(lib_dir / "libtarget.so")])
    assert result.returncode == 0, result.stderr
    harness = tmp_path / "harness.cpp"
    harness.write_text('#include <cstddef>\n#include <cstdint>\nextern "C" int crash();\n'
                       'extern "C" int LLVMFuzzerTestOneInput(const uint8_t*,size_t){return crash();}\n')
    seed = tmp_path / "seed"; seed.write_bytes(b"x")
    profile = tmp_path / "profile.jsonl"
    checker = Path(__file__).resolve().parents[1] / "tests/crash_tester.py"
    env = dict(os.environ, ASAN_SYMBOLIZER_PATH=str(selected), DEBUGINFOD_URLS="")
    command = [sys.executable, str(checker), str(harness), "heap-buffer-overflow", "--split",
               "--symbolize", "--crash-location-pattern=" + re.escape(str(source)) + r":1:\d+",
               f"--link-flags=-L{lib_dir} -ltarget", "--crash-input", str(seed), "--exec-timeout-ms=3000"]
    for args in (command, command + ["--profile-file", str(profile)]):
        result = run(args, env=env)
        assert result.returncode == 77, result.stdout + result.stderr
    record = json.loads(profile.read_text())
    assert record["result_code"] == 77 and record["compile_success"]
    durations = record["durations_ns"]
    assert durations["compile_ns"] > 0 and durations["link_ns"] > 0
    assert durations["execute_ns"] > 0 and durations["oracle_ns"] > 0


def test_missing_symbolization_keeps_strict_failure_and_saves_raw_output(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "TREEDUCER_DIR", str(tmp_path))
    output = "WARNING: Can't read from symbolizer\n    #0 0x1234 (/target.so+0x12)\n"
    with pytest.raises(ValueError, match="reference_symbolization_failure.log"):
        rr._record_symbolized_reference_crash_location(output, "harness.cpp", required=True)
    assert (tmp_path / rr.SYMBOLIZATION_FAILURE_LOG_NAME).read_text() == output
    rr.reset_stack_trace_state()
    assert not (tmp_path / rr.SYMBOLIZATION_FAILURE_LOG_NAME).exists()

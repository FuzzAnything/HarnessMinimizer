"""Real compilation/replay through the adapter, using a harmless exit-77 fixture.

No library defect is exercised: success deliberately prints a marker and exits.
This tests the production checker and runner without changing their oracles.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import json
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest

from harnessreducer import reducer_runner
from harnessreducer.process_supervisor import run_supervised
from harnessreducer.reduction_engines import write_perses_test_script


@pytest.mark.skipif(not shutil.which("clang++") or not shutil.which("timeout"), reason="native tools required")
@pytest.mark.parametrize("mode,amortized", [
    ("direct", False), ("split", False), ("pch", False),
    ("split", True), ("pch", True),
])
@pytest.mark.parametrize("symbolize", [False, True])
def test_real_checker_preserves_relative_data_and_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, amortized: bool, symbolize: bool,
) -> None:
    benchmark = tmp_path / "benchmark"
    benchmark.mkdir()
    monkeypatch.chdir(benchmark)
    # Restore this module's process-global work-directory settings at teardown.
    monkeypatch.setattr(reducer_runner, "TREEDUCER_DIR", None)
    monkeypatch.setattr(reducer_runner, "_IS_USER_WORK_DIR", False)
    work = Path(reducer_runner.configure_work_dir(str(tmp_path / "work")))
    data = benchmark / "data"
    data.mkdir()
    resource = data / "value.txt"
    resource.write_text("7")
    include = benchmark / "include"
    include.mkdir()
    (include / "target.h").write_text('extern "C" int target_value();\n')
    target_source = tmp_path / "target.cpp"
    target_source.write_text('extern "C" int target_value() { return 7; }\n')
    library = tmp_path / "libtarget.so"
    run_supervised(
        ["clang++", "-shared", "-fPIC", str(target_source), "-o", str(library)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30,
    )
    source = benchmark / "harness.cpp"
    source.write_text(
        '#include <cstdio>\n#include <cstdlib>\n#include <target.h>\n'
        '#include <fuzzer/FuzzedDataProvider.h>\n'
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
        '  if (!size) return 0;\n'
        '  FILE *f = std::fopen("data/value.txt", "r");\n'
        '  if (!f) return 0;\n'
        '  int value = std::fgetc(f); std::fclose(f);\n'
        '  FuzzedDataProvider fdp(data, size);\n'
        '  if (value == \'7\' && fdp.ConsumeIntegral<int>(101) == target_value()) {\n'
        '    std::fprintf(stderr, "HR_RELATIVE_RESOURCE_OK\\n");\n'
        '    std::_Exit(77);\n'
        '  }\n'
        '  return 0;\n}\n'
    )
    original_source = source.read_bytes()
    input_file = benchmark / "input.bin"
    input_file.write_bytes(b"x")
    trace = work / "trace.log"
    trace.write_text("S 101 7\n")
    profile = work / "profile.jsonl"
    compile_flags = "-Iinclude"  # Must resolve against the original directory.
    link_flags = shlex.join([str(library)])
    pch = None
    prepared = source
    if mode == "pch":
        pch = reducer_runner.prepare_phase3_pch_harness(
            str(source), compile_flags, use_replay=True, amortize_link=amortized,
        )
        prepared = Path(pch.body_source)
    runner_context = (
        reducer_runner.start_amortized_runner(
            link_flags, str(input_file), str(trace), symbolize=symbolize,
        ) if amortized else nullcontext(None)
    )
    with runner_context as runner:
        checker = [
            reducer_runner.get_crash_tester_path(), "@@.cpp", "HR_RELATIVE_RESOURCE_OK",
            f"--compile-flags={compile_flags}", f"--link-flags={link_flags}",
            "--crash-input", str(input_file), "--fdp-trace", str(trace),
            "--profile-file", str(profile), "--exec-timeout-ms", "5000",
            *reducer_runner.pch_tester_args(pch, mode),
        ]
        if symbolize:
            checker.append("--symbolize")
        if runner is not None:
            checker.extend(["--amortized-runner-socket", runner.socket_path])
        scripts = []
        variants = (
            prepared.read_text(),
            # A rejecting candidate returns before consuming replay data.
            # libFuzzer may repeat returning inputs to check for leaks, so a
            # finite trace must not be consumed on this negative path.
            prepared.read_text().replace('  FILE *f =', '  return 0;\n  FILE *f ='),
            "int broken = ;\n",
        )
        for index, text in enumerate(variants):
            candidate_dir = tmp_path / f"candidate-{index}"
            candidate_dir.mkdir()
            (candidate_dir / "candidate.cpp").write_text(text)
            script = candidate_dir / "interesting.sh"
            write_perses_test_script(script, checker)
            scripts.append(script)

        def check(script):
            return run_supervised(
                ["/bin/sh", str(script)], cwd=script.parent,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(check, scripts))
        assert [result.returncode for result in results] == [0, 1, 1], [
            result.stdout + result.stderr for result in results
        ]
        assert Path.cwd() == benchmark
        # Neither standalone nor persistent execution may silently find a
        # different copy of the resource when the original is absent.
        resource.unlink()
        missing = check(scripts[0])
        assert missing.returncode == 1, missing.stdout + missing.stderr

    records = [json.loads(line) for line in profile.read_text().splitlines()]
    assert sorted(record["result_code"] for record in records) == [-1, 1, 1, 77]
    for record in records:
        assert record["compile_success"] == (record["result_code"] != -1)
        assert record["mode"] == mode
        assert record["amortized_link"] is amortized
        assert record["symbolize"] is symbolize
        assert record["durations_ns"]["total_ns"] > 0
    assert source.read_bytes() == original_source
    assert trace.read_text() == "S 101 7\n"
    assert (include / "target.h").read_text() == 'extern "C" int target_value();\n'
    assert not list(benchmark.glob("*.o"))
    assert not list(benchmark.glob("*.out"))

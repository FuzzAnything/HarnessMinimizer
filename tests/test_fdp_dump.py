"""Empty FDP recordings are usable only with the original crash preserved."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from unittest.mock import patch

import pytest

from harnessminimizer import api, reducer_runner as runner


REPORT = (
    "/src/library.cpp:7:4: runtime error: division by zero\n"
    "    #0 0xaaa in target /src/library.cpp:7:4\n"
    "    #1 0xbbb in LLVMFuzzerTestOneInput /tmp/harness.cpp:8:3\n"
)


@pytest.fixture
def reference(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "TREEDUCER_DIR", None)
    monkeypatch.setattr(runner, "_IS_USER_WORK_DIR", False)
    runner.configure_work_dir(str(tmp_path / "work"))
    runner.reset_stack_trace_state()
    pattern = runner._extract_crash_signature_from_output(REPORT)
    runner.set_reference_crash_patterns(symbolize_0=pattern, symbolize_1=pattern)
    runner.set_symbolized_reference_crash_location_pattern(re.escape("/src/library.cpp:7:4"))
    runner.set_symbolized_reference_stack_depth(2)
    runner.set_normal_reference_stack_depth(2)
    yield Path(runner.get_work_dir())
    runner.reset_stack_trace_state()


@pytest.mark.parametrize("symbolize", [False, True])
def test_verified_empty_dump_uses_direct_input(reference, symbolize):
    with patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], 77, "", REPORT)) as run:
        assert runner.dump_fdp_trace("/tmp/target", "seed", harness_path="/tmp/harness.cpp", symbolize=symbolize) is None
    assert f"symbolize={int(symbolize)}" in run.call_args.kwargs["env"]["UBSAN_OPTIONS"]
    assert "exitcode=77" in run.call_args.kwargs["env"]["UBSAN_OPTIONS"]
    assert (reference / "fdp_dump.log").read_text() == "exit=77\n\n" + REPORT


@pytest.mark.parametrize("status, output, reason", [
    (0, "normal exit", "exit=0"),
    (127, "error while loading shared libraries: libmissing.so", "exit=127"),
    (77, REPORT.replace("division by zero", "signed integer overflow"), "crash pattern differs"),
    (77, REPORT.replace("in target /src/library.cpp:7:4", "in target /src/library.cpp:9:4"), "crash location"),
    (77, REPORT.splitlines()[0], "crash location"),
])
def test_empty_dump_failure_is_not_a_direct_input_fallback(reference, status, output, reason):
    with patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], status, "", output)):
        with pytest.raises(RuntimeError, match=reason):
            runner.dump_fdp_trace("/tmp/target", "seed", harness_path="/tmp/harness.cpp")
    assert output in (reference / "fdp_dump.log").read_text()


def test_empty_dump_requires_existing_reference(reference):
    runner.set_reference_crash_patterns()
    with patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], 77, "", REPORT)):
        with pytest.raises(RuntimeError, match="no reference crash pattern"):
            runner.dump_fdp_trace("/tmp/target", "seed")


def test_empty_trace_files_allow_verified_direct_input(reference):
    def execute(*args, **kwargs):
        (reference / "fdp_trace.log").touch()
        (reference / "fdp_trace.log.wide").touch()
        return subprocess.CompletedProcess([], 77, "", REPORT)
    with patch.object(runner, "run_command", side_effect=execute):
        assert runner.dump_fdp_trace("/tmp/target", "seed") is None


def test_empty_dump_requires_original_input(reference):
    with patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], 77, "", REPORT)):
        with pytest.raises(RuntimeError, match="no crash input is available"):
            runner.dump_fdp_trace("/tmp/target", None)


def test_empty_symbolized_dump_keeps_strict_depth_check(reference):
    runner.set_symbolized_reference_stack_depth_strict(True)
    runner.set_symbolized_reference_stack_depth(3)
    with patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], 77, "", REPORT)):
        with pytest.raises(RuntimeError, match="stack depth"):
            runner.dump_fdp_trace("/tmp/target", "seed")


def test_empty_fast_dump_keeps_dynamic_and_depth_checks(reference):
    runner.set_dynamic_reference_crash_site(runner.DynamicCrashSite("/tmp/libtarget.so", "libtarget.so", "0x123"))
    wrong_site = REPORT + "    #2 0xccc (/tmp/libtarget.so+0x999)\n"
    with patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], 77, "", wrong_site)):
        with pytest.raises(RuntimeError, match="dynamic crash site"):
            runner.dump_fdp_trace("/tmp/target", "seed", symbolize=False)
    runner.set_dynamic_reference_crash_site(None)
    runner.set_normal_reference_stack_depth(3)
    with patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], 77, "", REPORT)):
        with pytest.raises(RuntimeError, match="stack depth"):
            runner.dump_fdp_trace("/tmp/target", "seed", symbolize=False)


def test_dump_launch_failure_retains_diagnostic(reference):
    with patch.object(runner, "run_command", side_effect=PermissionError("cannot execute retained binary")):
        with pytest.raises(RuntimeError, match="cannot execute retained binary"):
            runner.dump_fdp_trace("/tmp/target", "seed")
    assert "cannot execute retained binary" in (reference / "fdp_dump.log").read_text()


def test_dump_timeout_retains_partial_output(reference):
    failure = subprocess.TimeoutExpired("target", 10, output=b"partial stdout\xff", stderr=b"partial stderr")
    with patch.object(runner, "run_command", side_effect=failure):
        with pytest.raises(RuntimeError, match="timed out"):
            runner.dump_fdp_trace("/tmp/target", "seed")
    diagnostic = (reference / "fdp_dump.log").read_text()
    assert "partial stdout\ufffd" in diagnostic
    assert "partial stderr" in diagnostic


def test_dump_write_failure_rejects_partial_trace(reference):
    error = "HARNESSMINIMIZER_FDP_TRACE_ERROR: cannot write fdp_trace.log"
    def execute(*args, **kwargs):
        (reference / "fdp_trace.log").write_text("S 100000 ")
        return subprocess.CompletedProcess([], 86, "", error)
    with patch.object(runner, "run_command", side_effect=execute):
        with pytest.raises(RuntimeError, match="trace recording failed"):
            runner.dump_fdp_trace("/tmp/target", "seed")
    assert error in (reference / "fdp_dump.log").read_text()


def test_wide_only_recording_still_uses_replay(reference):
    def execute(*args, **kwargs):
        (reference / "fdp_trace.log.wide").write_text("V 100000 U 16 1 7\n")
        return subprocess.CompletedProcess([], 77, "", REPORT)
    with patch.object(runner, "run_command", side_effect=execute):
        assert runner.dump_fdp_trace("/tmp/target", "seed") == str(reference / "fdp_trace.log")
    assert (reference / "fdp_trace.log").read_bytes() == b""


@pytest.fixture(scope="module")
def dump_error_binary(tmp_path_factory):
    if not shutil.which("clang++"):
        pytest.skip("clang++ is required")
    root = tmp_path_factory.mktemp("dump-errors")
    source = root / "dump.cpp"
    source.write_text('''#include <fuzzer/FuzzedDataProvider.h>
int main(int argc, char **argv) {
  auto &store = fdp_min_internal::TraceStore::Instance();
  uint8_t bytes[] = {1};
  uint16_t wide[] = {256};
  switch (argv[1][0]) {
    case 's': store.DumpScalar(100000, 1); break;
    case 'r': store.DumpRemaining(100000, 1); break;
    case 'p': store.DumpPickIndex(100000, 1); break;
    case 'b': store.DumpBytes(100000, bytes, 1); break;
    case 'w': store.DumpWideIntegralVector(100000, wide, 1); break;
  }
}
''')
    binary = root / "dump"
    subprocess.run(["clang++", "-std=c++17", "-DFDP_MIN_MODE_DUMP",
                    "-I" + runner.get_fdp_header_dir(), str(source), "-o", str(binary)],
                   check=True, capture_output=True, timeout=30)
    return binary


@pytest.mark.parametrize("kind", ["scalar", "remaining", "pick", "bytes", "wide"])
@pytest.mark.parametrize("operation", ["open", "write"])
def test_native_recorder_reports_io_failure(dump_error_binary, tmp_path, kind, operation):
    destination = str(tmp_path / "missing-directory" / "trace") if operation == "open" else "/dev/full"
    result = subprocess.run([str(dump_error_binary), kind], capture_output=True, text=True, timeout=10,
                            env={**os.environ, "FDP_TRACE_PATH": destination, "FDP_WIDE_TRACE_PATH": destination})
    assert result.returncode == 86
    assert f"HARNESSMINIMIZER_FDP_TRACE_ERROR: cannot {operation} {destination}" in result.stderr


@pytest.mark.parametrize("raw_input", [True, False])
def test_mixed_harness_reduces_and_exports_both_input_paths(tmp_path, monkeypatch, raw_input):
    if not shutil.which("clang++"):
        pytest.skip("clang++ is required")
    monkeypatch.setattr(runner, "TREEDUCER_DIR", None)
    monkeypatch.setattr(runner, "_IS_USER_WORK_DIR", False)
    # One stability sample suffices for this deterministic fixture. Compilation,
    # execution, recording, plugin checks, inlining and final replay stay real.
    monkeypatch.setattr(runner, "STACK_DEPTH_STABILITY_RUNS", 1)
    library_source = tmp_path / "library.cpp"
    library_source.write_text('extern "C" void target(int flag) { if (flag) { volatile int zero = 0; volatile int result = 7 / zero; (void)result; } }\n')
    library = tmp_path / "libtarget.so"
    subprocess.run(["clang++", "-shared", "-fPIC", "-fsanitize=address,undefined", "-g", "-O0",
                    str(library_source), "-o", str(library)], check=True, capture_output=True, timeout=30)
    harness = tmp_path / "harness.cpp"
    harness.write_text('''#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" void target(int);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!size) return 0;
  int flag = 1;
  if (data[0] != 'R') {
    FuzzedDataProvider fdp(data + 1, size - 1);
    flag = fdp.ConsumeIntegral<uint8_t>();
  }
  int unused = 123;
  target(flag);
  return 0;
}
''')
    original = harness.read_bytes()
    seed = tmp_path / "seed"
    seed.write_bytes(b"R\x01" if raw_input else b"F\x01")
    driver = tmp_path / "treereduce-c"
    driver.write_text(f"#!{sys.executable}\n" + '''import pathlib, subprocess, sys
args = sys.argv[1:]
if '--help' in args: raise SystemExit(0)
source = pathlib.Path(args[args.index('-s') + 1])
candidate = source.with_name('candidate.cpp')
candidate.write_text(source.read_text().replace('int unused = 123;', ''))
tester = [str(candidate) if arg == '@@.cpp' else arg for arg in args[args.index('--') + 1:]]
assert '--pch' in tester and '--amortized-runner-socket' in tester
''' + f"assert ('--fdp-trace' in tester) == {not raw_input!r}\n" + '''result = subprocess.run(tester, capture_output=True, text=True)
if result.returncode != 77:
  print(result.stdout + result.stderr)
  raise SystemExit(1)
pathlib.Path(args[args.index('-o') + 1]).write_bytes(candidate.read_bytes())
''')
    driver.chmod(0o755)
    monkeypatch.setenv("HARNESSMINIMIZER_TREEREDUCE", str(driver))
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("DEBUGINFOD_URLS", "")
    monkeypatch.setattr(api, "format_reduced_harness", lambda path: None)
    result = api.reduce_with_config(api.ReductionConfig(
        harness_path=str(harness), crash_input=str(seed), link_flags=str(library),
        work_dir=str(tmp_path / "work"), compilation_mode="pch", amortize_link=True, jobs=1,
    ))
    assert result.success
    assert (result.fdp_trace is None) == raw_input
    assert harness.read_bytes() == original
    assert "int unused = 123;" not in Path(result.reduced_harness).read_text()
    assert "FDP_ID" not in Path(result.reduced_harness).read_text()
    if raw_input:
        assert Path(result.tagged_harness).read_bytes() == original
    else:
        assert "S 100000 1" in Path(result.fdp_trace).read_text()
    public_binary = tmp_path / "public-poc"
    compile_result = subprocess.run([
        "clang++", "-fsanitize=address,fuzzer,undefined", "-g", "-O0",
        result.reduced_harness, str(library), "-o", str(public_binary),
    ], capture_output=True, text=True, timeout=30)
    assert compile_result.returncode == 0, compile_result.stderr
    replay = runner._run_harness_for_crash_reference(str(public_binary), str(seed), symbolize=True)
    assert replay.returncode == 77
    assert "division by zero" in replay.stderr

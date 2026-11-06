"""Native regressions for optional libFuzzer initialization in custom drivers."""

import json
import shutil
import subprocess

import pytest

from harnessminimizer import reducer_runner as runner
from harnessminimizer.process_supervisor import runner_request


@pytest.fixture(autouse=True)
def work_dir(tmp_path, monkeypatch):
    if not shutil.which("clang++"):
        pytest.skip("clang++ is required")
    monkeypatch.setattr(runner, "TREEDUCER_DIR", None)
    monkeypatch.setattr(runner, "_IS_USER_WORK_DIR", False)
    runner.configure_work_dir(str(tmp_path / "work"))


@pytest.fixture(scope="module")
def target_library(tmp_path_factory):
    if not shutil.which("clang++"):
        pytest.skip("clang++ is required")
    root = tmp_path_factory.mktemp("initialize-target")
    source = root / "target.cpp"
    source.write_text('extern "C" int record_initialization() { static int calls; return ++calls; }\n')
    library = root / "libtarget.so"
    subprocess.run(["clang++", "-shared", "-fPIC", str(source), "-o", str(library)],
                   check=True, capture_output=True, timeout=30)
    return str(library)


def compile_harness(tmp_path, source, *, plugin=True, link_flags=()):
    path = tmp_path / "harness.cpp"
    path.write_text(source)
    binary = tmp_path / ("candidate.so" if plugin else "reference")
    flags = ["-shared", "-fPIC", "-fsanitize=address,undefined"] if plugin else ["-fsanitize=address,undefined,fuzzer"]
    subprocess.run(["clang++", "-std=c++17", "-g", "-O0", *flags,
                    str(path), *link_flags, "-o", str(binary)], check=True, capture_output=True, timeout=30)
    return binary


def test_plugin_matches_libfuzzer_initialization_and_crash(tmp_path, target_library):
    source = '''#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <unistd.h>
static int initialized = 0;
extern "C" int record_initialization();
extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  if (record_initialization() != 1) _exit(21);
  ++initialized;
  fprintf(stderr, "initialized\\n");
  return 19; // libFuzzer ignores this value.
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (initialized != 1) _exit(22);
  if (size && data[0] == 'x') {
    volatile int zero = 0;
    volatile int result = 7 / zero;
    (void)result;
  }
  return 0;
}
'''
    seed = tmp_path / "seed"
    seed.write_bytes(b"x")
    reference = compile_harness(tmp_path, source, plugin=False, link_flags=[target_library])
    expected = runner._run_harness_for_crash_reference(str(reference), str(seed), symbolize=False)
    assert expected.returncode == 77
    assert "division by zero" in expected.stderr
    assert expected.stderr.count("initialized\n") == 1
    plugin = compile_harness(tmp_path, source)
    with runner.start_amortized_runner(target_library, str(seed), None, symbolize=False) as active:
        for _ in range(2):
            header, output = runner_request(active.socket_path, plugin, timeout=5)
            assert int(header[0]) == 77, output
            assert b"division by zero" in output
            assert output.count(b"initialized\n") == 1


@pytest.mark.parametrize("with_input", [False, True])
def test_plugin_initialization_arguments_are_writable_and_private(tmp_path, target_library, with_input):
    seed = tmp_path / "seed with spaces"
    seed.write_bytes(b"x")
    source = '''#include <cstddef>
#include <cstdint>
#include <cstring>
#include <unistd.h>
static int calls;
static char **retained_args;
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  if (++calls != 1 || *argc != EXPECTED_ARGC || !(*argv)[0] || (*argv)[*argc]) _exit(21);
  if (EXPECTED_ARGC == 2 && strcmp((*argv)[1], SEED_PATH)) _exit(22);
  retained_args = *argv;
  volatile char *first = (*argv)[0];
  char saved = *first;
  *first = '?';
  *first = saved;
  // Consuming arguments must not lose the selected crash input or invalidate
  // the original argument storage before LLVMFuzzerTestOneInput runs.
  *argv += 1;
  *argc -= 1;
  return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (calls != 1 || !retained_args || !retained_args[0][0]) return 23;
  if (EXPECTED_ARGC == 2 && (strcmp(retained_args[1], SEED_PATH) || size != 1 || data[0] != 'x')) return 24;
  if (EXPECTED_ARGC == 1 && size != 0) return 25;
  return 77;
}
'''.replace("EXPECTED_ARGC", "2" if with_input else "1").replace("SEED_PATH", json.dumps(str(seed)))
    plugin = compile_harness(tmp_path, source)
    with runner.start_amortized_runner(target_library, str(seed) if with_input else None,
                                      None, symbolize=False) as active:
        for _ in range(2):
            header, output = runner_request(active.socket_path, plugin, timeout=5)
            assert int(header[0]) == 77, output


@pytest.mark.parametrize("action,status", [
    ("_exit(23);", 23),
    ("sleep(8);", 124),
    ("volatile int zero = 0; volatile int result = 7 / zero; (void)result;", 77),
])
def test_plugin_initialization_failures_are_supervised(tmp_path, target_library, action, status):
    source = '''#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <unistd.h>
extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  fprintf(stderr, "initializer entered\\n");
  ACTION
  return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
  fprintf(stderr, "input should not run\\n");
  return 0;
}
'''.replace("ACTION", action)
    plugin = compile_harness(tmp_path, source)
    with runner.start_amortized_runner(target_library, None, None, symbolize=False, exec_timeout_ms=1000) as active:
        header, output = runner_request(active.socket_path, plugin, timeout=5)
        assert int(header[0]) == status, output
        assert b"initializer entered" in output
        assert b"input should not run" not in output
        assert active.process.poll() is None


@pytest.mark.parametrize("with_initializer", [False, True])
def test_coverage_records_initialized_input_path(tmp_path, with_initializer):
    if not shutil.which("llvm-profdata") or not shutil.which("llvm-cov"):
        pytest.skip("LLVM coverage tools are required")
    source = '''#include <cstddef>
#include <cstdint>
#include <unistd.h>
static int ready = INITIAL_READY;
INITIALIZER
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (ready != 1) return 0;
  if (size != 1 || data[0] != 'x') return 0;
  volatile int zero = 0;
  volatile int result = 7 / zero; // expected crashing path
  (void)result;
  return 0;
}
'''
    initializer = '''extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  if (*argc != 2 || !(*argv)[1] || (*argv)[2] || ready) _exit(21);
  ready = 1; // initialization coverage
  *argc = 1;
  *argv += 1;
  return 19;
}'''
    source = source.replace("INITIAL_READY", "0" if with_initializer else "1")
    source = source.replace("INITIALIZER", initializer if with_initializer else "")
    harness = tmp_path / "harness.cpp"
    harness.write_text(source)
    seed = tmp_path / "seed"
    seed.write_bytes(b"x")
    binary = runner.compile_coverage_harness(str(harness), None, None)
    coverage = runner.collect_harness_coverage(binary, str(harness), str(seed))
    for number, line in enumerate(source.splitlines(), start=1):
        if "expected crashing path" in line or "initialization coverage" in line:
            assert number in coverage.covered_lines


def test_coverage_flushes_when_initializer_crashes(tmp_path):
    if not shutil.which("llvm-profdata") or not shutil.which("llvm-cov"):
        pytest.skip("LLVM coverage tools are required")
    source = '''#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  volatile int zero = 0;
  volatile int result = 7 / zero; // crashing initialization
  (void)result;
  return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
  return 0; // must remain uncovered
}
'''
    harness = tmp_path / "harness.cpp"
    harness.write_text(source)
    binary = runner.compile_coverage_harness(str(harness), None, None)
    coverage = runner.collect_harness_coverage(binary, str(harness), None)
    for number, line in enumerate(source.splitlines(), start=1):
        if "crashing initialization" in line:
            assert number in coverage.covered_lines
        if "must remain uncovered" in line:
            assert number not in coverage.covered_lines

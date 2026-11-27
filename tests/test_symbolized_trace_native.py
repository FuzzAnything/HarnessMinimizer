"""Two observed library call stacks survive PCH reduction and final checks."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from harnessminimizer import api, reducer_runner as runner
from harnessminimizer.symbolized_trace import TRACE_SET_ENV


def test_symbolized_trace_variants_with_pch_and_amortized_link(tmp_path, monkeypatch):
    if not shutil.which("clang++"):
        pytest.skip("clang++ is required")
    monkeypatch.setattr(runner, "TREEDUCER_DIR", None)
    monkeypatch.setattr(runner, "_IS_USER_WORK_DIR", False)
    # The collector's exact 20-run count is separately tested. Two native
    # samples exercise both variants without repeating expensive compilation.
    monkeypatch.setattr(runner, "STACK_DEPTH_STABILITY_RUNS", 2)
    monkeypatch.setenv("DEBUGINFOD_URLS", "")
    library_source = tmp_path / "library.cpp"
    library_source.write_text('''__attribute__((noinline)) void fail() {
  volatile int zero = 0;
  volatile int result = 7 / zero;
  (void)result;
}
__attribute__((noinline)) void through_a() { fail(); }
__attribute__((noinline)) void through_b() { fail(); }
__attribute__((noinline)) void through_c() { fail(); }
extern "C" void target(int variant) {
  if (variant == 0) through_a();
  else if (variant == 1) through_b();
  else through_c();
}
''')
    library = tmp_path / "libtarget.so"
    subprocess.run(["clang++", "-shared", "-fPIC", "-fsanitize=address,undefined",
                    "-g", "-O0", str(library_source), "-o", str(library)],
                   check=True, capture_output=True, timeout=30)
    counter = tmp_path / "reference_count"
    harness = tmp_path / "harness.cpp"
    harness.write_text('''#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
extern "C" void target(int);
static int variant;
extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  int value = 0;
  if (FILE *file = fopen(COUNTER_PATH, "r")) {
    fscanf(file, "%d", &value);
    fclose(file);
  }
  if (FILE *file = fopen(COUNTER_PATH, "w")) {
    fprintf(file, "%d", value + 1);
    fclose(file);
  }
  variant = value % 2;
  if (getenv("HM_TEST_VARIANT_C")) variant = 2;
  return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!size || data[0] != 'x') return 0;
  int unused = 123;
  target(variant);
  return 0;
}
'''.replace("COUNTER_PATH", '"' + str(counter) + '"'))
    seed = tmp_path / "seed"
    seed.write_bytes(b"x")
    driver = tmp_path / "treereduce-c"
    driver.write_text(f"#!{sys.executable}\n" + '''import os, pathlib, subprocess, sys
args = sys.argv[1:]
if '--help' in args: raise SystemExit(0)
source = pathlib.Path(args[args.index('-s') + 1])
candidate = source.with_name('candidate.cpp')
candidate.write_text(source.read_text().replace('int unused = 123;', ''))
tester = [str(candidate) if arg == '@@.cpp' else arg for arg in args[args.index('--') + 1:]]
assert '--pch' in tester and '--amortized-runner-socket' in tester
assert '--require-reference-traces' in tester
assert '--stack-depth' not in tester and '--stack-trace-file' not in tester
assert os.environ.get('HARNESSMINIMIZER_SYMBOLIZED_TRACE_SET')
check = subprocess.run(tester, capture_output=True, text=True)
if check.returncode != 77:
  print(check.stdout + check.stderr)
  raise SystemExit(1)
pathlib.Path(args[args.index('-o') + 1]).write_bytes(candidate.read_bytes())
''')
    driver.chmod(0o755)
    monkeypatch.setenv("HARNESSMINIMIZER_TREEREDUCE", str(driver))
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(api, "format_reduced_harness", lambda path: None)
    result = api.reduce_with_config(api.ReductionConfig(
        harness_path=str(harness), crash_input=str(seed), link_flags=str(library),
        work_dir=str(tmp_path / "work"), compilation_mode="pch", amortize_link=True, jobs=1,
        symbolize=True,
    ))
    assert result.success
    assert "int unused = 123;" not in Path(result.reduced_harness).read_text()
    trace_set = runner.SYMBOLIZED_TRACE_REFERENCE
    assert trace_set.samples_completed == 2
    assert len(trace_set.normalized_patterns) == 2
    assert not (tmp_path / "work" / "stack_trace.pattern").exists()
    assert TRACE_SET_ENV not in os.environ

    pattern = runner.get_reference_crash_pattern_symbolize_1()
    assert runner.validate_symbolized_crash_pattern_depth_location(
        result.reduced_harness, pattern, str(seed), None, str(library),
    )
    monkeypatch.setenv("HM_TEST_VARIANT_C", "1")
    assert not runner.validate_symbolized_crash_pattern_depth_location(
        result.reduced_harness, pattern, str(seed), None, str(library),
    )

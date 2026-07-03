# HarnessReducer

HarnessReducer minimizes crashing C/C++ fuzz harnesses while preserving the crash.
It is designed for `FuzzedDataProvider`-based harnesses and combines:

- crash-pattern preservation
- optional stack-trace preservation
- optional check-mode stack-trace insight collection
- FDP trace dump/replay
- tree-based reduction
- conservative pre-reduction dynamic slicing
- optional final LLM cleanup

## Requirements

Install or make available in `PATH`:

- `clang++`
- `clang-format`
- `llvm-profdata`
- `llvm-cov`
- `treereduce-c`
- Python 3.12+

If you want to use `--llm`, also set the OpenAI-compatible environment variables expected by `src/harnessreducer/llm_reducer.py`.

## Install

```bash
cargo install treereduce-c
uv sync
```

## Basic CLI Usage

```bash
harnessreducer <harness.cpp> -o <reduced.cpp> [options]
```

Module form:

```bash
uv run python -m harnessreducer <harness.cpp> -o <reduced.cpp> [options]
```

## CLI Arguments

| Argument | Required | Description |
|---|---:|---|
| `harness` | Yes | Path to the original harness source file. |
| `-o`, `--output` | Yes | Where to copy the final reduced harness. |
| `--compile-flags "..."` | No | Compile/preprocessor flags, e.g. include paths, macros, language standard. |
| `--link-flags "..."` | No | Link-only flags, e.g. libraries, `-L`, `-l`, or full `.a` paths. |
| `--crash-input <file>` | No | Crash input passed to the harness binary. |
| `--work-dir <dir>` | No | Reuse a fixed work directory instead of a temporary one. |
| `--stable` | No | Use deterministic tree reduction mode instead of the faster randomized mode. |
| `--slice` | No | Enable coverage-guided dynamic slicing before tree reduction. When omitted, the original harness goes directly into the rest of the pipeline. |
| `--iteration <N>` | No | Enable periodic symbolized stack-trace validation every `N` crash-tester invocations during tree reduction. If omitted, a reference stack trace is still recorded initially, but reduction uses fast `symbolize=0` checks only. |
| `--statistics` | No | Record how many times `crash_tester.py` returns logical results `77`, `1`, and `-1` during tree reduction, and write `statistics.txt` in the work directory. Only active when `--iteration` is not set. |
| `--check` | No | Insight-only mode. Records the first entire stack trace and its frame count from the original crash, then runs tree reduction with `symbolize=1` for every candidate and reports how often the frame count and full first stack trace stay the same. |
| `--direct`, `--single-step` | No | Use the default single-step compile+link path. `--single-step` is the clearer alias; `--direct` is kept for compatibility. |
| `--split` | No | Use two-step mode: compile the full source to an object, then link it. No PCH is used. |
| `--pch` | No | Use precompiled-header mode for faster repeated candidate testing. |
| `--llm` | No | Run an additional final LLM-based semantic cleanup step after the normal reduction pipeline. |

## What the Main Options Do

### `--slice`

Enables the optional dynamic-slicing pre-pass:

- builds a separate source-coverage binary
- identifies uncovered executable regions
- tries a conservative syntax-preserving pre-slice
- validates the sliced result before continuing

If `--slice` is omitted, this pre-pass is skipped entirely.

### `--iteration`

Turns on deeper crash-equivalence checking during tree reduction:

- HarnessReducer always records an initial reference stack trace.
- With `--iteration N`, `crash_tester.py` periodically reruns candidates with `symbolize=1` and compares the stack trace against that reference.
- Matching candidates are backed up.
- If the final reduced result no longer matches, the last backup is restored.

The effective interval becomes more aggressive for small files:

- fewer than 75 lines: interval shrinks to 10
- fewer than 50 lines: interval shrinks to 1

These thresholds are currently hardcoded in `tests/crash_tester.py`.

### `--statistics`

When enabled without `--iteration`, HarnessReducer records how many tree-reducer candidate checks ended with:

- `77` — interesting / crash preserved
- `1` — candidate compiled but did not preserve the target crash behavior
- `-1` — candidate could not be compiled or linked

The counts and probabilities are written to `statistics.txt` in the work directory.

### `--check`

`--check` is a measurement-only mode for stack-trace drift during tree reduction.

When enabled, HarnessReducer:

- still records the normal crash pattern and truncated reference stack trace used by the main tool
- additionally records the **first entire** stack trace from the original symbolized crash
- counts its frame lines directly
- runs every tree-reduction candidate with `symbolize=1`
- if a candidate preserves the crash pattern, checks whether:
  - the first entire stack trace has the same frame count (`level_same`)
  - the **pre-harness** stack trace prefix matches the stored `stack_trace.pattern` (`stack_same`)
- prints `level_same`, `stack_same`, and `stack_same / level_same`
- writes each candidate's extracted full first stack trace and pre-harness comparison trace to `check_candidate_stack_traces.log` in the work directory for manual inspection

This mode is for diagnostics only; it does not tighten the main interestingness condition beyond crash-pattern preservation.

### `--split`

Uses a two-step compile/link path for the tree-reduction candidate-testing loop:

- compile the full source file into an object
- link the object into the executable
- no PCH
- uses `-O0 -gline-tables-only` like PCH mode

This is useful when you want separate compile and link stages without the include stripping / PCH machinery.

### `--pch`

Uses a precompiled-header for the tree-reduction candidate-testing loop:

- includes are moved into a generated prefix header
- a `.pch` is built once
- each candidate body is compiled against that PCH and then linked

One-off validation steps outside the main reduction loop still use direct compilation.

This can substantially reduce repeated compile cost for large harnesses with heavy includes.

### `--stable`

Runs `treereduce-c` in deterministic mode. Usually slower, but helpful when you want reproducible results.

## Typical Commands

### 1. Basic reduction

```bash
harnessreducer harness.cpp -o reduced.cpp
```

### 2. Reduction with include paths, libraries, and a crashing input

```bash
harnessreducer harness.cpp \
  --compile-flags "-std=c++17 -Iinclude -Ibuild/include" \
  --link-flags "build/lib/libtarget.a" \
  --crash-input crash-input \
  -o reduced.cpp
```

### 3. Use a fixed work directory

```bash
harnessreducer harness.cpp \
  --work-dir ./reducer-work \
  --crash-input crash-input \
  -o reduced.cpp
```

### 4. Enable periodic stack-trace validation

```bash
harnessreducer harness.cpp \
  --slice \
  --crash-input crash-input \
  --iteration 100 \
  -o reduced.cpp
```

### 5. Use PCH mode

```bash
harnessreducer harness.cpp \
  --slice \
  --pch \
  --crash-input crash-input \
  --compile-flags "-std=c++17 -Iinclude -Ibuild/include" \
  --link-flags "build/lib/libtarget.a" \
  -o reduced.cpp
```

### 6. Use split mode

```bash
harnessreducer harness.cpp \
  --slice \
  --split \
  --crash-input crash-input \
  --compile-flags "-std=c++17 -Iinclude -Ibuild/include" \
  --link-flags "build/lib/libtarget.a" \
  -o reduced.cpp
```

### 7. Stable + PCH + periodic stack-trace checks

```bash
harnessreducer harness.cpp \
  --slice \
  --pch \
  --stable \
  --iteration 100 \
  --crash-input crash-input \
  --compile-flags "-std=c++17 -Iinclude -Ibuild/include" \
  --link-flags "build/lib/libtarget.a" \
  -o reduced.cpp
```

### 8. Add the optional LLM post-pass

```bash
harnessreducer harness.cpp \
  --crash-input crash-input \
  --llm \
  -o reduced.cpp
```

### 9. Collect crash-tester return statistics

```bash
harnessreducer harness.cpp \
  --crash-input crash-input \
  --statistics \
  -o reduced.cpp
```

### 10. Inspect stack-trace stability during reduction

```bash
harnessreducer harness.cpp \
  --crash-input crash-input \
  --check \
  -o reduced.cpp
```

## Python API

```python
from harnessreducer import ReductionConfig, reduce_with_config

config = ReductionConfig(
    harness_path="harness.cpp",
    compile_flags="-std=c++17 -Iinclude -Ibuild/include",
    link_flags="build/lib/libtarget.a",
    crash_input="crash-input",
    phase3_mode="pch",      # or "split" / "direct"
    iteration=100,            # optional
    statistics=False,         # optional
    check=False,              # optional insight-only mode
    stable=False,
    use_llm=False,
)

result = reduce_with_config(config)
print(result.reduced_harness)
print(result.generated_headers)
```

There is also a convenience wrapper:

```python
from harnessreducer import process

reduced = process(
    harness_path="harness.cpp",
    compile_flags="-std=c++17 -Iinclude -Ibuild/include",
    link_flags="build/lib/libtarget.a",
    crash_input="crash-input",
    phase3_mode="direct",   # "single-step" alias is also accepted by the CLI
    iteration=100,
    statistics=False,
    check=False,
)
```

## Output and Artifacts

The final reduced harness is copied to `--output`.

During reduction, the work directory may also contain artifacts such as:

- `poc.out` — original crash-check binary
- `poc_cov.out` — source-coverage binary used for dynamic slicing
- `coverage.profraw`, `coverage.profdata`, `coverage_show.txt`, `coverage_export.json` — dynamic slicing coverage artifacts
- `stack_trace.pattern` — stored normalized reference stack trace
- `stack_trace.counter` — periodic validation counter
- `stack_trace.backup.cpp` — last stack-trace-verified candidate
- `statistics.txt` — optional crash-tester return-code statistics when `--statistics` is enabled without `--iteration`
- `reduced_harness.cpp` — tree-reducer output before final copy
- `*.inline.cpp` — FDP-inlined variant
- `harness_values.h` — generated only when large inlined FDP buffers are moved into a header

## Notes

- Dynamic slicing is conservative: if slicing, validation, or coverage collection fails, HarnessReducer falls back to the original harness and continues with the rest of the pipeline.
- If inline validation fails, the tool falls back to the tree-reduced harness.
- If LLM validation fails, the tool falls back to the non-LLM harness.

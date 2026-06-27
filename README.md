# HarnessReducer

HarnessReducer minimizes crashing C/C++ fuzz harnesses while preserving the crash.
It is designed for `FuzzedDataProvider`-based harnesses and combines:

- crash-pattern preservation
- optional stack-trace preservation
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
| `--iteration <N>` | No | Enable periodic symbolized stack-trace validation every `N` crash-tester invocations during tree reduction. If omitted, a reference stack trace is still recorded initially, but reduction uses fast `symbolize=0` checks only. |
| `--direct` | No | Use the default direct compile/link path. |
| `--pch` | No | Use precompiled-header mode for faster repeated candidate testing. |
| `--llm` | No | Run an additional final LLM-based semantic cleanup step after the normal reduction pipeline. |

## What the Main Options Do

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

### `--pch`

Uses a precompiled-header for candidate testing:

- includes are moved into a generated prefix header
- a `.pch` is built once
- each candidate body is compiled against that PCH and then linked

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
  --crash-input crash-input \
  --iteration 100 \
  -o reduced.cpp
```

### 5. Use PCH mode

```bash
harnessreducer harness.cpp \
  --pch \
  --crash-input crash-input \
  --compile-flags "-std=c++17 -Iinclude -Ibuild/include" \
  --link-flags "build/lib/libtarget.a" \
  -o reduced.cpp
```

### 6. Stable + PCH + periodic stack-trace checks

```bash
harnessreducer harness.cpp \
  --pch \
  --stable \
  --iteration 100 \
  --crash-input crash-input \
  --compile-flags "-std=c++17 -Iinclude -Ibuild/include" \
  --link-flags "build/lib/libtarget.a" \
  -o reduced.cpp
```

### 7. Add the optional LLM post-pass

```bash
harnessreducer harness.cpp \
  --crash-input crash-input \
  --llm \
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
    phase3_mode="pch",      # or "direct"
    iteration=100,            # optional
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
    phase3_mode="direct",
    iteration=100,
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
- `reduced_harness.cpp` — tree-reducer output before final copy
- `*.inline.cpp` — FDP-inlined variant
- `harness_values.h` — generated only when large inlined FDP buffers are moved into a header

## Notes

- Dynamic slicing is conservative: if slicing, validation, or coverage collection fails, HarnessReducer falls back to the original harness and continues with the rest of the pipeline.
- If inline validation fails, the tool falls back to the tree-reduced harness.
- If LLM validation fails, the tool falls back to the non-LLM harness.

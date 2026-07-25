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
- `llvm-objcopy` (optional, used to export hidden static-archive symbols for faster `--amortize-link`)
- `treereduce-c`
- Python 3.12+

If you want to use `--llm`, also set the OpenAI-compatible environment variables expected by `src/harnessreducer/llm_reducer.py`.

## Install

```bash
cargo install treereduce-c
uv sync
source .venv/bin/activate
hash -r
harnessreducer --help
```

`uv sync` installs this repository as an editable package and creates
`.venv/bin/harnessreducer`. You can also avoid shell activation entirely:

```bash
uv run harnessreducer --help
```

If `command -v harnessreducer` still names an older global installation after
activation, run `hash -r` (Bash) or invoke `.venv/bin/harnessreducer` directly.

### Container setup with `/usr/bin/python3`

For a container where the system interpreter is `/usr/bin/python3`, first
confirm that it is Python 3.12 or newer, then create and populate the virtual
environment explicitly:

```bash
/usr/bin/python3 --version
/usr/bin/python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
hash -r
command -v harnessreducer
harnessreducer --help
```

The final `command -v` should point to `<project>/.venv/bin/harnessreducer`.
If `/usr/bin/python3 -m venv` is unavailable in a Debian/Ubuntu-based image,
install its OS package first:

```bash
apt-get update
apt-get install -y python3-venv python3-pip
```

Shell activation does not persist between Dockerfile `RUN` instructions. For
a Docker image, put the virtual environment on `PATH` explicitly:

```dockerfile
WORKDIR /root/HarnessMinimizer
RUN /usr/bin/python3 -m venv .venv \
    && .venv/bin/python -m pip install --upgrade pip \
    && .venv/bin/python -m pip install -e .
ENV PATH="/root/HarnessMinimizer/.venv/bin:${PATH}"
RUN harnessreducer --help
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
| `--compile-flags="..."` | No | Compile/preprocessor flags, e.g. include paths, macros, language standard. |
| `--link-flags="..."` | No | Link-only flags, e.g. libraries, `-L`, `-l`, or full `.a` paths. |
| `--crash-input <file>` | No | Crash input passed to the harness binary. |
| `--work-dir <dir>` | No | Reuse a fixed work directory instead of a temporary one. |
| `--stable` | No | Use deterministic tree reduction mode instead of the faster randomized mode. |
| `--slice` | No | Enable coverage-guided dynamic slicing before tree reduction. When omitted, the original harness goes directly into the rest of the pipeline. |
| `--statistics` | No | Record how many times `crash_tester.py` returns logical results `77`, `1`, and `-1` during tree reduction, and write `statistics.txt` in the work directory. |
| `--symbolize` | No | Ablation mode. Runs reduction candidates with sanitizer `symbolize=1` and validates the symbolized crash pattern, symbolized first-stack-trace depth, and symbolized crash location instead of the default fast `symbolize=0` oracle. |
| `--check` | No | Insight-only mode. Records the first entire stack trace and its frame count from the original crash, then runs tree reduction with `symbolize=1` for every candidate and reports how often the frame count and pre-harness stack-trace prefix stay the same. |
| `--snapshot` | No | Enable `last_interesting.cpp` snapshotting during tree reduction and allow snapshot-based retry/fallback after reduction if inline validation fails. Disabled by default. |
| `--direct`, `--single-step` | No | Use the single-step compile+link path. `--single-step` is the clearer alias; `--direct` is kept for compatibility. |
| `--split` | No | Use two-step mode: compile the full source to an object, then link it. No PCH is used. This is the default when no Phase 3 mode is specified. |
| `--pch` | No | Use precompiled-header mode for faster repeated candidate testing. |
| `--amortize-link` | No | Reuse a persistent runner and shared/static target libraries during tree reduction. Works with split or PCH mode; when used alone, the default split mode applies. |
| `--llm` | No | Run an additional final LLM-based semantic cleanup step after the normal reduction pipeline. |

### Important shell syntax for flag arguments

Use the equals form for `--compile-flags` and `--link-flags`:

```bash
--compile-flags="-I/path/to/include"
--link-flags="-L/path/to/lib -ltarget"
```

This is important when the value begins with `-`. With the separated form,
Python's argument parser can mistake a single value such as `-I/path` or
`-ltarget` for another HarnessReducer option:

The ambiguous spelling would place a space between the option and value—shown
here as `<SPACE>` so it cannot be copied accidentally:

```text
--compile-flags<SPACE>"-I/path/to/include"
```

Use this unambiguous spelling instead:

```bash
--compile-flags="-I/path/to/include"
```

A separated value containing several flags may appear to work because it also
contains whitespace, but that behavior should not be relied on. All command
examples below use the unambiguous equals form.

## What the Main Options Do

### Crash-pattern references

HarnessReducer records separate crash-pattern regexes when sanitizer output
differs between fast and symbolized execution:

- `symbolize=0` pattern: used by normal tree-reduction candidates, amortized-link
  candidate checks, `--statistics`, LLM validation, and crash-identity checks
  for slicing/inline validation
- `symbolize=1` pattern: used by symbolized validation paths and public
  `--symbolize` reduction when the
  symbolized run produces an extractable crash signature

If the symbolized reference run cannot produce a separate pattern, symbolized
stack validations still require exit code `77`, symbolized stack depth, and the
stored stack trace when available, but they do not require a symbolized crash
regex. Public `--symbolize` reduction is stricter and fails early in this case,
because its candidate oracle requires the `symbolize=1` crash-pattern regex. The
matching stack-depth reference is also kept separately for each mode.

### `--slice`

Enables the optional dynamic-slicing pre-pass:

- builds a separate source-coverage binary
- identifies uncovered executable regions
- tries a conservative syntax-preserving pre-slice
- validates the sliced result before continuing; by default this uses the deeper
  symbolize=1 stack-trace validation, while public `--symbolize` uses the
  symbolized crash-location oracle

If `--slice` is omitted, this pre-pass is skipped entirely.

### `--statistics`

When enabled, HarnessReducer records how many tree-reducer candidate checks ended with:

- `77` — candidate preserved the crash pattern and first-stack-trace depth
- `1` — candidate compiled but did not preserve the target crash behavior
- `-1` — candidate could not be compiled or linked, including `-Werror=uninitialized` failures

The counts and probabilities are written to `statistics.txt` in the work directory.

### `--symbolize`

`--symbolize` is an ablation mode for measuring the cost of the default
`symbolize=0` reduction path.

When enabled, HarnessReducer records a symbolized crash location from the first
source location in the original symbolized pre-harness stack trace and writes it
to `symbolized_crash_location.pattern` for inspection. The same normalized
pattern is passed directly to `crash_tester.py` as an argument for candidate
checks, so the tree-reduction hot path does not read that file. Tree-reduction
candidates then run with `symbolize=1` and must preserve:

- the `symbolize=1` crash-pattern regex
- the symbolized first-stack-trace depth
- the recorded symbolized crash location

The dynamic shared-library offset check is not used in this mode, because
symbolized sanitizer output may no longer include the raw `.so+offset` frame.

### `--check`

`--check` is a measurement-only mode for stack-trace drift during tree reduction.

When enabled, HarnessReducer:

- still records the normal crash pattern and truncated reference stack trace used by the main tool
- records the `symbolize=0` and `symbolize=1` crash-pattern regexes used by the main tool
- records **two** reference stack depths for the main reducer:
  - a fast-path depth from a `symbolize=0` run, used by normal candidate checks
  - a symbolized depth from a `symbolize=1` run, used by slicing and inline crash-preservation validation
- additionally records the **first entire** stack trace from the original symbolized crash
- counts its frame lines directly
- runs every tree-reduction candidate with `symbolize=1`
- uses a diagnostic interestingness rule:
  - crash pattern must match
  - the first entire stack trace must have the same frame count
- for diagnostics, if a candidate preserves the crash pattern, also checks whether:
  - the first entire stack trace has the same frame count (`level_same`)
  - the **pre-harness** stack trace prefix matches the stored `stack_trace.pattern` (`stack_same`)
- prints `level_same`, `stack_same`, and `stack_same / level_same`
- writes each candidate's extracted full first stack trace and pre-harness comparison trace to `check_candidate_stack_traces.log` in the work directory for manual inspection; when a candidate returns `77`, its source code is also pasted into that log entry

This mode is for diagnostics only; it does not change the normal reducer's stored fast-path and symbolized reference depths. It is separate from public `--symbolize` ablation mode, which uses crash-location matching rather than full-stack drift statistics. During `--check`, each candidate log entry also records whether compilation failed and whether the failure matched an uninitialized-variable diagnostic.

### `--snapshot`

Enables optional last-interesting snapshot behavior:

- during tree reduction, candidates that actually return `77` may update `last_interesting.cpp`
- after reduction, if inline validation of the tree-reduced result fails, HarnessReducer may retry from that snapshot and fall back to it if needed

When `--snapshot` is omitted, no snapshot file is maintained and no snapshot-based fallback is attempted.

For all Phase 3 compile paths, HarnessReducer now keeps the existing debug info style for that mode but uses `-O0` and adds `-Werror=uninitialized`.

### `--split`

Uses a two-step compile/link path for the tree-reduction candidate-testing loop:

- compile the full source file into an object
- link the object into the executable
- no PCH
- uses `-O0 -gline-tables-only -Werror=uninitialized` like PCH mode

This is useful when you want separate compile and link stages without the include stripping / PCH machinery.

### `--pch`

Uses a precompiled-header for the tree-reduction candidate-testing loop:

- includes are moved into a generated prefix header
- a `.pch` is built once
- each candidate body is compiled against that PCH and then linked
- both the generated `.pch` and the candidate-body compile use `-O0 -gline-tables-only -Werror=uninitialized`

One-off validation steps outside the main reduction loop still use direct compilation.

This can substantially reduce repeated compile cost for large harnesses with heavy includes.

### `--amortize-link`

Enables the experimental linkage-amortization backend for the Phase 3 candidate loop:

- checks that `--link-flags` identifies at least one shared library (`.so`) or static archive (`.a`)
- rejects standalone object files in this mode
- builds one ASan/UBSan-enabled persistent runner
- loads shared targets and links the needed static archive members into the runner once
- compiles each candidate as a small position-independent plugin
- forks a child for each execution so a crashing candidate does not kill the runner
- recalibrates the candidate stack-depth reference through the same runner before reduction

Current restrictions:

- Linux/ELF only
- incompatible with `--direct` / `--single-step`
- target code must already be available as a sanitizer-compatible `.so` or `.a`
- full `.so` paths are recommended; linker scripts are rejected because `dlopen` cannot load them

Using `-L/path/to/lib -ltarget` is also supported: libraries found in explicit
`-L` directories are resolved as shared libraries first, then as static
archives. Use `-Wl,-Bstatic` and `-Wl,-Bdynamic` to select explicitly. Multiple
shared libraries, multiple static archives, and mixed inputs are supported.
Shared targets are preloaded with `dlopen`; static targets are linked once into
the persistent runner with exported symbols. For static archives, HarnessReducer
compiles a candidate-shaped object, extracts its unresolved symbols, and uses
those symbols as archive roots so normal linker extraction pulls only the needed
archive members. When `llvm-objcopy` is available, it also rewrites temporary
copies of the affected static archives so those root symbols have default ELF
visibility before the runner is linked. The original archives are not modified.
If no roots can be inferred, it falls back to the older whole-archive runner
link. If a candidate plugin still needs symbols the runner cannot export,
HarnessReducer relinks it once with the original `--link-flags`; after the first
such loader failure, later candidates start with that fallback link for a bounded
window before probing the fast path again.
Normal dependency flags such as `-lpthread`, `-lm`, and `-ldl` may remain in `--link-flags`. HarnessReducer also
converts relative `-L` paths to absolute paths and prepends shared-library
directories to `LD_LIBRARY_PATH`, so an additional runtime `rpath` is not
required when running through the tool.

`--split` and `--pch` keep their original behavior unless `--amortize-link` is present.

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
  --compile-flags="-std=c++17 -Iinclude -Ibuild/include" \
  --link-flags="build/lib/libtarget.a" \
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

### 4. Use PCH mode

```bash
harnessreducer harness.cpp \
  --slice \
  --pch \
  --crash-input crash-input \
  --compile-flags="-std=c++17 -Iinclude -Ibuild/include" \
  --link-flags="build/lib/libtarget.a" \
  -o reduced.cpp
```

### 5. Use split mode

```bash
harnessreducer harness.cpp \
  --slice \
  --split \
  --crash-input crash-input \
  --compile-flags="-std=c++17 -Iinclude -Ibuild/include" \
  --link-flags="build/lib/libtarget.a" \
  -o reduced.cpp
```

### 6. Stable + PCH

```bash
harnessreducer harness.cpp \
  --slice \
  --pch \
  --stable \
  --crash-input crash-input \
  --compile-flags="-std=c++17 -Iinclude -Ibuild/include" \
  --link-flags="build/lib/libtarget.a" \
  -o reduced.cpp
```

### 7. Add the optional LLM post-pass

```bash
harnessreducer harness.cpp \
  --crash-input crash-input \
  --llm \
  -o reduced.cpp
```

### 8. Collect crash-tester return statistics

```bash
harnessreducer harness.cpp \
  --crash-input crash-input \
  --statistics \
  -o reduced.cpp
```

### 9. Inspect stack-trace stability during reduction

```bash
harnessreducer harness.cpp \
  --crash-input crash-input \
  --check \
  -o reduced.cpp
```

### 10. Enable snapshot-based fallback

```bash
harnessreducer harness.cpp \
  --crash-input crash-input \
  --pch \
  --stable \
  --snapshot \
  -o reduced.cpp
```

### 11. Amortize linking with split mode

```bash
harnessreducer harness.cpp \
  --amortize-link \
  --crash-input crash-input \
  --compile-flags="-std=c++17 -Iinclude" \
  --link-flags="/absolute/path/libtarget_asan.so" \
  -o reduced.cpp
```

### 12. Amortize linking with PCH

```bash
harnessreducer harness.cpp \
  --pch \
  --amortize-link \
  --crash-input crash-input \
  --compile-flags="-std=c++17 -Iinclude" \
  --link-flags="/absolute/path/libtarget_asan.so" \
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
    amortize_link=False,     # requires split/PCH and shared or static target libraries
    statistics=False,         # optional
    check=False,              # optional insight-only mode
    snapshot=False,           # optional snapshot-based fallback
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
    phase3_mode="split",    # default; "direct" / "single-step" are also available
    statistics=False,
    check=False,
    snapshot=False,
)
```

## Output and Artifacts

The final reduced harness is copied to `--output`.

During reduction, the work directory may also contain artifacts such as:

- `poc.out` — original crash-check binary
- `poc_cov.out` — source-coverage binary used for dynamic slicing
- `coverage.profraw`, `coverage.profdata`, `coverage_show.txt`, `coverage_export.json` — dynamic slicing coverage artifacts
- `crash_pattern.symbolize0` — crash-pattern regex from the fast reference run
- `crash_pattern.symbolize1` — crash-pattern regex from the symbolized reference run, when available
- `stack_trace.pattern` — stored normalized reference stack trace
- `symbolized_crash_location.pattern` — stored normalized source location recorded for `--symbolize` reduction; candidate checks receive the same pattern directly as an argument
- `statistics.txt` — optional crash-tester return-code statistics when `--statistics` is enabled
- `last_interesting.cpp` — optional snapshot of the latest candidate source that actually returned `77`; created only when `--snapshot` is enabled
- `reduced_harness.cpp` — tree-reducer output before final copy
- `*.inline.cpp` — FDP-inlined variant
- `harness_values.h` — generated only when large inlined FDP buffers are moved into a header
- `harness_runner` — persistent sanitizer runner built for `--amortize-link`

## Notes

- Dynamic slicing is conservative: if slicing, validation, or coverage collection fails, HarnessReducer falls back to the original harness and continues with the rest of the pipeline.
- If `--snapshot` is enabled and inline validation of `reduced_harness.inline.cpp` fails, the tool retries the same FDP inlining + inline-validation flow from `last_interesting.cpp` when that snapshot differs from `reduced_harness.cpp`. If that retry also fails, the tool falls back to the snapshot base harness; otherwise it falls back to the tree-reduced harness. Without `--snapshot`, it falls back directly to the tree-reduced harness. By default, inline validation first checks the `symbolize=0` crash pattern, then checks symbolized stack depth and the stored pre-harness stack trace. With `--symbolize`, inline validation uses the symbolized crash pattern, symbolized stack depth, and recorded crash location.
- If LLM validation fails, the tool falls back to the non-LLM harness.

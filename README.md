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

Use Linux with the following tools available in `PATH`:

- `clang++`
- `clang-format`
- `llvm-profdata`
- `llvm-cov`
- `llvm-symbolizer` (or an explicit `ASAN_SYMBOLIZER_PATH` / `UBSAN_SYMBOLIZER_PATH`)
- `llvm-objcopy` (optional, used to export hidden static-archive symbols for faster `--amortize-link`)
- Python 3.12+
- Git and a C/C++ build toolchain
- Python's `venv` and `pip`, or `uv`, to install the Python package

Use Clang and the LLVM utilities from the same LLVM installation. You also need
at least one reduction engine; install the one you intend to use:

- **treereduce (default):** a current stable Rust toolchain (`rustc` and `cargo`)
  and `patch` to build the patched executable.
- **Perses, WDD, CDD, or SFC:** Java 17+, GNU `timeout`, and Bazelisk (or Bazel
  9.1.0) to build the shared Perses executable. Rust and treereduce are not
  required for these engines.

The installation steps below include downloading the engine source and build
dependencies, so network access is required. Installing the Python package alone
does not install a reduction engine.

On Ubuntu 24.04, missing system prerequisites can be installed with these
commands as root (or with `sudo` on a host):

```bash
apt-get update
apt-get install -y python3 python3-venv python3-pip \
  clang clang-format llvm build-essential patch pkg-config libssl-dev \
  git curl ca-certificates
```

For the optional `--llm` stage, also set `OPENAI_API_KEY`,
`OPENAI_BASE_URL`, and `OPENAI_MODEL` to your provider's API key, base URL, and
model name. These variables are not needed for ordinary reduction.

## Install

Start in the root of your clone of this repository, on the host or container
where reduction will run. First install the Python package, then install
[Perses and its variants](#2a-install-perses-wdd-cdd-and-sfc) or
[treereduce](#2b-install-treereduce-default), or both. No existing virtual
environment or Perses checkout is assumed.

### 1. Install the Python package

Use a Python 3.12+ interpreter to create a new virtual environment:

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
hash -r
harnessreducer --help
```

If `python3` is older than 3.12, use your installed Python 3.12+ executable in
its place. `harnessreducer --help` checks the Python installation; it does not
verify that an engine has been installed.

Alternatively, if you already use `uv`, use this block **instead** of the one
above:

```bash
uv sync
source .venv/bin/activate
hash -r
harnessreducer --help
```

Both methods install an editable Python package and provide
`.venv/bin/harnessreducer`. The remaining commands assume this environment is
active. In a new shell, return to the repository root and run
`source .venv/bin/activate` again. If Bash still selects an older global
`harnessreducer`, run `hash -r` or use `.venv/bin/harnessreducer` directly.

### 2a. Install Perses, WDD, CDD, and SFC

These engines share one Perses JAR (the Java executable). You only need to build
it once, and you can skip the treereduce installation below if you only use
these engines.

Install Java 17+ and GNU `timeout`. On Ubuntu 24.04, run as root or with `sudo`:

```bash
apt-get update
apt-get install -y openjdk-17-jdk-headless coreutils unzip zip
java -version
timeout --version
```

Next install [Bazelisk](https://github.com/bazelbuild/bazelisk#installation),
which downloads the Bazel version specified by the Perses checkout (9.1.0).
If Bazelisk or Bazel 9.1.0 is already on `PATH`, skip this block. Otherwise,
from the repository root, these commands install Bazelisk locally for Linux
**x86-64**. On Linux ARM64, replace `bazelisk-linux-amd64` with
`bazelisk-linux-arm64` in the URL. The binaries come from the official
[Bazelisk release](https://github.com/bazelbuild/bazelisk/releases/tag/v1.29.0).

```bash
mkdir -p .tools/bin
curl -fL --retry 3 \
  https://github.com/bazelbuild/bazelisk/releases/download/v1.29.0/bazelisk-linux-amd64 \
  -o .tools/bin/bazelisk
chmod +x .tools/bin/bazelisk
export PATH="$(pwd)/.tools/bin:$PATH"
```

Now download Perses, select the exact revision supported by this integration,
and build it. Run these commands from the HarnessMinimizer repository root,
with the Python environment from step 1 active:

```bash
mkdir -p .tools/perses
git clone https://github.com/uw-pluverse/perses.git .tools/perses/source
git -C .tools/perses/source checkout --detach 6c6ae0db20fa83b0f85a71ca447f0c4d5e056bd2
python tools/perses/install.py --source .tools/perses/source --jobs 2
java -Xmx4g -jar .tools/perses/perses_deploy.jar --verbosity SEVERE --version
```

The last command should print the Perses version and exit successfully. The
clone command is a one-time step and requires that `.tools/perses/source` does
not already exist. If you already have a separate, clean Perses checkout at
the required revision, skip cloning and pass its path to `--source` instead.
The build helper checks the revision and refuses tracked source changes; it
does not download or switch the source checkout for you.

The first build downloads dependencies and can take some time. `--jobs 2` here
limits **build** parallelism, not the number of reduction workers. The helper
installs `.tools/perses/perses_deploy.jar` and records its source revision,
build command, and fingerprint in `.tools/perses/build_info.json`.
HarnessReducer finds this JAR automatically; no JAR-path export is needed.
The `.tools` directory is local and ignored by Git, so each fresh installation
needs its own build (or a compatible JAR supplied through
`HARNESSREDUCER_PERSES_JAR`). For later builds in a new shell, repeat the local
Bazelisk `PATH` export if you used it; Bazelisk is not needed to run the built
JAR.

Select the engine with `--tool perses`, `--tool wdd`, `--tool cdd`, or
`--tool sfc`. If you omit `--tool`, HarnessReducer still selects treereduce,
even if only Perses is installed. Plain Perses, WDD, CDD, and SFC passed the
C++ integration tests. `--tool vulcan` is also selectable, but the pinned
Perses version has an unimplemented C++ grammar operation and is not a working
C++ evaluation option. See [Reduction engines](REDUCTION_ENGINES.md) for the
exact configurations and limitation.

### 2b. Install treereduce (default)

Skip this section if you only use the Perses engines. If Rust/Cargo is not
installed, install the stable toolchain and load it into the current shell:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

From the repository root, with the Python environment from step 1 active:

```bash
python tools/treereduce/install.py
export HARNESSREDUCER_TREEREDUCE="$(pwd)/.tools/bin/treereduce-c"
"$HARNESSREDUCER_TREEREDUCE" --harnessreducer-supervisor-version
```

The verification command must print `1`. The installer downloads a pinned
treereduce 0.4.1 source archive, checks its SHA-256, applies
`tools/treereduce/process-cleanup.patch`, then builds and installs the patched
executable into `.tools/bin`. The patch makes timed-out checkers and their recorded descendant groups terminate, and waits for the checker so its zombie process record is reaped.

The installer's `COMMIT` selects the upstream source snapshot; `SHA256` verifies
the downloaded archive before patching. The installer handles downloading and patching automatically.
The ordinary `--version` still reports `treereduce 0.4.1`; use
`--harnessreducer-supervisor-version` to identify this patched build.

The local installation leaves any global `treereduce-c` installation in place.
HarnessReducer selects `HARNESSREDUCER_TREEREDUCE` first, then this checkout's
`.tools/bin/treereduce-c`, then `treereduce-c` on `PATH`. The export above makes
the intended executable explicit, including when a container already has an
override. Running plain `treereduce-c` in your shell may still select a global
binary. `uv sync` or `pip install` installs the Python package only; it does
not apply the Rust patch or build treereduce.

To install treereduce outside the project folder (requires write access to the
destination):

```bash
python tools/treereduce/install.py --root /usr/local
export HARNESSREDUCER_TREEREDUCE=/usr/local/bin/treereduce-c
"$HARNESSREDUCER_TREEREDUCE" --harnessreducer-supervisor-version
```

Build the executable and create the Python environment where you will run
them.
For later shell sessions, activate the same virtual environment and repeat the
export for your chosen executable, or add those commands to your shell setup.

The repository's Dockerfile installs the patched executable under
`/usr/local/bin` and sets `HARNESSREDUCER_TREEREDUCE` accordingly.

### 3. Before starting reduction

Have the harness source, the crash input when needed, and the target library's
headers and compiled libraries available in the execution environment. Supply
their include paths with `--compile-flags` and their library paths/names with
`--link-flags`, as shown below. The tool builds its native persistent runner
when `--amortize-link` is requested; there is no separate runner install step.

If your harness opens data files using relative paths, run HarnessReducer from
the directory where those paths work for the original harness. Perses, WDD,
CDD, and SFC keep candidate files in private directories, but their checker
executes from that original invocation directory. This also applies without
`--amortize-link`; it does not require copying data into each candidate folder.

HarnessReducer automatically isolates external LLVM symbolizers from the
target library directories it adds to `LD_LIBRARY_PATH`. This prevents a
symbolizer that depends on libcurl, for example, from loading the instrumented
benchmark libcurl. It keeps your selected `ASAN_SYMBOLIZER_PATH` and
`UBSAN_SYMBOLIZER_PATH` tools (or finds `llvm-symbolizer` on `PATH`), and restores
the original library search path only for those helper processes. The harness
continues to load the target libraries. No manual wrapper, environment export,
LLVM upgrade, or Docker rebuild is needed for this isolation.

The bundled launchers exec the selected symbolizer without leaving a waiting
shell process. The `symbolize=0` path skips symbolizer preparation; symbolized
execution timings include the launcher cost in the existing measurement
regions. PCH, amortized linking, timeout calibration, and crash validation rules
are unchanged. If reference symbolization still fails, the work directory's
`reference_symbolization_failure.log` contains the raw sanitizer report,
including symbolizer startup errors. `--symbolize` still requires a valid
symbolized crash location.

## Basic CLI Usage

All reduction engines use the same preparation for harness-local `#define`
directives. Each definition still present after compilation-mode preparation is
temporarily replaced, at its original position, with an include of a generated
header. Existing `#include` directives are left unchanged. This protects
multiline definitions and macro operators such as `#` and `##` from source
reconstruction problems in Perses; treereduce uses the same policy for consistent
comparisons. It applies to direct, split, and PCH compilation, including
amortized linking and diagnostic check mode.

The compiler reads these as ordinary headers, so split/direct mode gains no PCH
or compilation caching. Surviving definitions are restored in the result and
fallback snapshots before post-processing and existing final validation; the
exported harness needs no temporary macro headers. Original source files and
library headers are not modified. Preparation adds no candidate checks or
validation stages. Reducers can remove a generated include but cannot edit the
macro's hidden body, so this is a new preparation configuration for performance
comparisons, including treereduce. Runs with no remaining definitions create no
macro artifacts. With definitions, `reducer-macros-*` under the work directory
contains the headers, prepared input, and restoration manifest; profile engine
metadata records the preparation policy and definition count.

```bash
harnessreducer <harness.cpp> -o <reduced.cpp> [options]
```

Module form:

```bash
python -m harnessreducer <harness.cpp> -o <reduced.cpp> [options]
```

## CLI Arguments

| Argument | Required | Description |
|---|---:|---|
| `harness` | Yes | Path to the original harness source file. |
| `-o`, `--output` | Yes | Where to copy the final reduced harness. |
| `--tool <name>` | No | Engine: `treereduce` (default), `perses`, `wdd`, `cdd`, `sfc`, or `vulcan`. |
| `--compile-flags="..."` | No | Compile/preprocessor flags, e.g. include paths, macros, language standard. |
| `--link-flags="..."` | No | Link-only flags, e.g. libraries, `-L`, `-l`, or full `.a` paths. |
| `--crash-input <file>` | No | Crash input passed to the harness binary. |
| `--work-dir <dir>` | No | Reuse a fixed work directory instead of a temporary one. |
| `--stable` | No | Repeat the selected engine's reduction passes until their stopping conditions are reached. |
| `-j`, `--jobs <1..63>` | No | Requested checker concurrency. Defaults to 60; actual concurrency depends on the engine. More workers can increase speculative/retried work. |
| `--slice` | No | Enable coverage-guided dynamic slicing before tree reduction. When omitted, the original harness goes directly into the rest of the pipeline. |
| `--statistics` | No | Record how many times `crash_tester.py` returns logical results `77`, `1`, and `-1` during tree reduction, and write `statistics.txt` in the work directory. |
| `--profile` | No | Record candidate-stage timings, result counts, concurrency, tree-reduction wall time, and checks/s. Writes `candidate_profile.jsonl` and `reduction_profile.{json,txt}`. |
| `--protect-initializers` | No | Opt in to one protected reduction retry if final validation fails and a one-time analyzer check finds an uninitialized use. Off by default; cannot currently be combined with `--slice` or `--llm`. |
| `--symbolize` | No | Ablation mode. Runs reduction candidates with sanitizer `symbolize=1` and validates the symbolized crash pattern, symbolized first-stack-trace depth, and symbolized crash location instead of the default fast `symbolize=0` oracle. |
| `--check` | No | Insight-only mode. Records the first entire stack trace and its frame count from the original crash, then runs tree reduction with `symbolize=1` for every candidate and reports how often the frame count and pre-harness stack-trace prefix stay the same. |
| `--debug` | No | Keep the normal reduction oracle and write detailed records for every candidate and post-reduction validation to `reduction_debug.log`. Cannot be combined with `--check`. |
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

`--statistics` uses a locked read/update/fsync for every candidate. Do not use it
for throughput measurements: `--profile` records the same logical result counts
with one append-only JSON write per candidate and no fsync.

### `--profile` and `--jobs`

`--profile` measures the actual tree-reduction hot loop. It records:

- completed interestingness checks and checks per second;
- result counts for `77`, `1`, and `-1`;
- compile, direct compile+link, link, execution, oracle, Python setup, and total tester time;
- mean and maximum in-flight checks; and
- estimated worker utilization.

Use it with a fixed work directory while sweeping worker counts:

```bash
for jobs in 1 2 4 8 16; do
  harnessreducer harness.cpp \
    --compile-flags="-I/path/to/include" \
    --link-flags="/path/to/libtarget.a" \
    --crash-input crash-input \
    --pch --amortize-link --stable \
    --jobs "$jobs" --profile \
    --work-dir "profile-j${jobs}" \
    -o "reduced-j${jobs}.cpp"
done
```

Compare both `checks_per_second` and total `wall_seconds`. A larger job count can
raise raw checks/s while making the reduction slower if many concurrently tested
candidates become stale after another worker accepts a reduction.

### `--protect-initializers`

This optional recovery helps when a reducer removes a variable's starting value.
For example, it may turn `Point p = {2, 3};` into `Point p;`. Compiler warnings do
not catch every such change, and the result may fail final validation.

Add `--protect-initializers` to your normal command to enable this policy.
The performance-sweep script enables it automatically for every run.

1. Reduce normally, then try the existing output validation and fallback steps.
   A successful run needs no static analysis or second reduction.
2. If no output passes validation, run Clang's analyzer once on the failed
   cleaned source. Only a relevant uninitialized-use report in the harness
   triggers recovery; an unrelated warning or failed analyzer does not.
3. Retry the same engine once from the original tagged source, using the original
   input, recorded values, and validation reference. Supported initialized local
   declarations are hidden behind macros during this retry. A reducer can delete
   an entire declaration, but cannot delete just its initializer.
4. Restore surviving declarations to ordinary C++ before inlining and final
   validation. The delivered source does not need the protection header.

This uses the existing Clang installation, not a compiler plugin. There is no
static analyzer or extra source parser in each candidate check. The protected
retry can take additional time and retain more code. It is not a general check
for uninitialized memory: initialization through later assignments or library
calls is not protected, and dependencies outside a declaration can still change.
Unsupported declaration forms are recorded as skipped. A one-time preprocessing
comparison rejects preparation that changes the original token stream.

The flag works with treereduce, Perses, WDD, CDD, and SFC; direct, split, and PCH
compilation; and either symbolization setting. Amortized linking remains available
with split/PCH. Existing final-validation requirements are not relaxed. If the
retry also fails, artifacts remain available for inspection, but the command
returns nonzero and does not copy an unvalidated file to `--output`.

With `--profile`, the usual top-level reports pool completed checker records from
both attempts. Reduction wall time is the sum of the two reducer invocation
times; compilation means still use successful compilations only. Analyzer,
preparation, and final-validation time belong to full-command wall time, not
candidate compile time. `initializer_recovery.json` records the outcome and
diagnosis. A recovery subdirectory preserves separate attempt reports, prepared
source, and the protection manifest. Source/log artifacts of the normal attempt
remain in the original work directory.

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

### `--debug`

`--debug` keeps the normal candidate path, including the selected Phase 3 mode,
stable mode, and amortized linking. It does not use the separate `--check`
oracle. Each candidate and post-reduction validation appends a locked record to
`reduction_debug.log` containing the source path, compile result, executable and
tester return codes, crash-pattern result, dynamic crash-site result, and first
stack trace. Candidate records may appear out of order because tree reduction
runs multiple workers concurrently. The CLI copies the log next to the requested
`--output`, so it remains available when no fixed `--work-dir` was supplied.

### `--snapshot`

Enables optional last-interesting snapshot behavior:

- during tree reduction, candidates that actually return `77` may update `last_interesting.cpp`
- after reduction, if final validation of the prepared result fails, HarnessReducer may retry from that snapshot and fall back to its non-inlined version if needed

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

For treereduce, retains `--stable --min-reduction 1` instead of `--fast`.
For Perses engines, enables main and global fixpoint reduction and the selected
transformation family's fixpoint mode. This repeats the passes until their
stopping conditions are reached; it does not guarantee identical results across
worker counts. See [Reduction engines](REDUCTION_ENGINES.md).

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
    tool="treereduce",       # or "perses", "wdd", "cdd", "sfc", "vulcan"
    compile_flags="-std=c++17 -Iinclude -Ibuild/include",
    link_flags="build/lib/libtarget.a",
    crash_input="crash-input",
    phase3_mode="pch",      # or "split" / "direct"
    amortize_link=False,     # requires split/PCH and shared or static target libraries
    statistics=False,         # optional
    profile=False,            # optional low-overhead hot-loop profile
    protect_initializers=False,  # optional failure-triggered protected retry
    jobs=8,                   # benchmark for the target and machine; valid range 1..63
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
    profile=False,
    jobs=8,
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
- `candidate_profile.jsonl` — one append-only per-check timing record when `--profile` is enabled
- `reduction_profile.json` and `reduction_profile.txt` — aggregate tree-reduction throughput and stage timing when `--profile` is enabled
- `reduction_debug.log` — per-candidate and post-reduction oracle details when `--debug` is enabled
- `last_interesting.cpp` — optional snapshot of the latest candidate source that actually returned `77`; created only when `--snapshot` is enabled
- `reduced_harness.cpp` — selected reduction engine's output before final preparation
- `*.inline.cpp` — prepared output for final validation, including unchanged copies when no input values need to be inlined
- `harness_values.h` — recorded sequences for repeated FDP calls, large buffers, and any required byte-conversion helpers
- `harness_runner` — persistent sanitizer runner built for `--amortize-link`

## Notes

- FDP inlining runs after tree reduction. It preserves the FDP result type for scalar replacements and reconstructs fresh strings/vectors from recorded values. Header storage uses globally available types; local aliases and deduced types are resolved at the original call site. This adds no candidate checks or compiler invocations to tree reduction. Final source generation and compilation do additional type-conversion work. Executing the generated harness may require copies where the previous inliner incorrectly substituted references to stored strings/vectors; the cost depends on the harness and buffer sizes.
- Dynamic slicing is conservative: if slicing, validation, or coverage collection fails, HarnessReducer falls back to the original harness and continues with the rest of the pipeline.
- Final validation is performed even when reduction removes every FDP call or removes the names or parameters of `LLVMFuzzerTestOneInput`. In direct-input mode, two named parameters retain the usual byte/length inlining; if only one of the two is named, only that value is assigned. An empty parameter list or two unnamed parameters need no assignments. Unsupported signatures are left unchanged and validated with the original input, rather than guessing which parameter represents data or size. A values header is generated only when input assignments are added. Signatures are not rewritten; a successful check applies to the current build/runtime environment, not arbitrary calling conventions on other machines.
- If `--snapshot` is enabled and final validation of `reduced_harness.inline.cpp` fails, the tool retries preparation and validation from `last_interesting.cpp` when that snapshot differs from `reduced_harness.cpp`. If that retry also fails, it validates the cleaned non-inlined snapshot. Without an eligible snapshot, it validates the cleaned non-inlined reduced harness. A fallback that passes can be returned successfully. Otherwise, it remains a diagnostic artifact: the API returns `success=False`, and the CLI exits nonzero without copying it to `--output`. These existing fallback steps do not rerun reduction; the optional `--protect-initializers` recovery described above can do so afterward. By default, final validation first checks the `symbolize=0` crash pattern, then checks symbolized stack depth and the stored pre-harness stack trace. With `--symbolize`, it uses the symbolized crash pattern, symbolized stack depth, and recorded crash location. Both optimized and non-optimized reductions retain the existing standalone final-validation path. Direct-input embedding still requires an available crash-input file; missing input is reported explicitly rather than invented.
- If LLM validation fails, the tool falls back to the non-LLM harness.

## Performance sweeps and CSV collection

From the repository root, with the Python environment from installation active,
run both compilation/execution configurations with the selected reduction engine:

```bash
python run_harnessreducer_perf_sweep.py \
  --dir libaom-1 --tool wdd \
  --compile-flags='-I{bench_dir}/build/sanitizer/include' \
  --link-flags='-L{bench_dir}/build/sanitizer/lib -laom'
```

Replace `wdd` with `treereduce`, `perses`, `cdd`, or `sfc`. Omitting `--tool`
uses treereduce. The sweep accepts the same engine choices as the main CLI,
including Vulcan with its known limitation; selecting it does not fix that
upstream issue. Build the selected engine before running a timed sweep.

The script substitutes `{bench_dir}` with the benchmark's absolute path. It
first runs `--pch --amortize-link` without symbolization, then `--split
--symbolize` without amortized linking. Each configuration uses workers
`1,2,4,8,16,32,60`, with `--stable --profile` and a separate work directory for
each case. Use `--jobs 1,2,4` for a smaller sweep. Results are saved under
`benchmark/library-bug/<benchmark>/harnessreducer-perf-comparison-<tool>-<timestamp>`.
The manifest and each job's metadata record the selected engine. The runner also
writes `latest_harnessreducer_perf_run_<tool>.txt` under the benchmark directory,
alongside the old global marker. These markers point to result directories,
including custom `--output-root` locations; the existing directory layout does
not change. Markers are written when a sweep starts. The manifest records
`running`, then `completed` or `failed` when the sweep exits normally; an
interrupted sweep may remain marked `running`.

The sweep always passes `--protect-initializers` to both configurations, for every
engine and job count. You do not need to add it to your sweep command; explicitly
passing it is still accepted for compatibility. The standalone `harnessreducer`
command and Python API remain opt-in. This enables failure-triggered recovery,
not protection during every first reduction. The full-command timer includes any recovery.
When this policy is present in saved profiles, the TXT report includes recovery
status and attempt counts; the CSV adds `initializer_recovery` and
`reduction_attempts` columns. A comparison cannot mix enabled and disabled policies,
but can compare enabled runs where only some needed a retry. Reports for older or
disabled runs retain their existing CSV columns. Token counts still compare the
original harness with the final restored output, not the temporary macro source.

Create TXT and CSV reports for the latest run of **each tool** for a benchmark:

```bash
python make_harnessreducer_perf_tables.py --dir libaom-1 --all-tools
```

For just the latest WDD run, use `--tool wdd` instead of `--all-tools`. With
neither option, the script retains single-report usage and selects the latest
run overall. Repository-root `command.txt` contains a loop over benchmarks using
`--all-tools`; it does not generate reports for every historical run.

The table script does not run a reducer. It reads the engine from saved
manifest/job/profile metadata and rejects conflicting names. Old data without
engine metadata is treated as treereduce, the old sweep's only engine. Latest
runs are chosen by the manifest's recorded start time, with the timestamp in
the directory name as the legacy fallback. Thus, generating a report in an
older folder does not make that run newer. For old custom folders with neither
timestamp, the manifest's modification time (or directory time if no manifest
exists) is the last-resort ordering. Both old and new directory names are
supported; stale pointers to missing directories are ignored.

"Latest" means the newest run, not the newest successful run. A latest sweep
that is incomplete or recorded as failed produces an error rather than silently
substituting an older result. With `--all-tools`, other tools still get their
reports, and the command exits nonzero if any selected run fails. Benchmarks
without any saved sweeps are skipped. To explicitly report an older run, use
`--results-dir /absolute/path/to/that/sweep`; an accompanying `--tool` checks its
recorded identity. The runner also prints that exact-run report command.

Default reports include both engine and benchmark names, for example:

- `performance_tables_wdd_libaom-1.txt`
- `performance_comparison_wdd_libaom-1.csv`

The CSV layout remains three rows per matched worker count: optimized,
non-optimized, and speedup. The timing columns, total checks, original/final
tokens, and token reduction percentage are unchanged. Time speedups are
non-optimized / optimized; throughput speedup is optimized / non-optimized.
Values below 1 are retained if an optimization was slower. Explicit `--output`
and `--csv-output` paths still override the default report names for a single
run; they cannot be combined with `--all-tools`.

Collect existing performance comparison CSV files from the entire
`benchmark/library-bug` tree:

```bash
python collect_harnessreducer_perf_csvs.py
```

This copies regular files whose names start with
`performance_comparison_` and end with `.csv` into repository-root `temp/`.
Perses working CSVs and other internal CSV files are skipped. Source files are
unchanged. Different contents with the same filename get `__2`, `__3`, etc.;
identical copies are reused, so rerunning does not duplicate unchanged files.
CSV symlinks and symlinked directories are not followed. Each invocation writes
a unique `csv_collection_*.json` mapping source paths to collected names.
`temp/` is ignored by Git. Use `--output-dir` to choose another destination
outside the benchmark tree. Existing CSV contents/names are not rewritten to
guess an engine; engine-bearing names come from the updated table generator.
Selecting latest runs for report generation does not delete historical reports.
The collector still collects **all existing performance comparison CSV files**,
including older reports already on disk; it does not itself filter to the latest
runs.

## Reducer throughput baseline

`measure_treereduce.py` compares two direct
`treereduce-c` workloads using the dependency-free
`benchmark/treereduce-throughput/compile_success.cpp`
fixture:

- `compile`: the normal documented workflow, with `clang++ @@.cpp -o /dev/null`
  as the interestingness check; and
- `grep`: a cheap stdin oracle that isolates reducer/process-launch overhead.

Run a worker sweep with:

```bash
./measure_treereduce.py --checker both --jobs 1,2,4,8,16 --repetitions 3
```

The timestamped result directory contains `summary.txt`, `summary.json`, each
reduced source, and failure tails. Add `--keep-logs` only when raw reducer traces
are needed; debug JSON can become very large when high worker counts cause many
retries. Retained logs are gzip-compressed.

Use this baseline together with `measure_time.py`:

- `measure_treereduce.py` answers how many real checks the reducer schedules,
  how quickly they complete, and how worker count affects convergence;
- `harnessreducer --profile` measures the same quantities in the real crash
  oracle; and
- `measure_time.py` decomposes unchanged-harness compile, link, load, execution,
  fork, socket, and Python oracle costs without a reduction run.

Compare total reduction wall time as well as checks per second: more workers
can increase speculative or repeated checks, so higher throughput does not
necessarily mean the harness finishes reducing sooner.

# HarnessReducer

HarnessReducer minimizes crashing C/C++ fuzz harnesses while preserving the crash.
It can be used through a command-line interface
(CLI) and a Python API.

## Installation

For direct use of HarnessReducer, run this on the host from the repository root
to build the image and create the `harnessminimizer` container.

```bash
./setup_docker.sh
docker exec -it harnessminimizer bash
cd /root/HarnessMinimizer
```

For the evaluation scripts below, use this alternative on the host to create
`harnessminimizer-eval` with the benchmark dependencies and liblouis table path.

```bash
./setup_docker_eval.sh
docker exec -it harnessminimizer-eval bash
cd /root/HarnessMinimizer
```

Both scripts mount the repository at `/root/HarnessMinimizer` and default to the
`harnessminimizer:latest` image; use `--image` or `--name` to override the names.
Run the remaining installation commands inside the chosen container.

Install the Python package and activate its environment using uv.

```bash
uv sync
source .venv/bin/activate
```

Install the prerequisites for Perses, WDD, CDD.

```bash
apt-get update
apt-get install -y openjdk-17-jdk-headless coreutils unzip zip
```

Install Bazelisk to build the Perses engines.

```bash
mkdir -p .tools/bin
curl -fL --retry 3 \
  https://github.com/bazelbuild/bazelisk/releases/download/v1.29.0/bazelisk-linux-amd64 \
  -o .tools/bin/bazelisk
chmod +x .tools/bin/bazelisk
export PATH="$(pwd)/.tools/bin:$PATH"
```

Build and install the pinned Perses revision.

```bash
mkdir -p .tools/perses
git clone https://github.com/uw-pluverse/perses.git .tools/perses/source
git -C .tools/perses/source checkout --detach 6c6ae0db20fa83b0f85a71ca447f0c4d5e056bd2
python tools/perses/install.py --source .tools/perses/source --jobs 2
```

Install and select patched treereduce.

```bash
python tools/treereduce/install.py
export HARNESSREDUCER_TREEREDUCE="$(pwd)/.tools/bin/treereduce-c"
```

## Reduce a harness

Replace the absolute paths below with your harness, crash input, target library,
and output locations, and replace `target` with the library name. The harness and
crash input can be in different directories. If the harness opens runtime files
using relative paths, run from the working directory those paths require.

Optimized pipeline:

```bash
harnessreducer /path/to/harness.cpp \
  --compile-flags="-I/path/to/library/include" \
  --link-flags="-L/path/to/library/lib -ltarget" \
  --crash-input /path/to/inputs/crash-input \
  --pch --amortize-link --stable \
  -o /path/to/output/reduced.cpp
```

Unoptimized pipeline:

```bash
harnessreducer /path/to/harness.cpp \
  --compile-flags="-I/path/to/library/include" \
  --link-flags="-L/path/to/library/lib -ltarget" \
  --crash-input /path/to/inputs/crash-input \
  --split --symbolize --stable \
  -o /path/to/output/reduced.cpp
```

By default, HarnessReducer uses **treereduce**, **split compilation**, and
**60 workers**. Amortized linking, profiling, symbolization, and stable mode are
**off** unless explicitly enabled.

| Argument | Purpose |
| --- | --- |
| `harness` | Required path to the original harness source. |
| `-o`, `--output` | Required destination for the reduced harness. |
| `--crash-input` | Optional crashing input file passed to the harness. |
| `--compile-flags="..."` | Compiler flags, such as include paths, defines, and language standard. |
| `--link-flags="..."` | Linker flags, such as library paths, library names, or full archive paths. |
| `--tool` | Engine: `treereduce` (default), `perses`, `wdd`, `cdd`. |
| `-j`, `--jobs` | Requested concurrent candidate checks: 1–63, default 60. |
| `--direct`, `--split`, `--pch` | Compile and link in one step; compile then link separately (default); or use precompiled headers with separate compilation and linking. |
| `--amortize-link` | Reuse a persistent runner and shared/static target libraries. |
| `--stable` | Repeat engine passes until their stopping conditions are reached. |
| `--symbolize` | Use symbolized crash traces when checking reduction candidates. |
| `--work-dir` | Directory for intermediate files; a temporary directory is created by default. |
| `--profile` | Record candidate timings and reduction throughput (for evaluation purpose only). |
| `--debug` | Log candidate compilation and crash-check details. |

Choose only one of `--direct`, `--split`, and `--pch`. `--amortize-link` requires
split or PCH mode and shared or static target libraries in the link flags.
Use the `--compile-flags="..."` and `--link-flags="..."` spelling shown above for
values beginning with `-`. See `harnessreducer --help` for the full option list.
The CLI copies any required generated header files beside the output harness.

### Python API

Run the same reduction from Python and check that it succeeded before using the result.

```python
from harnessreducer import ReductionConfig, reduce_with_config

result = reduce_with_config(ReductionConfig(
    harness_path="/path/to/harness.cpp",
    crash_input="/path/to/inputs/crash-input",
    compile_flags="-I/path/to/library/include",
    link_flags="-L/path/to/library/lib -ltarget",
    phase3_mode="pch",
    amortize_link=True,
    stable=True,
))
if not result.success:
    raise RuntimeError("Reduction did not preserve the crash")
print(result.reduced_harness)
```

The API uses the same defaults as the CLI. If you move the returned harness, copy
the files in `result.generated_headers` alongside it.

## Evaluation

Run these commands from the repository root with the benchmark data available under `benchmark/`.

GitHub limits repository file sizes, so build the benchmark libraries locally. For each case, check out the library's Git commit SHA listed in [library_version.csv](library_version.csv), build its dynamic (`.so`) and static (`.a`) libraries, and place them in that case's `build/sanitizer/lib/` folder under `benchmark/harness-bug/` or `benchmark/library-bug/`. Don't forget to instrument the libraries with AddressSanitizer and UndefinedBehaviorSanitizer (`-fsanitize=address,undefined`) when building them.

### Speedup Performance

Run performance evaluation for all four engines across both datasets.

```bash
./run_harnessreducer_evaluation.sh --tool all
```

### Crash Triage

Create the crash-triage configuration.

```bash
cp .env-template .env
```

Fill in `OPENAI_BASE_URL`, `LLM_API_KEY`, and `OPENAI_MODEL` in `.env`.

Run crash triage using the latest performance evaluation batch. Replace `n` with
the number of concurrent benchmark cases; tools within each case run sequentially.

```bash
./run_crash_triage_parallel.sh --tool all --jobs n
```

Retry failed or unfinished triage cases with `n` workers.

```bash
./run_crash_triage_parallel.sh --tool all --jobs n --resume
```

### FDP Replay Function Evaluation

Run the replay experiment across all cases with 10 treereduce workers per reduction.

```bash
./run_replay_evaluation.sh --jobs 10
```

Resume replay evaluation, retrying failed or incomplete cases.

```bash
./run_replay_evaluation.sh --jobs 10 --resume
```

### Crash Oracle Evaluation

Run the oracle experiment across both datasets.

```bash
./run_oracle_evaluation.sh --jobs 10
```

Resume oracle evaluation, retrying failed or incomplete cases.

```bash
./run_oracle_evaluation.sh --jobs 10 --resume
```

For replay and oracle experiments, `--jobs` controls reducer workers (default 10),
while `--parallel` controls concurrent cases (default 1). Crash triage instead uses
`--jobs` for concurrent cases. Results are saved under `output/replay-evaluation/`
and `output/oracle-evaluation/`; use `--results-root` to choose another location.

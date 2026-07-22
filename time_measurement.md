# Pipeline Timing Measurement

`measure_time` benchmarks HarnessReducer's compilation, linking, loading, and
execution stages without running reduction. It repeatedly uses the unchanged
input harness so that the normal, PCH, and linkage-amortized paths can be
compared directly.

## Requirements

- Run from the repository environment created by `uv sync`.
- `clang++` must be available.
- The target libraries must use sanitizer settings compatible with the harness.
- Supply a real crash input. Execution timing is not representative without it.

## Usage

```bash
./measure_time.py HARNESS \
  --compile-flags "..." \
  --link-flags "..." \
  --crash-input FILE \
  -o OUTPUT
```

If the executable bit is unavailable, use:

```bash
.venv/bin/python measure_time.py HARNESS \
  --compile-flags "..." \
  --link-flags "..." \
  --crash-input FILE \
  -o OUTPUT
```

`OUTPUT` is the name of the representative standalone executable. It is always
created in a timing directory beside the harness; it is not written to the path
outside that directory.

By default, the directory is `time`. Use `--suffix NAME` to create
`time-NAME` instead. For example, a harness at `/work/case/harness.cpp` with
`--suffix dynamic` produces `/work/case/time-dynamic/`.

Each repeated measurement uses 100 iterations by default. A smaller value is
useful for a quick smoke run:

```bash
./measure_time.py harness.cpp \
  --compile-flags "-Iinclude" \
  --link-flags "/path/libtarget.so" \
  --crash-input crash-input \
  --iterations 3 \
  --suffix smoke \
  -o harness.out
```

## Examples

### Dynamic target

```bash
./measure_time.py harness.cpp \
  --compile-flags "-I$(pwd)/build/sanitizer/include" \
  --link-flags "-L$(pwd)/build/sanitizer/lib -laom" \
  --crash-input crash-input \
  -o harness.out
```

### Static target

```bash
./measure_time.py harness.cpp \
  --compile-flags "-I$(pwd)/build/sanitizer/include" \
  --link-flags "$(pwd)/build/sanitizer/lib/libaom.a -lpthread -lm" \
  --crash-input crash-input \
  -o harness.out
```

### Mixed static and dynamic targets

```bash
./measure_time.py harness.cpp \
  --compile-flags "-I$(pwd)/build/sanitizer/include" \
  --link-flags "-L$(pwd)/build/sanitizer/lib \
    -Wl,-Bstatic -ltarget_static \
    -Wl,-Bdynamic -ltarget_shared -lpthread" \
  --crash-input crash-input \
  -o harness.out
```

## Output

All generated artifacts are placed beside the input harness in one of:

```text
<harness-directory>/time/
<harness-directory>/time-<suffix>/
```

The main files are:

```text
<timing-directory>/time.txt                 grouped human-readable report
<timing-directory>/raw_samples.json         every raw nanosecond sample
<timing-directory>/harness_prefix.h         generated PCH prefix header
<timing-directory>/harness_prefix.normal.pch
<timing-directory>/harness_prefix.amortized.pch
<timing-directory>/candidate.so             representative candidate plugin
<timing-directory>/candidate.fallback.so    plugin linked with --link-flags
                                            when static fallback is measurable
<timing-directory>/harness_runner           normal production runner build
<timing-directory>/timing_runner            instrumented measurement runner
```

Delete that `time/` or `time-<suffix>/` directory to remove all measurement
artifacts.

## What is measured

The compilation table contains four comparable rows:

| Output model | Header strategy | Important flags |
|---|---|---|
| Normal executable | Split | `address,fuzzer,undefined` |
| Normal executable | PCH | same sanitizers plus normal PCH |
| Amortized plugin | Split | `address,undefined -fPIC` |
| Amortized plugin | PCH | same plugin flags plus amortized PCH |

Two PCH files are built because normal and plugin compilation use different
sanitizer/PIC options. Clang requires the PCH options to be compatible with the
candidate compilation options.

The report also measures:

- source splitting and PCH creation;
- normal executable linking;
- candidate plugin linking;
- fallback candidate plugin linking, when static archives are present;
- static/dynamic/mixed library classification;
- production runner build time;
- dynamic-target `dlopen()` and crash-input loading;
- standalone execution with `symbolize=0` and `symbolize=1`;
- amortized execution with `symbolize=0` and `symbolize=1`;
- monitor/executor forks;
- `dlopen(candidate.so)`;
- `dlsym("LLVMFuzzerTestOneInput")`;
- function-call start until child termination; and
- socket request/response time.

For static targets, the report states whether the runner build used rooted
static archive extraction or the whole-archive fallback, and it reports the
number of inferred root symbols plus how many static archives were copied for
the export fix and how many static symbols were made exportable. The
dynamic-target `dlopen()` row is shown as not applicable because a static
archive is not loaded with `dlopen()`. In a mixed configuration, the build rows
carry the static-target note and the `dlopen()` row measures the dynamic
targets.
If a lightweight plugin load fails with `undefined symbol`, the timing runner
request measurement retries that iteration with `candidate.fallback.so`. The
output-linking section reports whether fallback was actually needed for
`symbolize=0` and `symbolize=1`. This distinguishes a fallback plugin that was
merely link-timed from one that was required by the measured candidate.

`dlsym()` only finds the harness function address. The following function-pointer
call performs the actual candidate execution. If the candidate crashes, its
execution interval ends when the monitor observes child termination. That
interval includes sanitizer crash reporting.

The output-pipe interval overlaps candidate execution and is reported
separately. Do not add it to the execution interval.

## Interpretation notes

- Times are wall-clock measurements, so CPU load and filesystem cache state
  matter.
- The first PCH and runner builds are one-time measurements, matching their use
  in the real pipeline.
- Repeated compile/link measurements naturally benefit from warm filesystem
  caches after early iterations.
- The script records mean, median, population standard deviation, minimum, and
  maximum. The requested average is the `Mean` column.
- Exit-status distributions are recorded instead of requiring every harness to
  crash with one particular status.
- A symbolized crash can generate substantial output. Capturing that output is
  intentionally included because the real tester captures sanitizer output too.
- `raw_samples.json` in the timing directory contains the individual
  measurements and exact command
  arrays used to produce the summary.

python3 measure_time.py benchmark/library-bug/libaom-6/harness.cpp \
  --compile-flags="-Ibenchmark/library-bug/libaom-6/build/sanitizer/include" \
  --link-flags="-Lbenchmark/library-bug/libaom-6/build/sanitizer/lib -laom" \
  --crash-input benchmark/library-bug/libaom-6/crash-input \
  --suffix dynamic \
  -o benchmark/library-bug/libaom-6/harness.out

python3 measure_time.py benchmark/library-bug/libaom-6/harness.cpp \
  --compile-flags="-Ibenchmark/library-bug/libaom-6/build/sanitizer/include" \
  --link-flags="benchmark/library-bug/libaom-6/build/sanitizer/lib/libaom.a" \
  --crash-input benchmark/library-bug/libaom-6/crash-input \
  --suffix static \
  -o benchmark/library-bug/libaom-6/harness.out

python3 measure_time.py benchmark/library-bug/libpcap-2/harness.cpp \
  --compile-flags="-Ibenchmark/library-bug/libpcap-2/build/sanitizer/include" \
  --link-flags="benchmark/library-bug/libpcap-2/build/sanitizer/lib/libpcap.a -lnl-genl-3 -lnl-3 -ldbus-1" \
  --crash-input benchmark/library-bug/libpcap-2/crash-input \
  --suffix static \
  -o benchmark/library-bug/libpcap-2/harness.out

python3 crash_triage.py benchmark/library-bug/libpcap-2/harness.cpp \
  --compile-flags="-Ibenchmark/library-bug/libpcap-2/build/sanitizer/include" \
  --link-flags="-Lbenchmark/library-bug/libpcap-2/build/sanitizer/lib -lpcap" \
  --crash-input benchmark/library-bug/libpcap-2/crash-input

python3 crash_triage.py benchmark/library-bug/libpcap-2/harness.cpp \
  --compile-flags="-Ibenchmark/library-bug/libpcap-2/build/sanitizer/include" \
  --link-flags="-Lbenchmark/library-bug/libpcap-2/build/sanitizer/lib -lpcap -lnl-genl-3 -lnl-3 -ldbus-1" \
  --crash-input benchmark/library-bug/libpcap-2/crash-input


strings -a benchmark/library-bug/libaom-1/build/sanitizer/lib/libaom.so \
  | grep -oEm1 '[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-g[0-9a-f]{7,40}' \
  | sed -E 's/.*-g//'

docker run -d \
  --name harnessminimizer-eval \
  --init \
  --pids-limit 4096 \
  --mount type=bind,src=/mnt/raid/home/lihaiying/HarnessMinimizer,dst=/root/HarnessMinimizer \
  harnessminimizer:latest \
  sleep infinity

docker start harnessminimizer-eval

git config --global user.email "lihy2022@connect.hku.hk"
git config --global user.name "FalconLi"

cat <<'EOF' >> ~/.bashrc

# Fast sanitizer symbolization inside container
export DEBUGINFOD_URLS=
export ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-21/bin/llvm-symbolizer
export UBSAN_SYMBOLIZER_PATH=/usr/lib/llvm-21/bin/llvm-symbolizer
EOF

source ~/.bashrc

echo "$DEBUGINFOD_URLS"
echo "$ASAN_SYMBOLIZER_PATH"
echo "$UBSAN_SYMBOLIZER_PATH"

cat <<'EOF' >> ~/.bashrc

export HKU_API_KEY=sk-wBxcGPTDAOihyZWR0jjMtRmXdcyChzqIsZIoM6H7Ktf65Brt
EOF

source ~/.bashrc

export ASAN_OPTIONS=symbolize=0:handle_abort=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:symbolize=0
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:symbolize=1

python3 measure_time.py benchmark/library-bug/opencv-1/harness.cpp \
  --compile-flags="-Ibenchmark/library-bug/opencv-1/build/sanitizer/include -fsanitize=vptr" \
  --link-flags="-Lbenchmark/library-bug/opencv-1/build/sanitizer/lib -lopencv_photo -lopencv_imgproc -lopencv_core -littnotify -lpthread -ldl -lz -fsanitize=vptr" \
  --crash-input benchmark/library-bug/opencv-1/crash-input \
  --suffix static \
  -o benchmark/library-bug/opencv-1/harness.out

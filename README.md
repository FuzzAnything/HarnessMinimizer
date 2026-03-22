# HarnessReducer

HarnessReducer is a reducer workflow for library fuzzing harnesses.
It focuses on preserving an existing crash while minimizing harness code,
with first-class support for `FuzzedDataProvider` (FDP).

## Install

1. Install `tree-reducer-c`:

```bash
cargo install treereduce-c
```

2. Use a Python 3.12+ environment and install project dependencies:

```bash
uv sync
```

3. Ensure `clang++` is available in `PATH`.

## Complex FDP Example

The repository contains a complex FDP-based harness example:

- `examples/fdp_complex_crash_harness.cpp`

This example intentionally includes:

- Multiple parsing stages (`header`, `records`, `metrics`)
- Rich FDP consumption APIs (`ConsumeBytesAsString`, `ConsumeIntegral`,
	`ConsumeRandomLengthString`, `ConsumeBytes`, `ConsumeFloatingPoint`, `ConsumeBool`)
- A deterministic crash gate to demonstrate crash-preserving reduction

### Build The Example

```bash
clang++ -std=c++17 -Iinclude -O0 -g \
	examples/fdp_complex_crash_harness.cpp \
	-o /tmp/fdp_complex_demo.out
```

## Testing

Run automated tests (compiles and executes the example):

```bash
uv run python -m unittest tests/test_fdp_complex_example.py -v
```

## CLI Usage

After installation, run:

```bash
harnessreducer <harness.cpp> <crash_regex> [--extra-flags "..."] [--crash-input seed.bin] [-o reduced.cpp]
```

Use a fixed working directory (no temporary directory creation):

```bash
harnessreducer <harness.cpp> <crash_regex> --work-dir ./workdir
```

Equivalent module invocation:

```bash
uv run python -m harnessreducer <harness.cpp> <crash_regex> [--extra-flags "..."] [--crash-input seed.bin] [-o reduced.cpp]
```

## Python API Usage

```python
from harnessreducer import ReductionConfig, reduce_with_config

config = ReductionConfig(
	harness_path="examples/fdp_complex_crash_harness.cpp",
	crash_pattern="AddressSanitizer|runtime error",
	extra_flags="-std=c++17",
	crash_input="seed.bin",
)

result = reduce_with_config(config)
print(result.reduced_harness)
```

## Notes

- FDP header is expected at `include/fuzzer/FuzzedDataProvider.h`.
- The reducer pipeline Python code is in `src/harnessreducer/`.
- Internal layering:
	- `harnessreducer.api`: orchestration/public API
	- `harnessreducer.fdp_transform`: FDP AST tagging + trace inlining
	- `harnessreducer.reducer_runner`: compile/run/tree-reducer execution
- Legacy compatibility entrypoint is still available at `python -m harnessreducer.main`.
- Legacy compatibility entrypoint is still available at `uv run python -m harnessreducer.main`.
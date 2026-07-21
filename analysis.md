# HarnessReducer — Codebase Analysis

## Overview

HarnessReducer minimizes crashing C/C++ fuzz harnesses while preserving crash behavior. It is aimed especially at `FuzzedDataProvider` (FDP) harnesses. The current pipeline combines:

1. original crash-pattern extraction
2. reference stack-trace recording
3. optional check-mode full-stack insight recording
4. optional conservative dynamic slicing using source-based coverage
5. FDP callsite tagging
6. FDP trace dump/replay
7. tree-based reduction with `treereduce-c`
8. FDP literal inlining
9. optional LLM cleanup
10. optional tree-reduction return-code statistics
11. optional persistent-runner linkage amortization for shared target libraries

The tool is intentionally conservative: when a new optimization step cannot be validated, it falls back to the last known-good harness and continues.

---

## Main Source Files

### `src/harnessreducer/`

| File | Lines | Role |
|---|---:|---|
| `__init__.py` | 3 | Re-exports public API symbols |
| `__main__.py` | 3 | `python -m harnessreducer` entry point |
| `main.py` | 6 | Legacy entry point |
| `cli.py` | 130 | CLI parser and output copy logic |
| `api.py` | 357 | End-to-end orchestration pipeline |
| `check_mode.py` | new | `--check` reference recording, statistics, and treereduce wrapper |
| `reducer_runner.py` | 984 | Compilation, execution, crash checking, coverage collection, treereduce integration |
| `dynamic_slicer.py` | 371 | Tree-sitter-based dynamic slicing engine |
| `fdp_transform.py` | 918 | FDP ID injection, trace-based literal inlining, cleanup |
| `llm_reducer.py` | 172 | Optional LLM post-pass |

### Important helper / test scripts

| File | Role |
|---|---|
| `tests/crash_tester.py` | Interestingness test used by `treereduce-c` and validation steps |
| `tests/check_tester.py` | Insight-only interestingness test used by `--check` tree reduction |
| `pattern_extraction.py` | Helper script to test Phase 1 pattern/stack extraction |
| `dynamic_slicing.py` | Helper script to inspect coverage artifacts and slicing results |
| `test_fdp.py` | Helper script to inspect FDP tagging/dump/inline behavior |
| `test_pch.py` | Helper script to inspect PCH-mode behavior |

---

## Current Pipeline (`reduce_with_config()`)

The main workflow lives in `src/harnessreducer/api.py`.

### 1. Configure work directory

- `configure_work_dir()` creates a temp directory unless `--work-dir` is provided.
- `reset_stack_trace_state()` deletes stale stack-trace state from previous runs:
  - `stack_trace.pattern`

### 2. Pre-flight checks

- `check_tree_reducer()` verifies `treereduce-c` is available.
- `check_harness_compilation()` builds the original harness into `poc.out` using:
  - `clang++`
  - `-fsanitize=address,fuzzer,undefined`
  - `-gline-tables-only -O0 -Werror=uninitialized`
  - user `compile_flags` and `link_flags`

### 3. Crash pattern extraction + reference stack trace

`extract_crash_pattern_from_output()` now performs two reference runs:

- a `symbolize=0` run to extract the fast crash pattern and record the **fast-path** first-stack-trace depth
- a `symbolize=1` run to extract the symbolized crash pattern, record the **symbolized** first-stack-trace depth, and save the truncated symbolized stack trace

The crash-pattern regexes are persisted as:

- `crash_pattern.symbolize0`
- `crash_pattern.symbolize1`, when the symbolized run yields a separate extractable signature

From the symbolized run it:

- extracts the first symbolized stack trace
- truncates the trace before the harness frame (preferred) or `LLVMFuzzerTestOneInput` (fallback)
- normalizes the trace with `normalize_crash_signature(..., escape=True)`
- stores it in `stack_trace.pattern`

The crash patterns are intentionally coarse enough to tolerate cosmetic changes.
Normal candidate checks use the `symbolize=0` pattern and fast-path depth. Deeper
symbolized equivalence checks use the `symbolize=1` pattern, symbolized depth,
and stored stack-trace pattern. If no `symbolize=1` pattern can be extracted, the
symbolized paths still require exit code `77`, symbolized depth, and the stored
stack-trace pattern when available, but skip the symbolized crash-regex match.

When `--check` is enabled, the tool also performs a second reference capture pass that:

- records the **first entire** stack trace without truncating at the harness frame
- counts its frame lines directly
- stores both the raw full trace and its normalized regex form in `check_reference.json`
- runs tree reduction with a checker whose interestingness rule matches the normal reducer except that candidate execution uses `symbolize=1`

### 4. Validate the extracted crash pattern

`check_reducer_crash_pattern()` calls `tests/crash_tester.py` on the original harness to ensure the extracted `symbolize=0` pattern and recorded fast-path first-stack-trace depth are valid before reduction proceeds.

`check_reducer_symbolized_crash_pattern()` then calls the symbolized
`validate_stack_trace()` path to ensure the `symbolize=1` pattern, when
available, symbolized first-stack-trace depth, and stored pre-harness trace are
valid before reduction continues. If no `symbolize=1` pattern was extracted, it
skips only the symbolized regex match.

### 5. Dynamic slicing (coverage-guided pre-slice)

`apply_coverage_guided_slice()` is an optional pre-reduction step enabled by `slice_enabled=True` / `--slice`.

#### Coverage backend

This step builds a separate coverage binary `poc_cov.out` with:

- `-fsanitize=address,undefined,fuzzer-no-link`
- `-fprofile-instr-generate`
- `-fcoverage-mapping`

A generated `coverage_driver.cpp`:

- calls `LLVMFuzzerTestOneInput()` directly
- installs a sanitizer death callback
- flushes LLVM profile data on sanitizer termination

The run produces:

- `coverage.profraw`
- `coverage.profdata`
- `coverage_show.txt`
- `coverage_export.json`

`collect_harness_coverage()` parses `llvm-cov show` and constructs a `CoverageMap` with:

- `executable_lines`
- `covered_lines`

#### Coverage semantics

The slicer uses **line-based executable coverage**, not old sanitizer point coverage:

- covered executable line → definitely live
- executable but uncovered line → removable candidate
- not reported / non-executable / unknown → keep

This is conservative and helps avoid deleting comments, braces, blank lines, or lines without a reliable executable mapping.

#### Slicing rules implemented in `dynamic_slicer.py`

The current slicer is AST-based and syntax-preserving where possible.

It can remove or rewrite these constructs:

1. **Uncovered helper functions**
   - function definitions outside `LLVMFuzzerTestOneInput`
   - deleted only if the function range has executable lines and none are covered

2. **`if` statements**
   - if the whole `if` statement is uncovered → delete whole statement
   - if the control/header part is uncovered → delete whole statement
   - if only the `else` branch is uncovered → delete only the `else`
   - if only the consequence/body is uncovered but the header is covered → replace body with `{}`

3. **Loops (`while`, `for`, `do`)**
   - if whole loop is uncovered → delete whole loop
   - if the loop header/control is uncovered → delete whole loop
   - if header is covered but body is uncovered → replace body with `{}`

4. **`switch` statements**
   - same policy as loops

5. **Standalone uncovered statements in compound blocks**
   - declarations
   - expression statements
   - some compound statements
   - removed only when their own start line is executable and the node range is fully uncovered

6. **Tail pruning after the last covered child in a block**
   - in each compound statement, uncovered statement-like children after the last covered child are deleted
   - this helps remove clearly dead post-crash/post-return tails

7. **Declaration dependency safety**
   - uncovered declarations are not deleted if a surviving later identifier use still depends on them

#### Validation and fallback

After slicing, the candidate is validated with:

- one `validate_crash_pattern_and_stack_trace()` call, which checks:
  - `symbolize=0` crash pattern and fast first-stack-trace depth
  - symbolized first-stack-trace depth
  - `symbolize=1` crash pattern when one was recorded
  - pre-harness stack trace when a stored `stack_trace.pattern` exists

If compilation, coverage collection, slicing, crash validation, or stack-trace validation fails, the tool discards the sliced version and continues with the original harness.

There is **no retry with a smaller removal set**.

### 6. FDP tagging

`tag_harness_with_fdp_ids()` calls `fdp_transform.inject_ids()` to append stable numeric IDs to supported FDP calls.

These IDs are the bridge between runtime FDP trace records and source callsites.

### 7. Dump-mode execution

`compile_dump_mode_harness()` builds a tagged harness with:

- `-DFDP_MIN_MODE_DUMP`
- `-I<project>/include`
- sanitizers enabled

`dump_fdp_trace()` runs the binary once and writes `fdp_trace.log`.

### 8. Tree reduction

`run_treereducer()` invokes `treereduce-c` and uses `tests/crash_tester.py` as the interestingness oracle.

When `--check` is enabled, `run_treereducer_with_check()` is used instead. It swaps in `tests/check_tester.py`, forces `symbolize=1` for every candidate execution, and records:

- `level_same`: candidate preserved the crash pattern and the first entire stack trace had the same frame count as the original
- `stack_same`: candidate preserved the crash pattern, matched the same frame count, and the pre-harness stack-trace prefix matched the stored `stack_trace.pattern`

At the end of tree reduction, the tool prints `level_same`, `stack_same`, and `stack_same / level_same`.
It also appends each candidate's extracted full first stack trace and pre-harness comparison trace to `check_candidate_stack_traces.log` in the work directory. Each log entry also records whether compilation failed and whether the failure matched an uninitialized-variable diagnostic. For candidates that return `77`, the candidate source text is also embedded in that log for manual inspection.
When `--snapshot` is enabled, `tests/crash_tester.py` and `tests/check_tester.py` also maintain a stable `last_interesting.cpp` snapshot by overwriting it only when a candidate returns `77` and its contents differ from the previous snapshot.

### 8.1 Inline fallback strategy

`inline_literals_in_reduced_harness()` still tries `reduced_harness.cpp` first:

1. inline/replay FDP calls into `reduced_harness.inline.cpp`
2. validate that inline result with `validate_crash_pattern_and_stack_trace()`

If `--snapshot` is enabled and `last_interesting.cpp` exists with different contents, the same inline/replay + validation flow is retried from the snapshot:

3. inline/replay FDP calls into `last_interesting.inline.cpp`
4. validate that inline result with `validate_crash_pattern_and_stack_trace()`

If the snapshot inline result also fails, the tool falls back to the snapshot base harness; otherwise it returns the validated snapshot inline harness. Without `--snapshot`, the tool skips this retry path and falls back directly to the tree-reduced harness.

Important options:

- `--fast` by default
- `--stable --min-reduction 1` when stable mode is requested
- `--fdp-trace <trace>` always passed during tree reduction so replay mode is active
- optional return-code statistics wired through `--statistics`

Phase 3 reduction-loop modes currently are:

- `direct` / `single-step`: one-step compile+link
- `split`: compile the full source to an object, then link (default)
- `pch`: compile the include-stripped body against a precompiled header, then link

With `--amortize-link`, split and PCH candidates are compiled as PIC
shared-object plugins without the stable target link flags. A persistent
ASan/UBSan runner loads target `.so` files, links needed static archive members,
and reads the crash input once, then forks a child to `dlopen` and execute each
candidate. Static archive members are selected from unresolved symbols in a
candidate-shaped object, with whole-archive retained only as a compatibility
fallback when no roots can be inferred. Normal and check-mode stack references
are recalibrated through this backend before `treereduce-c` starts.
Direct/single-step mode is incompatible with amortized linking.

All Phase 3 modes now add `-Werror=uninitialized` and use `-O0` while keeping their mode-specific debug flags:

- direct / single-step: `-gline-tables-only -O0 -Werror=uninitialized`
- split: `-O0 -gline-tables-only -Werror=uninitialized`
- pch: `-O0 -gline-tables-only -Werror=uninitialized`

When `phase3_mode="pch"`, the PCH path is used only for the main tree-reduction candidate-testing loop. One-off validations before and after reduction use direct compilation.

### 9. Formatting

`format_reduced_harness()` runs `clang-format -i --style=LLVM`.

### 10. FDP literal inlining

`inline_literals_in_reduced_harness()`:

- loads `fdp_trace.log`
- replaces FDP calls with concrete literals where possible
- writes `<reduced>.inline.cpp`
- optionally emits `harness_values.h` for large buffers
- validates the inlined result with `validate_stack_trace()`

If validation fails, it falls back to the tree-reduced harness.

### 11. Optional LLM cleanup

If `use_llm=True`, `apply_llm_reduction()` performs a final semantic cleanup and validates the result. On failure, it falls back to the non-LLM harness.

---

## Crash Equivalence Model

HarnessReducer currently uses a layered notion of “same crash”:

1. sanitizer exit code must be `77`
2. crash output must match the extracted crash regex
3. the first stack trace must have the same frame depth as the original run
4. when a symbolized validation path is used, the pre-harness stack trace must also match `stack_trace.pattern`

The crash regex catches the same broad bug type. The stack-depth check adds a cheap structural guard for every candidate. The symbolized stack-trace check catches deeper drift in crash location or call path.

### Pattern extraction priority

`extract_crash_pattern_from_output()` checks, in order:

1. abort/assert location
2. ASan summary
3. ASan error line
4. leak summary
5. runtime error line
6. UBSan summary
7. Abseil `Check failed:`
8. libFuzzer signal summary

All signatures go through `normalize_crash_signature()`, which replaces raw addresses with `0x[0-9a-fA-F]+`.

---

## `crash_tester.py`

This script is the reduction oracle.

### Compile modes

It supports three candidate-test backends:

- **Direct / single-step mode**: one-step compile+link
- **Split mode**: compile full source to an object, then link
- **PCH mode**: compile candidate body with `-include-pch`, then link

PCH mode is prepared by `prepare_phase3_pch_harness()` and restored afterward by `restore_pch_includes()`.

### Fast vs symbolized checks

Most candidate checks use `symbolize=0` for speed and compare against the stored fast-path crash pattern and reference depth from the original unsymbolized run.

Explicit deeper validation paths first check the `symbolize=0` crash pattern
under fast sanitizer output, then force `symbolize=1` to compare against the
symbolized reference depth and pre-harness stack trace. The `symbolize=1` crash
pattern is also checked when it was recorded.

### 9. Optional tree-reduction statistics

If `statistics=True`, `run_treereducer()` passes a `--statistics-file` argument to `tests/crash_tester.py`.

During the `treereduce-c` run, `crash_tester.py` records the logical result of each candidate check:

- `77` — candidate preserved the crash pattern and first-stack-trace depth
- `1` — candidate compiled but did not preserve the crash pattern
- `-1` — candidate failed to compile or link

The aggregated counts and probabilities are written to `statistics.txt` in the work directory.

---

## FDP Transformation Summary

`fdp_transform.py` provides three core capabilities:

1. `inject_ids()`
   - adds stable numeric IDs to supported FDP calls
2. `inline_source_with_report()`
   - replaces FDP calls with literals or generated arrays based on the dumped trace
3. `strip_injected_ids()`
   - removes internal instrumentation IDs before final output

Supported behaviors include:

- scalar literal replacement
- string literal replacement
- byte buffer replacement
- generated header-backed values for large buffers
- repeated-call replay handling for some loop-carried traces

---

## Public Interfaces

### CLI (`cli.py`)

Main flags:

- positional `harness`
- `-o/--output`
- `--compile-flags`
- `--link-flags`
- `--crash-input`
- `--work-dir`
- `--stable`
- `--statistics`
- `--snapshot`
- `--direct` / `--single-step`
- `--split`
- `--pch`
- `--llm`

### Python API

Exported from `harnessreducer.__init__`:

- `ReductionConfig`
- `ReductionResult`
- `reduce_with_config()`
- `process()`

Important config fields:

- `harness_path`
- `compile_flags`
- `link_flags`
- `crash_input`
- `work_dir`
- `start_id`
- `marker`
- `use_llm`
- `stable`
- `phase3_mode`

---

## Important Generated Artifacts

Typical work-dir files include:

- `poc.out`
- `poc_cov.out`
- `coverage_driver.cpp`
- `coverage.profraw`
- `coverage.profdata`
- `coverage_show.txt`
- `coverage_export.json`
- `crash_pattern.symbolize0`
- `crash_pattern.symbolize1`
- `stack_trace.pattern`
- `fdp_trace.log`
- `reduced_harness.cpp`
- `*.inline.cpp`
- `harness_values.h` (optional)
- `harness_prefix.h`, `harness_prefix.pch`, `*.harness_body.cpp` in PCH mode

---

## Design Notes

- Dynamic slicing is deliberately conservative and syntax-aware.
- Unknown coverage is treated as keep, not delete.
- Crash-pattern matching alone is not considered strong enough; first-stack-trace depth is enforced on every candidate, and symbolized stack-trace checking on deeper validation paths adds a stronger guard.
- FDP replay is essential during tree reduction; otherwise reduced harnesses would often consume different bytes and diverge.
- The tool prefers validated fallback over aggressive transformation.

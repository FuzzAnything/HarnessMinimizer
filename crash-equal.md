# Crash Equivalence in HarnessReducer

This document describes how HarnessReducer decides that a transformed harness still preserves the **same crash** as the original.

The current design combines:

1. crash-pattern extraction
2. reference stack-trace extraction
3. optional full-stack check-mode reference recording
4. conservative dynamic slicing with source-based coverage
5. fast crash-pattern checks during reduction
6. optional periodic deep stack-trace checks
7. FDP trace replay so remaining FDP calls observe the original values

---

## 1. Phase 1: Extract the Reference Crash

Before any reduction, HarnessReducer compiles the original harness with sanitizers and runs it once.

### 1.1 Original compile

`check_harness_compilation()` builds `poc.out` with:

```bash
clang++ -fsanitize=address,fuzzer,undefined -g -O0 \
  <compile_flags> <harness.cpp> -o poc.out <link_flags>
```

### 1.2 Original run

`extract_crash_pattern_from_output()` executes `poc.out` with symbolization enabled:

| Variable | Value |
|---|---|
| `ASAN_OPTIONS` | `exitcode=77:symbolize=1:handle_abort=1` |
| `UBSAN_OPTIONS` | `exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=1` |

The harness is expected to exit with code `77`.

### 1.3 Crash pattern extraction

A regex-based signature is extracted in this priority order:

1. abort/assert location
2. ASan summary
3. ASan error line
4. ASan leak summary
5. runtime error line
6. UBSan summary
7. Abseil `Check failed:` condition
8. libFuzzer signal summary

More explicitly, the current extraction order in `extract_crash_pattern_from_output()` is:

| Priority | Pattern name | Regex / source | Returned value |
|---|---|---|---|
| 1 | Abort/assert location | `ABORT_ASSERT_LOCATION_PATTERN` | `file:line` portion of the assertion failure |
| 2 | ASan summary | `ASAN_SUMMARY_PATTERN` | full matched summary line |
| 3 | ASan error | `ASAN_ERROR_PATTERN` | full matched error line |
| 4 | Leak summary | `LEAK_PATTERN` | full matched leak summary |
| 5 | Runtime error | `RUNTIME_ERROR_PATTERN` | full matched runtime-error line |
| 6 | UBSan summary | `UBSAN_PATTERN` | full matched UBSan summary |
| 7 | Abseil CHECK | `ABSL_CHECK_PATTERN` | extracted failed condition text |
| 8 | libFuzzer signal | `LIBFUZZER_SIGNAL_PATTERN` | extracted signal description |

The function returns the **first successful match only**.

All extracted signatures pass through `normalize_crash_signature()`:

- strips surrounding whitespace
- replaces raw addresses like `0x1234abcd` with `0x[0-9a-fA-F]+`
- when `escape=True`, also `re.escape()`s the rest of the text

This makes the pattern stable across runs even if raw addresses move.

### 1.4 Reference stack trace extraction

The same Phase 1 run also records a stack-trace reference.

`extract_stack_trace()`:

- scans symbolized frames matching `#N 0xADDR in ...`
- keeps only the **first** stack trace
- truncates it **before the first harness frame** when the harness path is known
- otherwise falls back to truncating before `LLVMFuzzerTestOneInput`

The captured raw trace is normalized with:

```python
normalize_crash_signature(raw_trace, escape=True)
```

and saved to:

- `stack_trace.pattern`

This stored value is a regex pattern, not a raw stack dump.

When `--check` is enabled, HarnessReducer also records a second reference for measurement purposes:

- the **first entire** stack trace, without truncation at the harness frame
- the direct count of frame lines in that first trace
- a normalized regex form of that full trace

These are written to `check_reference.json`.

### 1.5 Immediate validation

`check_reducer_crash_pattern()` runs `tests/crash_tester.py` on the original harness to make sure the extracted crash pattern actually matches before reduction continues.

---

## 2. Dynamic Slicing Before Tree Reduction

When `--slice` is enabled, HarnessReducer performs a conservative **dynamic slicing** step before FDP tagging and tree reduction.

### 2.1 Coverage build

A separate helper binary `poc_cov.out` is compiled by `compile_coverage_harness()` using:

```bash
clang++ -fsanitize=address,undefined,fuzzer-no-link \
  -fprofile-instr-generate -fcoverage-mapping \
  -g -O0 <compile_flags> <harness.cpp> coverage_driver.cpp \
  -o poc_cov.out <link_flags>
```

The generated `coverage_driver.cpp`:

- calls `LLVMFuzzerTestOneInput()` directly
- installs a sanitizer death callback
- flushes the LLVM profile on sanitizer death and normal return

This is important because many interesting runs terminate via ASan/UBSan.

### 2.2 Coverage collection

`collect_harness_coverage()` runs `poc_cov.out` with:

- `LLVM_PROFILE_FILE=<workdir>/coverage.profraw`
- fast sanitizer settings (`symbolize=0`)

Then it:

1. merges the raw profile into `coverage.profdata` with `llvm-profdata`
2. generates `coverage_show.txt` with `llvm-cov show`
3. generates `coverage_export.json` with `llvm-cov export`
4. parses `coverage_show.txt`

The parsed coverage model is line-based:

- `executable_lines`
- `covered_lines`

### 2.3 Coverage semantics

Dynamic slicing uses the following conservative rule set:

- **covered executable line** → keep
- **executable but uncovered line** → removable candidate
- **not reported / non-executable / unknown** → keep

That last case is important. Even source-based coverage does not give meaningful “covered vs uncovered” answers for every physical line. Comments, blank lines, braces, and some non-mapped lines are therefore treated as **keep**.

### 2.4 Slicing rules

`dynamic_slicer.py` performs syntax-aware AST edits.

Currently implemented rules:

1. **Delete uncovered helper functions**
   - only functions outside `LLVMFuzzerTestOneInput`
   - only when the function range has executable lines and none are covered

2. **`if` statements**
   - delete the entire `if` if the whole statement is uncovered
   - delete the entire `if` if the control/header itself is uncovered
   - delete only the uncovered `else` branch
   - replace an uncovered consequence/body with `{}` when the header is still covered

3. **Loops (`while`, `for`, `do`)**
   - delete the whole loop if the entire loop or its header is uncovered
   - replace the body with `{}` if the header is covered but the body is uncovered

4. **`switch` statements**
   - same policy as loops

5. **Standalone uncovered statements in blocks**
   - declarations
   - expression statements
   - some compound statements
   - removed only when their own start line is executable and the full node range is uncovered

6. **Tail pruning**
   - uncovered statement-like children after the last covered child inside a compound block are deleted

7. **Declaration dependency safety**
   - uncovered declarations are preserved if a surviving later identifier use would otherwise become invalid

### 2.5 Validation and fallback

A sliced harness candidate is accepted only if both checks pass:

1. `check_reducer_crash_pattern()`
2. `validate_stack_trace()`

If slicing fails at any point, the tool falls back to the original harness and continues.

There is currently **no retry with a smaller removal set**.

---

## 3. `crash_tester.py`: the Equivalence Oracle

`tests/crash_tester.py` is used by:

- `treereduce-c`
- inline validation
- final explicit stack-trace validation
- some helper scripts

In the normal pipeline, non-default Phase 3 modes are reserved for the main `treereduce-c` candidate-testing loop. One-off validation checks around that loop use direct compilation.

It returns:

- `77` → interesting / crash preserved
- `1` → not interesting
- `-1` → compile or link failure

When optional statistics collection is enabled (and `--iteration` is not set), these logical return values are also counted and summarized in `statistics.txt` in the work directory.

### 3.1 Candidate compilation modes

#### Direct / single-step mode

```bash
clang++ [replay flags] -fsanitize=address,fuzzer,undefined -g -O0 \
  <compile_flags> <source.cpp> -o <output> <link_flags>
```

#### Split mode

Compile object:

```bash
clang++ -Qunused-arguments [replay flags] \
  -fsanitize=address,fuzzer,undefined -O0 -gline-tables-only \
  -c <compile_flags> <source.cpp> -o <object.o>
```

Then link:

```bash
clang++ -Qunused-arguments -fsanitize=address,fuzzer,undefined \
  <object.o> -o <output> <link_flags>
```

#### PCH mode

Compile object:

```bash
clang++ -Qunused-arguments -include-pch <pch> [replay flags] \
  -fsanitize=address,fuzzer,undefined -O0 -gline-tables-only \
  -c <compile_flags> <source.cpp> -o <object.o>
```

Then link:

```bash
clang++ -Qunused-arguments -fsanitize=address,fuzzer,undefined \
  <object.o> -o <output> <link_flags>
```

Replay flags are added when `--fdp-trace` is present:

```bash
-I<project>/include -DFDP_MIN_MODE_REPLAY
```

### 3.2 Fast crash check

The normal fast path uses `symbolize=0`:

| Variable | Value |
|---|---|
| `ASAN_OPTIONS` | `exitcode=77:symbolize=0:handle_abort=1` |
| `UBSAN_OPTIONS` | `exitcode=77:symbolize=0:halt_on_error=1:print_stacktrace=1` |

A candidate is considered crash-equivalent in the fast path only if:

1. exit code is `77`
2. `re.search(crash_pattern, run_log)` succeeds

### 3.3 Symbolized deep check

When `--symbolize` is forced, or a periodic checkpoint fires, `crash_tester.py` reruns the candidate with `symbolize=1`.

Then `_check_stack_trace()`:

1. extracts the first stack trace from the symbolized output
2. uses the candidate source path to truncate before the harness frame when possible
3. checks `re.search(stored_pattern, run_log)`

If the stored stack-trace regex matches the new run log, the stack trace is treated as preserved.

### 3.4 `--check`: full-stack insight mode

When `--check` is enabled, HarnessReducer uses `tests/check_tester.py` instead of `tests/crash_tester.py` for the main tree-reduction loop.

Differences from the normal oracle:

- every candidate is executed with `symbolize=1`
- the interestingness condition still remains **crash-pattern preservation**
- after a candidate preserves the crash pattern, the checker inspects the candidate's **first entire** stack trace
- if the frame count matches the stored count, it increments `level_same`
- if the frame count matches and the candidate's **pre-harness** stack-trace prefix matches the stored `stack_trace.pattern`, it increments `stack_same`

At the end of reduction, HarnessReducer reports:

- `level_same`
- `stack_same`
- `stack_same / level_same`

It also writes each candidate's extracted full first stack trace and pre-harness comparison trace to `check_candidate_stack_traces.log` in the work directory for manual review.

### 3.5 Optional return-code statistics

If HarnessReducer enables `--statistics-file` for `crash_tester.py`, each candidate check also updates a shared `statistics.txt` file with:

- count of logical `77` results
- count of logical `1` results
- count of logical `-1` results
- probability of each outcome over the total number of recorded candidate checks

This mode is only used when `--iteration` is **not** set.

---

## 4. Periodic Stack-Trace Validation During Tree Reduction

`--iteration N` enables periodic symbolized stack checks during tree reduction.

### 4.1 Stored state

The mechanism uses files in the work directory:

- `stack_trace.pattern`
- `stack_trace.counter`
- `stack_trace.backup.cpp`

### 4.2 How the periodic check works

When all of these are present:

- `--iteration`
- `--counter-file`
- `--stack-trace-file`

`crash_tester.py`:

1. reads and increments the counter
2. computes an effective interval based on current source line count
3. every `effective_interval` invocations, switches to `symbolize=1`
4. validates the stack trace against `stack_trace.pattern`
5. if it matches, copies the candidate source to `stack_trace.backup.cpp`
6. if it does not match, returns `1` so `treereduce-c` rejects the candidate

### 4.3 Adaptive interval thresholds

These values are currently hardcoded in `tests/crash_tester.py`:

| Constant | Default |
|---|---:|
| `SMALL_HARNESS_LINE_THRESHOLD` | 75 |
| `TINY_HARNESS_LINE_THRESHOLD` | 50 |
| `SMALL_HARNESS_ITERATION` | 10 |
| `TINY_HARNESS_ITERATION` | 1 |

Meaning:

- line count `>= 75` → use the user-provided base iteration
- line count `< 75` and `>= 50` → use `10`
- line count `< 50` → use `1`

### 4.4 When `--iteration` is omitted

If the user does **not** pass `--iteration`:

- Phase 1 still records `stack_trace.pattern`
- tree reduction uses only the fast `symbolize=0` checks
- no periodic stack checks are performed
- no counter/backup mechanism is used

### 4.5 Final rollback after tree reduction

After `treereduce-c` finishes, `api.py` performs one final explicit stack-trace validation if `iteration` was enabled.

If the final reduced harness fails that validation:

- and `stack_trace.backup.cpp` exists → restore the backup
- otherwise → keep the current reduced harness with a warning

So the intended guarantee is:

- periodic checkpoints reject candidates with the wrong stack trace
- the final output is rolled back to the last stack-trace-verified backup when needed

---

## 5. FDP Trace Replay and Why It Matters

Crash equivalence would be unreliable if reduced harnesses consumed different FDP values.

### 5.1 Dump mode

Before tree reduction, the tagged harness is compiled in dump mode:

- `-DFDP_MIN_MODE_DUMP`

The runtime writes `fdp_trace.log`, keyed by injected FDP IDs.

### 5.2 Replay mode

During crash testing, candidates are compiled in replay mode:

- `-DFDP_MIN_MODE_REPLAY`

Remaining FDP calls read from the dumped trace instead of consuming bytes from the current reduced control flow.

This keeps the tested candidate aligned with the original crashing execution much more often.

### 5.3 Inlining phase

After tree reduction, `inline_literals_in_reduced_harness()` replaces many FDP calls with literals. Validation still passes `--fdp-trace`, because some callsites may remain un-inlined and still need replay.

---

## 6. Where Crash Equivalence Is Enforced

Crash equivalence is checked at multiple points:

| Stage | Check |
|---|---|
| Initial validation | crash pattern must match original harness |
| Dynamic slicing acceptance | crash pattern + stack trace |
| Tree reduction normal candidates | crash pattern |
| Tree reduction periodic checkpoints | crash pattern + stack trace |
| Post-tree final checkpoint | stack trace |
| FDP inline acceptance | crash pattern, plus periodic stack checks when enabled |
| LLM acceptance | crash pattern, plus the normal validation path used there |

---

## 7. Summary

The current notion of “same crash” in HarnessReducer is:

1. the transformed harness still crashes under sanitizers (`exit code 77`)
2. the runtime output still matches the extracted crash regex
3. when stack-trace validation is enabled, the first symbolized stack trace still matches the normalized reference trace

This is supported by:

- address normalization
- source-based dynamic slicing with conservative keep rules
- periodic deep validation during tree reduction
- backup and rollback
- FDP trace replay for deterministic candidate execution

The overall philosophy is conservative: when a transform cannot be validated, HarnessReducer keeps the last known-good result rather than trying to force a more aggressive reduction.

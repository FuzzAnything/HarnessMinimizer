# Crash Equivalence in HarnessReducer

This document describes in detail how HarnessReducer determines that a reduced harness preserves the **same crash** as the original. The mechanism has three layers: extracting a crash signature, compiling and running the candidate, and matching the output against the signature.

---

## 1. Crash Pattern Extraction (Phase 1)

Before any reduction begins, the original harness is compiled and executed once to extract a **crash pattern** — a short regex-compatible string that uniquely identifies the crash type.

### 1.1 Initial Compilation

`check_harness_compilation()` in `reducer_runner.py` compiles the original harness:

```
clang++ -fsanitize=address,fuzzer,undefined -g -O0 \
  <compile_flags> <harness.cpp> -o poc.out <link_flags>
```

This produces `poc.out` in the working directory.

### 1.2 Running and Capturing Output

`extract_crash_pattern_from_output()` executes `poc.out` (optionally with `crash_input`) under these environment variables:

| Variable | Value | Purpose |
|---|---|---|
| `ASAN_OPTIONS` | `exitcode=77:symbolize=0` | ASan exits with code 77; disables symbolization for speed |
| `UBSAN_OPTIONS` | `exitcode=77:halt_on_error=1:symbolize=0` | Same for UBSan; halts on first error |

The combined stdout + stderr becomes the raw crash output. The exit code **must be 77** (otherwise the harness is considered non-crashing and reduction aborts).

### 1.3 Pattern Selection (Priority Order)

The function applies regex patterns in strict priority order and returns the **first match**. All extracted signatures are passed through `normalize_crash_signature()` which replaces non-deterministic memory addresses (`0x...`) with the regex `0x[0-9a-fA-F]+`, ensuring the pattern matches across runs even when addresses change.

| Priority | Pattern Name | Regex | Extracted Value | Example Output |
|---|---|---|---|---|
| 1 | Assert/Abort | `((?:/[^\s:]+)+:\d+:.*Assertion .* failed\.)` | `file:line` portion of the match (split on `:` and taking the first two fields), normalized | `/root/src/lib.c:358` |
| 2 | ASan Summary | `SUMMARY:\s*AddressSanitizer:\s*([\w-]+)` | Full SUMMARY match (group 0), normalized | `SUMMARY: AddressSanitizer: heap-buffer-overflow` |
| 3 | ASan Error | `ERROR:\s*AddressSanitizer:\s*[\w-]+` | Full ERROR match (group 0), normalized | `ERROR: AddressSanitizer: heap-buffer-overflow` |
| 4 | Leak Summary | `SUMMARY: AddressSanitizer: \d+ byte\(s\) leaked in \d+ allocation\(s\)\.` | Full leak summary match (group 0), normalized | `SUMMARY: AddressSanitizer: 42 byte(s) leaked in 3 allocation(s).` |
| 5 | Runtime Error | `(?:/[^\s:]+)+:\d+:\d+:\s*runtime error:.*` | Full runtime error match (group 0), normalized with `escape=True` | `/src/foo.c:42:5: runtime error: ...` |
| 6 | UBSan Summary | `SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior\s+(\S+:\d+:\d+)` | Full SUMMARY match (group 0), normalized | `SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/foo.c:42:5` |
| 7 | Abseil CHECK | `Check failed:\s*(.+?)\s*\(` | Condition text (group 1), normalized | `last_returned_size_ > 0` |
| 8 | libFuzzer Signal | `SUMMARY:\s*libFuzzer:\s*([\w][\w\s-]*)` | Signal description (group 1), normalized | `deadly signal` |

If none match, a `ValueError` is raised — the crash is considered unrecognizable.

**Key design choice**: The pattern is intentionally **coarse** (e.g., the full SUMMARY line rather than the full stack trace), and non-deterministic memory addresses are replaced with a regex wildcard. This ensures that cosmetic changes during reduction (like variable renaming, statement reordering, or address shifts) will not break the equivalence check, while still ensuring the same *type* of bug is triggered.

The `normalize_crash_signature(signature, escape=False)` function handles address normalization: it strips the signature, replaces all `0x[hex]` occurrences with `0x[0-9a-fA-F]+`. When `escape=True` (used for the Runtime Error pattern), it also `re.escape()`s the rest of the signature before substituting the address pattern back, since the runtime error text may contain regex-special characters like colons.

### 1.4 Pattern Validation

`check_reducer_crash_pattern()` immediately validates the extracted pattern by running `crash_tester.py` against the **original** (unmodified) harness. If the pattern doesn't match even on the original, the tool aborts with an error — this prevents proceeding with a bad pattern.

---

## 2. Crash Tester (`crash_tester.py`) — The Equivalence Oracle

`crash_tester.py` is the **interestingness test** that decides whether a candidate reduced program still exhibits the same crash. It is invoked by `treereduce-c` for every candidate reduction, and also by the pipeline for inline validation and LLM validation.

### 2.1 Interface

```
crash_tester.py <source.cpp> <crash_pattern> \
  [--crash-input <path>] \
  [--compile-flags <flags>] [--link-flags <flags>] \
  [--fdp-trace <trace_path>] \
  (--direct | --pch [--pch-path <path>])
```

- `source.cpp` — The candidate harness to test.
- `crash_pattern` — The regex extracted in Phase 1.
- `--crash-input` — The PoC input file (if any).
- `--fdp-trace` — The FDP trace log for replay-mode execution.
- `--direct` / `--pch` — Two compilation modes (see §2.2).

### 2.2 Compilation Modes

#### Direct Mode (`--direct`)

Single-step compile+link:

```
clang++ [replay flags] -fsanitize=address,fuzzer,undefined -g -O0 \
  <compile_flags> <source.cpp> -o <output> <link_flags>
```

Replay flags are added when `--fdp-trace` is provided:
```
-I<fdp_header_dir> -DFDP_MIN_MODE_REPLAY
```

#### PCH Mode (`--pch --pch-path <pch>`)

Two-step compile then link:

**Step 1 — Compile to object:**
```
clang++ -Qunused-arguments -include-pch <pch> [replay flags] \
  -fsanitize=address,fuzzer,undefined -O1 -gline-tables-only \
  -c <compile_flags> <source.cpp> -o <object.o>
```

**Step 2 — Link:**
```
clang++ -Qunused-arguments -fsanitize=address,fuzzer,undefined \
  <object.o> -o <output> <link_flags>
```

PCH mode is faster for repeated testing because the expensive include parsing is done once upfront (precompiled header `fahm_prefix.pch`).

If compilation or linking fails, `crash_tester.py` returns `-1` (not interesting).

### 2.3 Execution

The compiled binary is executed with:

```python
exec_cmd = [output_path, crash_input]  # or [output_path] if no crash_input
```

Environment variables set:

| Variable | Value |
|---|---|
| `ASAN_OPTIONS` | `exitcode=77:symbolize=0` |
| `UBSAN_OPTIONS` | `exitcode=77:symbolize=0:halt_on_error=1` |
| `FDP_TRACE_PATH` | `<fdp_trace>` (only when `--fdp-trace` is provided) |

### 2.4 Crash Equivalence Decision

The decision logic is the core of crash equivalence:

```python
status = run_proc.returncode
run_log = run_proc.stdout + run_proc.stderr

if status == 77 and re.search(crash_pattern, run_log) is not None:
    # Crash preserved!
    return 77
else:
    # Crash NOT preserved
    return 1
```

**Two conditions must both hold:**

1. **Exit code is 77** — The sanitizer (ASan or UBSan) detected a bug and used the custom exit code. This ensures a sanitizer error actually fired (not a normal exit or unrelated signal).
2. **The crash pattern regex matches** the combined stdout+stderr — This ensures the crash is the *same type* as the original (e.g., same ASan bug type, same assert location, same UBSan source location).

If either condition fails, the candidate is rejected (return code 1, meaning "not interesting" to `treereduce-c`).

---

## 3. FDP Trace Replay — Ensuring Deterministic Behavior

A critical challenge in crash equivalence is that FDP calls consume bytes from the fuzz input sequentially. After AST reduction removes some statements, the remaining FDP calls may consume different bytes and produce different values, causing a different execution path (and potentially a different or no crash).

### 3.1 FDP Trace Dump

Before reduction, the tagged harness is compiled with `-DFDP_MIN_MODE_DUMP` and executed. In dump mode, every FDP method call writes its result to a trace file (`fdp_trace.log`) keyed by the injected `FDP_ID`:

- **Scalar values** (`S`): `S <fdp_id> <value>` — for `ConsumeIntegral`, `ConsumeBool`, `ConsumeFloatingPoint`, `ConsumeProbability`, `ConsumeEnum`, etc.
- **Remaining bytes** (`R`): `R <fdp_id> <count>` — for `remaining_bytes()`.
- **Byte sequences** (`B`): `B <fdp_id> <size> <byte0> <byte1> ...` — for `ConsumeBytes`, `ConsumeBytesAsString`, `ConsumeRandomLengthString`, etc.

### 3.2 FDP Trace Replay

During crash testing (when `--fdp-trace` is provided), the candidate is compiled with `-DFDP_MIN_MODE_REPLAY`. In replay mode:

- The `FuzzedDataProvider` constructor reads the trace file into in-memory maps (`scalar_streams_`, `remaining_streams_`, `bytes_streams_`) keyed by FDP ID.
- Each FDP method call checks the mode:
  - **Replay**: Returns the pre-recorded value from the trace (using the injected `FDP_ID` to look it up) instead of consuming from the fuzz input.
  - **Native**: Consumes from fuzz input normally (used when no trace is provided).

This ensures that even after statements are removed, the remaining FDP calls still return the **exact same values** they did in the original execution, preserving the crash-triggering execution path.

### 3.3 Trace in treereduce-c Invocations

When `treereduce-c` calls `crash_tester.py`, it passes `--fdp-trace <fdp_trace_file>`. This enables replay mode so that every candidate tested during AST reduction gets the same FDP values as the original harness.

### 3.4 Inline Validation and FDP Trace

After FDP literal inlining (which replaces FDP calls with their recorded constant values directly in source), the `--fdp-trace` flag is still passed during validation. This is because the inlining may not replace *all* FDP callsites (e.g., calls in loops or with dynamic indices may remain as FDP calls), so remaining calls still need the replay trace to return deterministic values.

---

## 4. When Crash Equivalence Is Checked in the Pipeline

Crash equivalence is verified at **four** points in the reduction pipeline:

| Step | Function | Context | Uses FDP Trace? |
|---|---|---|---|
| Pattern validation | `check_reducer_crash_pattern()` | After extraction, confirms pattern works on original harness | No |
| Tree reduction | `crash_tester.py` (via `treereduce-c`) | Every candidate during AST reduction | Yes |
| Inline validation | `inline_literals_in_reduced_harness()` | After FDP literal inlining | Yes |
| LLM validation | `apply_llm_reduction()` | After LLM semantic reduction | No |

### Fallback Behavior

If a later step fails crash equivalence:
- **Inline validation fails** → Falls back to the tree-reduced harness (without FDP inlining). The tree-reduced harness is already validated, so the fallback is safe. A `.validation.log` artifact is written with the returncode, stdout, and stderr.
- **LLM validation fails** → Falls back to the pre-LLM (inline-reduced or tree-reduced) harness.

---

## 5. Summary

Crash equivalence in HarnessReducer works through a **two-part check** applied consistently across the pipeline:

1. **Exit code 77**: The sanitizer must report an error (ASan/UBSan custom exit code).
2. **Pattern match**: The runtime output must contain the same crash signature (bug type, source location, or assertion) as the original.

This is made reliable by:
- **Deterministic FDP replay** ensuring consistent FDP return values across reductions.
- **Coarse-grained patterns** that tolerate cosmetic changes while catching different bug types.
- **Memory address normalization** via `normalize_crash_signature()` that scrubs non-deterministic `0x...` addresses from signatures, replacing them with a regex wildcard so the pattern matches even when addresses shift across runs.
- **Fallback mechanisms** that revert to the last known-good version when a reduction step breaks crash preservation.

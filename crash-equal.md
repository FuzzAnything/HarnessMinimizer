# Crash Equivalence in HarnessReducer

This document describes in detail how HarnessReducer determines that a reduced harness preserves the **same crash** as the original. The mechanism has multiple layers: extracting a crash signature, capturing a reference stack trace, compiling and running the candidate, matching the output against the signature, and periodically validating the full stack trace.

---

## 1. Crash Pattern Extraction (Phase 1)

Before any reduction begins, the original harness is compiled and executed once to extract a **crash pattern** — a short regex-compatible string that uniquely identifies the crash type — and a **reference stack trace** for periodic deep validation.

### 1.1 Initial Compilation

`check_harness_compilation()` in `reducer_runner.py` compiles the original harness:

```
clang++ -fsanitize=address,fuzzer,undefined -g -O0 \
  <compile_flags> <harness.cpp> -o poc.out <link_flags>
```

This produces `poc.out` in the working directory.

### 1.2 Running and Capturing Output

`extract_crash_pattern_from_output()` executes `poc.out` (optionally with `crash_input`) with **symbolization enabled** so the full stack trace is available:

| Variable | Value | Purpose |
|---|---|---|
| `ASAN_OPTIONS` | `exitcode=77:symbolize=1:handle_abort=1` | ASan exits with code 77; **enables symbolization** for stack trace capture |
| `UBSAN_OPTIONS` | `exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=1` | Same for UBSan; **enables symbolization** |

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

The `normalize_crash_signature(signature, escape=False)` function handles address normalization: it strips the signature, replaces all `0x[hex]` occurrences with `0x[0-9a-fA-F]+`. When `escape=True` (used for the Runtime Error pattern and stack trace patterns), it also `re.escape()`s the rest of the signature before substituting the address pattern back, since the text may contain regex-special characters like colons.

### 1.4 Stack Trace Capture

Because Phase 1 runs with `symbolize=1`, the output contains symbolized stack traces. `extract_stack_trace()` extracts the **first** stack trace from the output:

1. Scans lines matching `STACK_FRAME_PATTERN` (`#N 0xADDR in ...`).
2. Collects frames until it reaches a frame containing `LLVMFuzzerTestOneInput` — that frame and all subsequent frames belong to the fuzzer infrastructure and are excluded.
3. Only the **first** stack trace is kept. ASan may emit multiple (e.g., one for the overflow, one for the allocation site); subsequent traces are ignored.

Example — the captured frames from the original harness output:

```
    #0 0x5ea4dfe78fe6 in av1_one_pass_cbr_svc_start_layer /root/src/libaom/av1/encoder/svc_layercontext.c:444:18
    #1 0x5ea4dfc2cfe3 in av1_get_compressed_data /root/src/libaom/av1/encoder/encoder.c:5342:5
    #2 0x5ea4dfb42f7f in encoder_encode /root/src/libaom/av1/av1_cx_iface.c:3639:20
    #3 0x5ea4dfb36563 in aom_codec_encode /root/src/libaom/aom/src/aom_encoder.c:191:11
```

Frames `#4` onward (containing `LLVMFuzzerTestOneInput`, `fuzzer::Fuzzer::ExecuteCallback`, etc.) are excluded.

The raw trace text is then normalized via `normalize_crash_signature(escape=True)` — all `0x...` addresses are replaced with the regex `0x[0-9a-fA-F]+` and the remaining text is `re.escape()`d. The resulting regex pattern is saved to `stack_trace.pattern` in the work directory.

This stored pattern enables **periodic deep validation** during reduction: by comparing the full call path (not just the crash type), it catches cases where the crash type is preserved but the actual crash site has drifted due to aggressive reductions.

### 1.5 Pattern Validation

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
  (--direct | --pch [--pch-path <path>]) \
  [--symbolize] \
  [--stack-trace-file <path>] \
  [--iteration <N>] [--counter-file <path>] \
  [--backup-file <path>]
```

- `source.cpp` — The candidate harness to test.
- `crash_pattern` — The regex extracted in Phase 1.
- `--crash-input` — The PoC input file (if any).
- `--fdp-trace` — The FDP trace log for replay-mode execution.
- `--direct` / `--pch` — Two compilation modes (see §2.2).
- `--symbolize` — Force `symbolize=1` for this invocation (used for explicit stack trace validation).
- `--stack-trace-file` — Path to the stored normalized stack trace pattern.
- `--iteration` — Base interval for periodic symbolize=1 checks.
- `--counter-file` — Path to a file tracking the invocation count.
- `--backup-file` — Path to save a backup of the candidate source on successful stack trace validation.

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

Environment variables depend on whether symbolization is enabled for this invocation:

**Default (symbolize=0, fast):**

| Variable | Value |
|---|---|
| `ASAN_OPTIONS` | `exitcode=77:symbolize=0:handle_abort=1` |
| `UBSAN_OPTIONS` | `exitcode=77:symbolize=0:halt_on_error=1:print_stacktrace=1` |
| `FDP_TRACE_PATH` | `<fdp_trace>` (only when `--fdp-trace` is provided) |

**Stack trace check (symbolize=1):**

| Variable | Value |
|---|---|
| `ASAN_OPTIONS` | `exitcode=77:symbolize=1:handle_abort=1` |
| `UBSAN_OPTIONS` | `exitcode=77:symbolize=1:halt_on_error=1:print_stacktrace=1` |
| `FDP_TRACE_PATH` | `<fdp_trace>` (only when `--fdp-trace` is provided) |

### 2.4 Crash Equivalence Decision

The decision logic is the core of crash equivalence:

```python
status = run_proc.returncode
run_log = run_proc.stdout + run_proc.stderr

# Step 1: crash pattern must match
if status != 77 or re.search(crash_pattern, run_log) is None:
    return 1  # NOT interesting

# Step 2 (only when symbolized): stack trace validation
if use_symbolize and stack_trace_file:
    if not _check_stack_trace(run_log, stack_trace_file, source, backup_file):
        return 1  # Stack trace mismatch

return 77  # Crash preserved!
```

**Conditions for crash preservation:**

1. **Exit code is 77** — The sanitizer (ASan or UBSan) detected a bug and used the custom exit code.
2. **The crash pattern regex matches** the combined stdout+stderr — ensures the same crash *type*.
3. **(When symbolized) The stack trace matches** — the first stack trace from the output must match the stored normalized pattern via `re.search()`. This ensures the same crash *location* and *call path*.

If any condition fails, the candidate is rejected (return code 1, meaning "not interesting" to `treereduce-c`).

---

## 3. Periodic Stack Trace Validation

When `--iteration N` is provided to the pipeline, crash_tester.py performs periodic deep validation using symbolized stack traces alongside the fast crash-pattern checks.

### 3.1 Mechanism

Each invocation of `crash_tester.py` (when `--iteration`, `--counter-file`, and `--stack-trace-file` are all provided):

1. Reads and increments the counter file.
2. Computes the **effective iteration** based on the candidate source line count:
   - ≥ 75 lines → use the base `--iteration` value (e.g., 100)
   - < 75 and ≥ 50 lines → use `SMALL_HARNESS_ITERATION` (default 10)
   - < 50 lines → use `TINY_HARNESS_ITERATION` (default 1)
3. If `counter % effective_iteration == 0`, switches to `symbolize=1` for this invocation.
4. Runs the candidate with symbolized output.
5. If the crash pattern matches, also validates the stack trace against the stored pattern.
6. If the stack trace matches, saves a backup of the candidate source to `--backup-file`.
7. If the stack trace does not match, returns exit code 1 (not interesting).

The thresholds and default intervals are defined as constants in both `reducer_runner.py` and `crash_tester.py` (must be kept in sync):

| Constant | Default | Meaning |
|---|---|---|
| `SMALL_HARNESS_LINE_THRESHOLD` | 75 | Below this, interval shrinks |
| `TINY_HARNESS_LINE_THRESHOLD` | 50 | Below this, every candidate is checked |
| `SMALL_HARNESS_ITERATION` | 10 | Interval for small harnesses |
| `TINY_HARNESS_ITERATION` | 1 | Interval for tiny harnesses |

### 3.2 Backup and Rollback

- Each successful symbolize=1 checkpoint saves the current candidate source as `stack_trace.backup.cpp` (overwriting the previous backup).
- When a symbolize=1 check fails, `crash_tester.py` returns "not interesting" → treereduce-c rejects that candidate.
- After treereduce-c completes, `api.py` runs a **final symbolize=1 check** via `validate_stack_trace()`. If it fails, the last backup is restored as the reduced output.
- This guarantees the final output corresponds to a state where the full stack trace was verified to match the original.

### 3.3 When `--iteration` Is Not Provided

When `--iteration` is **not** provided:
- Phase 1 still runs with `symbolize=1` and the stack trace is extracted, normalized, and saved to `stack_trace.pattern`.
- During reduction, `symbolize=0` is used for all candidate checks — no periodic stack trace validation, no backups.
- This keeps the behavior fully backward-compatible; the only overhead is one extra symbolized run at Phase 1.

### 3.4 Explicit Symbolize Check

The `--symbolize` flag forces `symbolize=1` for a single invocation regardless of the counter. This is used by:
- `validate_stack_trace()` in `reducer_runner.py` for the final check after treereduce-c.
- Any external caller that wants to verify the stack trace of a specific candidate.

---

## 4. FDP Trace Replay — Ensuring Deterministic Behavior

A critical challenge in crash equivalence is that FDP calls consume bytes from the fuzz input sequentially. After AST reduction removes some statements, the remaining FDP calls may consume different bytes and produce different values, causing a different execution path (and potentially a different or no crash).

### 4.1 FDP Trace Dump

Before reduction, the tagged harness is compiled with `-DFDP_MIN_MODE_DUMP` and executed. In dump mode, every FDP method call writes its result to a trace file (`fdp_trace.log`) keyed by the injected `FDP_ID`:

- **Scalar values** (`S`): `S <fdp_id> <value>` — for `ConsumeIntegral`, `ConsumeBool`, `ConsumeFloatingPoint`, `ConsumeProbability`, `ConsumeEnum`, etc.
- **Remaining bytes** (`R`): `R <fdp_id> <count>` — for `remaining_bytes()`.
- **Byte sequences** (`B`): `B <fdp_id> <size> <byte0> <byte1> ...` — for `ConsumeBytes`, `ConsumeBytesAsString`, `ConsumeRandomLengthString`, etc.

### 4.2 FDP Trace Replay

During crash testing (when `--fdp-trace` is provided), the candidate is compiled with `-DFDP_MIN_MODE_REPLAY`. In replay mode:

- The `FuzzedDataProvider` constructor reads the trace file into in-memory maps (`scalar_streams_`, `remaining_streams_`, `bytes_streams_`) keyed by FDP ID.
- Each FDP method call checks the mode:
  - **Replay**: Returns the pre-recorded value from the trace (using the injected `FDP_ID` to look it up) instead of consuming from the fuzz input.
  - **Native**: Consumes from fuzz input normally (used when no trace is provided).

This ensures that even after statements are removed, the remaining FDP calls still return the **exact same values** they did in the original execution, preserving the crash-triggering execution path.

### 4.3 Trace in treereduce-c Invocations

When `treereduce-c` calls `crash_tester.py`, it passes `--fdp-trace <fdp_trace_file>`. This enables replay mode so that every candidate tested during AST reduction gets the same FDP values as the original harness.

### 4.4 Inline Validation and FDP Trace

After FDP literal inlining (which replaces FDP calls with their recorded constant values directly in source), the `--fdp-trace` flag is still passed during validation. This is because the inlining may not replace *all* FDP callsites (e.g., calls in loops or with dynamic indices may remain as FDP calls), so remaining calls still need the replay trace to return deterministic values.

---

## 5. When Crash Equivalence Is Checked in the Pipeline

Crash equivalence is verified at **up to six** points in the reduction pipeline:

| Step | Function | Context | Uses FDP Trace? | Stack Trace Check? |
|---|---|---|---|---|
| Pattern validation | `check_reducer_crash_pattern()` | After extraction, confirms pattern works on original harness | No | No |
| Tree reduction (fast) | `crash_tester.py` (via `treereduce-c`) | Most candidates during AST reduction | Yes | No (symbolize=0) |
| Tree reduction (periodic) | `crash_tester.py` (via `treereduce-c`) | Every N-th candidate when `--iteration` is set | Yes | Yes (symbolize=1) |
| Post-reduction validation | `validate_stack_trace()` | After treereduce-c completes (only with `--iteration`) | Yes | Yes (symbolize=1) |
| Inline validation | `inline_literals_in_reduced_harness()` | After FDP literal inlining | Yes | Periodic if `--iteration` |
| LLM validation | `apply_llm_reduction()` | After LLM semantic reduction | No | Periodic if `--iteration` |

### Fallback Behavior

If a later step fails crash equivalence:
- **Periodic stack trace check fails during treereduce-c** → `crash_tester.py` returns "not interesting", treereduce-c rejects the candidate and continues.
- **Final stack trace check fails after treereduce-c** → Restores the last backup from `stack_trace.backup.cpp`.
- **Inline validation fails** → Falls back to the tree-reduced harness (without FDP inlining). The tree-reduced harness is already validated, so the fallback is safe. A `.validation.log` artifact is written with the returncode, stdout, and stderr.
- **LLM validation fails** → Falls back to the pre-LLM (inline-reduced or tree-reduced) harness.

---

## 6. Summary

Crash equivalence in HarnessReducer works through a **multi-layered check** applied consistently across the pipeline:

1. **Exit code 77**: The sanitizer must report an error (ASan/UBSan custom exit code).
2. **Pattern match**: The runtime output must contain the same crash signature (bug type, source location, or assertion) as the original.
3. **Stack trace match** (when `--iteration` is enabled): The first symbolized stack trace must match the stored normalized pattern, ensuring the crash occurs at the same location with the same call path.

This is made reliable by:
- **Deterministic FDP replay** ensuring consistent FDP return values across reductions.
- **Coarse-grained patterns** that tolerate cosmetic changes while catching different bug types.
- **Memory address normalization** via `normalize_crash_signature()` that scrubs non-deterministic `0x...` addresses from signatures, replacing them with a regex wildcard so the pattern matches even when addresses shift across runs.
- **Periodic stack trace validation** with adaptive intervals that check more frequently as the harness shrinks, catching crash-location drift that the coarse pattern alone would miss.
- **Backup and rollback** mechanisms that revert to the last known-good version when a reduction step breaks crash preservation.

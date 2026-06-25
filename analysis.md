# HarnessReducer — Codebase Analysis

## Project Overview

HarnessReducer is a reducer workflow for library fuzzing harnesses. It minimizes harness C/C++ code while preserving an existing crash, with first-class support for FuzzedDataProvider (FDP). The pipeline combines AST-level reduction (treereduce-c), FDP trace-based literal inlining, and optional LLM semantic minimization.

---

## Source File Inventory (src/harnessreducer/)

| File | Lines | Role |
|---|---|---|
| __init__.py | 3 | Re-exports public API symbols |
| __main__.py | 3 | python -m harnessreducer entry point |
| main.py | 6 | Legacy entry point, delegates to cli.main() |
| cli.py | 130 | CLI argument parser and output handling |
| api.py | 343 | Orchestration engine — main pipeline logic |
| fdp_transform.py | 918 | FDP AST transformation (tag, inline, strip) |
| reducer_runner.py | 673 | Build/run/external-tool driver (all clang++ invocations) |
| llm_reducer.py | 172 | Optional LLM-based semantic reducer |

Additional external script:

| File | Role |
|---|---|
| tests/crash_tester.py | Interestingness test invoked by treereduce-c for every candidate reduction |

---

## File Functions in Execution Flow Order

The execution flow follows the reduce_with_config() function in api.py. Below each file is described in the order it is first reached during a run.

### 1. __main__.py — Package Entry Point

Invoked when the user runs python -m harnessreducer. Simply delegates to cli.main().

### 2. cli.py — CLI Argument Parsing and Output

Parses command-line arguments (see CLI Arguments section below), constructs a ReductionConfig, calls reduce_with_config(config), then copies the resulting reduced harness (and any generated header files) to the output path.

### 3. api.py — Orchestration Engine

Defines ReductionConfig and ReductionResult dataclasses, plus the main pipeline function reduce_with_config(). The pipeline steps in order:

1. Configure working directory — configure_work_dir()
2. Check prerequisites — check_tree_reducer(), check_harness_compilation()
3. Extract crash pattern — Run the harness with symbolize=1, parse ASan/UBSan/leak/runtime-error/abort/assert output for a regex pattern; memory addresses are normalized via normalize_crash_signature(). Additionally, the first symbolized stack trace is extracted, truncated at LLVMFuzzerTestOneInput, normalized via normalize_crash_signature(escape=True), and saved to stack_trace.pattern in the work dir
4. Validate crash pattern — check_reducer_crash_pattern() via crash_tester.py using the selected Phase 3 mode (--direct by default, or --pch)
5. Tag FDP callsites — tag_harness_with_fdp_ids() which calls fdp_transform.inject_ids()
6. Compile dump-mode binary — compile_dump_mode_harness()
7. Dump FDP trace — dump_fdp_trace() — runs the tagged binary with FDP_TRACE_PATH env var
8. Tree-reduce — run_treereducer() — invokes treereduce-c which calls crash_tester.py for each candidate. In --pch mode, this first creates fahm_prefix.h/fahm_prefix.pch, strips include lines from the candidate body during reduction, and restores the moved includes to the reduced output.
9. Format — format_reduced_harness() via clang-format
10. Inline FDP literals — inline_literals_in_reduced_harness() which calls fdp_transform.inline_source_with_report() and fdp_transform.strip_injected_ids()
11. Validate inlined harness — Runs crash_tester.py on the inlined version using the selected Phase 3 mode
12. (Optional) LLM reduction — apply_llm_reduction() if --llm flag is set; validation also uses the selected Phase 3 mode

Also defines:
- ADDITIONAL_HEADERS — A list of 12 standard C++ headers that get prepended to the fallback harness if missing.
- tag_harness_with_fdp_ids() — Reads the source, calls inject_ids(), writes the tagged file to the work dir.
- _prepend_additional_headers() — Ensures the harness has standard includes needed after inlining.
- _finalize_fallback_harness() — Strips injected IDs and prepends missing headers on the tree-reduced harness (used when inline validation fails).
- inline_literals_in_reduced_harness() — Performs the inline transform, writes .inline.cpp, generates harness_values.h for large buffers, and validates crash preservation. Falls back to tree-reduced harness if validation fails.
- _write_inline_validation_failure_artifact() — Writes a validation failure log file (<inline_harness>.validation.log) containing returncode, stdout, and stderr when inline validation fails.
- process() — Convenience wrapper: builds a ReductionConfig from kwargs and calls reduce_with_config().

### 4. fdp_transform.py — FDP AST Transformation Engine

Uses tree-sitter with the tree_sitter_cpp grammar to parse C++ source into an AST. Provides three core operations:

#### inject_ids(source, start_id=100000, marker="FDP_ID") -> (transformed_source, count)

Scans the AST for supported FDP method calls (e.g. ConsumeIntegral, ConsumeBool, ConsumeBytesAsString, etc.). Appends a unique numeric ID as an extra argument to each call:

  fuzz_data.ConsumeIntegral<int>()
  // After:
  fuzz_data.ConsumeIntegral<int>(/*FDP_ID*/100001)

The IDs start at start_id and increment by 1. These IDs allow the FDP trace records (dumped at runtime) to be mapped back to their source callsites.

Supports 16 FDP APIs defined in SUPPORTED_FDP_APIS, including ConsumeBytes, ConsumeBytesWithTerminator, ConsumeRemainingBytes, ConsumeBytesAsString, ConsumeRandomLengthString, ConsumeRemainingBytesAsString, ConsumeIntegral, ConsumeIntegralInRange, ConsumeFloatingPoint, ConsumeFloatingPointInRange, ConsumeProbability, ConsumeBool, ConsumeEnum, PickValueInArray, ConsumeData, remaining_bytes.

#### inline_source_with_report(source, streams) -> InlineResult

Replaces FDP calls with concrete literal values from the trace. Key behaviors:

- Scalar methods (ConsumeIntegral, ConsumeBool, ConsumeFloatingPoint, etc.) — replaced with C++ literals (e.g. 42, true, 3.14).
- String methods (ConsumeBytesAsString, ConsumeRandomLengthString, ConsumeRemainingBytesAsString) — replaced with C++ string literals, with escaping for non-printable characters.
- Bytes/buffer methods (ConsumeBytes, ConsumeBytesWithTerminator, ConsumeRemainingBytes, ConsumeData) — small buffers (64 bytes or less) become std::vector<uint8_t>{...} literals; large buffers (>64 bytes) are moved to a generated header file harness_values.h and referenced via an extern declaration.
- Loop-carried FDP calls (same callsite ID appearing multiple times in the trace) — handled by creating a static array/vector from all trace records for that ID, and wrapping the call in a loop indexed by a static counter.
- Returns InlineResult with fields: source, replaced count, skipped (callsites that could not be inlined), header_name, header_source, loop_replaced, header_replaced, large_buffer_replaced.

Key constants:
- MAX_INLINE_BUFFER_BYTES = 64 — buffers larger than this go to the header file.
- VALUES_HEADER_NAME = "harness_values.h" — the generated header filename.
- _HEADER_BYTES_PER_LINE = 16 — formatting for hex arrays in the header.
- _STRING_LITERAL_CHUNK_BYTES = 64 — chunk size for long string literals.

#### strip_injected_ids(source, start_id=100000) -> (cleaned_source, removed_count)

Removes the injected /*FDP_ID*/NNNNNN arguments from FDP calls in the source. This is the final cleanup step so the output harness does not contain internal instrumentation artifacts.

#### Supporting types:
- CallSite — Represents an FDP callsite in the AST with position, method name, key, fallback keys, argument texts, and optional template argument.
- InlineSkip — Records a callsite that was skipped during inlining (with reason).
- InlineResult — The result of the inline transformation.
- ValuesHeaderEntry — An entry for the generated header file (key, method, declaration, includes).

### 5. reducer_runner.py — Build/Run/External-Tool Driver

Handles all clang++ compilations, harness executions, and the treereduce-c integration. See Compilation Details section below for the full breakdown.

Key functions:
- get_project_root() — Resolves to <package_root>/../.. (the repo root).
- get_fdp_header_dir() — <project_root>/include — where the instrumented FuzzedDataProvider.h lives.
- get_crash_tester_path() — <project_root>/tests/crash_tester.py.
- configure_work_dir(work_dir) / get_work_dir() — Manages the working directory (temp dir by default, or user-specified via --work-dir). Temp dirs are cleaned up at exit.
- run_command(cmd, error_prefix, env, ignore_errors) — Generic subprocess runner with error handling.
- check_tree_reducer() — Verifies treereduce-c is installed and in PATH.
- check_harness_compilation(harness_path, compile_flags, link_flags) — Phase 1 compilation (see below).
- normalize_crash_signature(signature, escape=False) — Normalizes a crash signature by replacing memory addresses (0x...) with the regex pattern 0x[0-9a-fA-F]+. When escape=True, it also re.escapes the rest of the signature (used for runtime error patterns that contain regex-special characters like colons).
- extract_crash_pattern_from_output(crash_input) — Runs the compiled harness with symbolize=1 and parses the output to extract a crash regex pattern from ASan/UBSan/leak/abort/assert/runtime-error/libFuzzer output. All extracted signatures are passed through normalize_crash_signature() to scrub non-deterministic memory addresses. Also extracts and saves the normalized first stack trace to stack_trace.pattern.
- extract_stack_trace(output) — Extracts the first symbolized stack trace from sanitizer output, truncating at LLVMFuzzerTestOneInput. Returns the raw frame text or None.
- get_stack_trace_file() / get_stack_trace_counter_file() / get_stack_trace_backup_file() — Return paths for the stack trace pattern file, invocation counter, and backup source in the work dir.
- stack_trace_tester_args(iteration) — Builds the extra crash_tester.py arguments for periodic stack trace validation (--stack-trace-file, --iteration, --counter-file, --backup-file).
- validate_stack_trace(harness_path, crash_pattern, ...) — Runs a symbolize=1 check via crash_tester.py and compares the resulting stack trace against the stored pattern. Returns True if the trace matches (or no stored pattern exists).
- check_reducer_crash_pattern(harness_path, crash_pattern, crash_input, compile_flags, link_flags, phase3_mode) — Validates the crash pattern by running crash_tester.py in direct or PCH mode.
- compile_dump_mode_harness(harness_path, compile_flags, link_flags) — Phase 2 compilation (see below).
- dump_fdp_trace(harness_bin, crash_input) — Runs the dump-mode binary with FDP_TRACE_PATH env var to produce the FDP trace log.
- prepare_phase3_pch_harness(harness_path, compile_flags, use_replay) — For --pch mode, writes fahm_prefix.h, fahm_prefix.pch, and an include-stripped .fahm_body.cpp used by crash_tester.py.
- restore_pch_includes(harness_path, artifacts) — Prepends the moved include directives back to a reduced body after PCH-mode tree reduction so the final harness remains standalone.
- pch_tester_args(artifacts, phase3_mode) — Produces crash_tester.py mode arguments: --direct or --pch --pch-path <fahm_prefix.pch>.
- run_treereducer(harness_path, fdp_trace_file, crash_pattern, compile_flags, link_flags, crash_input, stable, phase3_mode) — Invokes treereduce-c with the crash tester as the interestingness test; in PCH mode it reduces the include-stripped body and restores the includes afterward.
- format_reduced_harness(reduced_harness_path) — Runs clang-format -i --style=LLVM on the reduced harness.

Crash pattern extraction regexes (defined in reducer_runner.py):
- MEMORY_ADDRESS_PATTERN — Matches hex memory addresses (0x...); used by normalize_crash_signature() to scrub non-deterministic addresses from signatures
- ASAN_SUMMARY_PATTERN — Matches SUMMARY: AddressSanitizer: <bug-type>
- ASAN_ERROR_PATTERN — Matches ERROR: AddressSanitizer: ...
- LEAK_PATTERN — Matches SUMMARY: AddressSanitizer: N byte(s) leaked in M allocation(s).
- RUNTIME_ERROR_PATTERN — Matches <path>:<line>:<col>: runtime error: ... (UBSan runtime errors without a SUMMARY line)
- UBSAN_PATTERN — Matches SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior <loc>
- ABORT_ASSERT_LOCATION_PATTERN — Matches <file>:<line>...Assertion ... failed. (full assertion line from abort/assert failures)
- ABSL_CHECK_PATTERN — Matches Check failed: <condition> from absl CHECK failures
- LIBFUZZER_SIGNAL_PATTERN — Matches SUMMARY: libFuzzer: <signal>
- STACK_FRAME_PATTERN — Matches symbolized stack frames (#N 0xADDR in ...); used by extract_stack_trace()
- LLVMFuzzerTestOneInput_PATTERN — Matches the harness entry point; stack trace extraction truncates at this boundary

### 6. tests/crash_tester.py — Interestingness Test

Called by treereduce-c (and by the inline validation step) to determine if a candidate reduction still preserves the crash. It:

1. Selects a Phase 3 backend:
   - --direct — the original one-step compile/link command.
   - --pch --pch-path <fahm_prefix.pch> — compile the include-stripped candidate body to an object with -include-pch, then link the object.
2. Compiles or compiles+links the candidate source with Phase 3 flags (see below).
3. Determines whether to use symbolize=0 (fast) or symbolize=1 (stack trace validation):
   - By default, symbolize=0 is used for speed.
   - If --symbolize is passed, symbolize=1 is forced for this invocation.
   - If --iteration N is provided along with --counter-file and --stack-trace-file, a counter is incremented each invocation and every N-th check (adapted by source line count) switches to symbolize=1 and validates the stack trace against the stored pattern.
4. Runs the resulting binary with the appropriate ASAN_OPTIONS/UBSAN_OPTIONS.
5. If the process exits with code 77 AND the crash pattern regex matches the output — proceeds to stack trace check if symbolized.
6. If symbolized and --stack-trace-file is provided, the stack trace from the output is compared against the stored normalized pattern. If it matches, the candidate source is saved to --backup-file. If it does not match, returns exit code 1 ("not interesting").
7. Otherwise returns exit code 77 ("interesting") or 1 ("not interesting").

If --fdp-trace is provided, sets FDP_TRACE_PATH env var and adds -DFDP_MIN_MODE_REPLAY -I<project>/include to the compile command.

Stack trace validation thresholds (defined in both reducer_runner.py and crash_tester.py, tune as needed):
- SMALL_HARNESS_LINE_THRESHOLD = 75 — below this, the iteration interval shrinks.
- TINY_HARNESS_LINE_THRESHOLD = 50 — below this, every candidate is checked.
- SMALL_HARNESS_ITERATION = 10 — interval when source has fewer than 75 lines.
- TINY_HARNESS_ITERATION = 1 — interval when source has fewer than 50 lines.
5. Otherwise returns exit code 1 ("not interesting").

If --fdp-trace is provided, sets FDP_TRACE_PATH env var and adds -DFDP_MIN_MODE_REPLAY -I<project>/include to the compile command.

### 7. llm_reducer.py — Optional LLM Semantic Reducer

Sends the reduced harness to an OpenAI-compatible LLM API for semantic minimization:

- Configuration: Reads OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL from environment variables (loaded via dotenv from /root/FuzzAgent/sub_modules/HarnessReducer/.env).
- Prompt: Instructs the LLM to perform constant folding, dead-code elimination, and control-flow flattening while preserving exact semantics and crash behavior. Has strict rules about not removing conditional branches unless the condition can be exactly evaluated.
- Validation: After LLM reduction, runs crash_tester.py with the selected Phase 3 mode (no --fdp-trace) to verify crash preservation. Falls back to the pre-LLM version if validation fails.
- Output: Writes to <reduced_harness>.llm.cpp on success.

---

## CLI Arguments

| Argument | Short | Required | Default | Description |
|---|---|---|---|---|
| harness | — | Yes (positional) | — | Path to the original harness source file (.c, .cc, .cpp). This is the file to be reduced. |
| --compile-flags | — | No | None | Flags passed to compile/preprocess stages. Split on whitespace. Used for -std=c++17, -I<path>, -D<macro>, etc. |
| --link-flags | — | No | None | Flags passed to link stages. Split on whitespace. Used for -L<path>, -l<lib>, static library paths, rpath flags, etc. |
| --crash-input | — | No | None | Path to a crashing input file (seed corpus entry) fed to the harness binary at runtime. If not provided, the harness is run without a file argument (libFuzzer built-in fuzzing loop executes). |
| --work-dir | — | No | None (auto temp dir) | Use a fixed working directory instead of creating a temporary one. When set, the directory is not cleaned up at exit. When omitted, a temp dir with prefix harness_reducer_ is created and removed at program exit. |
| --llm | — | No | False | Enable LLM-based semantic minimization as a final reduction pass. Requires OPENAI_API_KEY, OPENAI_BASE_URL, and OPENAI_MODEL environment variables to be set. |
| -o / --output | -o | Yes | — | Required output path for the reduced harness. The parent directory is created if needed. Any generated header files (e.g., harness_values.h) are copied to the same directory. |
| --stable | — | No | False | Use deterministic/stable reduction mode. Passes --stable --min-reduction 1 to treereduce-c instead of --fast. Ensures reproducible output across runs. |
| --iteration | — | No | None | Enable periodic stack trace validation every N crash-tester invocations during reduction. The interval adapts based on candidate line count (see thresholds above). When omitted, the stack trace is still recorded at startup (symbolize=1) but symbolize=0 is used throughout reduction (no periodic checks). |
| --direct | — | No | True | Use the original one-step Phase 3 compile/link path. This is the default and preserves the previous crash_tester.py behavior. Mutually exclusive with --pch. |
| --pch | — | No | False | Use precompiled-header Phase 3 mode. The tool builds fahm_prefix.h/fahm_prefix.pch, removes include lines from the tested candidate body, compiles candidates with -include-pch to .o files, and links separately. Mutually exclusive with --direct. |

### ReductionConfig fields (internal, built from CLI args)

| Field | Type | Default | Source |
|---|---|---|---|
| harness_path | str | — | args.harness |
| compile_flags | str or None | None | args.compile_flags |
| link_flags | str or None | None | args.link_flags |
| crash_input | str or None | None | args.crash_input |
| work_dir | str or None | None | args.work_dir |
| start_id | int | 100000 | Hardcoded |
| marker | str | "FDP_ID" | Hardcoded |
| use_llm | bool | False | args.llm |
| stable | bool | False | args.stable |
| phase3_mode | str | "direct" | args.direct / args.pch |
| iteration | int or None | None | args.iteration |

### ReductionResult fields

| Field | Type | Description |
|---|---|---|
| reduced_harness | str | Path to the final reduced harness file |
| tagged_harness | str | Path to the FDP-ID-tagged intermediate harness |
| fdp_trace | str | Path to the FDP trace log file |
| generated_headers | tuple[str, ...] | Paths to any generated header files (e.g., harness_values.h) |
| success | bool | Whether the reduction completed successfully |

---

## Compilation Details: Flags, Headers, and Libraries

There are three distinct compilation contexts in the tool. Phase 1 and Phase 2 are fixed; Phase 3 now has two selectable backends (--direct and --pch). Each path uses clang++ but with different flags depending on the phase/backend.

### Phase 1: Initial Compilation Check

Function: reducer_runner.py:check_harness_compilation()
Purpose: Verify the original harness compiles before starting the pipeline.

  clang++ -fsanitize=address,fuzzer,undefined -g -O0 [--compile-flags...] <harness.cpp> -o <work_dir>/poc.out [--link-flags...]

- Flags: -fsanitize=address,fuzzer,undefined -g -O0
- User flags: --compile-flags are placed before the source file; --link-flags are placed after the output option for linking.
- Include dirs: None added by the tool — the user include for fuzzer/FuzzedDataProvider.h must resolve from system paths or the user own -I in --compile-flags
- Linking: -fsanitize=fuzzer automatically links libFuzzer; -fsanitize=address,undefined links the sanitizer runtimes
- Define macros: None
- Output: <work_dir>/poc.out

### Phase 2: Tagged Harness Dump Mode Compilation

Function: reducer_runner.py:compile_dump_mode_harness()
Purpose: Build an instrumented binary that records every FDP call return value to a trace log.

  clang++ -DFDP_MIN_MODE_DUMP -I<project_root>/include -fsanitize=address,fuzzer,undefined -g -O0 [--compile-flags...] <tagged_harness.cpp> -o <work_dir>/tagged_harness.out [--link-flags...]

- Flags: Same base flags as Phase 1
- Define macros:
  - -DFDP_MIN_MODE_DUMP — Switches FuzzedDataProvider.h into dump mode. Every FDP call records its return value to the trace file (path from FDP_TRACE_PATH env var) instead of operating normally. The header contains #if defined(FDP_MIN_MODE_DUMP) / #elif defined(FDP_MIN_MODE_REPLAY) / #else conditional compilation blocks.
- Include dirs:
  - -I<project_root>/include — Explicitly adds the project include/ directory so the custom FuzzedDataProvider.h (with dump/replay instrumentation) is found instead of any system version. get_fdp_header_dir() resolves to <project_root>/include.
- User flags: --compile-flags are placed before the source file; --link-flags are placed after the output option for linking.
- Linking: Same as Phase 1
- Output: <work_dir>/tagged_harness.out

### Phase 3: Crash Tester Compilation / Linking

Script: tests/crash_tester.py:main()
Purpose: Interestingness test invoked by treereduce-c for every candidate reduction. Also used for crash-pattern pre-validation, inline validation, and LLM validation.

Phase 3 now has two selectable backends:

#### Phase 3A: Direct backend (--direct, default)

This preserves the previous behavior: each crash_tester.py invocation compiles and links the candidate in one clang++ command.

```bash
clang++ [-I<project_root>/include -DFDP_MIN_MODE_REPLAY] \
  -fsanitize=address,fuzzer,undefined -g -O0 \
  [--compile-flags...] <source.cpp> -o </tmp/poc_PID_XXXXX.out> [--link-flags...]
```

- Conditional flags (only when --fdp-trace argument is provided):
  - -I<project_root>/include — Same as Phase 2, uses the instrumented FuzzedDataProvider.h.
  - -DFDP_MIN_MODE_REPLAY — Switches FuzzedDataProvider.h into replay mode. FDP calls read their return values from the trace file instead of consuming the fuzz input, making execution deterministic.
- When --fdp-trace is NOT provided (e.g., initial crash-pattern validation and LLM validation): neither -I<project_root>/include nor -DFDP_MIN_MODE_REPLAY is added.
- User flags: --compile-flags are used before the source and --link-flags are used during the same final direct link command.
- Linking: Same as the old Phase 3 path; -fsanitize=fuzzer links libFuzzer and the sanitizer runtimes are linked by the sanitizer flags.
- Output: /tmp/poc_<PID>_<random>.out (temp file, deleted after test).

#### Phase 3B: PCH backend (--pch)

This mode amortizes repeated header parsing during minimization. reducer_runner.py prepares a precompiled-header environment, while crash_tester.py compiles each include-stripped candidate body to an object and then links that object.

Preparation function: reducer_runner.py:prepare_phase3_pch_harness()

1. Read the harness source being tested.
2. Copy its #include lines into <work_dir>/fahm_prefix.h, with these standard includes added first:

   #include <stdint.h>
   #include <stddef.h>

3. Remove those #include lines from the tested source body and write <stem>.fahm_body.cpp in the work directory.
4. For quoted local includes that exist relative to the source file, the PCH prefix rewrites them to absolute paths so moving the prefix into the work directory does not change quote-include lookup semantics. The restored final harness keeps the original include spelling.
5. Precompile the prefix header:

```bash
clang++ -Qunused-arguments [-I<project_root>/include -DFDP_MIN_MODE_REPLAY] \
  -fsanitize=address,fuzzer,undefined -O1 -gline-tables-only \
  -x c++-header [--compile-flags...] <work_dir>/fahm_prefix.h \
  -o <work_dir>/fahm_prefix.pch
```

Per crash_tester.py invocation in --pch mode:

```bash
clang++ -Qunused-arguments -include-pch <work_dir>/fahm_prefix.pch \
  [-I<project_root>/include -DFDP_MIN_MODE_REPLAY] \
  -fsanitize=address,fuzzer,undefined -O1 -gline-tables-only \
  -c [--compile-flags...] <candidate_body.cpp> -o </tmp/poc_PID_XXXXX.o>
```

```bash
clang++ -Qunused-arguments -fsanitize=address,fuzzer,undefined \
  </tmp/poc_PID_XXXXX.o> -o </tmp/poc_PID_XXXXX.out> [--link-flags...]
```

- Conditional replay flags are used in both PCH precompilation and per-candidate object compilation only when --fdp-trace is provided. They are not needed for the final link command.
- User flags: --compile-flags are appended to the PCH precompile and object compile commands. --link-flags are appended only to the final link command.
- Optimization/debug flags: PCH mode intentionally uses -O1 -gline-tables-only instead of -g -O0 for the PCH precompile and object compile. The --direct path still uses -g -O0.
- Temporary outputs: /tmp/poc_<PID>_<random>.o and /tmp/poc_<PID>_<random>.out are deleted after each test.
- In tree-reduction, treereduce-c receives the include-stripped .fahm_body.cpp as -s input in --pch mode. After treereduce-c writes reduced_harness.cpp, restore_pch_includes() prepends the moved include directives so the reduced harness remains a standalone source file.

### Compilation Flags Summary Table

| Flag / behavior | Phase 1 (check) | Phase 2 (dump) | Phase 3 --direct | Phase 3 --pch prefix | Phase 3 --pch object | Phase 3 --pch link |
|---|---|---|---|---|---|---|
| -fsanitize=address,fuzzer,undefined | Yes | Yes | Yes | Yes | Yes | Yes |
| -g -O0 | Yes | Yes | Yes | No | No | No |
| -O1 -gline-tables-only | No | No | No | Yes | Yes | No |
| -DFDP_MIN_MODE_DUMP | No | Yes | No | No | No | No |
| -DFDP_MIN_MODE_REPLAY | No | No | Only with --fdp-trace | Only with --fdp-trace | Only with --fdp-trace | No |
| -I<project>/include | No | Yes | Only with --fdp-trace | Only with --fdp-trace | Only with --fdp-trace | No |
| -x c++-header | No | No | No | Yes | No | No |
| -include-pch <fahm_prefix.pch> | No | No | No | No | Yes | No |
| -c to object | No | No | No | No | Yes | No |
| User --compile-flags | Yes | Yes | Yes | Yes | Yes | No |
| User --link-flags | Yes | Yes | Yes | No | No | Yes |

### Compilation Phase Execution Counts

Each compilation phase is invoked a different number of times during a single run of reduce_with_config():

- **Phase 1 (check_harness_compilation)**: Executed exactly **1 time**.
  Called as a pre-flight check before the pipeline begins.

- **Phase 2 (compile_dump_mode_harness)**: Executed exactly **1 time**.
  Produces the dump-mode binary used for trace extraction.

- **Phase 3 (crash_tester.py)**: Executed **N + 2 or 3 times** (where N is the number of interestingness tests treereduce-c performs, typically hundreds to thousands).

| Call site | --fdp-trace? | Count | Direct mode behavior | PCH mode behavior |
|---|---|---|---|---|
| check_reducer_crash_pattern() | No | 1 | One clang++ compile/link | Precompile a no-replay fahm_prefix.pch once, compile body to .o, link |
| Inside treereduce-c | Yes | N | One clang++ compile/link per candidate | Precompile one replay fahm_prefix.pch before treereduce; each candidate compiles body to .o and links |
| inline_literals_in_reduced_harness() | Yes | 1 if any FDP callsites were inlined | One clang++ compile/link | Precompile a replay fahm_prefix.pch once, compile body to .o, link |
| apply_llm_reduction() | No | 0 or 1 (only if --llm flag is set) | One clang++ compile/link | Precompile a no-replay fahm_prefix.pch once, compile body to .o, link |

Total crash_tester.py invocations:
- Without --llm: **N + 2**
- With --llm: **N + 3**

PCH-mode precompile count:
- Without --llm and with at least one inlined FDP callsite: **3** total PCH precompiles (pre-validation, treereduce replay, inline validation), but only **1** of them covers the N repeated treereduce candidates.
- With --llm: add **1** more no-replay PCH precompile for LLM validation.

Note: The extract_crash_pattern_from_output() function is NOT a Phase 3 invocation. It runs the Phase 1 compiled binary (poc.out) directly and executes exactly 1 time.

### Header Discovery

- The project own include/fuzzer/FuzzedDataProvider.h is the only header directory the tool explicitly adds via -I. It contains custom dump/replay instrumentation not present in the standard LLVM version.
- In --pch mode, the tool also creates <work_dir>/fahm_prefix.h and copies the tested harness #include lines into it. This is not a new include search directory; it is a generated prefix header that is precompiled into <work_dir>/fahm_prefix.pch.
- The header uses compile-time mode selection:
  - FDP_MIN_MODE_DUMP — Mode::kDump — FDP calls write return values to trace
  - FDP_MIN_MODE_REPLAY — Mode::kReplay — FDP calls read return values from trace
  - Neither defined — Mode::kNative — Normal FDP behavior
  - FDP_MIN_MODE_DUMP and FDP_MIN_MODE_REPLAY are mutually exclusive (the header has #error if both are defined).
- No other include paths are added by the tool — the user must supply any library-specific -I flags through --compile-flags. Quoted includes that exist relative to the source file are rewritten to absolute paths inside fahm_prefix.h only, so moving the generated prefix into the work directory does not break local quote-include lookup.

### Library Linking

- The tool relies entirely on -fsanitize=fuzzer to link libFuzzer and -fsanitize=address,undefined to link the ASan/UBSan runtimes.
- No -L flags or -l flags are added by the tool. Any library linking must come from the user --link-flags (e.g., -lpng, -L/path/to/lib, etc.).
- In --direct Phase 3 mode, --compile-flags and --link-flags are both appended to the single compile/link command in their stage-appropriate positions. In --pch Phase 3 mode, --compile-flags are used for PCH/object compilation and --link-flags are used only during the final link.

### Runtime Environment Variables

When running the compiled binaries (not compiling), these env vars are set:
| Variable | Value | When | Purpose |
|---|---|---|---|
| ASAN_OPTIONS | exitcode=77:symbolize=1 | Phase 1 crash extraction | Makes ASan exit with code 77; enables symbolization for stack trace capture |
| ASAN_OPTIONS | exitcode=77:symbolize=0:handle_abort=1 | Phase 3 crash tester (default) | Fast: disables symbolization for speed |
| ASAN_OPTIONS | exitcode=77:symbolize=1:handle_abort=1 | Phase 3 crash tester (periodic stack trace check) | Enables symbolization for stack trace validation |
| UBSAN_OPTIONS | exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=1 | Phase 1 crash extraction | Enables symbolization for stack trace capture |
| UBSAN_OPTIONS | exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=0 | Phase 3 crash tester (default) | Fast: disables symbolization for speed |
| UBSAN_OPTIONS | exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=1 | Phase 3 crash tester (periodic stack trace check) | Enables symbolization for stack trace validation |
| FDP_TRACE_PATH | <work_dir>/fdp_trace.log | Dump-mode execution and Phase 3 replay executions with --fdp-trace | Dump mode writes the trace; replay mode reads the trace |
| FDP_TRACE_PATH | <work_dir>/fdp_trace.log | Dump-mode execution and Phase 3 replay executions with --fdp-trace | Dump mode writes the trace; replay mode reads the trace |
---

## treereduce-c Integration

The tool invokes treereduce-c as an external process for AST-level reduction.

Direct mode:

```bash
treereduce-c -j 60 -s <tagged_harness.cpp> -o <reduced_harness.cpp> --fast \
  --timeout 300 --interesting-exit-code 77 \
  -- <crash_tester.py> @@.cpp <crash_pattern> \
     --crash-input <crash_input> --compile-flags <compile_flags> --link-flags <link_flags> \
     --fdp-trace <trace> --direct \
     [--stack-trace-file <stack_trace.pattern> --iteration <N> \
      --counter-file <stack_trace.counter> --backup-file <stack_trace.backup.cpp>]
```

PCH mode:

```bash
treereduce-c -j 60 -s <tagged_harness.fahm_body.cpp> -o <reduced_harness.cpp> --fast \
  --timeout 300 --interesting-exit-code 77 \
  -- <crash_tester.py> @@.cpp <crash_pattern> \
     --crash-input <crash_input> --compile-flags <compile_flags> --link-flags <link_flags> \
     --fdp-trace <trace> --pch --pch-path <work_dir>/fahm_prefix.pch \
     [--stack-trace-file <stack_trace.pattern> --iteration <N> \
      --counter-file <stack_trace.counter> --backup-file <stack_trace.backup.cpp>]
```

- -j 60 — Use up to 60 parallel jobs
- -s — Read the source file. In --pch mode this is the include-stripped .fahm_body.cpp, not the original tagged harness with includes.
- -o — Write the reduced output
- --fast (default) or --stable --min-reduction 1 — Reduction strategy
- --timeout 300 — Per-test timeout in seconds
- --interesting-exit-code 77 — The exit code that means this reduction is still interesting (matches ASan/UBSan exit code)
- @@.cpp — treereduce-c replaces this with the candidate source path
- After a PCH-mode treereduce run succeeds, restore_pch_includes() prepends the moved include lines to reduced_harness.cpp.
- The bracketed stack trace arguments are only present when --iteration is provided. They enable periodic symbolize=1 checks during the reduction and automatic source backup on successful stack trace validation. After treereduce-c completes, api.py runs a final symbolize=1 check via validate_stack_trace(); if it fails, the last backup is restored.

---

## Working Directory Layout

When using a temp dir (default), the working directory contains:

  harness_reducer_<random>/
  +-- <harness_name>.cpp          # Tagged harness (with FDP_IDs)
  +-- fahm_prefix.h               # Generated Phase 3 PCH prefix header (--pch mode)
  +-- fahm_prefix.pch             # Precompiled Phase 3 prefix (--pch mode)
  +-- *.fahm_body.cpp             # Include-stripped sources tested with the PCH (--pch mode)
  +-- tagged_harness.out          # Dump-mode compiled binary
  +-- poc.out                     # Phase 1 compiled binary
  +-- fdp_trace.log               # FDP trace from dump mode
  +-- reduced_harness.cpp         # Tree-reduced harness
  +-- reduced_harness.inline.cpp  # After FDP literal inlining
  +-- reduced_harness.llm.cpp     # After LLM reduction (if --llm)
  +-- harness_values.h            # Generated header for large buffers
  +-- stack_trace.pattern         # Normalized stack trace regex (from Phase 1 symbolize=1 run)
  +-- stack_trace.counter         # Invocation counter for periodic stack trace checks (--iteration)
  +-- stack_trace.backup.cpp      # Last known-good source backup from stack trace validation

When --work-dir is specified, the directory is not cleaned up at exit. Otherwise, it is removed via atexit handler.

---

## Additional Headers

The api.py module defines ADDITIONAL_HEADERS — 12 standard C++ headers that are prepended to the fallback harness if they are not already present:

  ADDITIONAL_HEADERS = [
      "#include <cstddef>",
      "#include <cstring>",
      "#include <string>",
      "#include <vector>",
      "#include <deque>",
      "#include <fstream>",
      "#include <map>",
      "#include <mutex>",
      "#include <sstream>",
      "#include <cmath>",
      "#include <iomanip>",
      "#include <limits>",
  ]

These are needed because the FDP literal inlining may introduce uses of these types (e.g., std::vector, std::string, std::deque) that were previously provided by FuzzedDataProvider.h.

---

## LLM Reducer Details

The LLM reducer (llm_reducer.py) is an optional final pass:

- Environment config: Reads from dotenv at /root/FuzzAgent/sub_modules/HarnessReducer/.env:
  - OPENAI_API_KEY — API key
  - OPENAI_BASE_URL — Base URL (supports non-OpenAI providers)
  - OPENAI_MODEL — Model name
- Model invocation: Uses openai Python client with temperature=1.0 and reasoning: {enabled: True} for chain-of-thought.
- Prompt strategy: Instructs the LLM to perform:
  1. Constant folding (evaluate compile-time-known expressions)
  2. Redundant statement elimination (remove unused variables/calls)
  3. Control-flow flattening (remove branches whose conditions are known)
  4. Strict rules: cannot remove branches unless the exact condition value is known; must preserve updated variable values through branches.
- Validation: After LLM output, compiles and runs with crash_tester.py using the selected Phase 3 mode (no --fdp-trace). Falls back to pre-LLM version if crash is not preserved.
- Output file: <reduced_harness>.llm.cpp

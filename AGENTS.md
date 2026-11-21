# Repository guidance

## README maintenance

- Keep `README.md` within its current scope and structure. Do not change or
  expand it as a routine part of implementation work.
- Unless the user explicitly requests a README edit, change it only when a code
  change makes its existing content inaccurate. Make the smallest correction
  needed; do not use that correction to add unrelated material.
- Do not append implementation notes, internal review guidance, development
  plans, change summaries, or test reports to the README. Put durable context
  needed for implementation and review in this file instead.
- Keep this guidance accurate as the implementation evolves. Verify behavior
  against the code rather than treating these notes as a substitute for review.
- Describe current behavior and review requirements directly. Do not include
  implementation history, branch provenance, or summaries of completed work.

## Implementation and review context

### Reduction budgets and recovery

- `ReductionConfig.reduction_timeout_seconds` bounds reduction search for
  all Perses presets. Preparation and final validation are outside
  that budget. Budget-driven checkpoints start only during the final four
  minutes; do not seed an initial checkpoint.
- `search_timeout_seconds`, when supplied together with the reduction budget,
  shares one deadline across reference preparation and search. Compilation and
  calibration consume it, retries cannot reset it, and exhausted preparation
  must not start search. Without it, the reduction budget covers search only.
  Finalization and validation run afterward; an embedding
  application's outer timeout remains authoritative.
- Perses-family engines use separate input and output directories. Timeout
  supervision must use the engine's working directory, environment, log
  destinations, and result publication mechanism. The reducer and descendant
  testers must stop before result recovery.
- On a Perses/WDD/CDD timeout, recover only a current-run accepted checkpoint;
  the engine's output may still contain its initial input. Clear previous-run
  checkpoints and outputs before starting a new run.
- On an engine error, checkpoint recovery requires checkpoint saving to be
  enabled. Reject missing, empty, stale, or unchanged checkpoints; do not
  substitute an unverified engine output.
- Normal completion and recovery must restore PCH/macro headers, inline the
  recorded FDP values, and validate the exported result. Failed final validation
  is a failure, not a successful reduction. The API result must include generated
  headers and any required runtime arguments.
- Main locations: `src/harnessminimizer/api.py`, `reduction_budget.py`,
  `reduction_engines.py`, and `reducer_runner.py` in the same package.

### Crash matching and execution

- Symbolized candidate checks and final validation use the recorded set of
  complete library traces before the harness frame. Matching uses verified
  source path aliases; do not replace them with loose
  basename matching or a depth-only check.
- In symbolized mode, UBSan diagnostic wording may differ only when the recorded
  crash location and a complete recorded library trace match. This exception
  does not apply to unsymbolized crash-pattern checks.
- Generated executable paths and build IDs may be normalized for source-less
  ASan `memcpy`, `memmove`, and `memset` interceptor frames. Keep the interceptor
  identity, frame order/depth, and project source coordinates significant.
  Retained crash evidence must remain unchanged.
- Reference, plugin, and candidate replays inherit an embedding application's
  explicit `ASAN_OPTIONS` setting of `detect_leaks=0` or `detect_leaks=1`.
  Other required ASan settings, including exit status, symbolization, and
  suppressions, are controlled by the minimizer.
- Amortized linking supports target libraries calling harness-defined
  callbacks. Fixed target code is linked once into a helper shared library;
  each candidate supplies the callbacks. Target objects must support PIC.
  Required plugin link flags must be supplied throughout validation and reduction.
- Main locations: `src/harnessminimizer/reducer_runner.py`,
  `symbolized_trace.py`, and `source_alias.py` in the same package, plus
  `tests/crash_tester.py` (a runtime candidate checker, despite its location).

### File handling

- Work and export directories may be symlink aliases. Checked source rewrites,
  checkpoint copies, and debug-log writes must reject symlink or hardlink files.
  Replacement copies must be atomic, and debug-log writes must be locked.
- Reuse `src/harnessminimizer/safe_files.py` and `debug_log.py` for these
  operations rather than bypassing their checks.

## Validation

- Run tests relevant to the changed behavior with
  `.venv/bin/python -m pytest <test paths>` in the repository's installed Python
  environment. Documentation-only changes need an accuracy and diff check,
  not a reduction run.
- Budget/recovery coverage: `tests/test_reduction_budget.py`,
  `tests/test_reduction_budget_integration.py`, `tests/test_engine_error_recovery.py`.
- Crash/linking coverage: `tests/test_symbolized_trace.py`,
  `tests/test_stack_trace_validation.py`, `tests/test_amortized_objects.py`.
- File handling coverage: `tests/test_safe_files.py`.
- Distinguish mocked or synthetic reducer tests from tests using the installed
  engine. Report skipped or unavailable native/engine checks accurately.

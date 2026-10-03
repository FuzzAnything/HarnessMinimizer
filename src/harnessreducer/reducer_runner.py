from __future__ import annotations

import atexit
from contextlib import ExitStack, contextmanager, nullcontext
import filecmp
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from harnessreducer.process_supervisor import (
    run_supervised, terminate_process_group, treereduce_binary, DEFAULT_COMMAND_TIMEOUT,
)
from harnessreducer.crash_evidence import (
    CANDIDATE_EVIDENCE_ATTEMPTS, REFERENCE_EVIDENCE_ATTEMPTS, retry_missing_evidence,
)

from harnessreducer.dynamic_slicer import CoverageMap, slice_source_by_coverage
from harnessreducer.reduction_profile import write_profile_summary
from harnessreducer.reduction_engines import RawOutputCapture

TREEDUCER_DIR: str | None = None
_IS_USER_WORK_DIR = False
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
PHASE3_DIRECT = "direct"
PHASE3_DIRECT_ALIAS = "single-step"
PHASE3_SPLIT = "split"
PHASE3_PCH = "pch"
PHASE3_MODES = {PHASE3_DIRECT, PHASE3_SPLIT, PHASE3_PCH}
PHASE3_SANITIZER_FLAGS = ["-fsanitize=address,fuzzer,undefined"]
PHASE3_PLUGIN_SANITIZER_FLAGS = ["-fsanitize=address,undefined"]
PHASE3_DIRECT_OPT_FLAGS = ["-gline-tables-only", "-O0"]
PHASE3_SPLIT_OPT_FLAGS = ["-O0", "-gline-tables-only"]
PHASE3_PCH_OPT_FLAGS = ["-O0", "-gline-tables-only"]
AUTO_VAR_INIT_PATTERN_FLAG = "-ftrivial-auto-var-init=pattern"
PHASE3_WARNING_FLAGS = [
    "-Werror=uninitialized",
    "-Werror=return-type",
]
POST_REDUCTION_VALIDATION_ATTEMPTS = 5
PCH_PREFIX_HEADER_NAME = "harness_prefix.h"
PCH_PREFIX_FILE_NAME = "harness_prefix.pch"
COVERAGE_BIN_FILE_NAME = "poc_cov.out"
COVERAGE_DRIVER_FILE_NAME = "coverage_driver.cpp"
SOURCE_COVERAGE_RAW_FILE_NAME = "coverage.profraw"
SOURCE_COVERAGE_DATA_FILE_NAME = "coverage.profdata"
SOURCE_COVERAGE_SHOW_FILE_NAME = "coverage_show.txt"
SOURCE_COVERAGE_EXPORT_FILE_NAME = "coverage_export.json"
STATISTICS_FILE_NAME = "statistics.txt"
DEBUG_LOG_FILE_NAME = "reduction_debug.log"
CANDIDATE_PROFILE_EVENTS_FILE_NAME = "candidate_profile.jsonl"
REDUCTION_PROFILE_JSON_FILE_NAME = "reduction_profile.json"
REDUCTION_PROFILE_TEXT_FILE_NAME = "reduction_profile.txt"
SLICED_HARNESS_SUFFIX = ".sliced"
DEFAULT_EXEC_TIMEOUT_MS = 300_000
DEFAULT_TREEREDUCE_JOBS = 60
MAX_TREEREDUCE_JOBS = 63
CALIBRATED_EXEC_TIMEOUT_MIN_MS = 2_000
CALIBRATED_EXEC_TIMEOUT_MAX_MS = 60_000
CALIBRATION_PROBE_RUNS = 5
CALIBRATION_WARMUP_RUNS = 1
CALIBRATED_EXEC_TIMEOUT_MULTIPLIER = 8
STACK_DEPTH_STABILITY_RUNS = 20
EXEC_TIME_MARKER_PREFIX = "HARNESSREDUCER_EXEC_TIME_MS="
POC_RUNTIME_ARG_MARKER_PREFIX = "HARNESSREDUCER_POC_RUNTIME_ARG="

STACK_TRACE_FILE_NAME = "stack_trace.pattern"
STACK_DEPTH_STABILITY_FILE_NAME = "stack_depth_stability.json"
CRASH_PATTERN_SYMBOLIZE_0_FILE_NAME = "crash_pattern.symbolize0"
CRASH_PATTERN_SYMBOLIZE_1_FILE_NAME = "crash_pattern.symbolize1"
DYNAMIC_CRASH_SITE_FILE_NAME = "dynamic_crash_site.json"
SYMBOLIZED_CRASH_LOCATION_FILE_NAME = "symbolized_crash_location.pattern"
SYMBOLIZATION_FAILURE_LOG_NAME = "reference_symbolization_failure.log"
LAST_INTERESTING_FILE_NAME = "last_interesting.cpp"
HARNESS_RUNNER_SOURCE_NAME = "harness_runner.cpp"
FDP_REPLAY_RUNTIME_SOURCE_NAME = "fdp_replay_runtime.cpp"
HARNESS_RUNNER_BINARY_NAME = "harness_runner"
AMORTIZED_FALLBACK_STATE_SUFFIX = ".fallback-state"
CRASH_PATTERN_SYMBOLIZE_0: str | None = None
CRASH_PATTERN_SYMBOLIZE_1: str | None = None
NORMAL_REFERENCE_STACK_DEPTH: int | None = None
SYMBOLIZED_REFERENCE_STACK_DEPTH: int | None = None
NORMAL_REFERENCE_STACK_DEPTH_STRICT = False
SYMBOLIZED_REFERENCE_STACK_DEPTH_STRICT = False
DYNAMIC_REFERENCE_CRASH_SITE = None
SYMBOLIZED_REFERENCE_CRASH_LOCATION_PATTERN: str | None = None
CURRENT_EXEC_TIMEOUT_MS: int | None = DEFAULT_EXEC_TIMEOUT_MS
REDUCTION_DEBUG_LOG_PATH: str | None = None
POC_RUNTIME_ARGS: list[str] = []
# Matches symbolized stack frames like:
#   #0 0x5ea4dfe78fe6 in av1_func /root/src/file.c:444:18
#   #5 0x5ea4dfa2f68f in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/path/fuzzer+0x46068f)
STACK_FRAME_PATTERN = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+")
STACK_FRAME_COUNT_PATTERN = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\b")
LLVMFuzzerTestOneInput_PATTERN = re.compile(r"\bLLVMFuzzerTestOneInput\b")
SOURCE_LOCATION_PATTERN = re.compile(r"(/[^:\s\)]+):(\d+)(?::(\d+))?")
LLVM_COV_SHOW_LINE_PATTERN = re.compile(r"^\s*(\d+)\|\s*([^|]*)\|")
EXEC_TIME_MARKER_PATTERN = re.compile(
    rf"^{re.escape(EXEC_TIME_MARKER_PREFIX)}(\d+)$",
    re.MULTILINE,
)
SHARED_LIBRARY_FRAME_PATTERN = re.compile(
    r"\((?P<library>[^()\s]+?\.so(?:\.[^()+\s]+)?)\+"
    r"(?P<offset>0x[0-9a-fA-F]+)\)"
)


def fdp_wide_trace_path(fdp_trace_file: str | os.PathLike[str]) -> str:
    return f"{fdp_trace_file}.wide"


ELF_NEEDED_PATTERN = re.compile(
    r"\(NEEDED\)\s+Shared library: \[(?P<name>[^\]]+)\]"
)
ELF_SONAME_PATTERN = re.compile(
    r"\(SONAME\)\s+Library soname: \[(?P<name>[^\]]+)\]"
)
LINKER_SCRIPT_SHARED_LIBRARY_PATTERN = re.compile(
    r"(?P<path>[^()\s]+\.so(?:\.[^()\s]+)*)"
)


@dataclass(frozen=True)
class PchArtifacts:
    body_source: str
    prefix_header: str
    pch_file: str
    restore_prefix: str
    amortize_link: bool = False


@dataclass(frozen=True)
class DynamicCrashSite:
    library_path: str
    library_name: str
    offset: str


class HarnessCrashDetected(RuntimeError):
    def __init__(self, location: str):
        self.location = location
        super().__init__(f"Crash location is inside the harness: {location}")


@dataclass(frozen=True)
class DynamicLibraryHints:
    exact_paths: tuple[str, ...] = ()
    exact_names: tuple[str, ...] = ()
    soname_prefixes: tuple[str, ...] = ()
    allow_output_fallback: bool = False

    @property
    def has_library_hints(self) -> bool:
        return bool(self.exact_paths or self.exact_names or self.soname_prefixes)


@dataclass(frozen=True)
class AmortizedRunner:
    socket_path: str
    process: subprocess.Popen[str]
    shared_libraries: tuple[str, ...]
    static_libraries: tuple[str, ...]
    plugin_link_flags: tuple[str, ...]


@dataclass(frozen=True)
class SharedLibraryInput:
    """Canonical ELF and verified link-time spellings, used only during setup."""

    load_path: str
    link_aliases: tuple[str, ...]


@dataclass(frozen=True)
class AmortizedLinkInputs:
    shared_libraries: tuple[str, ...]
    static_libraries: tuple[str, ...]
    runner_link_flags: tuple[str, ...]
    plugin_link_flags: tuple[str, ...] = ()
    shared_library_inputs: tuple[SharedLibraryInput, ...] = ()


@dataclass(frozen=True)
class StaticArchiveRootConfig:
    source: str
    compile_flags: str | None = None
    pch_path: str | None = None
    use_replay: bool = False


@dataclass(frozen=True)
class StaticArchiveLinkPlan:
    flags: tuple[str, ...]
    root_symbols: tuple[str, ...]
    uses_whole_archive: bool
    visibility_exported_libraries: tuple[str, ...] = ()
    visibility_exported_symbol_count: int = 0


def cleanup() -> None:
    global TREEDUCER_DIR

    if TREEDUCER_DIR is None or _IS_USER_WORK_DIR:
        return

    try:
        shutil.rmtree(TREEDUCER_DIR, ignore_errors=True)
    except OSError:
        pass


atexit.register(cleanup)

MEMORY_ADDRESS_PATTERN = re.compile(r"\b0x[0-9a-fA-F]+\b")
ASAN_SUMMARY_PATTERN = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*([\w-]+)")
ASAN_ERROR_PATTERN = re.compile(r"ERROR:\s*AddressSanitizer:\s*([\w-]+)")
LEAK_PATTERN = re.compile(
    r"SUMMARY: AddressSanitizer: \d+ byte\(s\) leaked in \d+ allocation\(s\)\."
)
RUNTIME_ERROR_PATTERN = re.compile(
    r"(?:/[^\s:]+)+:\d+:\d+:\s*runtime error:.*"
)
RUNTIME_ERROR_NUMBER_PATTERN = re.compile(
    r"(?<![\w.])[+-]?(?:0[xX][0-9a-fA-F]+|"
    r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)(?![\w.])"
)
UBSAN_PATTERN = re.compile(
    r"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior\s+(\S+:\d+:\d+)"
)
# Captures source location as file:line from abort/assert lines.
# Example line:
# poc.out: /root/src/libaom/av1/encoder/intra_mode_search.c:358: ... Assertion `...` failed.
ABORT_ASSERT_LOCATION_PATTERN = re.compile(
    r"((?:/[^\s:]+)+:\d+:.*Assertion .* failed\.)"
)
# Captures the condition from absl CHECK failure lines.
# Example line:
# F0000 00:00:... Check failed: last_returned_size_ > 0 (0 vs. 0) BackUp() ...
ABSL_CHECK_PATTERN = re.compile(r"Check failed:\s*(.+?)\s*\(")
# Generic fallback for any libFuzzer-reported signal crash.
# Example line:
# SUMMARY: libFuzzer: deadly signal
LIBFUZZER_SIGNAL_PATTERN = re.compile(r"SUMMARY:\s*libFuzzer:\s*([\w][\w\s-]*)")

def get_project_root() -> Path:
    return PROJECT_ROOT


def get_fdp_header_dir() -> str:
    return str(get_project_root() / "include")


def get_crash_tester_path() -> str:
    return str(get_project_root() / "tests" / "crash_tester.py")


def set_current_exec_timeout_ms(timeout_ms: int | None) -> None:
    global CURRENT_EXEC_TIMEOUT_MS

    if timeout_ms is None:
        CURRENT_EXEC_TIMEOUT_MS = None
        return
    CURRENT_EXEC_TIMEOUT_MS = max(1, int(timeout_ms))


def get_current_exec_timeout_ms() -> int | None:
    return CURRENT_EXEC_TIMEOUT_MS


def reset_poc_runtime_args() -> None:
    POC_RUNTIME_ARGS.clear()


def get_poc_runtime_args() -> tuple[str, ...]:
    return tuple(POC_RUNTIME_ARGS)


def _record_poc_runtime_args_from_validation(
    proc: subprocess.CompletedProcess[str],
) -> None:
    if proc.returncode != 77:
        return
    output = f"{proc.stdout}\n{proc.stderr}"
    for line in output.splitlines():
        if not line.startswith(POC_RUNTIME_ARG_MARKER_PREFIX):
            continue
        runtime_arg = line[len(POC_RUNTIME_ARG_MARKER_PREFIX):].strip()
        if runtime_arg and runtime_arg not in POC_RUNTIME_ARGS:
            POC_RUNTIME_ARGS.append(runtime_arg)


def append_exec_timeout_tester_args(
    cmd: list[str],
    timeout_ms: int | None = None,
) -> list[str]:
    effective_timeout_ms = (
        get_current_exec_timeout_ms() if timeout_ms is None else timeout_ms
    )
    if effective_timeout_ms is not None:
        cmd.append(f"--exec-timeout-ms={max(1, int(effective_timeout_ms))}")
    return cmd


def amortized_runner_exec_timeout_seconds(timeout_ms: int | None) -> int:
    effective_timeout_ms = (
        DEFAULT_EXEC_TIMEOUT_MS if timeout_ms is None else max(1, int(timeout_ms))
    )
    return max(1, (effective_timeout_ms + 999) // 1000)


def _extract_exec_time_marker_ms(output: str) -> int | None:
    match = EXEC_TIME_MARKER_PATTERN.search(output)
    if match is None:
        return None
    return int(match.group(1))


def calibrated_exec_timeout_ms_from_samples(samples_ms: list[int]) -> int | None:
    if len(samples_ms) <= CALIBRATION_WARMUP_RUNS:
        return None
    reference_ms = max(samples_ms[CALIBRATION_WARMUP_RUNS :])
    timeout_ms = max(
        CALIBRATED_EXEC_TIMEOUT_MIN_MS,
        CALIBRATED_EXEC_TIMEOUT_MULTIPLIER * reference_ms,
    )
    return min(CALIBRATED_EXEC_TIMEOUT_MAX_MS, timeout_ms)


def validate_phase3_mode(mode: str) -> str:
    if mode == PHASE3_DIRECT_ALIAS:
        return PHASE3_DIRECT
    if mode not in PHASE3_MODES:
        raise ValueError(
            f"Unsupported phase 3 compilation mode {mode!r}; "
            f"expected one of: {', '.join(sorted(PHASE3_MODES | {PHASE3_DIRECT_ALIAS}))}"
        )
    return mode


def _split_flags(flags: str | None) -> list[str]:
    return flags.split() if flags else []


def runtime_library_directories(link_flags: str | None) -> tuple[str, ...]:
    """Return absolute runtime search directories implied by linker flags."""
    tokens = _split_flags(link_flags)
    directories: list[str] = []

    def add(path_text: str) -> None:
        directory = str(Path(path_text).expanduser().resolve())
        if directory not in directories:
            directories.append(directory)

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-L" and index + 1 < len(tokens):
            add(tokens[index + 1])
            index += 2
            continue
        if token.startswith("-L") and len(token) > 2:
            add(token[2:])
        elif _is_shared_library_path(Path(token)):
            add(str(Path(token).expanduser().resolve().parent))
        index += 1
    return tuple(directories)


def runtime_library_env(
    link_flags: str | None,
    base_env: dict[str, str] | None = None,
    *,
    symbolize: bool = True,
) -> dict[str, str]:
    """Build an execution environment that can locate dynamically linked targets."""
    env = dict(base_env) if base_env is not None else os.environ.copy()
    directories = runtime_library_directories(link_flags)
    if not directories:
        return env
    if symbolize:
        from harnessreducer.symbolizer import isolate_symbolizer_environment
        isolate_symbolizer_environment(env)
    existing = env.get("LD_LIBRARY_PATH", "")
    prefix = os.pathsep.join(directories)
    env["LD_LIBRARY_PATH"] = prefix + (os.pathsep + existing if existing else "")
    return env


def sanitizer_asan_options(
    *,
    symbolize: bool,
    detect_odr_violation: bool = True,
) -> str:
    symbolized = "1" if symbolize else "0"
    options = [
        "exitcode=77",
        f"symbolize={symbolized}",
        "handle_abort=1",
    ]
    if not detect_odr_violation:
        options.append("detect_odr_violation=0")
    return ":".join(options)


def absolutize_link_flags(link_flags: str | None) -> str | None:
    """Make path-bearing link flags stable when treereduce changes cwd."""
    if not link_flags:
        return link_flags
    tokens = _split_flags(link_flags)
    normalized: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-L" and index + 1 < len(tokens):
            normalized.extend(
                ["-L", str(Path(tokens[index + 1]).expanduser().resolve())]
            )
            index += 2
            continue
        if token == "-l" and index + 1 < len(tokens):
            normalized.extend([token, tokens[index + 1]])
            index += 2
            continue
        if token.startswith("-L") and len(token) > 2:
            normalized.append(
                "-L" + str(Path(token[2:]).expanduser().resolve())
            )
        elif token.startswith("-l"):
            normalized.append(token)
        elif _is_shared_library_path(Path(token)):
            # Keep the link-time alias: without SONAME, the linker may record
            # this path in DT_NEEDED. Classification resolves the ELF separately.
            normalized.append(str(Path(token).expanduser().absolute()))
        elif token.endswith((".a", ".o", ".lo")):
            normalized.append(str(Path(token).expanduser().resolve()))
        else:
            normalized.append(token)
        index += 1
    return " ".join(normalized)


def _is_shared_library_path(path: Path) -> bool:
    return bool(re.search(r"\.so(?:\..+)?$", path.name))


def _is_static_library_path(path: Path) -> bool:
    return path.name.endswith(".a")


def _has_elf_magic(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def _resolve_linker_script_shared_library(
    path: Path,
    *,
    seen: set[Path] | None = None,
    link_aliases: list[str] | None = None,
) -> Path | None:
    candidate = path.expanduser().resolve()
    if seen is None:
        seen = set()
    if candidate in seen:
        return None
    seen.add(candidate)
    try:
        script_text = candidate.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    for match in LINKER_SCRIPT_SHARED_LIBRARY_PATTERN.finditer(script_text):
        token = match.group("path")
        referenced = Path(token)
        if not referenced.is_absolute():
            referenced = candidate.parent / referenced
        referenced_alias = referenced.expanduser()
        referenced = referenced_alias.resolve()
        if not referenced.exists():
            continue
        if _has_elf_magic(referenced):
            if link_aliases is not None:
                link_aliases.extend((token, str(referenced_alias.absolute())))
            return referenced
        nested = _resolve_linker_script_shared_library(
            referenced, seen=seen, link_aliases=link_aliases,
        )
        if nested is not None:
            return nested
    return None


def _resolve_loadable_shared_library(
    path: Path, *, link_aliases: list[str] | None = None,
) -> Path | None:
    candidate = path.expanduser().resolve()
    if _has_elf_magic(candidate):
        return candidate
    return _resolve_linker_script_shared_library(candidate, link_aliases=link_aliases)


def _dedupe_preserving_order(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _shared_library_prefix_for_name(name: str) -> str | None:
    marker = ".so"
    index = name.find(marker)
    if index < 0:
        return None
    return name[: index + len(marker)]


def _add_shared_library_name_hints(
    *,
    name: str,
    exact_names: list[str],
    soname_prefixes: list[str],
) -> None:
    if not name:
        return
    exact_names.append(name)
    prefix = _shared_library_prefix_for_name(name)
    if prefix:
        soname_prefixes.append(prefix)


def _library_names_for_link_flag(library_name: str) -> tuple[str, ...]:
    if library_name.startswith(":"):
        return (library_name[1:],)
    return (f"lib{library_name}.so",)


def _find_existing_shared_library(
    library_name: str,
    library_dirs: list[Path],
) -> Path | None:
    file_names = _library_names_for_link_flag(library_name)
    for directory in library_dirs:
        for file_name in file_names:
            candidate = directory / file_name
            if candidate.exists():
                return candidate
    return None


def _find_existing_static_library(
    library_name: str,
    library_dirs: list[Path],
) -> Path | None:
    file_names = (
        (library_name[1:],)
        if library_name.startswith(":")
        else (f"lib{library_name}.a",)
    )
    for directory in library_dirs:
        for file_name in file_names:
            candidate = directory / file_name
            if candidate.exists():
                return candidate
    return None


def _linker_mode_token(token: str) -> str | None:
    # The normal spelling is one token, e.g. -Wl,-Bstatic.  Some command
    # generators can place several linker options in the same comma-separated
    # token, so check the comma fields instead of only exact equality.
    if not token.startswith("-Wl,"):
        return None
    fields = token.split(",")[1:]
    if "-Bstatic" in fields:
        return "static"
    if "-Bdynamic" in fields:
        return "dynamic"
    return None


def _collect_link_library_dirs(tokens: list[str]) -> list[Path]:
    library_dirs: list[Path] = []
    for index, token in enumerate(tokens):
        if token == "-L" and index + 1 < len(tokens):
            library_dirs.append(Path(tokens[index + 1]).expanduser().resolve())
        elif token.startswith("-L") and len(token) > 2:
            library_dirs.append(Path(token[2:]).expanduser().resolve())
    return library_dirs


def has_static_target_libraries(link_flags: str | None) -> bool:
    """Best-effort static-library detection for user-facing warnings."""
    tokens = _split_flags(link_flags)
    library_dirs = _collect_link_library_dirs(tokens)
    prefer_static = False

    index = 0
    while index < len(tokens):
        token = tokens[index]
        mode = _linker_mode_token(token)
        if mode == "static":
            prefer_static = True
            index += 1
            continue
        if mode == "dynamic":
            prefer_static = False
            index += 1
            continue
        if token == "-L":
            index += 2
            continue
        if token.startswith("-L") and len(token) > 2:
            index += 1
            continue
        if token == "-l" and index + 1 < len(tokens):
            library_name = tokens[index + 1]
            shared = _find_existing_shared_library(library_name, library_dirs)
            static = _find_existing_static_library(library_name, library_dirs)
            if prefer_static or (static is not None and shared is None):
                return True
            index += 2
            continue
        if token.startswith("-l") and len(token) > 2:
            library_name = token[2:]
            shared = _find_existing_shared_library(library_name, library_dirs)
            static = _find_existing_static_library(library_name, library_dirs)
            if prefer_static or (static is not None and shared is None):
                return True
            index += 1
            continue
        if _is_static_library_path(Path(token)):
            return True
        index += 1
    return False


def infer_target_dynamic_library_hints(link_flags: str | None) -> DynamicLibraryHints:
    """Infer which shared libraries may represent the fuzzed target.

    Link flags give strong hints when they contain explicit .so paths or when a
    -l name can be resolved through an explicit -L directory.  If there are no
    static target libraries, unresolved -l names are also kept as weak hints so
    container/runtime search paths can still be handled from the crash output.
    """
    tokens = _split_flags(link_flags)
    if not tokens:
        return DynamicLibraryHints()

    library_dirs = _collect_link_library_dirs(tokens)
    exact_paths: list[str] = []
    exact_names: list[str] = []
    soname_prefixes: list[str] = []
    unresolved_dynamic_names: list[str] = []
    unresolved_after_explicit_dynamic_mode: list[str] = []
    saw_static_target = False
    explicit_dynamic_target = False
    prefer_static = False
    saw_explicit_dynamic_mode = False

    def add_shared_path(path: Path) -> None:
        nonlocal explicit_dynamic_target
        candidate = path.expanduser()
        resolved = candidate.resolve() if candidate.exists() else candidate
        exact_paths.append(str(resolved))
        _add_shared_library_name_hints(
            name=resolved.name,
            exact_names=exact_names,
            soname_prefixes=soname_prefixes,
        )
        explicit_dynamic_target = True

    def add_shared_link_name(library_name: str) -> None:
        for name in _library_names_for_link_flag(library_name):
            _add_shared_library_name_hints(
                name=name,
                exact_names=exact_names,
                soname_prefixes=soname_prefixes,
            )

    index = 0
    while index < len(tokens):
        token = tokens[index]
        mode = _linker_mode_token(token)
        if mode == "static":
            prefer_static = True
            index += 1
            continue
        if mode == "dynamic":
            prefer_static = False
            saw_explicit_dynamic_mode = True
            index += 1
            continue
        if token == "-L":
            index += 2
            continue
        if token.startswith("-L") and len(token) > 2:
            index += 1
            continue

        library_name: str | None = None
        if token == "-l" and index + 1 < len(tokens):
            library_name = tokens[index + 1]
            index += 2
        elif token.startswith("-l") and len(token) > 2:
            library_name = token[2:]
            index += 1
        else:
            path = Path(token)
            if _is_shared_library_path(path):
                add_shared_path(path)
            elif _is_static_library_path(path):
                saw_static_target = True
            index += 1
            continue

        if prefer_static:
            saw_static_target = True
            continue

        shared = _find_existing_shared_library(library_name, library_dirs)
        static = _find_existing_static_library(library_name, library_dirs)
        if shared is not None:
            add_shared_path(shared)
        elif static is not None:
            saw_static_target = True
        else:
            unresolved_dynamic_names.append(library_name)
            if saw_explicit_dynamic_mode:
                unresolved_after_explicit_dynamic_mode.append(library_name)

    include_unresolved = (
        unresolved_after_explicit_dynamic_mode
        if saw_static_target
        else unresolved_dynamic_names
    )
    if not explicit_dynamic_target:
        for library_name in include_unresolved:
            add_shared_link_name(library_name)

    return DynamicLibraryHints(
        exact_paths=_dedupe_preserving_order(exact_paths),
        exact_names=_dedupe_preserving_order(exact_names),
        soname_prefixes=_dedupe_preserving_order(soname_prefixes),
        allow_output_fallback=explicit_dynamic_target or bool(include_unresolved),
    )


def _normalize_library_path_for_compare(path_text: str) -> str:
    # Keep candidate checking on string operations only.  This function runs in
    # the hot path for dynamic-library offset validation, so avoid filesystem
    # metadata calls such as exists() or resolve().
    return os.path.normpath(path_text)


def _library_matches_name_or_prefix(
    library_name: str,
    *,
    exact_names: tuple[str, ...],
    soname_prefixes: tuple[str, ...],
) -> bool:
    if library_name in exact_names:
        return True
    return any(
        library_name == prefix or library_name.startswith(prefix + ".")
        for prefix in soname_prefixes
    )


def _dynamic_site_matches_hints(
    site: DynamicCrashSite,
    hints: DynamicLibraryHints,
) -> bool:
    normalized_site_path = _normalize_library_path_for_compare(site.library_path)
    if normalized_site_path in hints.exact_paths:
        return True
    return _library_matches_name_or_prefix(
        site.library_name,
        exact_names=hints.exact_names,
        soname_prefixes=hints.soname_prefixes,
    )


def _dynamic_site_matches_expected_library(
    site: DynamicCrashSite,
    expected_library: str,
) -> bool:
    expected_path = _normalize_library_path_for_compare(expected_library)
    site_path = _normalize_library_path_for_compare(site.library_path)
    if expected_path == site_path:
        return True

    expected_name = Path(expected_library).name
    prefix = _shared_library_prefix_for_name(expected_name)
    return _library_matches_name_or_prefix(
        site.library_name,
        exact_names=(expected_name,),
        soname_prefixes=(prefix,) if prefix else (),
    )


def _is_runtime_shared_library(library_name: str) -> bool:
    runtime_prefixes = (
        "ld-linux",
        "linux-vdso",
        "libasan.so",
        "libubsan.so",
        "liblsan.so",
        "libtsan.so",
        "libmsan.so",
        "libc.so",
        "libstdc++.so",
        "libgcc_s.so",
        "libpthread.so",
        "libdl.so",
        "libm.so",
        "librt.so",
        "libatomic.so",
        "libunwind.so",
    )
    return any(
        library_name == prefix or library_name.startswith(prefix + ".")
        for prefix in runtime_prefixes
    )


def _extract_shared_library_sites_from_first_trace(
    output: str,
) -> list[DynamicCrashSite]:
    trace = extract_first_sanitizer_stack_trace(output)
    if not trace:
        return []

    sites: list[DynamicCrashSite] = []
    for line in trace.splitlines():
        match = SHARED_LIBRARY_FRAME_PATTERN.search(line)
        if not match:
            continue
        library_path = match.group("library")
        sites.append(
            DynamicCrashSite(
                library_path=library_path,
                library_name=Path(library_path).name,
                offset=match.group("offset").lower(),
            )
        )
    return sites


def extract_first_dynamic_library_crash_site(
    output: str,
    link_flags: str | None = None,
    *,
    expected_library: str | None = None,
) -> DynamicCrashSite | None:
    """Extract the first relevant shared-library + offset frame.

    Only the first contiguous stack-trace block is examined.  With an expected
    library, the first frame from that library is returned.  Otherwise link
    flags are used as target-library hints, falling back to the first
    non-runtime .so frame only when the flags suggest a dynamic target but do
    not give a resolvable path.
    """
    sites = _extract_shared_library_sites_from_first_trace(output)
    if not sites:
        return None

    if expected_library:
        return next(
            (
                site
                for site in sites
                if _dynamic_site_matches_expected_library(site, expected_library)
            ),
            None,
        )

    hints = infer_target_dynamic_library_hints(link_flags)
    if hints.has_library_hints:
        matched = next(
            (site for site in sites if _dynamic_site_matches_hints(site, hints)),
            None,
        )
        if matched is not None:
            return matched

    if not hints.allow_output_fallback:
        return None

    return next(
        (
            site
            for site in sites
            if not _is_runtime_shared_library(site.library_name)
        ),
        None,
    )


def resolve_amortized_link_inputs(
    link_flags: str | None,
) -> AmortizedLinkInputs:
    """Classify target libraries for the persistent amortized-link runner."""
    tokens = _split_flags(link_flags)
    library_dirs: list[Path] = []
    for index, token in enumerate(tokens):
        if token == "-L" and index + 1 < len(tokens):
            library_dirs.append(Path(tokens[index + 1]).expanduser().resolve())
        elif token.startswith("-L") and len(token) > 2:
            library_dirs.append(Path(token[2:]).expanduser().resolve())

    shared_libraries: list[str] = []
    shared_aliases: dict[str, list[str]] = {}
    static_libraries: list[str] = []
    runner_link_flags: list[str] = []

    def add_shared_library(
        path: Path,
        *,
        fallback_flags: list[str] | None = None,
    ) -> None:
        candidate = path.expanduser().resolve()
        if not candidate.exists():
            raise ValueError(f"Shared library does not exist: {candidate}")
        if not _is_shared_library_path(candidate):
            raise ValueError(
                "--amortize-link received an unsupported shared-library input: "
                f"{candidate}"
            )
        aliases: list[str] = []
        resolved = _resolve_loadable_shared_library(candidate, link_aliases=aliases)
        if resolved == candidate:
            # The original path resolved to this ELF, so it is a verified alias.
            # A -l input can become a bare DT_NEEDED name; an explicit path must
            # retain its directory so same-basename libraries cannot cross-match.
            aliases.extend((str(path), str(path.expanduser().absolute())))
            if fallback_flags is not None:
                aliases.append(path.name)
        if resolved is not None and resolved != candidate:
            print(
                "[+] Resolved shared-library linker script for amortized-link: "
                f"{candidate} -> {resolved}"
            )
            candidate = resolved
        elif resolved is not None:
            candidate = resolved
        if resolved is None:
            if fallback_flags is not None:
                print(
                    "[+] Treating non-loadable shared-library input as normal "
                    "runner link flags for amortized-link: "
                    f"{candidate} -> {' '.join(fallback_flags)}"
                )
                runner_link_flags.extend(fallback_flags)
                return
            raise ValueError(
                "--amortize-link requires a loadable ELF shared library, but "
                f"{candidate} appears to be a linker script or another file type."
            )
        value = str(candidate)
        if value not in shared_libraries:
            shared_libraries.append(value)
        recorded = shared_aliases.setdefault(value, [])
        for alias in aliases:
            if alias not in recorded:
                recorded.append(alias)

    def add_static_library(path: Path) -> None:
        candidate = path.expanduser().resolve()
        if not candidate.exists():
            raise ValueError(f"Static library does not exist: {candidate}")
        if not _is_static_library_path(candidate):
            raise ValueError(f"Unsupported static-library input: {candidate}")
        try:
            with candidate.open("rb") as handle:
                archive_magic = handle.read(8)
        except OSError as exc:
            raise ValueError(f"Could not inspect static library {candidate}: {exc}") from exc
        if archive_magic not in {b"!<arch>\n", b"!<thin>\n"}:
            raise ValueError(
                "--amortize-link requires a valid static archive, but "
                f"{candidate} does not have an ar archive header."
            )
        value = str(candidate)
        if value not in static_libraries:
            static_libraries.append(value)

    def find_library(library_name: str, prefer_static: bool) -> Path | None:
        if library_name.startswith(":"):
            file_names = [library_name[1:]]
        elif prefer_static:
            file_names = [f"lib{library_name}.a"]
        else:
            # This matches the normal linker preference: shared first, with a
            # static archive as a fallback when no shared object is present.
            file_names = [f"lib{library_name}.so", f"lib{library_name}.a"]
        return next(
            (
                directory / file_name
                for directory in library_dirs
                for file_name in file_names
                if (directory / file_name).exists()
            ),
            None,
        )

    index = 0
    prefer_static = False
    while index < len(tokens):
        token = tokens[index]
        if token == "-Wl,-Bstatic":
            prefer_static = True
            index += 1
            continue
        if token == "-Wl,-Bdynamic":
            prefer_static = False
            index += 1
            continue
        if token == "-L":
            if index + 1 < len(tokens):
                runner_link_flags.extend(
                    ["-L", str(Path(tokens[index + 1]).expanduser().resolve())]
                )
            index += 2
            continue
        if token.startswith("-L") and len(token) > 2:
            runner_link_flags.append(
                "-L" + str(Path(token[2:]).expanduser().resolve())
            )
            index += 1
            continue
        if token == "-l" and index + 1 < len(tokens):
            library_name = tokens[index + 1]
            original_library_flags = ["-l", library_name]
            index += 2
        elif token.startswith("-l") and len(token) > 2:
            library_name = token[2:]
            original_library_flags = [token]
            index += 1
        else:
            path = Path(token)
            if token.endswith((".o", ".lo")):
                raise ValueError(
                    "--amortize-link does not support standalone object files: "
                    f"{token}"
                )
            if _is_shared_library_path(path):
                add_shared_library(path)
            elif _is_static_library_path(path):
                add_static_library(path)
            else:
                runner_link_flags.append(token)
            index += 1
            continue

        found = find_library(library_name, prefer_static)
        if found is None:
            # Keep system libraries and dependencies for the one-time runner
            # link. Preserve an explicit static request around that library.
            if prefer_static:
                runner_link_flags.append("-Wl,-Bstatic")
                runner_link_flags.extend(original_library_flags)
                runner_link_flags.append("-Wl,-Bdynamic")
            else:
                runner_link_flags.extend(original_library_flags)
        elif _is_static_library_path(found):
            add_static_library(found)
        elif _is_shared_library_path(found):
            add_shared_library(found, fallback_flags=original_library_flags)
        else:
            raise ValueError(f"Unsupported library input resolved from -l: {found}")

    # Static archives are first tried through the fast runner-export path. These
    # original flags are only used if a specific candidate fails to dlopen with
    # an unresolved symbol, which covers hidden static APIs without penalizing
    # candidates that never reference them.
    plugin_link_flags = tuple(tokens) if static_libraries else ()

    if not shared_libraries and not static_libraries:
        raise ValueError(
            "--amortize-link requires at least one target library in --link-flags."
            " Pass a full .so/.a path or use -L/path -ltarget."
        )
    return AmortizedLinkInputs(
        shared_libraries=tuple(shared_libraries),
        static_libraries=tuple(static_libraries),
        runner_link_flags=tuple(runner_link_flags),
        plugin_link_flags=plugin_link_flags,
        shared_library_inputs=tuple(
            SharedLibraryInput(library, tuple(shared_aliases[library]))
            for library in shared_libraries
        ),
    )


def _print_amortized_link_classification(link_inputs: AmortizedLinkInputs) -> None:
    print("[+] Amortized-link target shared libraries:")
    if link_inputs.shared_libraries:
        for library in link_inputs.shared_libraries:
            print(f"    {library}")
    else:
        print("    (none)")
    print("[+] Amortized-link target static libraries:")
    if link_inputs.static_libraries:
        for library in link_inputs.static_libraries:
            print(f"    {library}")
    else:
        print("    (none)")
    print("[+] Amortized-link normal runner link flags:")
    if link_inputs.runner_link_flags:
        print("    " + " ".join(link_inputs.runner_link_flags))
    else:
        print("    (none)")


def resolve_amortized_shared_libraries(link_flags: str | None) -> tuple[str, ...]:
    """Return shared targets selected for the amortized runner."""
    return resolve_amortized_link_inputs(link_flags).shared_libraries


def _read_elf_dynamic_metadata(
    elf_path: str | Path,
) -> tuple[tuple[str, ...], str | None]:
    """Return an ELF file's DT_NEEDED names and optional DT_SONAME."""
    proc = run_supervised(
        ["readelf", "-dW", str(elf_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or proc.stdout.strip() or "Unknown readelf error"
        raise RuntimeError(
            f"Failed to inspect dynamic dependencies in {elf_path}: {err_msg}"
        )
    needed = tuple(
        match.group("name") for match in ELF_NEEDED_PATTERN.finditer(proc.stdout)
    )
    soname_match = ELF_SONAME_PATTERN.search(proc.stdout)
    soname = soname_match.group("name") if soname_match is not None else None
    return needed, soname


def filter_amortized_shared_libraries_for_reference(
    link_inputs: AmortizedLinkInputs,
    reference_executable: str | Path | None,
) -> AmortizedLinkInputs:
    """Keep only shared inputs retained by the original harness link.

    Stateful linker flags such as ``--as-needed`` can cause the original
    executable to discard some explicitly listed DSOs.  The persistent runner
    has no direct references to target symbols, so its required DSO set cannot
    be inferred by relinking the runner.  The already validated original
    executable is the authoritative record of which direct dynamic inputs the
    linker selected.

    A missing-SONAME input may be recorded under a verified link alias rather
    than its canonical filename. Such aliases never override SONAME matching.

    Static archives are deliberately left unchanged.  Their member selection
    is handled separately by the static-root planning path.
    """
    if reference_executable is None or not link_inputs.shared_libraries:
        return link_inputs

    needed, _ = _read_elf_dynamic_metadata(reference_executable)
    needed_names = set(needed)
    needed_basenames = {Path(name).name for name in needed}
    retained: list[str] = []
    needed_alias_owners: dict[str, set[str]] | None = None
    for library in link_inputs.shared_libraries:
        library_path = Path(library)
        _, soname = _read_elf_dynamic_metadata(library_path)
        if (
            str(library_path) in needed_names
            or library_path.name in needed_names
            or library_path.name in needed_basenames
            or (soname is not None and soname in needed_names)
        ):
            retained.append(library)
        elif soname is None and link_inputs.shared_library_inputs:
            # Only unmatched, missing-SONAME inputs need the alias fallback.
            # Keep exact link identities, not guessed basenames/version prefixes.
            if needed_alias_owners is None:
                alias_owners: dict[str, set[str]] = {}
                for shared in link_inputs.shared_library_inputs:
                    for alias in shared.link_aliases:
                        alias_owners.setdefault(alias, set()).add(shared.load_path)
                needed_alias_owners = {}
                for name in needed:
                    owners = alias_owners.get(name)
                    if owners is None and not Path(name).is_absolute():
                        # The reference was linked before relative input paths
                        # were made absolute for treereduce's changed cwd.
                        owners = alias_owners.get(str(Path(name).absolute()))
                    if owners is not None:
                        needed_alias_owners[name] = owners
            matched_alias = next(
                (name for name in needed if needed_alias_owners.get(name) == {library}),
                None,
            )
            if matched_alias is not None:
                retained.append(library)
                print(
                    "[+] Retained shared library without DT_SONAME via verified link alias: "
                    f"{matched_alias} -> {library}"
                )

    return AmortizedLinkInputs(
        shared_libraries=tuple(retained),
        static_libraries=link_inputs.static_libraries,
        runner_link_flags=link_inputs.runner_link_flags,
        plugin_link_flags=link_inputs.plugin_link_flags,
        shared_library_inputs=tuple(
            shared for shared in link_inputs.shared_library_inputs
            if shared.load_path in retained
        ),
    )


def runner_dynamic_dependency_link_flags(
    link_inputs: AmortizedLinkInputs,
) -> list[str]:
    """Return one-time runner flags that retain dynamic dependencies.

    The runner may not directly reference symbols from target DSOs or their
    helper libraries.  Without --no-as-needed, the linker can omit them from the
    runner's DT_NEEDED list, leaving a later dlopen(target.so, RTLD_NOW) unable
    to resolve helper symbols such as libpcap's nl_socket_alloc.
    """
    dynamic_flags = [*link_inputs.shared_libraries, *link_inputs.runner_link_flags]
    if not dynamic_flags:
        return []
    if not link_inputs.shared_libraries:
        return list(link_inputs.runner_link_flags)
    return ["-Wl,--no-as-needed", *dynamic_flags, "-Wl,--as-needed"]


def _nm_posix_symbols(
    command: list[str],
    error_prefix: str,
    symbol_types: set[str] | None = None,
) -> set[str]:
    proc = run_supervised(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or proc.stdout.strip() or "Unknown nm error"
        raise RuntimeError(f"{error_prefix}: {err_msg}")

    symbols: set[str] = set()
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.endswith(":"):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and (
            symbol_types is None or parts[1] in symbol_types
        ):
            symbols.add(parts[0])
    return symbols


def undefined_symbols_from_object(object_path: str | Path) -> tuple[str, ...]:
    symbols = _nm_posix_symbols(
        ["nm", "-u", "--format=posix", str(object_path)],
        f"Failed to inspect undefined symbols in {object_path}",
        symbol_types={"U"},
    )
    return tuple(sorted(symbols))


def defined_symbols_from_static_libraries(
    static_libraries: tuple[str, ...],
) -> tuple[str, ...]:
    if not static_libraries:
        return ()
    symbols = _nm_posix_symbols(
        ["nm", "--defined-only", "--format=posix", *static_libraries],
        "Failed to inspect symbols in static target libraries",
    )
    return tuple(sorted(symbols))


def static_archive_root_symbols_from_object(
    object_path: str | Path,
    static_libraries: tuple[str, ...],
) -> tuple[str, ...]:
    if not static_libraries:
        return ()
    undefined_symbols = set(undefined_symbols_from_object(object_path))
    defined_symbols = set(defined_symbols_from_static_libraries(static_libraries))
    return tuple(sorted(undefined_symbols & defined_symbols))


def _archive_magic(path: str | Path) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            return handle.read(8)
    except OSError:
        return b""


def _llvm_objcopy_supports_symbol_visibility(objcopy: str) -> bool:
    proc = run_supervised(
        [objcopy, "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return proc.returncode == 0 and "--set-symbols-visibility" in proc.stdout


def _prepare_visibility_exported_static_libraries(
    static_libraries: tuple[str, ...],
    root_symbols: tuple[str, ...],
    *,
    export_dir: str | Path | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...], int]:
    if not static_libraries or not root_symbols:
        return static_libraries, (), 0

    objcopy = shutil.which("llvm-objcopy")
    if objcopy is None or not _llvm_objcopy_supports_symbol_visibility(objcopy):
        return static_libraries, (), 0

    root_symbol_set = set(root_symbols)
    output_root = Path(export_dir) if export_dir is not None else Path(get_work_dir())
    output_dir = output_root / f"amortized_static_exports_{time.time_ns()}"
    rewritten_libraries: list[str] = []
    visibility_exported_libraries: list[str] = []
    exported_symbol_count = 0

    for index, library in enumerate(static_libraries):
        library_path = Path(library)
        if _archive_magic(library_path) != b"!<arch>\n":
            rewritten_libraries.append(library)
            continue

        try:
            library_symbols = set(defined_symbols_from_static_libraries((library,)))
        except RuntimeError:
            rewritten_libraries.append(library)
            continue

        exported_symbols = tuple(sorted(root_symbol_set & library_symbols))
        if not exported_symbols:
            rewritten_libraries.append(library)
            continue

        output_dir.mkdir(parents=True, exist_ok=True)
        symbol_file = output_dir / f"{index}_{library_path.name}.symbols"
        rewritten_library = output_dir / f"{index}_{library_path.name}"
        symbol_file.write_text("\n".join(exported_symbols) + "\n", encoding="utf-8")
        proc = run_supervised(
            [
                objcopy,
                f"--set-symbols-visibility={symbol_file}=default",
                str(library_path),
                str(rewritten_library),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not rewritten_library.exists():
            rewritten_libraries.append(library)
            continue

        rewritten_libraries.append(str(rewritten_library))
        visibility_exported_libraries.append(str(rewritten_library))
        exported_symbol_count += len(exported_symbols)

    return (
        tuple(rewritten_libraries),
        tuple(visibility_exported_libraries),
        exported_symbol_count,
    )


def plan_static_archive_runner_link(
    link_inputs: AmortizedLinkInputs,
    static_root_object: str | Path | None = None,
    *,
    export_dir: str | Path | None = None,
) -> StaticArchiveLinkPlan:
    if not link_inputs.static_libraries:
        return StaticArchiveLinkPlan(flags=(), root_symbols=(), uses_whole_archive=False)

    if static_root_object is not None:
        root_symbols = static_archive_root_symbols_from_object(
            static_root_object,
            link_inputs.static_libraries,
        )
        if root_symbols:
            (
                static_libraries,
                visibility_exported_libraries,
                visibility_exported_symbol_count,
            ) = _prepare_visibility_exported_static_libraries(
                link_inputs.static_libraries,
                root_symbols,
                export_dir=export_dir,
            )
            flags: list[str] = [
                "-no-pie",
                "-Wl,--export-dynamic",
                *(f"-Wl,-u,{symbol}" for symbol in root_symbols),
                *static_libraries,
            ]
            return StaticArchiveLinkPlan(
                flags=tuple(flags),
                root_symbols=root_symbols,
                uses_whole_archive=False,
                visibility_exported_libraries=visibility_exported_libraries,
                visibility_exported_symbol_count=visibility_exported_symbol_count,
            )

    return StaticArchiveLinkPlan(
        flags=(
            "-no-pie",
            "-Wl,--export-dynamic",
            "-Wl,--whole-archive",
            *link_inputs.static_libraries,
            "-Wl,--no-whole-archive",
        ),
        root_symbols=(),
        uses_whole_archive=True,
    )


def amortized_runner_link_tail(
    link_inputs: AmortizedLinkInputs,
    static_root_object: str | Path | None = None,
    *,
    export_dir: str | Path | None = None,
) -> list[str]:
    static_plan = plan_static_archive_runner_link(
        link_inputs,
        static_root_object,
        export_dir=export_dir,
    )
    return [
        *static_plan.flags,
        *runner_dynamic_dependency_link_flags(link_inputs),
    ]


def compile_static_archive_root_object(config: StaticArchiveRootConfig) -> str:
    output = Path(get_work_dir()) / f"amortized_static_roots_{time.time_ns()}.o"
    cmd = ["clang++", "-Qunused-arguments"]
    if config.pch_path is not None:
        cmd.extend(["-include-pch", config.pch_path])
        opt_flags = PHASE3_PCH_OPT_FLAGS
    else:
        opt_flags = PHASE3_SPLIT_OPT_FLAGS
    cmd.extend(
        [
            *_phase3_replay_flags(
                config.use_replay,
                external_replay_runtime=config.use_replay,
            ),
            *PHASE3_PLUGIN_SANITIZER_FLAGS,
            *opt_flags,
            *PHASE3_WARNING_FLAGS,
            "-fPIC",
            "-c",
            *_split_flags(config.compile_flags),
            config.source,
            "-o",
            str(output),
        ]
    )
    run_command(cmd, "Failed to compile static-archive root object")
    return str(output)


def _compile_harness_runner(
    link_inputs: AmortizedLinkInputs,
    static_root_config: StaticArchiveRootConfig | None = None,
) -> str:
    source = SCRIPT_DIR / HARNESS_RUNNER_SOURCE_NAME
    replay_runtime_source = SCRIPT_DIR / FDP_REPLAY_RUNTIME_SOURCE_NAME
    output = Path(get_work_dir()) / HARNESS_RUNNER_BINARY_NAME
    static_root_object = (
        compile_static_archive_root_object(static_root_config)
        if static_root_config is not None and link_inputs.static_libraries
        else None
    )
    link_tail = amortized_runner_link_tail(link_inputs, static_root_object)
    run_command(
        [
            "clang++",
            "-std=c++17",
            f"-I{get_fdp_header_dir()}",
            *PHASE3_PLUGIN_SANITIZER_FLAGS,
            "-O1",
            "-gline-tables-only",
            "-fno-omit-frame-pointer",
            "-Wl,--export-dynamic",
            str(source),
            str(replay_runtime_source),
            *link_tail,
            "-ldl",
            "-o",
            str(output),
        ],
        "Failed to compile amortized-link runner",
    )
    return str(output)


@contextmanager
def start_amortized_runner(
    link_flags: str | None,
    crash_input: str | None,
    fdp_trace_file: str | None,
    *,
    symbolize: bool,
    static_root_config: StaticArchiveRootConfig | None = None,
    exec_timeout_ms: int | None = None,
    reference_executable: str | Path | None = None,
    reuse_binary: str | None = None,
):
    unfiltered_link_inputs = resolve_amortized_link_inputs(link_flags)
    link_inputs = filter_amortized_shared_libraries_for_reference(
        unfiltered_link_inputs,
        reference_executable,
    )
    if len(link_inputs.shared_libraries) != len(
        unfiltered_link_inputs.shared_libraries
    ):
        print(
            "[+] Original harness dependency filtering retained "
            f"{len(link_inputs.shared_libraries)} of "
            f"{len(unfiltered_link_inputs.shared_libraries)} shared libraries "
            "for the amortized runner."
        )
    _print_amortized_link_classification(link_inputs)
    shared_libraries = link_inputs.shared_libraries
    runner_binary = reuse_binary or _compile_harness_runner(link_inputs, static_root_config)
    socket_dir = tempfile.mkdtemp(prefix="harness_runner_")
    socket_path = str(Path(socket_dir) / "runner.sock")
    env = runtime_library_env(link_flags, symbolize=symbolize)
    env["HARNESSREDUCER_RUNNER_PARENT_PID"] = str(os.getpid())
    symbolized = "1" if symbolize else "0"
    env["ASAN_OPTIONS"] = sanitizer_asan_options(
        symbolize=symbolize,
        detect_odr_violation=False,
    )
    env["UBSAN_OPTIONS"] = (
        f"exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize={symbolized}"
    )
    from harnessreducer.oracle_evaluation import reference_root
    if symbolize and reference_root() is not None:
        from harnessreducer.oracle_paired_execution import configure_symbolized_environment
        configure_symbolized_environment(env)
    if fdp_trace_file is not None:
        env["FDP_TRACE_PATH"] = fdp_trace_file
        env["FDP_WIDE_TRACE_PATH"] = fdp_wide_trace_path(fdp_trace_file)
    else:
        env.pop("FDP_TRACE_PATH", None)
        env.pop("FDP_WIDE_TRACE_PATH", None)
    library_dirs = tuple(dict.fromkeys(str(Path(path).parent) for path in shared_libraries))
    if library_dirs:
        if symbolize:
            from harnessreducer.symbolizer import isolate_symbolizer_environment
            isolate_symbolizer_environment(env)
        existing = env.get("LD_LIBRARY_PATH", "")
        prefix = os.pathsep.join(library_dirs)
        env["LD_LIBRARY_PATH"] = prefix + (os.pathsep + existing if existing else "")

    process = subprocess.Popen(
        [
            runner_binary,
            socket_path,
            crash_input or "",
            str(amortized_runner_exec_timeout_seconds(exec_timeout_ms)),
            *shared_libraries,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    deadline = time.monotonic() + 15.0
    try:
        while not os.path.exists(socket_path):
            return_code = process.poll()
            if return_code is not None:
                terminate_process_group(process)
                stdout, stderr = process.communicate(timeout=1)
                raise RuntimeError(
                    "Amortized-link runner failed during startup:\n"
                    f"{stdout}{stderr}\n"
                    "If the persistent runner cannot load this dependency set, "
                    "rerun without --amortize-link."
                )
            if time.monotonic() >= deadline:
                raise RuntimeError("Timed out waiting for amortized-link runner socket.")
            time.sleep(0.02)
        yield AmortizedRunner(
            socket_path=socket_path,
            process=process,
            shared_libraries=shared_libraries,
            static_libraries=link_inputs.static_libraries,
            plugin_link_flags=link_inputs.plugin_link_flags,
        )
    finally:
        terminate_process_group(process)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


def run_amortized_reference_candidate(
    harness_path: str,
    fdp_trace_file: str | None,
    crash_pattern: str,
    compile_flags: str | None,
    link_flags: str | None,
    crash_input: str | None,
    phase3_mode: str,
    runner_socket: str,
    pch_artifacts: PchArtifacts | None,
    plugin_link_flags: tuple[str, ...] = (),
    *,
    symbolize: bool,
    require_crash_pattern: bool = True,
    auto_var_init_pattern: bool = False,
) -> str:
    cmd = [
        get_crash_tester_path(),
        pch_artifacts.body_source if pch_artifacts is not None else harness_path,
        crash_pattern,
        "--crash-input",
        crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
        "--amortized-runner-socket",
        runner_socket,
    ]
    if fdp_trace_file:
        cmd.extend(["--fdp-trace", fdp_trace_file])
    if plugin_link_flags:
        cmd.append(
            f"--amortized-plugin-fallback-link-flags={' '.join(plugin_link_flags)}"
        )
    if symbolize:
        cmd.append("--symbolize")
        cmd.extend(symbolized_crash_location_tester_args())
    else:
        cmd.extend(dynamic_crash_site_tester_args())
    if not require_crash_pattern:
        cmd.append("--skip-crash-pattern")
    cmd.extend(auto_var_init_tester_args(auto_var_init_pattern))
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    append_exec_timeout_tester_args(cmd)
    proc = run_command(
        cmd,
        "Amortized-link reference candidate failed",
        ignore_errors=True,
    )
    output = proc.stdout + proc.stderr
    if proc.returncode != 77:
        raise RuntimeError(
            "The original harness did not preserve the crash in amortized-link mode.\n"
            f"{output}"
        )
    return output


def _phase3_replay_flags(
    use_replay: bool,
    *,
    external_replay_runtime: bool = False,
) -> list[str]:
    if not use_replay:
        return []
    flags = [f"-I{get_fdp_header_dir()}", "-DFDP_MIN_MODE_REPLAY"]
    if external_replay_runtime:
        flags.append("-DFDP_MIN_EXTERNAL_REPLAY_RUNTIME")
    return flags


def _build_pch_compile_command(
    prefix_header: str,
    pch_file: str,
    compile_flags: str | None,
    use_replay: bool,
    amortize_link: bool = False,
    auto_var_init_pattern: bool = False,
) -> list[str]:
    sanitizer_flags = (
        PHASE3_PLUGIN_SANITIZER_FLAGS if amortize_link else PHASE3_SANITIZER_FLAGS
    )
    cmd = [
        "clang++",
        "-Qunused-arguments",
        *_phase3_replay_flags(
            use_replay,
            external_replay_runtime=use_replay and amortize_link,
        ),
        *sanitizer_flags,
        *PHASE3_PCH_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
        *([AUTO_VAR_INIT_PATTERN_FLAG] if auto_var_init_pattern else []),
        *(["-fPIC"] if amortize_link else []),
        "-x",
        "c++-header",
        *_split_flags(compile_flags),
        prefix_header,
        "-o",
        pch_file,
    ]
    return cmd


_INCLUDE_DIRECTIVE_PATTERN = re.compile(r"^\s*#\s*include\b")
_QUOTED_INCLUDE_PATTERN = re.compile(r'^(\s*#\s*include\s*)"([^"]+)"(.*)$')
_PREPROCESSOR_DIRECTIVE_PATTERN = re.compile(r"^\s*#\s*([A-Za-z_]\w*)")
_BLOCK_COMMENT_START_PATTERN = re.compile(r"^\s*/\*")
_BLOCK_COMMENT_END_PATTERN = re.compile(r"\*/")
_LINE_COMMENT_PATTERN = re.compile(r"^\s*//")
_BLOCK_COMMENT_CONTINUATION_PATTERN = re.compile(r"^\s*(?:\*|/\*)")
_PREPROCESSOR_CONDITIONAL_OPENERS = {"if", "ifdef", "ifndef"}


def _preprocessor_directive_keyword(line: str) -> str | None:
    match = _PREPROCESSOR_DIRECTIVE_PATTERN.match(line)
    if match is None:
        return None
    return match.group(1)


def _classify_prologue_line(line: str, in_block_comment: bool) -> tuple[str, bool]:
    stripped = line.strip()
    if in_block_comment:
        if _BLOCK_COMMENT_END_PATTERN.search(line):
            trailing = line.split("*/", 1)[1].strip()
            if trailing:
                if trailing.startswith("#"):
                    return "preprocessor", False
                if trailing.startswith("//"):
                    return "comment", False
                return "code", False
            return "comment", False
        return "comment", True
    if not stripped:
        return "blank", False
    if _LINE_COMMENT_PATTERN.match(line):
        return "comment", False
    if _BLOCK_COMMENT_START_PATTERN.match(line):
        if _BLOCK_COMMENT_END_PATTERN.search(line):
            trailing = line.split("*/", 1)[1].strip()
            if trailing:
                if trailing.startswith("#"):
                    return "preprocessor", False
                if trailing.startswith("//"):
                    return "comment", False
                return "code", False
            return "comment", False
        return "comment", True
    if _BLOCK_COMMENT_CONTINUATION_PATTERN.match(line):
        return "comment", _BLOCK_COMMENT_END_PATTERN.search(line) is None
    if _preprocessor_directive_keyword(line) is not None:
        return "preprocessor", False
    return "code", False


def _extract_pch_move_region(lines: list[str]) -> tuple[list[str], list[str]]:
    """Split the initial include prologue from the body for PCH mode.

    We move the initial preprocessor/include region that precedes the first
    non-comment, non-blank code line, but stop before trailing post-include
    macros once the last include-related conditional closes.
    """

    prologue_end = 0
    in_block_comment = False
    for index, line in enumerate(lines):
        kind, in_block_comment = _classify_prologue_line(line, in_block_comment)
        if kind == "code":
            prologue_end = index
            break
    else:
        prologue_end = len(lines)

    prologue = lines[:prologue_end]
    remainder = lines[prologue_end:]
    include_indices = [
        index for index, line in enumerate(prologue)
        if _INCLUDE_DIRECTIVE_PATTERN.match(line)
    ]
    if not include_indices:
        return [], lines

    last_include_index = include_indices[-1]
    conditional_depth = 0
    move_end_index = last_include_index
    for index, line in enumerate(prologue):
        directive = _preprocessor_directive_keyword(line)
        if directive in _PREPROCESSOR_CONDITIONAL_OPENERS:
            conditional_depth += 1
        elif directive == "endif" and conditional_depth > 0:
            conditional_depth -= 1
        if index >= last_include_index:
            move_end_index = index
            if conditional_depth == 0:
                break

    moved_lines = prologue[: move_end_index + 1]
    body_lines = prologue[move_end_index + 1 :] + remainder
    return moved_lines, body_lines


def _rewrite_local_quoted_include_for_pch(line: str, source_dir: Path) -> str:
    """Preserve quote-include semantics after moving includes into the work dir.

    Direct compilation resolves #include "local.h" relative to the source file
    first. The generated harness_prefix.h lives in the reducer work directory, so a
    plain copy of that line could accidentally change the lookup root.  If the
    quoted header exists relative to the source being split, rewrite it to the
    resolved absolute path inside the PCH prefix.  The final restored harness
    still receives the original include spelling.
    """

    line_without_newline = line.rstrip("\r\n")
    newline = line[len(line_without_newline):]
    match = _QUOTED_INCLUDE_PATTERN.match(line_without_newline)
    if not match:
        return line

    include_name = match.group(2)
    if os.path.isabs(include_name):
        return line

    local_header = (source_dir / include_name).resolve()
    if not local_header.exists():
        return line

    escaped_header = str(local_header).replace("\\", "\\\\").replace('"', '\\"')
    return f'{match.group(1)}"{escaped_header}"{match.group(3)}{newline}'


def _split_source_for_pch(source: str, source_dir: Path) -> tuple[str, str, str]:
    """Return (pch_prefix, restore_prefix, include-stripped_body)."""

    standard_include_keys = {"#include <stdint.h>", "#include <stddef.h>"}
    lines = source.splitlines(keepends=True)
    moved_lines, body_lines = _extract_pch_move_region(lines)
    pch_prefix_lines = ["// Generated by HarnessReducer for Phase 3 PCH compilation.\n"]
    restore_prefix_lines: list[str] = []

    first_include_index = next(
        (index for index, line in enumerate(moved_lines) if _INCLUDE_DIRECTIVE_PATTERN.match(line)),
        len(moved_lines),
    )
    pre_include_lines = moved_lines[:first_include_index]
    include_region_lines = moved_lines[first_include_index:]

    for line in pre_include_lines:
        pch_prefix_lines.append(line)
        restore_prefix_lines.append(line)

    pch_prefix_lines.extend(["#include <stdint.h>\n", "#include <stddef.h>\n"])
    restore_prefix_lines.extend(["#include <stdint.h>\n", "#include <stddef.h>\n"])

    for line in include_region_lines:
        if _INCLUDE_DIRECTIVE_PATTERN.match(line):
            if line.strip() in standard_include_keys:
                continue
            pch_prefix_lines.append(_rewrite_local_quoted_include_for_pch(line, source_dir))
            restore_prefix_lines.append(line)
            continue
        pch_prefix_lines.append(line)
        restore_prefix_lines.append(line)

    return (
        "".join(pch_prefix_lines),
        "".join(restore_prefix_lines),
        "".join(body_lines),
    )


def prepare_phase3_pch_harness(
    harness_path: str,
    compile_flags: str | None,
    use_replay: bool,
    amortize_link: bool = False,
    auto_var_init_pattern: bool = False,
) -> PchArtifacts:
    """Create harness_prefix.h/.pch and an include-stripped harness body.

    The PCH is compiled with Phase 3's conditional replay flags when
    ``use_replay`` is true.  The candidate body is what should be passed to
    crash_tester.py with ``--pch --pch-path <pch>``.
    """

    source_path = Path(harness_path)
    source = source_path.read_text(encoding="utf-8", errors="ignore")
    pch_prefix, restore_prefix, body = _split_source_for_pch(source, source_path.parent)

    work_dir = Path(get_work_dir())
    prefix_header = work_dir / PCH_PREFIX_HEADER_NAME
    pch_file = work_dir / PCH_PREFIX_FILE_NAME
    suffix = source_path.suffix or ".cpp"
    body_source = work_dir / f"{source_path.stem}.harness_body{suffix}"

    prefix_header.write_text(pch_prefix, encoding="utf-8")
    body_source.write_text(body, encoding="utf-8")

    compile_cmd = _build_pch_compile_command(
        str(prefix_header),
        str(pch_file),
        compile_flags,
        use_replay=use_replay,
        amortize_link=amortize_link,
        auto_var_init_pattern=auto_var_init_pattern,
    )
    print(f"[+] Precompiling Phase 3 header: {prefix_header} -> {pch_file}")
    run_command(compile_cmd, "Failed to precompile Phase 3 PCH header")
    print(f"[+] Wrote include-stripped Phase 3 harness body: {body_source}")

    return PchArtifacts(
        body_source=str(body_source),
        prefix_header=str(prefix_header),
        pch_file=str(pch_file),
        restore_prefix=restore_prefix,
        amortize_link=amortize_link,
    )


def restore_pch_includes(harness_path: str, artifacts: PchArtifacts) -> None:
    """Prepend the moved include directives back to a reduced body harness."""

    if not artifacts.restore_prefix:
        return
    path = Path(harness_path)
    body = path.read_text(encoding="utf-8", errors="ignore")
    path.write_text(artifacts.restore_prefix + body, encoding="utf-8")


def pch_tester_args(artifacts: PchArtifacts | None, phase3_mode: str) -> list[str]:
    mode = validate_phase3_mode(phase3_mode)
    if mode == PHASE3_DIRECT:
        return ["--single-step"]
    if mode == PHASE3_SPLIT:
        return ["--split"]
    if artifacts is None:
        raise ValueError("PCH Phase 3 mode requires prepared PCH artifacts.")
    args = ["--pch", "--pch-path", artifacts.pch_file]
    if artifacts.amortize_link:
        args.append("--pch-amortized-link")
    return args


def configure_work_dir(work_dir: str | None) -> str:
    global TREEDUCER_DIR, _IS_USER_WORK_DIR

    if work_dir:
        path = str(Path(work_dir).expanduser().resolve())
        Path(path).mkdir(parents=True, exist_ok=True)
        TREEDUCER_DIR = path
        _IS_USER_WORK_DIR = True
        return TREEDUCER_DIR

    if TREEDUCER_DIR is None:
        TREEDUCER_DIR = tempfile.mkdtemp(prefix="harness_reducer_")
        _IS_USER_WORK_DIR = False
    return TREEDUCER_DIR


def get_work_dir() -> str:
    return configure_work_dir(None)


@contextmanager
def isolated_attempt_work_dir(path: Path):
    """Temporarily switch artifacts, preserving original reference globals."""
    global TREEDUCER_DIR, _IS_USER_WORK_DIR
    previous = TREEDUCER_DIR, _IS_USER_WORK_DIR
    configure_work_dir(str(path))
    try:
        yield
    finally:
        TREEDUCER_DIR, _IS_USER_WORK_DIR = previous


def configure_debug_logging(enabled: bool) -> str | None:
    global REDUCTION_DEBUG_LOG_PATH

    if not enabled:
        REDUCTION_DEBUG_LOG_PATH = None
        return None

    debug_log_path = str(Path(get_work_dir()) / DEBUG_LOG_FILE_NAME)
    Path(debug_log_path).write_text(
        "===== HarnessMinimizer normal-path reduction debug log =====\n"
        "Candidate records can be out of order because treereduce-c runs "
        "multiple workers concurrently.\n",
        encoding="utf-8",
    )
    REDUCTION_DEBUG_LOG_PATH = debug_log_path
    print(f"[DEBUG] Reduction candidate log: {debug_log_path}")
    return debug_log_path


def get_debug_log_path() -> str | None:
    return REDUCTION_DEBUG_LOG_PATH


def debug_tester_args(stage: str) -> list[str]:
    if REDUCTION_DEBUG_LOG_PATH is None:
        return []
    return [
        "--debug-log",
        REDUCTION_DEBUG_LOG_PATH,
        "--debug-stage",
        stage,
    ]


def retry_oom_tester_args(enabled: bool) -> list[str]:
    if not enabled:
        return []
    return ["--retry-oom-without-rss-limit"]


def evidence_attempt_tester_args(attempts: int | None) -> list[str]:
    if attempts is None:
        return []
    return ["--evidence-attempts", str(max(1, attempts))]


def auto_var_init_tester_args(enabled: bool) -> list[str]:
    return ["--auto-var-init-pattern"] if enabled else []


def run_command(cmd: list[str], error_prefix: str, env: dict[str, str] | None = None, ignore_errors: bool = False) -> subprocess.CompletedProcess[str]:
    proc = run_supervised(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
        timeout=DEFAULT_COMMAND_TIMEOUT + 310,
    )
    if proc.returncode != 0 and not ignore_errors:
        err_msg = proc.stderr.strip() or proc.stdout.strip() or "Unknown error"
        raise RuntimeError(f"{error_prefix}: {err_msg}")
    return proc


def _run_restore_transition_stack_diagnostic(
    source_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    fdp_trace_file: str | None,
    *,
    phase3_mode: str,
    pch_artifacts: PchArtifacts | None,
    symbolize: bool,
    debug_stage: str,
    retry_oom_without_rss_limit: bool = False,
) -> tuple[int, str, str | None]:
    cmd = [
        get_crash_tester_path(),
        source_path,
        crash_pattern,
        "--crash-input",
        crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
    ]
    if fdp_trace_file:
        cmd.extend(["--fdp-trace", fdp_trace_file])
    if symbolize:
        cmd.append("--symbolize")
    cmd.extend(debug_tester_args(debug_stage))
    cmd.extend(retry_oom_tester_args(retry_oom_without_rss_limit))
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    append_exec_timeout_tester_args(cmd)

    proc = run_command(
        cmd,
        "Restore-transition stack diagnostic failed",
        ignore_errors=True,
    )
    output = proc.stdout + "\n" + proc.stderr
    return proc.returncode, output, extract_first_sanitizer_stack_trace(output)


def _append_restore_transition_stack_diagnostics(
    log_path: str,
    *,
    section_label: str,
    source_path: str,
    phase3_mode: str,
    pch_artifacts: PchArtifacts | None,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    fdp_trace_file: str | None,
    crash_pattern_symbolize_0: str | None,
    crash_pattern_symbolize_1: str | None,
    retry_oom_without_rss_limit: bool = False,
) -> None:
    expected_dynamic_site = get_dynamic_reference_crash_site()
    lines = [
        f"\n--- {section_label}: {source_path} ---",
        f"phase3_mode: {phase3_mode}",
    ]
    if expected_dynamic_site is not None:
        lines.extend(
            [
                "expected_dynamic_crash_site:",
                f"  library: {expected_dynamic_site.library_path}",
                f"  offset: {expected_dynamic_site.offset}",
            ]
        )

    for symbolize in (False, True):
        pattern = (
            crash_pattern_symbolize_1 or crash_pattern_symbolize_0 or ".*"
            if symbolize
            else crash_pattern_symbolize_0 or crash_pattern_symbolize_1 or ".*"
        )
        returncode, output, trace = _run_restore_transition_stack_diagnostic(
            source_path,
            pattern,
            crash_input,
            compile_flags,
            link_flags,
            fdp_trace_file,
            phase3_mode=phase3_mode,
            pch_artifacts=pch_artifacts,
            symbolize=symbolize,
            debug_stage=(
                f"post_reduction_{section_label}_symbolize_{int(symbolize)}"
            ),
            retry_oom_without_rss_limit=retry_oom_without_rss_limit,
        )
        mode_label = f"symbolize={int(symbolize)}"
        lines.append(f"{mode_label} returncode: {returncode}")
        if expected_dynamic_site is not None:
            actual_site = extract_first_dynamic_library_crash_site(
                output,
                link_flags,
                expected_library=expected_dynamic_site.library_path,
            )
            if actual_site is None:
                lines.append(f"{mode_label} dynamic_crash_site: <not found>")
            else:
                lines.append(
                    f"{mode_label} dynamic_crash_site: "
                    f"{actual_site.library_path}+{actual_site.offset}"
                )
        lines.append(f"{mode_label} first_stack_trace:")
        lines.append(trace if trace else "<no-first-stack-trace-found>")

    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def check_tree_reducer() -> None:
    print("[+] Checking for tree-reducer availability...")
    run_command(
        [treereduce_binary(), "--help"],
        "tree-reducer is not available. Run python3 tools/treereduce/install.py or configure HARNESSREDUCER_TREEREDUCE",
    )
    print("[+] tree-reducer is available.")


def reference_harness_compile_command(
    harness_path: str,
    compile_flags: str | None,
    link_flags: str | None,
    output_bin: str,
) -> list[str]:
    return [
        "clang++",
        "-fsanitize=address,fuzzer,undefined",
        *PHASE3_DIRECT_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
        *_split_flags(compile_flags),
        harness_path,
        "-o",
        output_bin,
        *_split_flags(link_flags),
    ]


def check_harness_compilation(
    harness_path: str,
    compile_flags: str | None,
    link_flags: str | None,
) -> None:
    print("[+] Checking harness compilation...")
    work_dir = get_work_dir()
    output_bin = os.path.join(work_dir, "poc.out")
    compile_cmd = reference_harness_compile_command(
        harness_path,
        compile_flags,
        link_flags,
        output_bin,
    )

    run_command(compile_cmd, "Failed to compile the original harness. Please fix compilation errors before reduction.")
    print("[+] Harness compiles successfully.")


def compile_coverage_harness(
    harness_path: str,
    compile_flags: str | None,
    link_flags: str | None,
) -> str:
    """Compile a source-coverage-instrumented harness binary for pre-slicing."""
    work_dir = get_work_dir()
    output_bin = os.path.join(work_dir, COVERAGE_BIN_FILE_NAME)
    driver_source = Path(work_dir) / COVERAGE_DRIVER_FILE_NAME
    driver_source.write_text(
        """
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <sanitizer/common_interface_defs.h>
#include <string>
#include <vector>

extern "C" int __llvm_profile_write_file(void);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void coverageDeathCallback() {
    __llvm_profile_write_file();
}

int main(int argc, char **argv) {
    __sanitizer_set_death_callback(coverageDeathCallback);
    std::vector<uint8_t> data;
    if (argc > 1 && argv[1] != nullptr && argv[1][0] != '\\0') {
        std::ifstream input(argv[1], std::ios::binary);
        data.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }
    const int result = LLVMFuzzerTestOneInput(data.empty() ? nullptr : data.data(), data.size());
    __llvm_profile_write_file();
    return result;
}
""".lstrip(),
        encoding="utf-8",
    )
    compile_cmd = [
        "clang++",
        "-fsanitize=address,undefined,fuzzer-no-link",
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
        *PHASE3_DIRECT_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
        *_split_flags(compile_flags),
        harness_path,
        str(driver_source),
        "-o",
        output_bin,
        *_split_flags(link_flags),
    ]
    run_command(compile_cmd, "Failed to compile coverage-enabled harness")
    return output_bin

def normalize_crash_signature(signature: str, escape: bool = False) -> str:
    signature = signature.strip()
    if escape:
        placeholder = "__ADDR__"
        signature = MEMORY_ADDRESS_PATTERN.sub(placeholder, signature)
        signature = re.escape(signature)
        return signature.replace(re.escape(placeholder), r"0x[0-9a-fA-F]+")

    return MEMORY_ADDRESS_PATTERN.sub(r"0x[0-9a-fA-F]+", signature)

def _frame_matches_harness_source(frame_line: str, harness_path: str | None) -> bool:
    if not harness_path:
        return False

    harness_resolved = str(Path(harness_path).resolve())
    if harness_resolved in frame_line:
        return True

    match = SOURCE_LOCATION_PATTERN.search(frame_line)
    if not match:
        return Path(harness_path).name in frame_line

    frame_source = match.group(1)
    try:
        if Path(frame_source).resolve() == Path(harness_path).resolve():
            return True
    except OSError:
        pass
    return Path(frame_source).name == Path(harness_path).name


def _source_location_matches_harness(location: str, harness_path: str | None) -> bool:
    if not harness_path:
        return False
    match = SOURCE_LOCATION_PATTERN.search(location)
    if not match:
        return False
    return _frame_matches_harness_source(match.group(0), harness_path)


def extract_stack_trace(output: str, harness_path: str | None = None) -> str | None:
    """Extract the first stack trace from symbolized sanitizer output.

    Parses sanitizer stack frames (lines beginning ``#N 0xADDR``) and returns
    the first stack trace, truncated before the harness frames. Symbolized
    reports can contain unsymbolized middle frames, so collection must not
    require every frame to contain ``in``. When ``harness_path`` is provided,
    truncation happens at the first frame whose source location belongs to that
    harness file. Otherwise it falls back to truncating at
    ``LLVMFuzzerTestOneInput``.

    Only the *first* stack trace is kept (ASan may emit multiple — e.g., one
    for the overflow and one for the allocation site).
    Returns None if no stack frames are found.
    """
    frames: list[str] = []
    in_first_trace = False
    for line in output.splitlines():
        if STACK_FRAME_COUNT_PATTERN.match(line):
            in_first_trace = True
            if _frame_matches_harness_source(line, harness_path):
                break
            # Backward-compatible / robustness fallback.
            if LLVMFuzzerTestOneInput_PATTERN.search(line):
                break
            frames.append(line)
        elif in_first_trace:
            # A non-frame line after we started collecting means the first
            # trace is over.  Do not continue into a second trace.
            break
    if not frames:
        return None
    return "\n".join(frames)


def extract_first_sanitizer_stack_trace(output: str) -> str | None:
    """Extract the first contiguous sanitizer-style stack trace block.

    This helper is used for frame-depth counting and does not truncate at
    harness frames. It recognizes the common sanitizer frame shape
    ``#N 0x...`` and therefore works for both symbolized and unsymbolized
    sanitizer output, including ASan and UBSan traces that use that format.
    """
    frames: list[str] = []
    in_first_trace = False
    for line in output.splitlines():
        if STACK_FRAME_COUNT_PATTERN.match(line):
            in_first_trace = True
            frames.append(line)
        elif in_first_trace:
            break
    if not frames:
        return None
    return "\n".join(frames)


_GENERIC_ABORT_FRAME_TOKENS = (
    " in __pthread_kill_implementation ",
    " in __pthread_kill_internal ",
    " in pthread_kill ",
    " in raise ",
    " in abort ",
    " in __assert_fail ",
)

_GENERIC_ABORT_LOCATION_SUFFIXES = (
    "/pthread_kill.c",
    "/raise.c",
    "/abort.c",
    "/assert.c",
)

_GENERIC_SANITIZER_WRAPPER_FRAME_TOKENS = (
    " in __asan_memset ",
    " in __asan_memcpy ",
    " in __asan_memmove ",
    " in __interceptor_memset ",
    " in __interceptor_memcpy ",
    " in __interceptor_memmove ",
)

_GENERIC_SANITIZER_WRAPPER_LOCATION_SUFFIXES = (
    "/asan_interceptors_memintrinsics.cpp",
    "/sanitizer_common_interceptors_memintrinsics.inc",
    "/asan_malloc_linux.cpp",
    "/asan_malloc.cpp",
    "/asan_new_delete.cpp",
    "/sanitizer_allocator_dlsym.h",
    "/sanitizer_allocator.cpp",
    "/sanitizer_allocator.h",
)


def _is_generic_abort_frame(line: str, location: str) -> bool:
    location_path = location.split(":", 1)[0]
    return any(token in line for token in _GENERIC_ABORT_FRAME_TOKENS) or any(
        location_path.endswith(suffix) for suffix in _GENERIC_ABORT_LOCATION_SUFFIXES
    )


def _is_generic_sanitizer_wrapper_frame(line: str, location: str) -> bool:
    location_path = location.split(":", 1)[0]
    return any(token in line for token in _GENERIC_SANITIZER_WRAPPER_FRAME_TOKENS) or any(
        location_path.endswith(suffix)
        for suffix in _GENERIC_SANITIZER_WRAPPER_LOCATION_SUFFIXES
    )


def extract_symbolized_crash_location(
    output: str,
    harness_path: str | None = None,
) -> str | None:
    """Return the best source location from the symbolized pre-harness trace."""
    trace = extract_stack_trace(output, harness_path=harness_path)
    if not trace:
        return None
    first_location: str | None = None
    for line in trace.splitlines():
        match = SOURCE_LOCATION_PATTERN.search(line)
        if match:
            location = match.group(0)
            if first_location is None:
                first_location = location
            if not _is_generic_abort_frame(line, location) and not _is_generic_sanitizer_wrapper_frame(
                line, location
            ):
                return location
    return first_location


def extract_harness_crash_location(
    output: str,
    harness_path: str | None = None,
) -> str | None:
    """Return the harness source location when the original crash is in the harness."""
    if not harness_path:
        return None

    runtime_error_match = RUNTIME_ERROR_PATTERN.search(output)
    if runtime_error_match:
        location_match = SOURCE_LOCATION_PATTERN.search(runtime_error_match.group(0))
        if location_match and _source_location_matches_harness(
            location_match.group(0),
            harness_path,
        ):
            return location_match.group(0)

    trace = extract_first_sanitizer_stack_trace(output)
    if not trace:
        return None

    for line in trace.splitlines():
        match = SOURCE_LOCATION_PATTERN.search(line)
        location = match.group(0) if match else ""
        if location and (
            _is_generic_abort_frame(line, location)
            or _is_generic_sanitizer_wrapper_frame(line, location)
        ):
            continue
        if _frame_matches_harness_source(line, harness_path):
            return location or line.strip()
        if location:
            return None
    return None


def count_first_stack_trace_frames(output: str) -> int:
    trace = extract_first_sanitizer_stack_trace(output)
    if not trace:
        return 0
    return sum(1 for line in trace.splitlines() if STACK_FRAME_COUNT_PATTERN.match(line))


def set_reference_crash_patterns(
    *,
    symbolize_0: str | None = None,
    symbolize_1: str | None = None,
) -> None:
    global CRASH_PATTERN_SYMBOLIZE_0, CRASH_PATTERN_SYMBOLIZE_1
    CRASH_PATTERN_SYMBOLIZE_0 = symbolize_0
    CRASH_PATTERN_SYMBOLIZE_1 = symbolize_1


def get_reference_crash_pattern_symbolize_0() -> str | None:
    return CRASH_PATTERN_SYMBOLIZE_0


def get_reference_crash_pattern_symbolize_1() -> str | None:
    return CRASH_PATTERN_SYMBOLIZE_1


def set_normal_reference_stack_depth(depth: int | None) -> None:
    global NORMAL_REFERENCE_STACK_DEPTH
    NORMAL_REFERENCE_STACK_DEPTH = depth


def get_normal_reference_stack_depth() -> int | None:
    return NORMAL_REFERENCE_STACK_DEPTH


def set_normal_reference_stack_depth_strict(strict: bool) -> None:
    global NORMAL_REFERENCE_STACK_DEPTH_STRICT
    NORMAL_REFERENCE_STACK_DEPTH_STRICT = bool(strict)


def get_normal_reference_stack_depth_strict() -> bool:
    return NORMAL_REFERENCE_STACK_DEPTH_STRICT


def set_symbolized_reference_stack_depth(depth: int | None) -> None:
    global SYMBOLIZED_REFERENCE_STACK_DEPTH
    SYMBOLIZED_REFERENCE_STACK_DEPTH = depth


def get_symbolized_reference_stack_depth() -> int | None:
    return SYMBOLIZED_REFERENCE_STACK_DEPTH


def set_symbolized_reference_stack_depth_strict(strict: bool) -> None:
    global SYMBOLIZED_REFERENCE_STACK_DEPTH_STRICT
    SYMBOLIZED_REFERENCE_STACK_DEPTH_STRICT = bool(strict)


def get_symbolized_reference_stack_depth_strict() -> bool:
    return SYMBOLIZED_REFERENCE_STACK_DEPTH_STRICT


def set_dynamic_reference_crash_site(site: DynamicCrashSite | None) -> None:
    global DYNAMIC_REFERENCE_CRASH_SITE
    DYNAMIC_REFERENCE_CRASH_SITE = site


def get_dynamic_reference_crash_site() -> DynamicCrashSite | None:
    return DYNAMIC_REFERENCE_CRASH_SITE


def set_symbolized_reference_crash_location_pattern(pattern: str | None) -> None:
    global SYMBOLIZED_REFERENCE_CRASH_LOCATION_PATTERN
    SYMBOLIZED_REFERENCE_CRASH_LOCATION_PATTERN = pattern


def get_symbolized_reference_crash_location_pattern() -> str | None:
    return SYMBOLIZED_REFERENCE_CRASH_LOCATION_PATTERN


def get_stack_trace_file() -> str:
    return os.path.join(get_work_dir(), STACK_TRACE_FILE_NAME)


def get_stack_depth_stability_file() -> str:
    return os.path.join(get_work_dir(), STACK_DEPTH_STABILITY_FILE_NAME)


def get_crash_pattern_file(*, symbolized: bool) -> str:
    file_name = (
        CRASH_PATTERN_SYMBOLIZE_1_FILE_NAME
        if symbolized
        else CRASH_PATTERN_SYMBOLIZE_0_FILE_NAME
    )
    return os.path.join(get_work_dir(), file_name)


def get_dynamic_crash_site_file() -> str:
    return os.path.join(get_work_dir(), DYNAMIC_CRASH_SITE_FILE_NAME)


def get_symbolized_crash_location_file() -> str:
    return os.path.join(get_work_dir(), SYMBOLIZED_CRASH_LOCATION_FILE_NAME)


def get_last_interesting_file() -> str:
    return os.path.join(get_work_dir(), LAST_INTERESTING_FILE_NAME)

def get_statistics_file() -> str:
    return os.path.join(get_work_dir(), STATISTICS_FILE_NAME)


def get_candidate_profile_events_file() -> str:
    return os.path.join(get_work_dir(), CANDIDATE_PROFILE_EVENTS_FILE_NAME)


def get_reduction_profile_json_file() -> str:
    return os.path.join(get_work_dir(), REDUCTION_PROFILE_JSON_FILE_NAME)


def get_reduction_profile_text_file() -> str:
    return os.path.join(get_work_dir(), REDUCTION_PROFILE_TEXT_FILE_NAME)


def initialize_candidate_profile_events_file() -> str:
    path = Path(get_candidate_profile_events_file())
    path.write_text("", encoding="utf-8")
    return str(path)


def reset_stack_trace_state() -> None:
    """Remove persisted stack-trace validation artifacts from the work dir."""
    set_reference_crash_patterns()
    set_normal_reference_stack_depth(None)
    set_symbolized_reference_stack_depth(None)
    set_normal_reference_stack_depth_strict(False)
    set_symbolized_reference_stack_depth_strict(False)
    set_dynamic_reference_crash_site(None)
    set_symbolized_reference_crash_location_pattern(None)
    for path in (
        get_stack_trace_file(),
        get_stack_depth_stability_file(),
        get_crash_pattern_file(symbolized=False),
        get_crash_pattern_file(symbolized=True),
        get_dynamic_crash_site_file(),
        get_symbolized_crash_location_file(),
        str(Path(get_work_dir()) / SYMBOLIZATION_FAILURE_LOG_NAME),
        str(Path(get_work_dir()) / "crash_reference.symbolize0.failure.log"),
        str(Path(get_work_dir()) / "crash_reference.symbolize1.failure.log"),
    ):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def reset_last_interesting_state() -> None:
    try:
        os.remove(get_last_interesting_file())
    except FileNotFoundError:
        pass


def candidate_files_match(path_a: str, path_b: str) -> bool:
    try:
        return filecmp.cmp(path_a, path_b, shallow=False)
    except FileNotFoundError:
        return False


def reset_statistics_state() -> None:
    try:
        os.remove(get_statistics_file())
    except FileNotFoundError:
        pass


def _format_statistics_text(
    count_77: int,
    count_1: int,
    count_neg1: int,
) -> str:
    total = count_77 + count_1 + count_neg1

    def probability(count: int) -> float:
        return 0.0 if total == 0 else count / total

    return (
        f"total: {total}\n"
        f"count_77: {count_77}\n"
        f"count_1: {count_1}\n"
        f"count_-1: {count_neg1}\n"
        f"probability_77: {probability(count_77):.6f}\n"
        f"probability_1: {probability(count_1):.6f}\n"
        f"probability_-1: {probability(count_neg1):.6f}\n"
    )


def initialize_statistics_file() -> str:
    path = get_statistics_file()
    Path(path).write_text(_format_statistics_text(0, 0, 0), encoding="utf-8")
    return path


def _source_coverage_raw_path() -> Path:
    return Path(get_work_dir()) / SOURCE_COVERAGE_RAW_FILE_NAME


def _source_coverage_data_path() -> Path:
    return Path(get_work_dir()) / SOURCE_COVERAGE_DATA_FILE_NAME


def _source_coverage_show_path() -> Path:
    return Path(get_work_dir()) / SOURCE_COVERAGE_SHOW_FILE_NAME


def _source_coverage_export_path() -> Path:
    return Path(get_work_dir()) / SOURCE_COVERAGE_EXPORT_FILE_NAME


def _clear_source_coverage_artifacts() -> None:
    for path in (
        _source_coverage_raw_path(),
        _source_coverage_data_path(),
        _source_coverage_show_path(),
        _source_coverage_export_path(),
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _coverage_count_is_nonzero(count_text: str) -> bool:
    text = count_text.strip()
    if not text or text in {"-", "#####"}:
        return False
    return not re.fullmatch(r"0+(?:\.0+)?[kMGTPE]?", text)


def _parse_llvm_cov_show_text(report_text: str) -> CoverageMap:
    executable_lines: set[int] = set()
    covered_lines: set[int] = set()

    for line in report_text.splitlines():
        match = LLVM_COV_SHOW_LINE_PATTERN.match(line)
        if not match:
            continue
        line_no = int(match.group(1))
        count_text = match.group(2).strip()
        if not count_text:
            continue
        executable_lines.add(line_no)
        if _coverage_count_is_nonzero(count_text):
            covered_lines.add(line_no)

    return CoverageMap(
        executable_lines=frozenset(executable_lines),
        covered_lines=frozenset(covered_lines),
    )


def _merge_source_coverage_profile(raw_path: Path, profdata_path: Path) -> None:
    run_command(
        [
            "llvm-profdata",
            "merge",
            "-sparse",
            str(raw_path),
            "-o",
            str(profdata_path),
        ],
        "Failed to merge source coverage profile",
    )


def generate_harness_coverage_reports(
    coverage_bin: str,
    harness_path: str,
) -> dict[str, str]:
    """Generate llvm-cov reports for a previously collected source-coverage run."""
    profdata_path = _source_coverage_data_path()
    if not profdata_path.exists():
        raise RuntimeError("Coverage profile data is missing; collect coverage first.")

    harness_realpath = str(Path(harness_path).resolve())
    show_proc = run_command(
        [
            "llvm-cov",
            "show",
            coverage_bin,
            f"-instr-profile={profdata_path}",
            harness_realpath,
        ],
        "Failed to generate line coverage report",
    )
    export_proc = run_command(
        [
            "llvm-cov",
            "export",
            coverage_bin,
            f"-instr-profile={profdata_path}",
            f"--sources={harness_realpath}",
        ],
        "Failed to export coverage report",
    )

    _source_coverage_show_path().write_text(show_proc.stdout, encoding="utf-8")
    _source_coverage_export_path().write_text(export_proc.stdout, encoding="utf-8")
    return {
        SOURCE_COVERAGE_SHOW_FILE_NAME: show_proc.stdout,
        SOURCE_COVERAGE_EXPORT_FILE_NAME: export_proc.stdout,
    }


def collect_harness_coverage(
    coverage_bin: str,
    harness_path: str,
    crash_input: str | None,
    link_flags: str | None = None,
) -> CoverageMap:
    """Run the crashing input under source-based coverage and return line sets."""
    _clear_source_coverage_artifacts()
    raw_path = _source_coverage_raw_path()
    profdata_path = _source_coverage_data_path()

    env = runtime_library_env(link_flags, symbolize=False)
    env["ASAN_OPTIONS"] = "exitcode=77:symbolize=0:handle_abort=1"
    env["UBSAN_OPTIONS"] = "exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=0"
    env["LLVM_PROFILE_FILE"] = str(raw_path)
    cmd = [coverage_bin]
    if crash_input:
        cmd.append(crash_input)
    run_command(
        cmd,
        "Failed to execute coverage-enabled harness",
        env=env,
        ignore_errors=True,
    )

    if not raw_path.exists() or raw_path.stat().st_size == 0:
        raise RuntimeError("No source coverage profile was produced.")

    _merge_source_coverage_profile(raw_path, profdata_path)
    reports = generate_harness_coverage_reports(coverage_bin, harness_path)
    return _parse_llvm_cov_show_text(reports[SOURCE_COVERAGE_SHOW_FILE_NAME])


def apply_coverage_guided_slice(
    harness_path: str,
    crash_pattern: str | None,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    phase3_mode: str = PHASE3_DIRECT,
    crash_pattern_symbolize_0: str | None = None,
    symbolize: bool = False,
) -> str:
    """Conservatively prune uncovered harness code before tree reduction.

    If coverage collection, slicing, or validation fails, the original harness
    path is returned unchanged.
    """
    fast_crash_pattern = crash_pattern_symbolize_0 or crash_pattern
    if not fast_crash_pattern:
        print("[!] Coverage-guided slicing skipped: no fast crash pattern is available.")
        return harness_path

    try:
        coverage_bin = compile_coverage_harness(harness_path, compile_flags, link_flags)
        coverage = collect_harness_coverage(
            coverage_bin,
            harness_path,
            crash_input,
            link_flags,
        )
        if not coverage.executable_lines:
            print("[*] Coverage-guided slicing skipped: no executable harness lines were found.")
            return harness_path

        source = Path(harness_path).read_text(encoding="utf-8", errors="ignore")
        slice_result = slice_source_by_coverage(source, coverage)
        if slice_result.removed_nodes == 0 or slice_result.source == source:
            print("[*] Coverage-guided slicing found no removable uncovered blocks.")
            return harness_path

        source_path = Path(harness_path)
        sliced_path = Path(get_work_dir()) / f"{source_path.stem}{SLICED_HARNESS_SUFFIX}{source_path.suffix or '.cpp'}"
        sliced_path.write_text(slice_result.source, encoding="utf-8")

        if symbolize:
            if not crash_pattern:
                print(
                    "[!] Coverage-guided slicing failed: no symbolized crash pattern "
                    "is available for --symbolize validation."
                )
                return harness_path
            preserved = validate_symbolized_crash_pattern_depth_location(
                str(sliced_path),
                crash_pattern,
                crash_input,
                compile_flags,
                link_flags,
                phase3_mode=phase3_mode,
            )
        else:
            preserved = validate_crash_pattern_and_stack_trace(
                str(sliced_path),
                fast_crash_pattern,
                crash_pattern,
                crash_input,
                compile_flags,
                link_flags,
                phase3_mode=phase3_mode,
            )
        if not preserved:
            print("[!] Coverage-guided slicing failed crash-preservation validation. Falling back to the original harness.")
            return harness_path

        print(
            f"[+] Coverage-guided slicing removed {slice_result.removed_nodes} uncovered nodes: {sliced_path}"
        )
        return str(sliced_path)
    except Exception as exc:
        print(f"[!] Coverage-guided slicing skipped: {exc}")
        return harness_path


def _run_harness_for_crash_reference(
    output_bin: str,
    crash_input: str | None,
    *,
    symbolize: bool,
    link_flags: str | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [output_bin]
    if crash_input:
        cmd.append(crash_input)
    env = runtime_library_env(link_flags, symbolize=symbolize)
    symbolized = "1" if symbolize else "0"
    env["UBSAN_OPTIONS"] = f"exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize={symbolized}"
    env["ASAN_OPTIONS"] = f"exitcode=77:symbolize={symbolized}:handle_abort=1"
    from harnessreducer.oracle_evaluation import reference_root
    if symbolize and reference_root() is not None:
        # Module identity lets the observer select the same target frames in
        # symbolized references and raw candidate reports. Frame depth is intact.
        for variable in ("ASAN_OPTIONS", "UBSAN_OPTIONS"):
            env[variable] += ":stack_trace_format='    #%n %p in %f %S (%m+%o)'"
    return run_command(
        cmd,
        env=env,
        error_prefix="Failed to execute harness for crash pattern extraction",
        ignore_errors=True,
    )


def _update_stack_depth_stability_record(
    *,
    symbolize: bool,
    depths: list[int],
    stable: bool,
    expected_depth: int | None,
    wall_ns: int,
    failed_run: int | None = None,
    failed_stage: str | None = None,
    returncode: int | None = None,
) -> None:
    path = Path(get_stack_depth_stability_file())
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        record = {"schema_version": 1, "runs_per_mode": STACK_DEPTH_STABILITY_RUNS, "modes": {}}
    if not isinstance(record, dict):
        record = {"schema_version": 1, "runs_per_mode": STACK_DEPTH_STABILITY_RUNS, "modes": {}}
    modes = record.setdefault("modes", {})
    if not isinstance(modes, dict):
        modes = {}
        record["modes"] = modes
    modes[f"symbolize_{int(symbolize)}"] = {
        "depths": depths,
        "stable": stable,
        "expected_depth": expected_depth,
        "wall_ns": wall_ns,
        "failed_run": failed_run,
        "failed_stage": failed_stage,
        "returncode": returncode,
    }
    total_wall_ns = 0
    for mode in modes.values():
        if isinstance(mode, dict):
            try:
                total_wall_ns += int(mode.get("wall_ns", 0))
            except (TypeError, ValueError):
                pass
    record["total_wall_ns"] = total_wall_ns
    record["total_wall_seconds"] = total_wall_ns / 1_000_000_000.0
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _probe_reference_stack_depth_stability(
    harness_path: str | None,
    crash_input: str | None,
    *,
    symbolize: bool,
    compile_flags: str | None,
    link_flags: str | None,
    expected_depth: int | None,
) -> bool:
    label = f"symbolize={int(symbolize)}"
    if not harness_path:
        _update_stack_depth_stability_record(
            symbolize=symbolize,
            depths=[],
            stable=False,
            expected_depth=expected_depth,
            wall_ns=0,
        )
        print(f"[*] Stack-depth strictness disabled for {label}: no harness path was provided.")
        return False
    if expected_depth is None:
        _update_stack_depth_stability_record(
            symbolize=symbolize,
            depths=[],
            stable=False,
            expected_depth=None,
            wall_ns=0,
        )
        print(f"[*] Stack-depth strictness disabled for {label}: no reference depth was recorded.")
        return False

    depths: list[int] = []
    started_ns = time.perf_counter_ns()
    probe_dir = Path(get_work_dir()) / "stack_depth_stability_probes"
    probe_dir.mkdir(parents=True, exist_ok=True)
    for run_index in range(1, STACK_DEPTH_STABILITY_RUNS + 1):
        output_bin = probe_dir / f"symbolize{int(symbolize)}_{run_index}.out"
        compile_proc = run_command(
            reference_harness_compile_command(
                harness_path,
                compile_flags,
                link_flags,
                str(output_bin),
            ),
            "Failed to compile harness for stack-depth stability probing",
            ignore_errors=True,
        )
        if compile_proc.returncode != 0:
            from harnessreducer.oracle_evaluation import capture_reference
            capture_reference(symbolize, run_index, compile_proc, str(output_bin), harness_path, link_flags, stage="compile")
            wall_ns = time.perf_counter_ns() - started_ns
            _update_stack_depth_stability_record(
                symbolize=symbolize,
                depths=depths,
                stable=False,
                expected_depth=expected_depth,
                wall_ns=wall_ns,
                failed_run=run_index,
                failed_stage="compile",
                returncode=compile_proc.returncode,
            )
            print(
                f"[!] Stack-depth strictness disabled for {label}: "
                f"stability compile {run_index}/{STACK_DEPTH_STABILITY_RUNS} "
                f"failed (exit={compile_proc.returncode})."
            )
            try:
                output_bin.unlink()
            except FileNotFoundError:
                pass
            return False

        proc = _run_harness_for_crash_reference(
            str(output_bin),
            crash_input,
            symbolize=symbolize,
            link_flags=link_flags,
        )
        from harnessreducer.oracle_evaluation import capture_reference
        capture_reference(symbolize, run_index, proc, str(output_bin), harness_path, link_flags)
        try:
            output_bin.unlink()
        except FileNotFoundError:
            pass
        output = proc.stdout + "\n" + proc.stderr
        if proc.returncode != 77:
            wall_ns = time.perf_counter_ns() - started_ns
            _update_stack_depth_stability_record(
                symbolize=symbolize,
                depths=depths,
                stable=False,
                expected_depth=expected_depth,
                wall_ns=wall_ns,
                failed_run=run_index,
                failed_stage="execute",
                returncode=proc.returncode,
            )
            print(
                f"[!] Stack-depth strictness disabled for {label}: "
                f"stability execution {run_index}/{STACK_DEPTH_STABILITY_RUNS} "
                f"did not reproduce the reference crash (exit={proc.returncode})."
            )
            return False
        depths.append(count_first_stack_trace_frames(output))

    wall_ns = time.perf_counter_ns() - started_ns
    stable = bool(depths) and all(depth == expected_depth for depth in depths)
    _update_stack_depth_stability_record(
        symbolize=symbolize,
        depths=depths,
        stable=stable,
        expected_depth=expected_depth,
        wall_ns=wall_ns,
    )
    if stable:
        print(
            f"[+] Stack-depth strictness enabled for {label}: "
            f"{STACK_DEPTH_STABILITY_RUNS}/{STACK_DEPTH_STABILITY_RUNS} compile+execute samples "
            f"had depth {expected_depth}."
        )
    else:
        unique_depths = ", ".join(str(depth) for depth in sorted(set(depths)))
        print(
            f"[!] Stack-depth strictness disabled for {label}: "
            f"observed depths [{unique_depths}] across "
            f"{STACK_DEPTH_STABILITY_RUNS} compile+execute samples; reference depth is {expected_depth}."
        )
    return stable


def _capture_crash_reference_with_evidence(
    output_bin: str,
    crash_input: str | None,
    *,
    symbolize: bool,
    link_flags: str | None,
    harness_path: str | None,
    require_location: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Select one report before persisting reference state; never rebuild the binary."""
    expected_pattern = None
    dynamic_applicable = None
    for attempt in range(1, REFERENCE_EVIDENCE_ATTEMPTS + 1):
        proc = _run_harness_for_crash_reference(
            output_bin, crash_input, symbolize=symbolize, link_flags=link_flags,
        )
        output = proc.stdout + "\n" + proc.stderr
        if proc.returncode != 77:
            return proc
        if symbolize:
            harness_location = extract_harness_crash_location(output, harness_path=harness_path)
            if harness_location:
                raise HarnessCrashDetected(harness_location)

        pattern = _extract_crash_signature_from_output(output)
        if attempt > 1 and pattern != expected_pattern:
            diagnostic = _save_reference_evidence_failure(output, symbolize=symbolize)
            raise ValueError(
                f"Crash pattern changed during reference evidence retry (symbolize={int(symbolize)}, "
                f"attempt {attempt}/{REFERENCE_EVIDENCE_ATTEMPTS}). "
                f"Expected {expected_pattern!r}, got {pattern!r}. Raw sanitizer output: {diagnostic}"
            )
        if pattern is None:
            # No identity to preserve across retries: retain the caller's existing handling.
            return proc
        expected_pattern = pattern

        if symbolize:
            if require_location and extract_symbolized_crash_location(output, harness_path=harness_path) is None:
                missing = "symbolized crash-location evidence"
            elif extract_stack_trace(output, harness_path=harness_path) is None:
                missing = "symbolized stack-trace evidence"
            else:
                return proc
        else:
            if extract_first_dynamic_library_crash_site(output, link_flags) is not None:
                return proc
            if dynamic_applicable is None:
                hints = infer_target_dynamic_library_hints(link_flags)
                # Runtime-only flags such as -lpthread do not identify a fuzzed
                # target. Explicit library paths still express target intent.
                dynamic_applicable = bool(hints.exact_paths) or any(
                    not _is_runtime_shared_library(name) for name in hints.exact_names
                )
            if not dynamic_applicable:
                return proc
            missing = "dynamic crash-site evidence"

        if not retry_missing_evidence(
            missing, attempt, REFERENCE_EVIDENCE_ATTEMPTS,
            context=f"reference symbolize={int(symbolize)}",
        ):
            diagnostic = _save_reference_evidence_failure(output, symbolize=symbolize)
            print(f"[!] Raw sanitizer output: {diagnostic}")
            # Required/optional exhaustion semantics remain in the caller.
            return proc


def _save_reference_evidence_failure(output: str, *, symbolize: bool) -> str:
    path = Path(get_work_dir()) / f"crash_reference.symbolize{int(symbolize)}.failure.log"
    path.write_text(output, encoding="utf-8")
    return str(path)


def _persist_reference_crash_pattern(pattern: str | None, *, symbolized: bool) -> None:
    path = Path(get_crash_pattern_file(symbolized=symbolized))
    if pattern is None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return

    path.write_text(pattern + "\n", encoding="utf-8")


def _persist_dynamic_reference_crash_site(site: DynamicCrashSite | None) -> None:
    path = Path(get_dynamic_crash_site_file())
    if site is None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return

    path.write_text(
        json.dumps(
            {
                "library_path": site.library_path,
                "library_name": site.library_name,
                "offset": site.offset,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _persist_symbolized_reference_crash_location(pattern: str | None) -> None:
    path = Path(get_symbolized_crash_location_file())
    if pattern is None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return

    path.write_text(pattern + "\n", encoding="utf-8")


def _record_dynamic_reference_crash_site(
    output: str,
    link_flags: str | None,
) -> DynamicCrashSite | None:
    site = extract_first_dynamic_library_crash_site(output, link_flags)
    set_dynamic_reference_crash_site(site)
    _persist_dynamic_reference_crash_site(site)
    if site is not None:
        print(f"[+] Recorded dynamic crash-site library: {site.library_path}")
        print(f"[+] Recorded dynamic crash-site offset: {site.offset}")
    return site


def _record_symbolized_reference_crash_location(
    output: str,
    harness_path: str | None,
    *,
    required: bool,
) -> str | None:
    location = extract_symbolized_crash_location(output, harness_path=harness_path)
    if location is None:
        set_symbolized_reference_crash_location_pattern(None)
        _persist_symbolized_reference_crash_location(None)
        message = "No symbolized crash location found in the first pre-harness stack trace."
        diagnostic = _save_symbolization_failure(output)
        message += f" Raw sanitizer output: {diagnostic}"
        if required:
            raise ValueError(message)
        print(f"[!] {message}")
        return None

    pattern = normalize_crash_signature(location, escape=True)
    set_symbolized_reference_crash_location_pattern(pattern)
    _persist_symbolized_reference_crash_location(pattern)
    print(f"[+] Recorded symbolized crash location: {location}")
    return pattern


def _save_symbolization_failure(output: str) -> str:
    path = Path(get_work_dir()) / SYMBOLIZATION_FAILURE_LOG_NAME
    path.write_text(output, encoding="utf-8")
    return str(path)


def _normalize_runtime_error_signature(signature: str) -> str:
    """Keep the source location and wording exact; generalize message numbers only."""
    location, marker, message = signature.strip().partition("runtime error:")
    parts = [re.escape(location + marker)]
    end = 0
    for number in RUNTIME_ERROR_NUMBER_PATTERN.finditer(message):
        parts.append(re.escape(message[end:number.start()]))
        parts.append(RUNTIME_ERROR_NUMBER_PATTERN.pattern)
        end = number.end()
    parts.append(re.escape(message[end:]))
    return "".join(parts)


def _extract_crash_signature_from_output(output: str) -> str | None:
    abort_assert_match = ABORT_ASSERT_LOCATION_PATTERN.search(output)
    if abort_assert_match:
        parts = abort_assert_match.group(0).split(":")
        signature = parts[0] + ":" + parts[1]
        return normalize_crash_signature(signature)

    # Prefer SUMMARY when extracting the error type, but accept either report
    # prefix during validation. Both sources produce an identical regex, so a
    # missing SUMMARY also cannot change the identity during evidence retries.
    asan_match = ASAN_SUMMARY_PATTERN.search(output) or ASAN_ERROR_PATTERN.search(output)
    if asan_match:
        error_type = re.escape(asan_match.group(1))
        return rf"(?:SUMMARY|ERROR):\s*AddressSanitizer:\s*{error_type}(?![\w-])"

    leak_match = LEAK_PATTERN.search(output)
    if leak_match:
        return normalize_crash_signature(leak_match.group(0))

    runtime_error_match = RUNTIME_ERROR_PATTERN.search(output)
    if runtime_error_match:
        return _normalize_runtime_error_signature(runtime_error_match.group(0))

    ubsan_match = UBSAN_PATTERN.search(output)
    if ubsan_match:
        return normalize_crash_signature(ubsan_match.group(0))

    absl_check_match = ABSL_CHECK_PATTERN.search(output)
    if absl_check_match:
        return normalize_crash_signature(absl_check_match.group(1))

    libfuzzer_signal_match = LIBFUZZER_SIGNAL_PATTERN.search(output)
    if libfuzzer_signal_match:
        return normalize_crash_signature(libfuzzer_signal_match.group(1))

    return None


def extract_crash_pattern_from_output(
    crash_input: str | None,
    harness_path: str | None = None,
    compile_flags: str | None = None,
    link_flags: str | None = None,
    record_symbolized_crash_location: bool = False,
) -> str | None:
    work_dir = get_work_dir()
    if not record_symbolized_crash_location:
        set_symbolized_reference_crash_location_pattern(None)
        _persist_symbolized_reference_crash_location(None)
    output_bin = os.path.join(work_dir, "poc.out")
    proc = _capture_crash_reference_with_evidence(
        output_bin,
        crash_input,
        symbolize=False,
        link_flags=link_flags,
        harness_path=harness_path,
    )
    output = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 77:
        print("[!] Warning: No crash detected when running the harness. Output:\n" + output)
        set_reference_crash_patterns()
        set_normal_reference_stack_depth(None)
        set_symbolized_reference_stack_depth(None)
        set_normal_reference_stack_depth_strict(False)
        set_symbolized_reference_stack_depth_strict(False)
        set_dynamic_reference_crash_site(None)
        set_symbolized_reference_crash_location_pattern(None)
        _persist_reference_crash_pattern(None, symbolized=False)
        _persist_reference_crash_pattern(None, symbolized=True)
        _persist_dynamic_reference_crash_site(None)
        _persist_symbolized_reference_crash_location(None)
        return None

    normal_reference_stack_depth = count_first_stack_trace_frames(output)
    set_normal_reference_stack_depth(normal_reference_stack_depth or None)
    if normal_reference_stack_depth:
        print(f"[+] Recorded fast-path stack trace depth: {normal_reference_stack_depth}")
    else:
        print("[!] No fast-path stack-trace frames found for reference depth extraction.")

    _record_dynamic_reference_crash_site(output, link_flags)
    set_normal_reference_stack_depth_strict(
        _probe_reference_stack_depth_stability(
            harness_path,
            crash_input,
            symbolize=False,
            compile_flags=compile_flags,
            link_flags=link_flags,
            expected_depth=get_normal_reference_stack_depth(),
        )
    )

    crash_pattern = _extract_crash_signature_from_output(output)
    if not crash_pattern:
        raise ValueError("Failed to extract a valid crash pattern from the harness output. Output:\n" + output)
    set_reference_crash_patterns(symbolize_0=crash_pattern)
    _persist_reference_crash_pattern(crash_pattern, symbolized=False)

    symbolized_proc = _capture_crash_reference_with_evidence(
        output_bin,
        crash_input,
        symbolize=True,
        link_flags=link_flags,
        harness_path=harness_path,
        require_location=record_symbolized_crash_location,
    )
    symbolized_output = symbolized_proc.stdout + "\n" + symbolized_proc.stderr
    if symbolized_proc.returncode != 77:
        set_reference_crash_patterns(symbolize_0=crash_pattern)
        set_symbolized_reference_stack_depth(None)
        set_symbolized_reference_stack_depth_strict(False)
        set_symbolized_reference_crash_location_pattern(None)
        _persist_reference_crash_pattern(None, symbolized=True)
        _persist_symbolized_reference_crash_location(None)
        try:
            os.remove(get_stack_trace_file())
        except FileNotFoundError:
            pass
        print(
            "[!] Warning: Symbolized reference execution did not reproduce the crash; "
            "skipping symbolized stack-trace reference capture."
        )
        return crash_pattern

    harness_crash_location = extract_harness_crash_location(
        symbolized_output,
        harness_path=harness_path,
    )
    if harness_crash_location:
        raise HarnessCrashDetected(harness_crash_location)

    symbolized_crash_pattern = _extract_crash_signature_from_output(symbolized_output)
    if symbolized_crash_pattern:
        set_reference_crash_patterns(
            symbolize_0=crash_pattern,
            symbolize_1=symbolized_crash_pattern,
        )
        _persist_reference_crash_pattern(symbolized_crash_pattern, symbolized=True)
        print(f"[+] Extracted symbolized crash pattern: {symbolized_crash_pattern}")
    else:
        set_reference_crash_patterns(symbolize_0=crash_pattern)
        _persist_reference_crash_pattern(None, symbolized=True)
        print(
            "[!] Warning: Could not extract a symbolized crash pattern; "
            "symbolized stack validations will not require a symbolized crash regex."
        )

    symbolized_reference_stack_depth = count_first_stack_trace_frames(symbolized_output)
    set_symbolized_reference_stack_depth(symbolized_reference_stack_depth or None)
    if symbolized_reference_stack_depth:
        print(f"[+] Recorded symbolized stack trace depth: {symbolized_reference_stack_depth}")
    else:
        print("[!] No symbolized stack-trace frames found for reference depth extraction.")
    set_symbolized_reference_stack_depth_strict(
        _probe_reference_stack_depth_stability(
            harness_path,
            crash_input,
            symbolize=True,
            compile_flags=compile_flags,
            link_flags=link_flags,
            expected_depth=get_symbolized_reference_stack_depth(),
        )
    )

    # Extract and save the first stack trace (normalized) for deeper symbolized validation.
    raw_stack_trace = extract_stack_trace(symbolized_output, harness_path=harness_path)
    if raw_stack_trace:
        normalized_trace = normalize_crash_signature(raw_stack_trace, escape=True)
        trace_file = get_stack_trace_file()
        Path(trace_file).write_text(normalized_trace, encoding="utf-8")
        print(f"[+] Saved stack trace pattern to {trace_file}")
    else:
        try:
            os.remove(get_stack_trace_file())
        except FileNotFoundError:
            pass
        diagnostic = _save_symbolization_failure(symbolized_output)
        print(f"[!] No symbolized stack trace found in crash output. Raw sanitizer output: {diagnostic}")
    if record_symbolized_crash_location:
        _record_symbolized_reference_crash_location(
            symbolized_output,
            harness_path,
            required=True,
        )
    return crash_pattern


def check_reducer_crash_pattern(
    harness_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    phase3_mode: str = PHASE3_DIRECT,
) -> None:
    print("[+] Checking crash pattern validity...")
    if not crash_pattern:
        raise ValueError("Crash pattern cannot be empty.")
    validate_phase3_mode(phase3_mode)

    pch_artifacts: PchArtifacts | None = None
    tester_source = harness_path
    if phase3_mode == PHASE3_PCH:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=False,
        )
        tester_source = pch_artifacts.body_source

    cmd = [
        get_crash_tester_path(),
        tester_source,
        crash_pattern,
        "--crash-input", crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
    ]
    cmd.extend(stack_depth_tester_args(symbolized=False))
    cmd.extend(dynamic_crash_site_tester_args())
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    append_exec_timeout_tester_args(cmd)
    proc = run_command(cmd, "Invalid crash pattern.", ignore_errors=True)
    if proc.returncode != 77:
        print("Tester command: " + " ".join(cmd))
        raise ValueError(f"Crash pattern did not match the crash behavior. Tester output:\n{proc.stdout}\n{proc.stderr}")
    print("[+] Crash pattern is valid.")

def compile_dump_mode_harness(
    harness_path: str,
    compile_flags: str | None,
    link_flags: str | None,
) -> str:
    tagged_harness_bin = os.path.join(get_work_dir(), "tagged_harness.out")
    compile_cmd = [
        "clang++",
        "-DFDP_MIN_MODE_DUMP",
        f"-I{get_fdp_header_dir()}",
        "-fsanitize=address,fuzzer,undefined",
        *PHASE3_DIRECT_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
        *_split_flags(compile_flags),
        harness_path,
        "-o",
        tagged_harness_bin,
        *_split_flags(link_flags),
    ]

    run_command(compile_cmd, "Failed to compile tagged harness with dump mode")
    return tagged_harness_bin


def dump_fdp_trace(
    harness_bin: str,
    crash_input: str | None,
    link_flags: str | None = None,
) -> str:
    fdp_trace_file = os.path.join(get_work_dir(), "fdp_trace.log")
    fdp_wide_trace_file = fdp_wide_trace_path(fdp_trace_file)
    # The dump runtime appends trace records, so remove any trace left by an
    # earlier run when a fixed work directory is reused.
    for trace_file in (fdp_trace_file, fdp_wide_trace_file):
        try:
            os.remove(trace_file)
        except FileNotFoundError:
            pass

    env = runtime_library_env(link_flags)
    env["FDP_TRACE_PATH"] = fdp_trace_file
    env["FDP_WIDE_TRACE_PATH"] = fdp_wide_trace_file

    exec_cmd = [harness_bin, crash_input] if crash_input else [harness_bin]
    run_command(exec_cmd, "Failed to execute tagged harness in dump mode", env=env, ignore_errors=True)

    if not os.path.exists(fdp_trace_file):
        if os.path.exists(fdp_wide_trace_file):
            Path(fdp_trace_file).touch()
            return fdp_trace_file
        raise RuntimeError("FDP trace file was not created as expected.")
    return fdp_trace_file


def calibrate_exec_timeout_ms(
    harness_path: str,
    fdp_trace_file: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    crash_input: str | None,
    *,
    phase3_mode: str = PHASE3_DIRECT,
    pch_artifacts: PchArtifacts | None = None,
    symbolize: bool,
    runner_socket: str | None = None,
    plugin_link_flags: tuple[str, ...] = (),
) -> int:
    samples_ms: list[int] = []
    tester_source = pch_artifacts.body_source if pch_artifacts is not None else harness_path

    for _ in range(CALIBRATION_PROBE_RUNS):
        cmd = [
            get_crash_tester_path(),
            tester_source,
            ".*",
            "--crash-input",
            crash_input or "",
            f"--compile-flags={compile_flags or ''}",
            f"--link-flags={link_flags or ''}",
            "--skip-crash-pattern",
            "--print-exec-time-ms",
        ]
        if fdp_trace_file:
            cmd.extend(["--fdp-trace", fdp_trace_file])
        if symbolize:
            cmd.append("--symbolize")
        if runner_socket is not None:
            cmd.extend(["--amortized-runner-socket", runner_socket])
        if plugin_link_flags:
            cmd.append(
                "--amortized-plugin-fallback-link-flags="
                + " ".join(plugin_link_flags)
            )
        cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
        append_exec_timeout_tester_args(cmd, DEFAULT_EXEC_TIMEOUT_MS)
        proc = run_command(
            cmd,
            "Execution-time calibration run failed",
            ignore_errors=True,
        )
        output = proc.stdout + proc.stderr
        if proc.returncode != 77:
            print(
                "[!] Execution-time calibration fell back to the default timeout "
                f"after a non-crashing probe (exit={proc.returncode})."
            )
            return DEFAULT_EXEC_TIMEOUT_MS
        sample_ms = _extract_exec_time_marker_ms(output)
        if sample_ms is None:
            print(
                "[!] Execution-time calibration fell back to the default timeout "
                "because the probe did not report an execution-time marker."
            )
            return DEFAULT_EXEC_TIMEOUT_MS
        samples_ms.append(sample_ms)

    calibrated_timeout_ms = calibrated_exec_timeout_ms_from_samples(samples_ms)
    if calibrated_timeout_ms is None:
        print(
            "[!] Execution-time calibration fell back to the default timeout "
            "because there were not enough timing samples."
        )
        return DEFAULT_EXEC_TIMEOUT_MS
    print(
        "[+] Calibrated execution timeout: "
        f"{calibrated_timeout_ms} ms from probe samples {samples_ms}"
    )
    return calibrated_timeout_ms


def run_treereducer(
    harness_path: str,
    fdp_trace_file: str | None,
    crash_pattern: str,
    compile_flags: str | None,
    link_flags: str | None,
    crash_input: str | None,
    stable: bool = False,
    phase3_mode: str = PHASE3_SPLIT,
    statistics: bool = False,
    snapshot: bool = False,
    amortize_link: bool = False,
    symbolize: bool = False,
    jobs: int = DEFAULT_TREEREDUCE_JOBS,
    profile: bool = False,
    tool: str = "treereduce",
    auto_var_init_pattern: bool = False,
    raw_output_capture: RawOutputCapture | None = None,
) -> str:
    from harnessreducer.reduction_engines import prepare_reducer_invocation, validate_tool

    validate_tool(tool)
    # Reducers change cwd to a temp dir when invoking the tester, so relative
    # paths for crash_input would not be found.  Resolve to absolute here.
    if crash_input:
        crash_input = str(Path(crash_input).resolve())
    link_flags = absolutize_link_flags(link_flags)
    validate_phase3_mode(phase3_mode)
    if not 1 <= jobs <= MAX_TREEREDUCE_JOBS:
        raise ValueError(
            f"Reducer jobs must be between 1 and {MAX_TREEREDUCE_JOBS}."
        )
    if amortize_link and phase3_mode == PHASE3_DIRECT:
        raise ValueError("Amortized linking requires split or PCH mode.")
    reference_executable = (
        str(Path(get_work_dir()) / "poc.out") if amortize_link else None
    )
    pch_artifacts: PchArtifacts | None = None
    reducer_source = harness_path
    if phase3_mode == PHASE3_PCH:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=fdp_trace_file is not None,
            amortize_link=amortize_link,
        )
        reducer_source = pch_artifacts.body_source

    exec_timeout_ms = DEFAULT_EXEC_TIMEOUT_MS
    if amortize_link:
        calibration_root = StaticArchiveRootConfig(
            source=reducer_source,
            compile_flags=compile_flags,
            pch_path=pch_artifacts.pch_file if pch_artifacts is not None else None,
            use_replay=fdp_trace_file is not None,
        )
        with start_amortized_runner(
            link_flags,
            crash_input,
            fdp_trace_file,
            symbolize=symbolize,
            static_root_config=calibration_root,
            exec_timeout_ms=DEFAULT_EXEC_TIMEOUT_MS,
            reference_executable=reference_executable,
        ) as calibration_runner:
            calibration_plugin_link_flags = getattr(
                calibration_runner,
                "plugin_link_flags",
                (),
            )
            exec_timeout_ms = calibrate_exec_timeout_ms(
                harness_path,
                fdp_trace_file,
                compile_flags,
                link_flags,
                crash_input,
                phase3_mode=phase3_mode,
                pch_artifacts=pch_artifacts,
                symbolize=symbolize,
                runner_socket=calibration_runner.socket_path,
                plugin_link_flags=calibration_plugin_link_flags,
            )
    else:
        exec_timeout_ms = calibrate_exec_timeout_ms(
            harness_path,
            fdp_trace_file,
            compile_flags,
            link_flags,
            crash_input,
            phase3_mode=phase3_mode,
            pch_artifacts=pch_artifacts,
            symbolize=symbolize,
        )
    set_current_exec_timeout_ms(exec_timeout_ms)
    print(f"[+] Using fixed execution timeout: {exec_timeout_ms} ms")

    if phase3_mode == PHASE3_PCH and auto_var_init_pattern:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=fdp_trace_file is not None,
            amortize_link=amortize_link,
            auto_var_init_pattern=True,
        )
        reducer_source = pch_artifacts.body_source

    reduced_harness = os.path.join(get_work_dir(), "reduced_harness.cpp")
    cmd = [
        get_crash_tester_path(),
        "@@.cpp",
        crash_pattern,
        "--crash-input", crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
    ]
    append_exec_timeout_tester_args(cmd, exec_timeout_ms)
    if fdp_trace_file:
        cmd.extend(["--fdp-trace", fdp_trace_file])
    if snapshot:
        cmd.extend(["--last-interesting-file", get_last_interesting_file()])
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    cmd.extend(auto_var_init_tester_args(auto_var_init_pattern))
    cmd.extend(debug_tester_args("reduction_candidate"))
    from harnessreducer.oracle_evaluation import reference_root
    if reference_root() is not None:
        cmd.extend(["--oracle-evaluation", str(reference_root())])
        if pch_artifacts is not None:
            prefix = Path(get_work_dir()) / "oracle_restore_prefix.h"
            prefix.write_text(pch_artifacts.restore_prefix)
            cmd.extend(["--oracle-prefix", str(prefix)])
    if statistics:
        cmd.extend(["--statistics-file", initialize_statistics_file()])
    profile_events_path: str | None = None
    if profile:
        profile_events_path = initialize_candidate_profile_events_file()
        cmd.extend(["--profile-file", profile_events_path])
    if symbolize:
        cmd.append("--symbolize")
        if not amortize_link:
            cmd.extend(required_stack_depth_tester_args(symbolized=True))
        cmd.extend(required_symbolized_crash_location_tester_args())
    else:
        cmd.extend(dynamic_crash_site_tester_args())

    runner_context = (
        start_amortized_runner(
            link_flags,
            crash_input,
            fdp_trace_file,
            symbolize=symbolize,
            static_root_config=StaticArchiveRootConfig(
                source=reducer_source,
                compile_flags=compile_flags,
                pch_path=pch_artifacts.pch_file if pch_artifacts is not None else None,
                use_replay=fdp_trace_file is not None,
            ),
            exec_timeout_ms=exec_timeout_ms,
            reference_executable=reference_executable,
        )
        if amortize_link
        else nullcontext(None)
    )
    with runner_context as amortized_runner, ExitStack() as evaluation_runners:
        if amortized_runner is not None:
            plugin_link_flags = getattr(amortized_runner, "plugin_link_flags", ())
            reference_output = run_amortized_reference_candidate(
                harness_path,
                fdp_trace_file,
                crash_pattern,
                compile_flags,
                link_flags,
                crash_input,
                phase3_mode,
                amortized_runner.socket_path,
                pch_artifacts,
                plugin_link_flags,
                symbolize=symbolize,
                auto_var_init_pattern=auto_var_init_pattern,
            )
            reference_depth = count_first_stack_trace_frames(reference_output)
            if reference_depth:
                cmd.extend(["--stack-depth", str(reference_depth)])
                strict_depth = (
                    get_symbolized_reference_stack_depth_strict()
                    if symbolize
                    else get_normal_reference_stack_depth_strict()
                )
                if strict_depth:
                    cmd.append("--strict-stack-depth")
            elif symbolize:
                raise RuntimeError(
                    "Could not extract a symbolized amortized-link reference stack depth."
                )
            cmd.extend(
                ["--amortized-runner-socket", amortized_runner.socket_path]
            )
            if plugin_link_flags:
                cmd.append(
                    "--amortized-plugin-fallback-link-flags="
                    + " ".join(plugin_link_flags)
                )
        else:
            if not symbolize:
                cmd.extend(stack_depth_tester_args(symbolized=False))

        evaluation_options = {}
        from harnessreducer.oracle_paired_execution import (
            PAIRED_MODE, MIN_SYMBOLIZED_TIMEOUT_MS, comparison_mode,
        )
        if reference_root() is not None and comparison_mode(reference_root()) == PAIRED_MODE:
            symbolized_timeout_ms = max(exec_timeout_ms, MIN_SYMBOLIZED_TIMEOUT_MS)
            cmd.extend(["--oracle-symbolized-timeout-ms", str(symbolized_timeout_ms)])
            if amortized_runner is not None:
                # A fresh parent is necessary because sanitizer options are read
                # at process startup. Reuse the exact already linked runner.
                symbolized_runner = evaluation_runners.enter_context(start_amortized_runner(
                    link_flags, crash_input, fdp_trace_file, symbolize=True,
                    exec_timeout_ms=symbolized_timeout_ms,
                    reference_executable=reference_executable,
                    reuse_binary=amortized_runner.process.args[0],
                ))
                cmd.extend(["--oracle-symbolized-runner-socket", symbolized_runner.socket_path])
            # Keep F's execution deadline unchanged and allow the additional
            # observations to finish before the reducer kills the whole query.
            evaluation_options["candidate_timeout_seconds"] = (
                300 + 2 * CANDIDATE_EVIDENCE_ATTEMPTS * ((symbolized_timeout_ms + 999) // 1000 + 5)
            )
            from harnessreducer.evaluation_common import write_json
            write_json(reference_root() / "paired_execution.json", {
                "fast_execution_timeout_ms": exec_timeout_ms,
                "symbolized_execution_timeout_ms": symbolized_timeout_ms,
                "candidate_timeout_seconds": evaluation_options["candidate_timeout_seconds"],
                "operational_oracle": "unsymbolized",
            })
        invocation = prepare_reducer_invocation(
            tool=tool, source=reducer_source, output=reduced_harness,
            checker_command=cmd, stable=stable, jobs=jobs,
            **evaluation_options,
        )
        print(f"[+] Running reduction engine: {tool}")
        reduction_started_ns = time.perf_counter_ns()
        try:
            proc = invocation.run(run_supervised)
        except (OSError, subprocess.SubprocessError) as exc:
            # Preserve spent work in the profile even when a supervised reducer
            # invocation times out or cannot complete normally.
            proc = subprocess.CompletedProcess(
                invocation.command, 124 if isinstance(exc, subprocess.TimeoutExpired) else 1,
                "", str(exc),
            )
        reduction_wall_ns = time.perf_counter_ns() - reduction_started_ns
    if profile and profile_events_path is not None:
        profile_summary = write_profile_summary(
            profile_events_path,
            get_reduction_profile_json_file(),
            get_reduction_profile_text_file(),
            wall_ns=reduction_wall_ns,
            jobs=jobs,
            returncode=proc.returncode,
            configuration={
                "tool": tool,
                "engine": invocation.metadata,
                "jobs": jobs,
                "phase3_mode": phase3_mode,
                "amortize_link": amortize_link,
                "symbolize": symbolize,
                "stable": stable,
                "auto_var_init_pattern": auto_var_init_pattern,
                "source": str(Path(reducer_source).resolve()),
                "source_bytes": Path(reducer_source).stat().st_size,
            },
        )
        reducer_summary = profile_summary["reducer"]
        assert isinstance(reducer_summary, dict)
        print(
            "[+] Tree-reduction profile: "
            f"{reducer_summary['profiled_checks']} checks in "
            f"{float(reducer_summary['wall_seconds']):.3f}s "
            f"({float(reducer_summary['checks_per_second']):.3f} checks/s)"
        )
        print(f"[+] Profile report: {get_reduction_profile_text_file()}")
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to run {tool} reducer:\n{proc.stdout} {proc.stderr}")
    invocation.publish_result(raw_output_capture)
    if not os.path.exists(reduced_harness):
        raise RuntimeError("Reduced harness file was not created as expected.")

    restore_transition_log_path = os.path.join(
        get_work_dir(),
        "reduced_harness.restore_transition.log",
    )
    if pch_artifacts is not None:
        try:
            os.remove(restore_transition_log_path)
        except FileNotFoundError:
            pass
        header = [
            "===== pre/post-restore stack diagnostics =====",
            "These diagnostics are not used for the pass/fail decision above.",
        ]
        Path(restore_transition_log_path).write_text(
            "\n".join(header) + "\n",
            encoding="utf-8",
        )
        _append_restore_transition_stack_diagnostics(
            restore_transition_log_path,
            section_label="before_restore",
            source_path=reduced_harness,
            phase3_mode=PHASE3_PCH,
            pch_artifacts=pch_artifacts,
            crash_input=crash_input,
            compile_flags=compile_flags,
            link_flags=link_flags,
            fdp_trace_file=fdp_trace_file,
            crash_pattern_symbolize_0=get_reference_crash_pattern_symbolize_0(),
            crash_pattern_symbolize_1=get_reference_crash_pattern_symbolize_1(),
            retry_oom_without_rss_limit=True,
        )

    if pch_artifacts is not None:
        restore_pch_includes(reduced_harness, pch_artifacts)
        _append_restore_transition_stack_diagnostics(
            restore_transition_log_path,
            section_label="after_restore",
            source_path=reduced_harness,
            phase3_mode=PHASE3_DIRECT,
            pch_artifacts=None,
            crash_input=crash_input,
            compile_flags=compile_flags,
            link_flags=link_flags,
            fdp_trace_file=fdp_trace_file,
            crash_pattern_symbolize_0=get_reference_crash_pattern_symbolize_0(),
            crash_pattern_symbolize_1=get_reference_crash_pattern_symbolize_1(),
            retry_oom_without_rss_limit=True,
        )
        if snapshot:
            last_interesting_file = get_last_interesting_file()
            if os.path.exists(last_interesting_file):
                restore_pch_includes(last_interesting_file, pch_artifacts)

    return reduced_harness


def format_reduced_harness(reduced_harness_path: str) -> None:
    print(f"Formatting reduced harness with clang-format: {reduced_harness_path}")
    run_command(
        ["clang-format", "-i", "--style=LLVM", reduced_harness_path],
        "Failed to format reduced harness with clang-format",
    )


def stack_depth_tester_args(*, symbolized: bool = False) -> list[str]:
    depth = (
        get_symbolized_reference_stack_depth()
        if symbolized
        else get_normal_reference_stack_depth()
    )
    if depth is None:
        return []
    args = ["--stack-depth", str(depth)]
    strict = (
        get_symbolized_reference_stack_depth_strict()
        if symbolized
        else get_normal_reference_stack_depth_strict()
    )
    if strict:
        args.append("--strict-stack-depth")
    return args


def required_stack_depth_tester_args(*, symbolized: bool = False) -> list[str]:
    args = stack_depth_tester_args(symbolized=symbolized)
    if args:
        return args
    mode = "symbolized" if symbolized else "fast-path"
    raise ValueError(f"A {mode} reference stack depth is required for this oracle.")


def dynamic_crash_site_tester_args() -> list[str]:
    site = get_dynamic_reference_crash_site()
    if site is None:
        return []
    return [
        "--dynamic-crash-site-library",
        site.library_path,
        "--dynamic-crash-site-offset",
        site.offset,
    ]


def symbolized_crash_location_tester_args() -> list[str]:
    pattern = get_symbolized_reference_crash_location_pattern()
    if not pattern or not pattern.strip():
        return []
    return ["--crash-location-pattern", pattern]


def required_symbolized_crash_location_tester_args() -> list[str]:
    args = symbolized_crash_location_tester_args()
    if args:
        return args
    raise ValueError(
        "A symbolized crash-location reference is required for --symbolize reduction."
    )


def _write_validation_failure_log(
    validation_log_path: str | None,
    proc: subprocess.CompletedProcess[str],
) -> None:
    if validation_log_path is None:
        return
    artifact = (
        f"returncode: {proc.returncode}\n"
        "===== stdout =====\n"
        f"{proc.stdout}"
        "\n===== stderr =====\n"
        f"{proc.stderr}"
    )
    Path(validation_log_path).write_text(artifact, encoding="utf-8")


def _validation_failed_after_sanitizer_exit(proc: subprocess.CompletedProcess[str]) -> bool:
    output = f"{proc.stdout}\n{proc.stderr}"
    return "Crash pattern did not match. Exit status: 77" in output


def validate_crash_pattern(
    harness_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    fdp_trace_file: str | None = None,
    phase3_mode: str = PHASE3_DIRECT,
    validation_log_path: str | None = None,
    debug_stage: str | None = None,
    retry_oom_without_rss_limit: bool = False,
    evidence_attempts: int | None = None,
    auto_var_init_pattern: bool = False,
) -> bool:
    """Run a fast symbolize=0 crash-pattern/depth validation."""
    validate_phase3_mode(phase3_mode)
    pch_artifacts: PchArtifacts | None = None
    tester_source = harness_path
    if phase3_mode == PHASE3_PCH:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=fdp_trace_file is not None,
            auto_var_init_pattern=auto_var_init_pattern,
        )
        tester_source = pch_artifacts.body_source

    cmd = [
        get_crash_tester_path(),
        tester_source,
        crash_pattern,
        "--crash-input", crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
    ]
    cmd.extend(stack_depth_tester_args(symbolized=False))
    cmd.extend(dynamic_crash_site_tester_args())
    if fdp_trace_file:
        cmd.extend(["--fdp-trace", fdp_trace_file])
    cmd.extend(retry_oom_tester_args(retry_oom_without_rss_limit))
    cmd.extend(evidence_attempt_tester_args(evidence_attempts))
    cmd.extend(auto_var_init_tester_args(auto_var_init_pattern))
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    append_exec_timeout_tester_args(cmd)
    if debug_stage:
        cmd.extend(debug_tester_args(debug_stage))

    proc = None
    retry_attempts = evidence_attempts or CANDIDATE_EVIDENCE_ATTEMPTS
    max_attempts = (
        retry_attempts
        if get_dynamic_reference_crash_site() is not None
        else 1
    )
    for attempt in range(1, max_attempts + 1):
        proc = run_command(
            cmd,
            "Fast crash-pattern validation failed.",
            ignore_errors=True,
        )
        _record_poc_runtime_args_from_validation(proc)
        if proc.returncode == 77:
            return True
        if not _validation_failed_after_sanitizer_exit(proc) or attempt >= max_attempts:
            break
        print(
            "[!] Fast validation saw sanitizer exit 77 but the first crash text "
            f"did not match on attempt {attempt}/{max_attempts}; retrying because "
            "a dynamic crash-site anchor is available."
        )
    if proc is not None:
        _write_validation_failure_log(validation_log_path, proc)
    return False


def validate_stack_trace(
    harness_path: str,
    crash_pattern: str | None,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    fdp_trace_file: str | None = None,
    phase3_mode: str = PHASE3_DIRECT,
    validation_log_path: str | None = None,
    require_crash_pattern: bool = True,
    debug_stage: str | None = None,
    retry_oom_without_rss_limit: bool = False,
    evidence_attempts: int | None = None,
    auto_var_init_pattern: bool = False,
) -> bool:
    """Run a symbolize=1 crash-preservation check.

    This always validates exit code 77 and first-stack-trace depth. It validates
    the symbolized crash pattern when one is available. When a stored non-empty
    ``stack_trace.pattern`` exists, it also validates the pre-harness stack trace
    against that pattern.
    """
    if require_crash_pattern and not crash_pattern:
        raise ValueError("Symbolized crash pattern cannot be empty.")
    stack_trace_file = get_stack_trace_file()
    stack_trace_arg: list[str] = []
    if not os.path.exists(stack_trace_file):
        print("[*] No stored stack trace pattern; running crash/depth validation only.")
    else:
        stored_pattern = Path(stack_trace_file).read_text(encoding="utf-8")
        if not stored_pattern.strip():
            print("[*] Stored stack trace pattern is empty; running crash/depth validation only.")
        else:
            stack_trace_arg = ["--stack-trace-file", stack_trace_file]

    validate_phase3_mode(phase3_mode)
    pch_artifacts: PchArtifacts | None = None
    tester_source = harness_path
    if phase3_mode == PHASE3_PCH:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=fdp_trace_file is not None,
            auto_var_init_pattern=auto_var_init_pattern,
        )
        tester_source = pch_artifacts.body_source

    cmd = [
        get_crash_tester_path(),
        tester_source,
        crash_pattern or ".*",
        "--crash-input", crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
        "--symbolize",  # force symbolize=1 for this check
    ]
    if not require_crash_pattern:
        cmd.append("--skip-crash-pattern")
    cmd.extend(stack_trace_arg)
    cmd.extend(stack_depth_tester_args(symbolized=True))
    # The symbolized crash-location anchor is the authoritative gate on this
    # path.  The full symbolized stack-trace match (stack_trace_arg above) is
    # advisory: it can fluctuate for multithreaded targets whose worker thread
    # wins the crash race nondeterministically.
    cmd.extend(symbolized_crash_location_tester_args())
    if fdp_trace_file:
        cmd.extend(["--fdp-trace", fdp_trace_file])
    cmd.extend(retry_oom_tester_args(retry_oom_without_rss_limit))
    cmd.extend(evidence_attempt_tester_args(evidence_attempts))
    cmd.extend(auto_var_init_tester_args(auto_var_init_pattern))
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    append_exec_timeout_tester_args(cmd)
    if debug_stage:
        cmd.extend(debug_tester_args(debug_stage))

    proc = run_command(cmd, "Stack trace validation failed.", ignore_errors=True)
    _record_poc_runtime_args_from_validation(proc)
    if validation_log_path is not None and proc.returncode != 77:
        _write_validation_failure_log(validation_log_path, proc)
    return proc.returncode == 77


def validate_symbolized_crash_pattern_depth_location(
    harness_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    fdp_trace_file: str | None = None,
    phase3_mode: str = PHASE3_DIRECT,
    validation_log_path: str | None = None,
    debug_stage: str | None = None,
    retry_oom_without_rss_limit: bool = False,
    evidence_attempts: int | None = None,
    auto_var_init_pattern: bool = False,
) -> bool:
    """Run a symbolize=1 crash-pattern/depth/location validation."""
    if not crash_pattern:
        raise ValueError("Symbolized crash pattern cannot be empty.")
    validate_phase3_mode(phase3_mode)
    pch_artifacts: PchArtifacts | None = None
    tester_source = harness_path
    if phase3_mode == PHASE3_PCH:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=fdp_trace_file is not None,
            auto_var_init_pattern=auto_var_init_pattern,
        )
        tester_source = pch_artifacts.body_source

    cmd = [
        get_crash_tester_path(),
        tester_source,
        crash_pattern,
        "--crash-input", crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
        "--symbolize",
    ]
    cmd.extend(required_stack_depth_tester_args(symbolized=True))
    cmd.extend(required_symbolized_crash_location_tester_args())
    if fdp_trace_file:
        cmd.extend(["--fdp-trace", fdp_trace_file])
    cmd.extend(retry_oom_tester_args(retry_oom_without_rss_limit))
    cmd.extend(evidence_attempt_tester_args(evidence_attempts))
    cmd.extend(auto_var_init_tester_args(auto_var_init_pattern))
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    append_exec_timeout_tester_args(cmd)
    if debug_stage:
        cmd.extend(debug_tester_args(debug_stage))

    proc = None
    retry_attempts = evidence_attempts or CANDIDATE_EVIDENCE_ATTEMPTS
    max_attempts = (
        retry_attempts
        if get_symbolized_reference_crash_location_pattern()
        else 1
    )
    for attempt in range(1, max_attempts + 1):
        proc = run_command(
            cmd,
            "Symbolized crash-location validation failed.",
            ignore_errors=True,
        )
        _record_poc_runtime_args_from_validation(proc)
        if proc.returncode == 77:
            return True
        if not _validation_failed_after_sanitizer_exit(proc) or attempt >= max_attempts:
            break
        print(
            "[!] Symbolized validation saw sanitizer exit 77 but the first crash "
            f"text did not match on attempt {attempt}/{max_attempts}; retrying "
            "because a symbolized crash-location anchor is available."
        )
    if validation_log_path is not None and proc is not None:
        _write_validation_failure_log(validation_log_path, proc)
    return False


def validate_crash_pattern_and_stack_trace(
    harness_path: str,
    crash_pattern_symbolize_0: str,
    crash_pattern_symbolize_1: str | None,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    fdp_trace_file: str | None = None,
    phase3_mode: str = PHASE3_DIRECT,
    validation_log_path: str | None = None,
    debug_stage: str | None = None,
    retry_oom_without_rss_limit: bool = False,
    evidence_attempts: int | None = None,
    auto_var_init_pattern: bool = False,
) -> bool:
    """Validate crash identity with symbolize=0, then stack identity with symbolize=1."""
    if not validate_crash_pattern(
        harness_path,
        crash_pattern_symbolize_0,
        crash_input,
        compile_flags,
        link_flags,
        fdp_trace_file=fdp_trace_file,
        phase3_mode=phase3_mode,
        validation_log_path=validation_log_path,
        debug_stage=(f"{debug_stage}_symbolize_0" if debug_stage else None),
        retry_oom_without_rss_limit=retry_oom_without_rss_limit,
        evidence_attempts=evidence_attempts,
        auto_var_init_pattern=auto_var_init_pattern,
    ):
        return False

    if crash_pattern_symbolize_1 is None:
        print(
            "[*] No symbolize=1 crash pattern is available; "
            "checking symbolized stack/depth without a symbolized crash regex."
        )
    return validate_stack_trace(
        harness_path,
        crash_pattern_symbolize_1,
        crash_input,
        compile_flags,
        link_flags,
        fdp_trace_file=fdp_trace_file,
        phase3_mode=phase3_mode,
        validation_log_path=validation_log_path,
        require_crash_pattern=crash_pattern_symbolize_1 is not None,
        debug_stage=(f"{debug_stage}_symbolize_1" if debug_stage else None),
        retry_oom_without_rss_limit=retry_oom_without_rss_limit,
        evidence_attempts=evidence_attempts,
        auto_var_init_pattern=auto_var_init_pattern,
    )


def check_reducer_symbolized_reduction_oracle(
    harness_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    phase3_mode: str = PHASE3_DIRECT,
) -> None:
    print("[+] Checking symbolized reduction crash-location oracle validity...")
    if not validate_symbolized_crash_pattern_depth_location(
        harness_path,
        crash_pattern,
        crash_input,
        compile_flags,
        link_flags,
        phase3_mode=phase3_mode,
    ):
        raise ValueError(
            "Symbolized reduction crash-location oracle did not match the original crash behavior."
        )
    print("[+] Symbolized reduction crash-location oracle is valid.")


def check_reducer_symbolized_crash_pattern(
    harness_path: str,
    crash_pattern: str | None,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    phase3_mode: str = PHASE3_DIRECT,
) -> None:
    if crash_pattern:
        print("[+] Checking symbolized crash pattern validity...")
    else:
        print("[+] Checking symbolized stack-trace validity without a symbolized crash pattern...")
    if not validate_stack_trace(
        harness_path,
        crash_pattern,
        crash_input,
        compile_flags,
        link_flags,
        phase3_mode=phase3_mode,
        require_crash_pattern=crash_pattern is not None,
    ):
        raise ValueError(
            "Symbolized crash behavior did not match the original crash behavior."
        )
    if crash_pattern:
        print("[+] Symbolized crash pattern is valid.")
    else:
        print("[+] Symbolized stack-trace validation is valid.")

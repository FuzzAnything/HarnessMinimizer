from __future__ import annotations

import atexit
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

TREEDUCER_DIR: str | None = None
_IS_USER_WORK_DIR = False
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
PHASE3_DIRECT = "direct"
PHASE3_PCH = "pch"
PHASE3_MODES = {PHASE3_DIRECT, PHASE3_PCH}
PHASE3_SANITIZER_FLAGS = ["-fsanitize=address,fuzzer,undefined"]
PHASE3_DIRECT_OPT_FLAGS = ["-g", "-O0"]
PHASE3_PCH_OPT_FLAGS = ["-O1", "-gline-tables-only"]
PCH_PREFIX_HEADER_NAME = "fahm_prefix.h"
PCH_PREFIX_FILE_NAME = "fahm_prefix.pch"

STACK_TRACE_FILE_NAME = "stack_trace.pattern"
STACK_TRACE_COUNTER_FILE_NAME = "stack_trace.counter"
STACK_TRACE_BACKUP_FILE_NAME = "stack_trace.backup.cpp"
# Matches symbolized stack frames like:
#   #0 0x5ea4dfe78fe6 in av1_func /root/src/file.c:444:18
#   #5 0x5ea4dfa2f68f in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/path/fuzzer+0x46068f)
STACK_FRAME_PATTERN = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+")
LLVMFuzzerTestOneInput_PATTERN = re.compile(r"\bLLVMFuzzerTestOneInput\b")


@dataclass(frozen=True)
class PchArtifacts:
    body_source: str
    prefix_header: str
    pch_file: str
    restore_prefix: str


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
ASAN_ERROR_PATTERN = re.compile(r"ERROR:\s*AddressSanitizer:\s*[\w-]+")
LEAK_PATTERN = re.compile(
    r"SUMMARY: AddressSanitizer: \d+ byte\(s\) leaked in \d+ allocation\(s\)\."
)
RUNTIME_ERROR_PATTERN = re.compile(
    r"(?:/[^\s:]+)+:\d+:\d+:\s*runtime error:.*"
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


def validate_phase3_mode(mode: str) -> str:
    if mode not in PHASE3_MODES:
        raise ValueError(
            f"Unsupported phase 3 compilation mode {mode!r}; "
            f"expected one of: {', '.join(sorted(PHASE3_MODES))}"
        )
    return mode


def _split_flags(flags: str | None) -> list[str]:
    return flags.split() if flags else []


def _phase3_replay_flags(use_replay: bool) -> list[str]:
    if not use_replay:
        return []
    return [f"-I{get_fdp_header_dir()}", "-DFDP_MIN_MODE_REPLAY"]


def _build_pch_compile_command(
    prefix_header: str,
    pch_file: str,
    compile_flags: str | None,
    use_replay: bool,
) -> list[str]:
    cmd = [
        "clang++",
        "-Qunused-arguments",
        *_phase3_replay_flags(use_replay),
        *PHASE3_SANITIZER_FLAGS,
        *PHASE3_PCH_OPT_FLAGS,
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


def _rewrite_local_quoted_include_for_pch(line: str, source_dir: Path) -> str:
    """Preserve quote-include semantics after moving includes into the work dir.

    Direct compilation resolves #include "local.h" relative to the source file
    first.  The generated fahm_prefix.h lives in the reducer work directory, so a
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
    pch_prefix_lines = [
        "// Generated by HarnessReducer for Phase 3 PCH compilation.\n",
        "#include <stdint.h>\n",
        "#include <stddef.h>\n",
    ]
    restore_prefix_lines = [
        "#include <stdint.h>\n",
        "#include <stddef.h>\n",
    ]
    body_lines: list[str] = []

    for line in source.splitlines(keepends=True):
        if _INCLUDE_DIRECTIVE_PATTERN.match(line):
            if line.strip() in standard_include_keys:
                continue
            pch_prefix_lines.append(_rewrite_local_quoted_include_for_pch(line, source_dir))
            restore_prefix_lines.append(line)
        else:
            body_lines.append(line)

    return (
        "".join(pch_prefix_lines),
        "".join(restore_prefix_lines),
        "".join(body_lines),
    )


def prepare_phase3_pch_harness(
    harness_path: str,
    compile_flags: str | None,
    use_replay: bool,
) -> PchArtifacts:
    """Create fahm_prefix.h/.pch and an include-stripped harness body.

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
    body_source = work_dir / f"{source_path.stem}.fahm_body{suffix}"

    prefix_header.write_text(pch_prefix, encoding="utf-8")
    body_source.write_text(body, encoding="utf-8")

    compile_cmd = _build_pch_compile_command(
        str(prefix_header),
        str(pch_file),
        compile_flags,
        use_replay=use_replay,
    )
    print(f"[+] Precompiling Phase 3 header: {prefix_header} -> {pch_file}")
    run_command(compile_cmd, "Failed to precompile Phase 3 PCH header")
    print(f"[+] Wrote include-stripped Phase 3 harness body: {body_source}")

    return PchArtifacts(
        body_source=str(body_source),
        prefix_header=str(prefix_header),
        pch_file=str(pch_file),
        restore_prefix=restore_prefix,
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
        return ["--direct"]
    if artifacts is None:
        raise ValueError("PCH Phase 3 mode requires prepared PCH artifacts.")
    return ["--pch", "--pch-path", artifacts.pch_file]


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


def run_command(cmd: list[str], error_prefix: str, env: dict[str, str] | None = None, ignore_errors: bool = False) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0 and not ignore_errors:
        err_msg = proc.stderr.strip() or proc.stdout.strip() or "Unknown error"
        raise RuntimeError(f"{error_prefix}: {err_msg}")
    return proc


def check_tree_reducer() -> None:
    print("[+] Checking for tree-reducer availability...")
    run_command(
        ["treereduce-c", "--help"],
        "tree-reducer is not available. Please ensure it is installed and in your PATH",
    )
    print("[+] tree-reducer is available.")

def check_harness_compilation(
    harness_path: str,
    compile_flags: str | None,
    link_flags: str | None,
) -> None:
    print("[+] Checking harness compilation...")
    work_dir = get_work_dir()
    output_bin = os.path.join(work_dir, "poc.out")
    compile_cmd = [
        "clang++",
        "-fsanitize=address,fuzzer,undefined",
        "-g",
        "-O0",
        *_split_flags(compile_flags),
        harness_path,
        "-o",
        output_bin,
        *_split_flags(link_flags),
    ]

    run_command(compile_cmd, "Failed to compile the original harness. Please fix compilation errors before reduction.")
    print("[+] Harness compiles successfully.")

def normalize_crash_signature(signature: str, escape: bool = False) -> str:
    signature = signature.strip()
    if escape:
        placeholder = "__ADDR__"
        signature = MEMORY_ADDRESS_PATTERN.sub(placeholder, signature)
        signature = re.escape(signature)
        return signature.replace(re.escape(placeholder), r"0x[0-9a-fA-F]+")

    return MEMORY_ADDRESS_PATTERN.sub(r"0x[0-9a-fA-F]+", signature)

def extract_stack_trace(output: str) -> str | None:
    """Extract the first stack trace from symbolized sanitizer output.

    Parses stack frames (lines matching ``#N 0xADDR in ...``), truncates at
    ``LLVMFuzzerTestOneInput``, and returns the raw text of those frames.
    Only the *first* stack trace is kept (ASan may emit multiple — e.g., one
    for the overflow and one for the allocation site).
    Returns None if no stack frames are found.
    """
    frames: list[str] = []
    in_first_trace = False
    for line in output.splitlines():
        if STACK_FRAME_PATTERN.match(line):
            in_first_trace = True
            # Stop if this frame belongs to the harness / fuzzer infrastructure.
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

def get_stack_trace_file() -> str:
    return os.path.join(get_work_dir(), STACK_TRACE_FILE_NAME)

def get_stack_trace_counter_file() -> str:
    return os.path.join(get_work_dir(), STACK_TRACE_COUNTER_FILE_NAME)

def get_stack_trace_backup_file() -> str:
    return os.path.join(get_work_dir(), STACK_TRACE_BACKUP_FILE_NAME)


def reset_stack_trace_state() -> None:
    """Remove persisted stack-trace validation artifacts from the work dir."""
    for path in (
        get_stack_trace_file(),
        get_stack_trace_counter_file(),
        get_stack_trace_backup_file(),
    ):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

def extract_crash_pattern_from_output(crash_input: str | None) -> str | None:
    work_dir = get_work_dir()
    output_bin = os.path.join(work_dir, "poc.out")
    cmd = [output_bin]
    if crash_input:
        cmd.append(crash_input)
    env = os.environ.copy()
    env["UBSAN_OPTIONS"] = "exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=1"
    env["ASAN_OPTIONS"] = "exitcode=77:symbolize=1:handle_abort=1"
    proc = run_command(cmd, env=env, error_prefix="Failed to execute harness for crash pattern extraction", ignore_errors=True)
    output = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 77:
        print("[!] Warning: No crash detected when running the harness. Output:\n" + output)
        return None

    # Extract and save the first stack trace (normalized) for periodic validation.
    raw_stack_trace = extract_stack_trace(output)
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
        print("[!] No symbolized stack trace found in crash output.")

    # for line in output.splitlines():
    #     if "Assertion" in line and "failed." in line:
    #         abort_assert_match = ABORT_ASSERT_LOCATION_PATTERN.search(line)
    #         if abort_assert_match:
    #             return re.escape(abort_assert_match.group(1))

    abort_assert_match = ABORT_ASSERT_LOCATION_PATTERN.search(output)
    if abort_assert_match:
        parts = abort_assert_match.group(0).split(":")
        signature = parts[0] + ":" + parts[1]
        return normalize_crash_signature(signature)

    asan_summary_match = ASAN_SUMMARY_PATTERN.search(output)
    if asan_summary_match:
        return normalize_crash_signature(asan_summary_match.group(0))

    asan_error_match = ASAN_ERROR_PATTERN.search(output)
    if asan_error_match:
        return normalize_crash_signature(asan_error_match.group(0))

    leak_match = LEAK_PATTERN.search(output)
    if leak_match:
        return normalize_crash_signature(leak_match.group(0))

    runtime_error_match = RUNTIME_ERROR_PATTERN.search(output)
    if runtime_error_match:
        return normalize_crash_signature(runtime_error_match.group(0), escape=True)

    ubsan_match = UBSAN_PATTERN.search(output)
    if ubsan_match:
        return normalize_crash_signature(ubsan_match.group(0))

    absl_check_match = ABSL_CHECK_PATTERN.search(output)
    if absl_check_match:
        return normalize_crash_signature(absl_check_match.group(1))

    libfuzzer_signal_match = LIBFUZZER_SIGNAL_PATTERN.search(output)
    if libfuzzer_signal_match:
        return normalize_crash_signature(libfuzzer_signal_match.group(1))

    raise ValueError("Failed to extract a valid crash pattern from the harness output. Output:\n" + output)


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
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
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
        "-g",
        "-O0",
        *_split_flags(compile_flags),
        harness_path,
        "-o",
        tagged_harness_bin,
        *_split_flags(link_flags),
    ]

    run_command(compile_cmd, "Failed to compile tagged harness with dump mode")
    return tagged_harness_bin


def dump_fdp_trace(harness_bin: str, crash_input: str | None) -> str:
    fdp_trace_file = os.path.join(get_work_dir(), "fdp_trace.log")
    env = os.environ.copy()
    env["FDP_TRACE_PATH"] = fdp_trace_file

    exec_cmd = [harness_bin, crash_input] if crash_input else [harness_bin]
    run_command(exec_cmd, "Failed to execute tagged harness in dump mode", env=env, ignore_errors=True)

    if not os.path.exists(fdp_trace_file):
        raise RuntimeError("FDP trace file was not created as expected.")
    return fdp_trace_file


def run_treereducer(
    harness_path: str,
    fdp_trace_file: str,
    crash_pattern: str,
    compile_flags: str | None,
    link_flags: str | None,
    crash_input: str | None,
    stable: bool = False,
    phase3_mode: str = PHASE3_DIRECT,
    iteration: int | None = None,
) -> str:
    # treereduce changes cwd to a temp dir when invoking the tester, so relative
    # paths for crash_input would not be found.  Resolve to absolute here.
    if crash_input:
        crash_input = str(Path(crash_input).resolve())
    validate_phase3_mode(phase3_mode)
    pch_artifacts: PchArtifacts | None = None
    reducer_source = harness_path
    if phase3_mode == PHASE3_PCH:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=True,
        )
        reducer_source = pch_artifacts.body_source

    reduced_harness = os.path.join(get_work_dir(), "reduced_harness.cpp")
    cmd = [
        "treereduce-c",
        "-j",
        "60",
        "-s",
        reducer_source,
        "-o",
        reduced_harness,
    ]
    if stable:
        cmd.append("--stable")
        cmd.append("--min-reduction")
        cmd.append("1")
    else:
        cmd.append("--fast")
    cmd.extend([
        "--timeout",
        "300",
        "--interesting-exit-code",
        "77",
        "--",
        get_crash_tester_path(),
        "@@.cpp",
        crash_pattern,
        "--crash-input", crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
        "--fdp-trace", fdp_trace_file,
    ])
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    cmd.extend(stack_trace_tester_args(iteration))

    proc = subprocess.run(
        cmd,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to run tree-reducer:\n{proc.stdout} {proc.stderr}")
    if not os.path.exists(reduced_harness):
        raise RuntimeError("Reduced harness file was not created as expected.")

    if pch_artifacts is not None:
        restore_pch_includes(reduced_harness, pch_artifacts)

    return reduced_harness


def format_reduced_harness(reduced_harness_path: str) -> None:
    print(f"Formatting reduced harness with clang-format: {reduced_harness_path}")
    run_command(
        ["clang-format", "-i", "--style=LLVM", reduced_harness_path],
        "Failed to format reduced harness with clang-format",
    )


def stack_trace_tester_args(
    iteration: int | None,
) -> list[str]:
    """Build extra crash_tester.py args for stack trace validation."""
    if iteration is None:
        return []
    args: list[str] = []
    stack_trace_file = get_stack_trace_file()
    if os.path.exists(stack_trace_file):
        args.extend(["--stack-trace-file", stack_trace_file])
    args.extend(["--iteration", str(iteration)])
    args.extend(["--counter-file", get_stack_trace_counter_file()])
    args.extend(["--backup-file", get_stack_trace_backup_file()])
    return args


def validate_stack_trace(
    harness_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    fdp_trace_file: str | None = None,
    phase3_mode: str = PHASE3_DIRECT,
) -> bool:
    """Run a symbolize=1 check and compare the stack trace against the stored pattern.

    Returns True if the stack trace matches (or no stored pattern exists).
    """
    stack_trace_file = get_stack_trace_file()
    if not os.path.exists(stack_trace_file):
        print("[*] No stored stack trace pattern; skipping stack trace validation.")
        return True

    stored_pattern = Path(stack_trace_file).read_text(encoding="utf-8")
    if not stored_pattern.strip():
        print("[*] Stored stack trace pattern is empty; skipping stack trace validation.")
        return True

    validate_phase3_mode(phase3_mode)
    pch_artifacts: PchArtifacts | None = None
    tester_source = harness_path
    if phase3_mode == PHASE3_PCH:
        pch_artifacts = prepare_phase3_pch_harness(
            harness_path,
            compile_flags,
            use_replay=fdp_trace_file is not None,
        )
        tester_source = pch_artifacts.body_source

    cmd = [
        get_crash_tester_path(),
        tester_source,
        crash_pattern,
        "--crash-input", crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
        "--symbolize",  # force symbolize=1 for this check
        "--stack-trace-file", stack_trace_file,
    ]
    if fdp_trace_file:
        cmd.extend(["--fdp-trace", fdp_trace_file])
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))

    proc = run_command(cmd, "Stack trace validation failed.", ignore_errors=True)
    return proc.returncode == 77

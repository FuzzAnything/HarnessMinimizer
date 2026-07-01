#!/usr/bin/env python3
import fcntl
import os
import re
import shutil
import subprocess
import sys
import tempfile
import argparse
from pathlib import Path

__script_dir__ = os.path.dirname(os.path.realpath(__file__))
__project_root__ = Path(__script_dir__).parent
sys.path.insert(0, str(__project_root__ / "src"))
PHASE3_SANITIZER_FLAGS = ["-fsanitize=address,fuzzer,undefined"]
PHASE3_DIRECT_OPT_FLAGS = ["-g", "-O0"]
PHASE3_SPLIT_OPT_FLAGS = ["-O0", "-gline-tables-only"]
PHASE3_PCH_OPT_FLAGS = ["-O0", "-gline-tables-only"]

# Stack trace validation thresholds (tune these values as needed).
SMALL_HARNESS_LINE_THRESHOLD = 75   # below this, iteration interval shrinks
TINY_HARNESS_LINE_THRESHOLD = 50    # below this, every candidate is checked
SMALL_HARNESS_ITERATION = 10        # interval when lines < SMALL_HARNESS_LINE_THRESHOLD
TINY_HARNESS_ITERATION = 1          # interval when lines < TINY_HARNESS_LINE_THRESHOLD

from harnessreducer.reducer_runner import (
    STACK_FRAME_PATTERN,
    LLVMFuzzerTestOneInput_PATTERN,
    _frame_matches_harness_source,
)
# STACK_FRAME_PATTERN = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+")
# LLVMFuzzerTestOneInput_PATTERN = re.compile(r"\bLLVMFuzzerTestOneInput\b")


def get_project_root():
    return __project_root__

def get_fdp_header_dir():
    return os.path.join(get_project_root(), "include")


def split_flags(flags: str | None) -> list[str]:
    return flags.split() if flags else []


def phase3_replay_flags(fdp_trace: str | None) -> list[str]:
    if not fdp_trace:
        return []
    return [f"-I{get_fdp_header_dir()}", "-DFDP_MIN_MODE_REPLAY"]


def extract_stack_trace(output: str, harness_path: str | None = None) -> str | None:
    """Extract the first stack trace from symbolized sanitizer output.

    Parses stack frames, truncates at the first harness frame when
    ``harness_path`` is provided, otherwise falls back to LLVMFuzzerTestOneInput.
    Only the first stack trace is kept.
    Returns None if no stack frames are found.
    """
    frames: list[str] = []
    in_first_trace = False
    for line in output.splitlines():
        if STACK_FRAME_PATTERN.match(line):
            in_first_trace = True
            if _frame_matches_harness_source(line, harness_path):
                break
            if LLVMFuzzerTestOneInput_PATTERN.search(line):
                break
            frames.append(line)
        elif in_first_trace:
            break
    if not frames:
        return None
    return "\n".join(frames)


def _effective_iteration(base_iteration: int, source_path: str) -> int:
    try:
        with open(source_path, encoding="utf-8", errors="ignore") as f:
            line_count = sum(1 for _ in f)
    except OSError:
        return base_iteration
    if line_count < TINY_HARNESS_LINE_THRESHOLD:
        return TINY_HARNESS_ITERATION
    if line_count < SMALL_HARNESS_LINE_THRESHOLD:
        return SMALL_HARNESS_ITERATION
    return base_iteration


def _read_counter(counter_file: str) -> int:
    try:
        return int(Path(counter_file).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0


def _write_counter(counter_file: str, value: int) -> None:
    Path(counter_file).write_text(str(value), encoding="utf-8")


def _statistics_counts_from_text(text: str) -> dict[int, int]:
    counts = {77: 0, 1: 0, -1: 0}
    patterns = {
        77: re.compile(r"^count_77:\s*(\d+)\s*$", re.MULTILINE),
        1: re.compile(r"^count_1:\s*(\d+)\s*$", re.MULTILINE),
        -1: re.compile(r"^count_-1:\s*(\d+)\s*$", re.MULTILINE),
    }
    for code, pattern in patterns.items():
        match = pattern.search(text)
        if match:
            counts[code] = int(match.group(1))
    return counts


def _format_statistics_text(counts: dict[int, int]) -> str:
    count_77 = counts.get(77, 0)
    count_1 = counts.get(1, 0)
    count_neg1 = counts.get(-1, 0)
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


def _update_statistics_file(statistics_file: str, result_code: int) -> None:
    if result_code not in {77, 1, -1}:
        return

    stats_path = Path(statistics_file)
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    with stats_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        counts = _statistics_counts_from_text(handle.read())
        counts[result_code] = counts.get(result_code, 0) + 1
        handle.seek(0)
        handle.truncate()
        handle.write(_format_statistics_text(counts))
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _finalize_result(args: argparse.Namespace, result_code: int) -> int:
    if args.statistics_file and args.iteration is None:
        _update_statistics_file(args.statistics_file, result_code)
    return result_code


def compile_direct(args: argparse.Namespace, output_path: str) -> tuple[int, str | None]:
    compile_cmd = [
        "clang++",
        *phase3_replay_flags(args.fdp_trace),
        *PHASE3_SANITIZER_FLAGS,
        *PHASE3_DIRECT_OPT_FLAGS,
        *split_flags(args.compile_flags),
        args.source,
        "-o",
        output_path,
        *split_flags(args.link_flags),
    ]

    compile_proc = subprocess.run(
        compile_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if compile_proc.returncode != 0:
        err_msg = compile_proc.stderr.strip() or compile_proc.stdout.strip() or "Unknown compilation error"
        print(f"Compilation failed: {compile_cmd} {err_msg}", file=sys.stderr)
        return -1, None
    return 0, None


def compile_split(args: argparse.Namespace, output_path: str) -> tuple[int, str | None]:
    pid = os.getpid()
    with tempfile.NamedTemporaryFile(prefix=f"poc_{pid}_", suffix=".o", delete=False, dir="/tmp") as obj_file:
        object_path = obj_file.name

    compile_cmd = [
        "clang++",
        "-Qunused-arguments",
        *phase3_replay_flags(args.fdp_trace),
        *PHASE3_SANITIZER_FLAGS,
        *PHASE3_SPLIT_OPT_FLAGS,
        "-c",
        *split_flags(args.compile_flags),
        args.source,
        "-o",
        object_path,
    ]

    compile_proc = subprocess.run(
        compile_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if compile_proc.returncode != 0:
        err_msg = compile_proc.stderr.strip() or compile_proc.stdout.strip() or "Unknown compilation error"
        print(f"Compilation failed: {compile_cmd} {err_msg}", file=sys.stderr)
        return -1, object_path

    link_cmd = [
        "clang++",
        "-Qunused-arguments",
        *PHASE3_SANITIZER_FLAGS,
        object_path,
        "-o",
        output_path,
        *split_flags(args.link_flags),
    ]
    link_proc = subprocess.run(
        link_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if link_proc.returncode != 0:
        err_msg = link_proc.stderr.strip() or link_proc.stdout.strip() or "Unknown link error"
        print(f"Linking failed: {link_cmd} {err_msg}", file=sys.stderr)
        return -1, object_path
    return 0, object_path


def compile_with_pch(args: argparse.Namespace, output_path: str) -> tuple[int, str | None]:
    if not args.pch_path:
        print("Compilation failed: --pch requires --pch-path", file=sys.stderr)
        return -1, None
    if not os.path.exists(args.pch_path):
        print(f"Compilation failed: PCH file does not exist: {args.pch_path}", file=sys.stderr)
        return -1, None

    pid = os.getpid()
    with tempfile.NamedTemporaryFile(prefix=f"poc_{pid}_", suffix=".o", delete=False, dir="/tmp") as obj_file:
        object_path = obj_file.name

    compile_cmd = [
        "clang++",
        "-Qunused-arguments",
        "-include-pch",
        args.pch_path,
        *phase3_replay_flags(args.fdp_trace),
        *PHASE3_SANITIZER_FLAGS,
        *PHASE3_PCH_OPT_FLAGS,
        "-c",
        *split_flags(args.compile_flags),
        args.source,
        "-o",
        object_path,
    ]

    compile_proc = subprocess.run(
        compile_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if compile_proc.returncode != 0:
        err_msg = compile_proc.stderr.strip() or compile_proc.stdout.strip() or "Unknown compilation error"
        print(f"Compilation failed: {compile_cmd} {err_msg}", file=sys.stderr)
        return -1, object_path

    link_cmd = [
        "clang++",
        "-Qunused-arguments",
        *PHASE3_SANITIZER_FLAGS,
        object_path,
        "-o",
        output_path,
        *split_flags(args.link_flags),
    ]
    link_proc = subprocess.run(
        link_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if link_proc.returncode != 0:
        err_msg = link_proc.stderr.strip() or link_proc.stdout.strip() or "Unknown link error"
        print(f"Linking failed: {link_cmd} {err_msg}", file=sys.stderr)
        return -1, object_path
    return 0, object_path


def _check_stack_trace(
    run_log: str,
    stack_trace_file: str,
    source_path: str,
    backup_file: str | None,
) -> bool:
    """Check the stack trace from a symbolize=1 run against the stored pattern.

    Returns True if the stack trace matches. If backup_file is provided and
    the check passes, the current source is saved as the new backup.
    """
    stored_pattern = Path(stack_trace_file).read_text(encoding="utf-8").strip()
    if not stored_pattern:
        print("[*] No stored stack trace pattern; skipping stack trace check.")
        return True

    raw_trace = extract_stack_trace(run_log, harness_path=source_path)
    if raw_trace is None:
        print("[-] No stack trace found in symbolized output.")
        return False

    if re.search(stored_pattern, run_log) is not None:
        print("[+] Stack trace validation passed.")
        if backup_file:
            shutil.copy2(source_path, backup_file)
            print(f"[+] Stack trace backup saved to {backup_file}")
        return True

    print("[-] Stack trace does not match the stored pattern.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=str, help="Source file to compile")
    parser.add_argument("crash_pattern", type=str, help="Regex pattern to identify the crash in the output")
    parser.add_argument("--crash-input", type=str, default=None, help="Optional input to feed to the binary during execution")
    parser.add_argument("--compile-flags", type=str, default=None, help="Optional flags used while compiling/preprocessing")
    parser.add_argument("--link-flags", type=str, default=None, help="Optional flags used while linking")
    parser.add_argument("--fdp-trace", type=str, default=None, help="Optional FDP trace path used for replay-mode execution")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--direct", "--single-step", dest="direct", action="store_true", help="Use the single-step Phase 3 compile/link command")
    mode_group.add_argument("--split", action="store_true", help="Use split Phase 3 mode: compile the full source to an object, then link")
    mode_group.add_argument("--pch", action="store_true", help="Use PCH Phase 3 mode: compile object with -include-pch, then link")
    parser.add_argument("--pch-path", type=str, default=None, help="Path to fahm_prefix.pch when --pch is used")
    # Stack trace validation arguments
    parser.add_argument("--symbolize", action="store_true", help="Force symbolize=1 for this run (used for stack trace validation)")
    parser.add_argument("--stack-trace-file", type=str, default=None, help="Path to stored normalized stack trace pattern")
    parser.add_argument("--iteration", type=int, default=None, help="Base iteration interval for periodic symbolize=1 checks")
    parser.add_argument("--counter-file", type=str, default=None, help="Path to the counter file tracking invocation count")
    parser.add_argument("--backup-file", type=str, default=None, help="Path to save source backup on successful stack trace check")
    parser.add_argument("--statistics-file", type=str, default=None, help="Path to statistics.txt for tracking crash_tester return-code counts")
    args = parser.parse_args()
    pid = os.getpid()

    with tempfile.NamedTemporaryFile(prefix=f"poc_{pid}_", suffix=".out", delete=False, dir="/tmp") as out_file:
        output_path = out_file.name
    object_path = None

    try:
        if args.pch:
            compile_status, object_path = compile_with_pch(args, output_path)
        elif args.split:
            compile_status, object_path = compile_split(args, output_path)
        else:
            compile_status, object_path = compile_direct(args, output_path)
        if compile_status != 0:
            return _finalize_result(args, -1)

        # Determine whether this invocation should use symbolize=1.
        force_symbolize = args.symbolize
        periodic_check = False
        if not force_symbolize and args.iteration is not None and args.counter_file and args.stack_trace_file:
            counter = _read_counter(args.counter_file)
            counter += 1
            _write_counter(args.counter_file, counter)
            effective = _effective_iteration(args.iteration, args.source)
            if counter % effective == 0:
                periodic_check = True

        use_symbolize = force_symbolize or periodic_check

        env = os.environ.copy()
        if use_symbolize:
            env["ASAN_OPTIONS"] = "exitcode=77:symbolize=1:handle_abort=1"
            env["UBSAN_OPTIONS"] = "exitcode=77:symbolize=1:halt_on_error=1:print_stacktrace=1"
        else:
            env["ASAN_OPTIONS"] = "exitcode=77:symbolize=0:handle_abort=1"
            env["UBSAN_OPTIONS"] = "exitcode=77:symbolize=0:halt_on_error=1:print_stacktrace=1"
        if args.fdp_trace:
            env["FDP_TRACE_PATH"] = args.fdp_trace

        exec_cmd = [output_path, args.crash_input] if args.crash_input else [output_path]
        run_proc = subprocess.run(
            exec_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            check=False,
        )

        status = run_proc.returncode

        run_log = run_proc.stdout + run_proc.stderr

        # First: crash pattern must match.
        if status != 77 or re.search(args.crash_pattern, run_log) is None:
            print(f"Crash pattern did not match. Exit status: {status}\n, crash pattern: {args.crash_pattern}\nExecution log:\n{run_log}")
            return _finalize_result(args, 1)

        # Crash pattern matched.  If symbolized, also validate stack trace.
        if use_symbolize and args.stack_trace_file and os.path.exists(args.stack_trace_file):
            if not _check_stack_trace(run_log, args.stack_trace_file, args.source, args.backup_file):
                return _finalize_result(args, 1)

        print("execution log: ")
        print(run_log)
        print("Crash behavior preserved.")
        return _finalize_result(args, 77)
    finally:
        if object_path:
            try:
                os.remove(object_path)
            except FileNotFoundError:
                pass
        try:
            os.remove(output_path)
        except FileNotFoundError:
                pass


if __name__ == "__main__":
    sys.exit(main())

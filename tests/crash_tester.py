#!/usr/bin/env python3
import fcntl
import os
import filecmp
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import argparse
from pathlib import Path

__script_dir__ = os.path.dirname(os.path.realpath(__file__))
__project_root__ = Path(__script_dir__).parent
sys.path.insert(0, str(__project_root__ / "src"))
PHASE3_SANITIZER_FLAGS = ["-fsanitize=address,fuzzer,undefined"]

from harnessreducer.reducer_runner import (
    PHASE3_DIRECT_OPT_FLAGS,
    PHASE3_PCH_OPT_FLAGS,
    PHASE3_SPLIT_OPT_FLAGS,
    PHASE3_WARNING_FLAGS,
    PHASE3_PLUGIN_SANITIZER_FLAGS,
    STACK_FRAME_PATTERN,
    LLVMFuzzerTestOneInput_PATTERN,
    _frame_matches_harness_source,
    count_first_stack_trace_frames,
    runtime_library_env,
)
# STACK_FRAME_PATTERN = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+")
# LLVMFuzzerTestOneInput_PATTERN = re.compile(r"\bLLVMFuzzerTestOneInput\b")
UNINITIALIZED_COMPILE_ERROR_PATTERN = re.compile(r"(?i)(?:\[-Wuninitialized\]|uninitialized)")


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
    if args.statistics_file:
        _update_statistics_file(args.statistics_file, result_code)
    return result_code


def _update_last_interesting_file(source_path: str, snapshot_path: str | None) -> None:
    if not snapshot_path:
        return

    snapshot = Path(snapshot_path)
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    try:
        if snapshot.exists() and filecmp.cmp(source_path, snapshot_path, shallow=False):
            return
    except FileNotFoundError:
        pass

    tmp_snapshot = snapshot.with_suffix(snapshot.suffix + ".tmp")
    shutil.copyfile(source_path, tmp_snapshot)
    os.replace(tmp_snapshot, snapshot)


def compile_error_mentions_uninitialized(error_text: str | None) -> bool:
    return bool(error_text and UNINITIALIZED_COMPILE_ERROR_PATTERN.search(error_text))


def _remember_compile_failure(
    args: argparse.Namespace,
    *,
    err_msg: str,
    compile_cmd: list[str],
) -> None:
    args._last_compile_error = err_msg
    args._last_compile_cmd = list(compile_cmd)
    args._last_compile_uninitialized = compile_error_mentions_uninitialized(err_msg)


def _reset_compile_failure_state(args: argparse.Namespace) -> None:
    args._last_compile_error = None
    args._last_compile_cmd = None
    args._last_compile_uninitialized = False


def compile_direct(args: argparse.Namespace, output_path: str) -> tuple[int, str | None]:
    _reset_compile_failure_state(args)
    compile_cmd = [
        "clang++",
        *phase3_replay_flags(args.fdp_trace),
        *PHASE3_SANITIZER_FLAGS,
        *PHASE3_DIRECT_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
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
        _remember_compile_failure(args, err_msg=err_msg, compile_cmd=compile_cmd)
        print(f"Compilation failed: {compile_cmd} {err_msg}", file=sys.stderr)
        return -1, None
    return 0, None


def compile_split(args: argparse.Namespace, output_path: str) -> tuple[int, str | None]:
    _reset_compile_failure_state(args)
    pid = os.getpid()
    with tempfile.NamedTemporaryFile(prefix=f"poc_{pid}_", suffix=".o", delete=False, dir="/tmp") as obj_file:
        object_path = obj_file.name

    compile_cmd = [
        "clang++",
        "-Qunused-arguments",
        *phase3_replay_flags(args.fdp_trace),
        *PHASE3_SANITIZER_FLAGS,
        *PHASE3_SPLIT_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
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
        _remember_compile_failure(args, err_msg=err_msg, compile_cmd=compile_cmd)
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
        _remember_compile_failure(args, err_msg=err_msg, compile_cmd=link_cmd)
        print(f"Linking failed: {link_cmd} {err_msg}", file=sys.stderr)
        return -1, object_path
    return 0, object_path


def compile_with_pch(args: argparse.Namespace, output_path: str) -> tuple[int, str | None]:
    _reset_compile_failure_state(args)
    if not args.pch_path:
        _remember_compile_failure(args, err_msg="--pch requires --pch-path", compile_cmd=["clang++"])
        print("Compilation failed: --pch requires --pch-path", file=sys.stderr)
        return -1, None
    if not os.path.exists(args.pch_path):
        _remember_compile_failure(
            args,
            err_msg=f"PCH file does not exist: {args.pch_path}",
            compile_cmd=["clang++", "-include-pch", args.pch_path],
        )
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
        *PHASE3_WARNING_FLAGS,
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
        _remember_compile_failure(args, err_msg=err_msg, compile_cmd=compile_cmd)
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
        _remember_compile_failure(args, err_msg=err_msg, compile_cmd=link_cmd)
        print(f"Linking failed: {link_cmd} {err_msg}", file=sys.stderr)
        return -1, object_path
    return 0, object_path


def compile_amortized_plugin(
    args: argparse.Namespace,
    output_path: str,
) -> tuple[int, str | None]:
    """Compile a candidate as a small DSO without relinking target libraries."""
    _reset_compile_failure_state(args)
    pid = os.getpid()
    with tempfile.NamedTemporaryFile(
        prefix=f"poc_{pid}_", suffix=".o", delete=False, dir="/tmp"
    ) as obj_file:
        object_path = obj_file.name

    compile_cmd = ["clang++", "-Qunused-arguments"]
    if args.pch:
        if not args.pch_path or not os.path.exists(args.pch_path):
            err_msg = f"PCH file does not exist: {args.pch_path}"
            _remember_compile_failure(args, err_msg=err_msg, compile_cmd=compile_cmd)
            print(f"Compilation failed: {err_msg}", file=sys.stderr)
            return -1, object_path
        compile_cmd.extend(["-include-pch", args.pch_path])
        opt_flags = PHASE3_PCH_OPT_FLAGS
    else:
        opt_flags = PHASE3_SPLIT_OPT_FLAGS
    compile_cmd.extend(
        [
            *phase3_replay_flags(args.fdp_trace),
            *PHASE3_PLUGIN_SANITIZER_FLAGS,
            *opt_flags,
            *PHASE3_WARNING_FLAGS,
            "-fPIC",
            "-c",
            *split_flags(args.compile_flags),
            args.source,
            "-o",
            object_path,
        ]
    )
    compile_proc = subprocess.run(
        compile_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if compile_proc.returncode != 0:
        err_msg = compile_proc.stderr.strip() or compile_proc.stdout.strip() or "Unknown compilation error"
        _remember_compile_failure(args, err_msg=err_msg, compile_cmd=compile_cmd)
        print(f"Compilation failed: {compile_cmd} {err_msg}", file=sys.stderr)
        return -1, object_path

    link_cmd = [
        "clang++",
        "-Qunused-arguments",
        "-shared",
        *PHASE3_PLUGIN_SANITIZER_FLAGS,
        object_path,
        "-o",
        output_path,
    ]
    link_proc = subprocess.run(
        link_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if link_proc.returncode != 0:
        err_msg = link_proc.stderr.strip() or link_proc.stdout.strip() or "Unknown plugin link error"
        _remember_compile_failure(args, err_msg=err_msg, compile_cmd=link_cmd)
        print(f"Plugin linking failed: {link_cmd} {err_msg}", file=sys.stderr)
        return -1, object_path
    return 0, object_path


def run_with_amortized_runner(socket_path: str, plugin_path: str) -> tuple[int, str]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(socket_path)
        client.sendall(os.path.abspath(plugin_path).encode("utf-8") + b"\n")
        stream = client.makefile("rb")
        header = stream.readline()
        if not header:
            raise RuntimeError("Amortized-link runner closed the connection without a response.")
        try:
            status_text, size_text = header.decode("ascii").strip().split(" ", 1)
            status = int(status_text)
            expected_size = int(size_text)
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError(f"Invalid amortized-link runner response: {header!r}") from exc
        output = stream.read(expected_size)
        if len(output) != expected_size:
            raise RuntimeError(
                "Amortized-link runner returned a truncated execution log: "
                f"expected {expected_size} bytes, got {len(output)}."
            )
        return status, output.decode("utf-8", errors="replace")


def _check_stack_trace(
    run_log: str,
    stack_trace_file: str,
    source_path: str,
) -> bool:
    """Check the stack trace from a symbolize=1 run against the stored pattern."""
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
    parser.add_argument("--pch-path", type=str, default=None, help="Path to harness_prefix.pch when --pch is used")
    # Stack trace validation arguments
    parser.add_argument("--symbolize", action="store_true", help="Force symbolize=1 for this run (used for stack trace validation)")
    parser.add_argument("--stack-trace-file", type=str, default=None, help="Path to stored normalized stack trace pattern")
    parser.add_argument("--stack-depth", type=int, default=None, help="Expected frame count of the first stack trace")
    parser.add_argument("--statistics-file", type=str, default=None, help="Path to statistics.txt for tracking crash_tester return-code counts")
    parser.add_argument("--last-interesting-file", type=str, default=None, help="Stable snapshot path for the latest candidate that returns 77")
    parser.add_argument("--amortized-runner-socket", type=str, default=None, help="Unix socket for persistent amortized-link execution")
    args = parser.parse_args()
    pid = os.getpid()

    with tempfile.NamedTemporaryFile(prefix=f"poc_{pid}_", suffix=".out", delete=False, dir="/tmp") as out_file:
        output_path = out_file.name
    object_path = None

    try:
        if args.amortized_runner_socket:
            if args.direct:
                print("Compilation failed: amortized linking does not support direct mode", file=sys.stderr)
                return _finalize_result(args, -1)
            compile_status, object_path = compile_amortized_plugin(args, output_path)
        elif args.pch:
            compile_status, object_path = compile_with_pch(args, output_path)
        elif args.split:
            compile_status, object_path = compile_split(args, output_path)
        else:
            compile_status, object_path = compile_direct(args, output_path)
        if compile_status != 0:
            return _finalize_result(args, -1)

        use_symbolize = args.symbolize

        env = runtime_library_env(args.link_flags)
        if use_symbolize:
            env["ASAN_OPTIONS"] = "exitcode=77:symbolize=1:handle_abort=1"
            env["UBSAN_OPTIONS"] = "exitcode=77:symbolize=1:halt_on_error=1:print_stacktrace=1"
        else:
            env["ASAN_OPTIONS"] = "exitcode=77:symbolize=0:handle_abort=1"
            env["UBSAN_OPTIONS"] = "exitcode=77:symbolize=0:halt_on_error=1:print_stacktrace=1"
        if args.fdp_trace:
            env["FDP_TRACE_PATH"] = args.fdp_trace

        if args.amortized_runner_socket:
            try:
                status, run_log = run_with_amortized_runner(
                    args.amortized_runner_socket,
                    output_path,
                )
            except Exception as exc:
                print(f"Amortized-link execution failed: {exc}", file=sys.stderr)
                return _finalize_result(args, 1)
        else:
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

        if args.stack_depth is not None:
            candidate_stack_depth = count_first_stack_trace_frames(run_log)
            if candidate_stack_depth != args.stack_depth:
                print(
                    "Stack depth did not match. "
                    f"Expected {args.stack_depth}, got {candidate_stack_depth}."
                )
                return _finalize_result(args, 1)

        # Crash pattern matched.  If symbolized, also validate stack trace.
        if use_symbolize and args.stack_trace_file and os.path.exists(args.stack_trace_file):
            if not _check_stack_trace(run_log, args.stack_trace_file, args.source):
                return _finalize_result(args, 1)

        _update_last_interesting_file(args.source, args.last_interesting_file)
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

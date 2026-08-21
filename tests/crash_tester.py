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
import time
import argparse
from pathlib import Path

__script_dir__ = os.path.dirname(os.path.realpath(__file__))
__project_root__ = Path(__script_dir__).parent
sys.path.insert(0, str(__project_root__ / "src"))
PHASE3_SANITIZER_FLAGS = ["-fsanitize=address,fuzzer,undefined"]

from harnessreducer.reducer_runner import (
    AMORTIZED_FALLBACK_STATE_SUFFIX,
    PHASE3_DIRECT_OPT_FLAGS,
    PHASE3_PCH_OPT_FLAGS,
    PHASE3_SPLIT_OPT_FLAGS,
    PHASE3_WARNING_FLAGS,
    PHASE3_PLUGIN_SANITIZER_FLAGS,
    STACK_FRAME_PATTERN,
    LLVMFuzzerTestOneInput_PATTERN,
    _frame_matches_harness_source,
    count_first_stack_trace_frames,
    extract_first_dynamic_library_crash_site,
    extract_first_sanitizer_stack_trace,
    extract_symbolized_crash_location,
    runtime_library_env,
)
# STACK_FRAME_PATTERN = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+")
# LLVMFuzzerTestOneInput_PATTERN = re.compile(r"\bLLVMFuzzerTestOneInput\b")
UNINITIALIZED_COMPILE_ERROR_PATTERN = re.compile(r"(?i)(?:\[-Wuninitialized\]|uninitialized)")
AMORTIZED_UNDEFINED_SYMBOL_LOAD_PATTERN = re.compile(
    r"dlopen candidate failed: .*undefined symbol:"
)
LIBFUZZER_OOM_PATTERN = re.compile(r"ERROR:\s*libFuzzer:\s*out-of-memory\b")
POC_RUNTIME_ARG_MARKER = "HARNESSREDUCER_POC_RUNTIME_ARG="
AMORTIZED_FALLBACK_FAST_PROBE_INTERVAL = 1000


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
    try:
        _append_debug_record(args, result_code)
    except Exception as exc:
        print(f"[DEBUG] Failed to append candidate record: {exc}", file=sys.stderr)
    if args.statistics_file:
        _update_statistics_file(args.statistics_file, result_code)
    exec_time_ms = getattr(args, "_last_exec_time_ms", None)
    if getattr(args, "print_exec_time_ms", False) and exec_time_ms is not None:
        print(f"HARNESSREDUCER_EXEC_TIME_MS={exec_time_ms}")
    return result_code


def _debug_field(value) -> str:
    if value is None:
        return "not-evaluated"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _append_debug_record(args: argparse.Namespace, tester_return_code: int) -> None:
    debug_log = getattr(args, "debug_log", None)
    if not debug_log:
        return

    actual_site = getattr(args, "_debug_dynamic_crash_site", None)
    if actual_site is None:
        actual_site_text = "not-found"
    else:
        actual_site_text = f"{actual_site.library_path}+{actual_site.offset}"

    trace = getattr(args, "_debug_first_stack_trace", None)
    compile_error = getattr(args, "_last_compile_error", None)
    compile_cmd = getattr(args, "_last_compile_cmd", None)
    lines = [
        "===== candidate =====",
        f"stage: {getattr(args, 'debug_stage', 'unspecified')}",
        f"pid: {os.getpid()}",
        f"source_path: {Path(args.source).resolve()}",
        f"compile_success: {_debug_field(getattr(args, '_debug_compile_success', None))}",
        f"first_execution_return_code: {_debug_field(getattr(args, '_debug_first_execution_return_code', None))}",
        f"execution_return_code: {_debug_field(getattr(args, '_debug_execution_return_code', None))}",
        f"oom_retry_attempted: {_debug_field(getattr(args, '_debug_oom_retry_attempted', None))}",
        f"tester_return_code: {tester_return_code}",
        f"returned_77: {_debug_field(tester_return_code == 77)}",
        f"crash_pattern_matched: {_debug_field(getattr(args, '_debug_crash_pattern_matched', None))}",
        f"dynamic_crash_site_found: {_debug_field(getattr(args, '_debug_dynamic_crash_site_found', None))}",
        f"dynamic_crash_site_matched: {_debug_field(getattr(args, '_debug_dynamic_crash_site_matched', None))}",
        f"dynamic_crash_site: {actual_site_text}",
    ]
    if compile_cmd:
        lines.append(f"compile_command: {' '.join(compile_cmd)}")
    if compile_error:
        lines.extend(["compile_error:", compile_error])
    lines.extend(
        [
            "first_stack_trace:",
            trace or "<no-first-stack-trace-found>",
            "===== end candidate =====",
            "",
        ]
    )

    debug_path = Path(debug_log)
    debug_path.parent.mkdir(parents=True, exist_ok=True)
    with debug_path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.write("\n".join(lines))
        handle.flush()
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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


def _amortized_fallback_state_path(socket_path: str) -> Path:
    return Path(socket_path + AMORTIZED_FALLBACK_STATE_SUFFIX)


def _parse_amortized_fallback_remaining(text: str) -> int:
    try:
        return max(0, int(text.strip() or "0"))
    except ValueError:
        return 0


def _read_locked_amortized_fallback_remaining(handle) -> int:
    handle.seek(0)
    return _parse_amortized_fallback_remaining(handle.read())


def _write_locked_amortized_fallback_remaining(handle, remaining: int) -> None:
    handle.seek(0)
    handle.truncate()
    handle.write(f"{max(0, remaining)}\n")
    handle.flush()


def _fallback_link_flags(args: argparse.Namespace) -> str | None:
    return getattr(args, "amortized_plugin_fallback_link_flags", None)


def _enable_amortized_fallback_first(
    args: argparse.Namespace,
    *,
    probe_interval: int = AMORTIZED_FALLBACK_FAST_PROBE_INTERVAL,
) -> None:
    socket_path = getattr(args, "amortized_runner_socket", None)
    if not socket_path or not _fallback_link_flags(args):
        return

    state_path = _amortized_fallback_state_path(socket_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with state_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        remaining = _read_locked_amortized_fallback_remaining(handle)
        _write_locked_amortized_fallback_remaining(
            handle,
            max(remaining, probe_interval),
        )
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _reserve_amortized_fallback_first(args: argparse.Namespace) -> bool:
    socket_path = getattr(args, "amortized_runner_socket", None)
    if not socket_path or not _fallback_link_flags(args):
        return False

    state_path = _amortized_fallback_state_path(socket_path)
    try:
        handle = state_path.open("r+", encoding="utf-8")
    except FileNotFoundError:
        return False

    with handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        remaining = _read_locked_amortized_fallback_remaining(handle)
        if remaining <= 0:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return False
        _write_locked_amortized_fallback_remaining(handle, remaining - 1)
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return True


def amortized_initial_plugin_link_flags(args: argparse.Namespace) -> str | None:
    fallback_link_flags = _fallback_link_flags(args)
    if fallback_link_flags and _reserve_amortized_fallback_first(args):
        return fallback_link_flags
    return None


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

    sanitizer_flags = (
        PHASE3_PLUGIN_SANITIZER_FLAGS
        if getattr(args, "pch_amortized_link", False)
        else PHASE3_SANITIZER_FLAGS
    )

    compile_cmd = [
        "clang++",
        "-Qunused-arguments",
        "-include-pch",
        args.pch_path,
        *phase3_replay_flags(args.fdp_trace),
        *sanitizer_flags,
        *PHASE3_PCH_OPT_FLAGS,
        *PHASE3_WARNING_FLAGS,
        *(["-fPIC"] if getattr(args, "pch_amortized_link", False) else []),
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
    link_flags: str | None = None,
) -> tuple[int, str | None]:
    """Compile a candidate as a small DSO without relinking target libraries."""
    _reset_compile_failure_state(args)
    args._amortized_plugin_fallback_linked = False
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

    if link_amortized_plugin(args, object_path, output_path, link_flags) != 0:
        return -1, object_path
    args._amortized_plugin_fallback_linked = bool(link_flags)
    return 0, object_path


def link_amortized_plugin(
    args: argparse.Namespace,
    object_path: str,
    output_path: str,
    link_flags: str | None = None,
) -> int:
    link_cmd = [
        "clang++",
        "-Qunused-arguments",
        "-shared",
        *PHASE3_PLUGIN_SANITIZER_FLAGS,
        object_path,
        *split_flags(link_flags),
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
        return -1
    return 0


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


def run_executable(
    exec_cmd: list[str],
    *,
    env: dict[str, str],
    exec_timeout_ms: int | None,
) -> tuple[int, str, int]:
    timeout_seconds = (
        None
        if exec_timeout_ms is None or exec_timeout_ms <= 0
        else exec_timeout_ms / 1000.0
    )
    started_at = time.monotonic()
    try:
        run_proc = subprocess.run(
            exec_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            check=False,
            timeout=timeout_seconds,
        )
        status = run_proc.returncode
        run_log = run_proc.stdout + run_proc.stderr
    except subprocess.TimeoutExpired as exc:
        status = 124
        parts: list[str] = []
        if exc.stdout:
            parts.append(exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode("utf-8", errors="replace"))
        if exc.stderr:
            parts.append(exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode("utf-8", errors="replace"))
        if timeout_seconds is None:
            parts.append("Execution timed out.\n")
        else:
            parts.append(f"Execution timed out after {timeout_seconds:.3f} seconds.\n")
        run_log = "".join(parts)
    elapsed_ms = max(1, int((time.monotonic() - started_at) * 1000))
    return status, run_log, elapsed_ms


def _standalone_retry_exec_cmd_without_rss_limit(exec_cmd: list[str]) -> list[str]:
    if not exec_cmd:
        return exec_cmd
    return [exec_cmd[0], "-rss_limit_mb=0", *exec_cmd[1:]]


def _should_retry_without_rss_limit(
    args: argparse.Namespace,
    run_log: str,
) -> bool:
    return bool(
        getattr(args, "retry_oom_without_rss_limit", False)
        and LIBFUZZER_OOM_PATTERN.search(run_log)
    )


def run_standalone_candidate(
    args: argparse.Namespace,
    exec_cmd: list[str],
    *,
    env: dict[str, str],
) -> tuple[int, str, int]:
    status, run_log, exec_time_ms = run_executable(
        exec_cmd,
        env=env,
        exec_timeout_ms=args.exec_timeout_ms,
    )
    args._debug_first_execution_return_code = status
    args._debug_oom_retry_attempted = False

    if not _should_retry_without_rss_limit(args, run_log):
        return status, run_log, exec_time_ms

    args._debug_oom_retry_attempted = True
    retry_cmd = _standalone_retry_exec_cmd_without_rss_limit(exec_cmd)
    retry_status, retry_log, retry_exec_time_ms = run_executable(
        retry_cmd,
        env=env,
        exec_timeout_ms=args.exec_timeout_ms,
    )
    if retry_status == 77:
        print(f"{POC_RUNTIME_ARG_MARKER}-rss_limit_mb=0")
    return retry_status, retry_log, retry_exec_time_ms


def should_retry_amortized_plugin_with_fallback(status: int, run_log: str) -> bool:
    return status == 125 and bool(AMORTIZED_UNDEFINED_SYMBOL_LOAD_PATTERN.search(run_log))


def run_with_amortized_runner_timed(
    socket_path: str,
    plugin_path: str,
) -> tuple[int, str, int]:
    started_at = time.monotonic()
    status, run_log = run_with_amortized_runner(socket_path, plugin_path)
    elapsed_ms = max(1, int((time.monotonic() - started_at) * 1000))
    return status, run_log, elapsed_ms


def run_with_amortized_runner_maybe_fallback(
    args: argparse.Namespace,
    output_path: str,
    object_path: str | None,
) -> tuple[int | None, str]:
    status, run_log = run_with_amortized_runner(
        args.amortized_runner_socket,
        output_path,
    )
    fallback_link_flags = getattr(args, "amortized_plugin_fallback_link_flags", None)
    if (
        object_path
        and fallback_link_flags
        and not bool(getattr(args, "_amortized_plugin_fallback_linked", False))
        and should_retry_amortized_plugin_with_fallback(status, run_log)
    ):
        if link_amortized_plugin(
            args,
            object_path,
            output_path,
            fallback_link_flags,
        ) != 0:
            return None, ""
        args._amortized_plugin_fallback_linked = True
        _enable_amortized_fallback_first(args)
        status, run_log = run_with_amortized_runner(
            args.amortized_runner_socket,
            output_path,
        )
    return status, run_log


def run_with_amortized_runner_maybe_fallback_timed(
    args: argparse.Namespace,
    output_path: str,
    object_path: str | None,
) -> tuple[int | None, str, int | None]:
    status, run_log, exec_time_ms = run_with_amortized_runner_timed(
        args.amortized_runner_socket,
        output_path,
    )
    fallback_link_flags = getattr(args, "amortized_plugin_fallback_link_flags", None)
    if (
        object_path
        and fallback_link_flags
        and not bool(getattr(args, "_amortized_plugin_fallback_linked", False))
        and should_retry_amortized_plugin_with_fallback(status, run_log)
    ):
        if link_amortized_plugin(
            args,
            object_path,
            output_path,
            fallback_link_flags,
        ) != 0:
            return None, "", None
        args._amortized_plugin_fallback_linked = True
        _enable_amortized_fallback_first(args)
        status, run_log, exec_time_ms = run_with_amortized_runner_timed(
            args.amortized_runner_socket,
            output_path,
        )
    return status, run_log, exec_time_ms


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


def _check_dynamic_crash_site(
    run_log: str,
    expected_library: str,
    expected_offset: str,
) -> bool:
    site = extract_first_dynamic_library_crash_site(
        run_log,
        expected_library=expected_library,
    )
    if site is None:
        print(
            "[-] Dynamic crash-site offset did not match. "
            f"Could not find a frame for {expected_library} in the first stack trace."
        )
        return False

    if site.offset.lower() == expected_offset.lower():
        print("[+] Dynamic crash-site offset validation passed.")
        return True

    print(
        "[-] Dynamic crash-site offset did not match. "
        f"Expected {expected_library}+{expected_offset.lower()}, "
        f"got {site.library_path}+{site.offset}."
    )
    return False


def _check_crash_location_pattern(
    run_log: str,
    stored_pattern: str,
    source_path: str,
) -> bool:
    pattern = stored_pattern.strip()
    if not pattern:
        print("[*] No stored crash-location pattern; skipping crash-location check.")
        return True

    location = extract_symbolized_crash_location(run_log, harness_path=source_path)
    if location is None:
        print("[-] No symbolized crash location found in the first stack trace.")
        return False

    if re.fullmatch(pattern, location) is not None:
        print("[+] Symbolized crash-location validation passed.")
        return True

    print(
        "[-] Symbolized crash location did not match. "
        f"Expected pattern {pattern!r}, got {location!r}."
    )
    return False


def _check_crash_location(
    run_log: str,
    crash_location_file: str,
    source_path: str,
) -> bool:
    stored_pattern = Path(crash_location_file).read_text(encoding="utf-8").strip()
    return _check_crash_location_pattern(run_log, stored_pattern, source_path)


def _stack_depth_is_advisory(
    args: argparse.Namespace,
    *,
    use_symbolize: bool,
) -> bool:
    if use_symbolize:
        return True
    return bool(args.dynamic_crash_site_library and args.dynamic_crash_site_offset)


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
    parser.add_argument("--pch-amortized-link", action="store_true", help=argparse.SUPPRESS)
    # Stack trace validation arguments
    parser.add_argument("--symbolize", action="store_true", help="Force symbolize=1 for this run (used for stack trace validation)")
    parser.add_argument("--skip-crash-pattern", action="store_true", help="Require exit 77 but do not match the crash regex")
    parser.add_argument("--stack-trace-file", type=str, default=None, help="Path to stored normalized stack trace pattern")
    parser.add_argument("--crash-location-pattern", type=str, default=None, help="Normalized symbolized crash-location pattern")
    parser.add_argument("--crash-location-file", type=str, default=None, help="Path to stored normalized symbolized crash-location pattern")
    parser.add_argument("--stack-depth", type=int, default=None, help="Expected frame count of the first stack trace")
    parser.add_argument("--dynamic-crash-site-library", type=str, default=None, help="Expected target shared library in the first stack trace")
    parser.add_argument("--dynamic-crash-site-offset", type=str, default=None, help="Expected target shared-library offset in the first stack trace")
    parser.add_argument("--statistics-file", type=str, default=None, help="Path to statistics.txt for tracking crash_tester return-code counts")
    parser.add_argument("--last-interesting-file", type=str, default=None, help="Stable snapshot path for the latest candidate that returns 77")
    parser.add_argument("--amortized-runner-socket", type=str, default=None, help="Unix socket for persistent amortized-link execution")
    parser.add_argument("--exec-timeout-ms", type=int, default=None, help="Execution-only timeout in milliseconds")
    parser.add_argument("--print-exec-time-ms", action="store_true", help="Print the measured execution time marker")
    parser.add_argument("--debug-log", type=str, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--debug-stage", type=str, default="unspecified", help=argparse.SUPPRESS)
    parser.add_argument("--retry-oom-without-rss-limit", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--amortized-plugin-fallback-link-flags",
        "--amortized-plugin-link-flags",
        dest="amortized_plugin_fallback_link_flags",
        type=str,
        default=None,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    args._last_exec_time_ms = None
    args._debug_compile_success = None
    args._debug_first_execution_return_code = None
    args._debug_execution_return_code = None
    args._debug_oom_retry_attempted = None
    args._debug_crash_pattern_matched = None
    args._debug_dynamic_crash_site_found = None
    args._debug_dynamic_crash_site_matched = None
    args._debug_dynamic_crash_site = None
    args._debug_first_stack_trace = None
    args._last_compile_error = None
    args._last_compile_cmd = None
    pid = os.getpid()

    with tempfile.NamedTemporaryFile(prefix=f"poc_{pid}_", suffix=".out", delete=False, dir="/tmp") as out_file:
        output_path = out_file.name
    object_path = None

    try:
        if args.amortized_runner_socket:
            if args.direct:
                print("Compilation failed: amortized linking does not support direct mode", file=sys.stderr)
                return _finalize_result(args, -1)
            initial_link_flags = amortized_initial_plugin_link_flags(args)
            compile_status, object_path = compile_amortized_plugin(
                args,
                output_path,
                initial_link_flags,
            )
        elif args.pch:
            compile_status, object_path = compile_with_pch(args, output_path)
        elif args.split:
            compile_status, object_path = compile_split(args, output_path)
        else:
            compile_status, object_path = compile_direct(args, output_path)
        if compile_status != 0:
            args._debug_compile_success = False
            return _finalize_result(args, -1)
        args._debug_compile_success = True

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
                status, run_log, exec_time_ms = run_with_amortized_runner_maybe_fallback_timed(
                    args,
                    output_path,
                    object_path,
                )
                args._last_exec_time_ms = exec_time_ms
            except Exception as exc:
                print(f"Amortized-link execution failed: {exc}", file=sys.stderr)
                return _finalize_result(args, 1)
            if status is None:
                return _finalize_result(args, -1)
        else:
            exec_cmd = [output_path, args.crash_input] if args.crash_input else [output_path]
            status, run_log, exec_time_ms = run_standalone_candidate(
                args,
                exec_cmd,
                env=env,
            )
            args._last_exec_time_ms = exec_time_ms

        if args.debug_log:
            args._debug_execution_return_code = status
            args._debug_crash_pattern_matched = (
                None
                if args.skip_crash_pattern
                else re.search(args.crash_pattern, run_log) is not None
            )
            args._debug_dynamic_crash_site = extract_first_dynamic_library_crash_site(
                run_log,
                args.link_flags,
                expected_library=args.dynamic_crash_site_library,
            )
            args._debug_dynamic_crash_site_found = (
                args._debug_dynamic_crash_site is not None
            )
            if args.dynamic_crash_site_library and args.dynamic_crash_site_offset:
                args._debug_dynamic_crash_site_matched = bool(
                    args._debug_dynamic_crash_site is not None
                    and args._debug_dynamic_crash_site.offset.lower()
                    == args.dynamic_crash_site_offset.lower()
                )
            args._debug_first_stack_trace = extract_first_sanitizer_stack_trace(run_log)

        if status != 77:
            print(
                f"Crash did not reproduce. Exit status: {status}\n"
                f"Execution log:\n{run_log}"
            )
            return _finalize_result(args, 1)

        # First: crash pattern must match unless a caller intentionally uses
        # this run only for symbolized stack/depth validation.
        if not args.skip_crash_pattern and re.search(args.crash_pattern, run_log) is None:
            print(f"Crash pattern did not match. Exit status: {status}\n, crash pattern: {args.crash_pattern}\nExecution log:\n{run_log}")
            return _finalize_result(args, 1)

        # Location-identifying anchor checks run first: these are the gates
        # that can reject a candidate.  Stack depth is advisory below, because
        # it can fluctuate across runs for multithreaded targets (e.g. libaom
        # row-MT) even when the crash site itself is stable.
        if (
            not use_symbolize
            and args.dynamic_crash_site_library
            and args.dynamic_crash_site_offset
        ):
            if not _check_dynamic_crash_site(
                run_log,
                args.dynamic_crash_site_library,
                args.dynamic_crash_site_offset,
            ):
                return _finalize_result(args, 1)

        if args.crash_location_pattern:
            if not _check_crash_location_pattern(
                run_log,
                args.crash_location_pattern,
                args.source,
            ):
                return _finalize_result(args, 1)
        elif args.crash_location_file and os.path.exists(args.crash_location_file):
            if not _check_crash_location(run_log, args.crash_location_file, args.source):
                return _finalize_result(args, 1)

        # Stack-depth handling depends on the active oracle.  When a crash-site
        # anchor is available (symbolized crash location or fast-path DSO+offset),
        # depth is advisory.  In fast non-symbolized mode without a dynamic
        # crash-site anchor, depth becomes part of the hard equivalence check.
        if args.stack_depth is not None:
            candidate_stack_depth = count_first_stack_trace_frames(run_log)
            if candidate_stack_depth != args.stack_depth:
                if _stack_depth_is_advisory(args, use_symbolize=use_symbolize):
                    print(
                        "[!] Warning: stack depth did not match. "
                        f"Expected {args.stack_depth}, got {candidate_stack_depth}. "
                        "Treating as advisory; crash site/location anchor already validated."
                    )
                else:
                    print(
                        "[-] Stack depth did not match. "
                        f"Expected {args.stack_depth}, got {candidate_stack_depth}. "
                        "No dynamic crash-site anchor is available in non-symbolized mode."
                    )
                    return _finalize_result(args, 1)
            else:
                print("[+] Stack depth validation passed.")

        # Advisory full symbolized stack-trace check.  The recorded trace can
        # differ run-to-run for multithreaded targets (different worker thread
        # reaches the crash first, different intermediate frames), so a regex
        # mismatch is logged as a warning rather than rejecting the candidate.
        # The crash-location anchor above is the authoritative gate.
        if use_symbolize and args.stack_trace_file and os.path.exists(args.stack_trace_file):
            if not _check_stack_trace(run_log, args.stack_trace_file, args.source):
                print(
                    "[!] Warning: full symbolized stack trace did not match the "
                    "stored pattern. Treating as advisory; crash-location anchor "
                    "already validated."
                )

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

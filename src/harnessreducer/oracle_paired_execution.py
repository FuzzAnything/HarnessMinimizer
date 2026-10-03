"""Independent symbolized executions for the oracle experiment."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import time

from harnessreducer.evaluation_common import read_json


PAIRED_MODE = "paired-execution"
OFFLINE_MODE = "offline"
MIN_SYMBOLIZED_TIMEOUT_MS = 10_000
# These frames belong to sanitizer interceptors or the C runtime. Some ASan
# builds print their names without source coordinates.
RUNTIME_FUNCTIONS = {
    "malloc", "calloc", "realloc", "reallocarray", "free", "cfree",
    "memcpy", "memmove", "memset", "memcmp", "memchr",
    "strlen", "strnlen", "strcmp", "strncmp", "strcpy", "strncpy",
    "strcat", "strncat", "strdup", "strndup", "bcmp", "bcopy", "bzero",
}


def comparison_mode(root: Path) -> str:
    mode = read_json(root / "run_manifest.json")["settings"]["symbolized_comparison"]
    if mode not in {PAIRED_MODE, OFFLINE_MODE}:
        raise ValueError(f"Unsupported oracle comparison mode: {mode}")
    return mode


def configure_symbolized_environment(env: dict[str, str]) -> None:
    """Request module names in live reports without changing instrumentation."""
    env.pop("DEBUGINFOD_URLS", None)
    for variable in ("ASAN_OPTIONS", "UBSAN_OPTIONS"):
        env[variable] = env.get(variable, "") + (
            ":stack_trace_format='    #%n %p in %f %S (%m+%o)'"
        )


def normalized_online_trace(report, link_flags, *, binary=None, harness=None):
    """Read what the sanitizer printed, without invoking an offline symbolizer.

    Source coordinates are preferred. A named library function without source
    coordinates remains a function-level frame and is explicitly tagged. An
    unnamed target frame falls back to the target module and offset, which is
    stable when the library binary remains fixed during reduction.
    """
    from harnessreducer.oracle_evaluation import (
        LOCATION, MODULE, SYSTEM_FUNCTION, _target_module, frame_relevant,
    )
    from harnessreducer.reducer_runner import extract_first_sanitizer_stack_trace

    trace = extract_first_sanitizer_stack_trace(report)
    if not trace:
        return [], "missing_crash_stack", ""
    frames, rendered, errors = [], [], []
    for raw in trace.splitlines():
        module_match = MODULE.search(raw)
        module = module_match["module"] if module_match else None
        if module and not _target_module(module, link_flags, binary):
            continue
        payload = raw.split(" in ", 1)[1] if " in " in raw else ""
        if "LLVMFuzzerTestOneInput" in payload:
            break
        location = LOCATION.search(payload)
        if location:
            function = payload[:location.start()].strip()
        else:
            function = MODULE.sub("", payload).strip()
            function = re.sub(r"\s+(?:<null>|\?\?(?::0(?::0)?)?)\s*$", "", function).strip()
        bare_function = function.split("(", 1)[0]
        if (SYSTEM_FUNCTION.search(function) or
                bare_function in RUNTIME_FUNCTIONS or
                bare_function in {"main", "_start", "__libc_start_main"}):
            continue
        if not function or function in {"<null>", "??"}:
            if module_match and module:
                identity = Path(module).name if ".so" in Path(module).name else "<target-executable>"
                offset = module_match["offset"]
                frame = {"function": f"{identity}+{offset}", "file": None, "line": None,
                         "module": identity, "offset": offset, "resolution": "module_offset"}
                rendered.append(f"#{len(frames)} {identity}+{offset} ({identity}, source unavailable)")
                frames.append(frame)
            else:
                errors.append("unresolved_target_frame")
            continue
        if location and location["file"] != "??" and int(location["line"]) > 0:
            frame = {"function": function, "file": os.path.normpath(location["file"]),
                     "line": int(location["line"])}
            if not frame_relevant(frame, harness):
                continue
            rendered.append(f"#{len(frames)} {function} {frame['file']}:{frame['line']}")
        elif module:
            identity = Path(module).name if ".so" in Path(module).name else "<target-executable>"
            frame = {"function": function, "file": None, "line": None,
                     "module": identity, "resolution": "function"}
            rendered.append(f"#{len(frames)} {function} ({identity}, source unavailable)")
        else:
            errors.append("missing_target_module_and_source")
            continue
        frames.append(frame)
    error = ", ".join(dict.fromkeys(errors)) or (None if frames else "no_usable_library_frames")
    return frames, error, "\n".join(rendered)


def execute_symbolized(args, binary, command=None):
    """Execute the same built candidate in an independent process."""
    from harnessreducer.process_supervisor import (
        OutputLimitExceeded, run_supervised, runner_request,
    )
    from harnessreducer.reducer_runner import runtime_library_env, sanitizer_asan_options
    from harnessreducer.symbolizer import isolate_symbolizer_environment

    timeout_ms = getattr(args, "oracle_symbolized_timeout_ms", MIN_SYMBOLIZED_TIMEOUT_MS)
    socket_path = getattr(args, "oracle_symbolized_runner_socket", None)
    started = time.monotonic()
    try:
        if getattr(args, "amortized_runner_socket", None):
            if not socket_path:
                raise ValueError("Missing runner for the independent symbolized execution")
            header, output = runner_request(socket_path, binary, timeout=timeout_ms / 1000 + 5)
            if len(header) != 2:
                raise ValueError("Invalid response from the symbolized runner")
            status, report = int(header[0]), output.decode("utf-8", errors="replace")
        else:
            env = runtime_library_env(args.link_flags, symbolize=True)
            isolate_symbolizer_environment(env)
            env["ASAN_OPTIONS"] = sanitizer_asan_options(symbolize=True)
            env["UBSAN_OPTIONS"] = "exitcode=77:symbolize=1:halt_on_error=1:print_stacktrace=1"
            configure_symbolized_environment(env)
            if args.fdp_trace:
                env["FDP_TRACE_PATH"] = args.fdp_trace
                env["FDP_WIDE_TRACE_PATH"] = args.fdp_trace + ".wide"
            else:
                env.pop("FDP_TRACE_PATH", None)
                env.pop("FDP_WIDE_TRACE_PATH", None)
            proc = run_supervised(
                command or [binary, *([args.crash_input] if args.crash_input else [])],
                env=env, capture_output=True, text=True, check=False,
                timeout=timeout_ms / 1000,
            )
            status, report = proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as exc:
        parts = [part.decode(errors="replace") if isinstance(part, bytes) else part
                 for part in (exc.stdout, exc.stderr) if part]
        status, report = 124, "".join(parts) + "\nSymbolized execution timed out.\n"
    except (OSError, ValueError, RuntimeError, OutputLimitExceeded) as exc:
        status, report = 125, str(exc)
    return status, report, (time.monotonic() - started) * 1000


def symbolized_verdict(status, report, references, link_flags, *, binary=None, harness=None):
    from harnessreducer.oracle_evaluation import match_trace, pattern_verdict

    if status in (None, 124, 125):
        return "unavailable", "symbolized_execution_incomplete", None, [], "unavailable"
    pattern = references.get("symbolized_pattern") or references.get("fast_pattern")
    if not pattern:
        return "unavailable", "missing_symbolized_crash_pattern", None, [], "unavailable"
    p = pattern_verdict(status, report, pattern)
    if p != "accept":
        return p, "symbolized_pattern_or_crash_gate", None, [], p
    frames, error, _ = normalized_online_trace(
        report, link_flags, binary=binary, harness=harness,
    )
    if error:
        return "unavailable", error, None, frames, p
    verdict, reason, trace_id = match_trace(frames, references.get("traces", []))
    return verdict, reason, trace_id, frames, p

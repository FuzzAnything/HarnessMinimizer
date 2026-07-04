from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from harnessreducer.reducer_runner import (
    PHASE3_DIRECT,
    PHASE3_PCH,
    PchArtifacts,
    STACK_FRAME_PATTERN,
    get_last_interesting_file,
    extract_first_sanitizer_stack_trace,
    get_project_root,
    get_work_dir,
    normalize_crash_signature,
    pch_tester_args,
    prepare_phase3_pch_harness,
    restore_pch_includes,
    run_command,
    get_stack_trace_file,
    validate_phase3_mode,
)

CHECK_REFERENCE_FILE_NAME = "check_reference.json"
CHECK_STATISTICS_FILE_NAME = "check_statistics.txt"
CHECK_CANDIDATE_STACK_TRACES_FILE_NAME = "check_candidate_stack_traces.log"


@dataclass(frozen=True)
class CheckReference:
    crash_pattern: str
    full_stack_trace: str
    full_stack_trace_pattern: str
    frame_count: int


@dataclass(frozen=True)
class CheckStatistics:
    level_same: int
    stack_same: int

    @property
    def ratio(self) -> float:
        return 0.0 if self.level_same == 0 else self.stack_same / self.level_same


def get_check_reference_file() -> str:
    return os.path.join(get_work_dir(), CHECK_REFERENCE_FILE_NAME)


def get_check_statistics_file() -> str:
    return os.path.join(get_work_dir(), CHECK_STATISTICS_FILE_NAME)


def get_check_candidate_stack_traces_file() -> str:
    return os.path.join(get_work_dir(), CHECK_CANDIDATE_STACK_TRACES_FILE_NAME)


def get_check_tester_command() -> list[str]:
    tester_path = get_project_root() / "tests" / "check_tester.py"
    return [sys.executable, str(tester_path)]


def reset_check_state() -> None:
    for path in (
        get_check_reference_file(),
        get_check_statistics_file(),
        get_check_candidate_stack_traces_file(),
    ):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def extract_first_entire_stack_trace(output: str) -> str | None:
    return extract_first_sanitizer_stack_trace(output)


def count_stack_trace_frames(stack_trace: str | None) -> int:
    if not stack_trace:
        return 0
    return sum(1 for line in stack_trace.splitlines() if STACK_FRAME_PATTERN.match(line))


def write_check_reference(reference: CheckReference) -> str:
    path = Path(get_check_reference_file())
    path.write_text(json.dumps(asdict(reference), indent=2) + "\n", encoding="utf-8")
    return str(path)


def load_check_reference(path: str | None = None) -> CheckReference:
    data = json.loads(Path(path or get_check_reference_file()).read_text(encoding="utf-8"))
    return CheckReference(
        crash_pattern=data["crash_pattern"],
        full_stack_trace=data["full_stack_trace"],
        full_stack_trace_pattern=data["full_stack_trace_pattern"],
        frame_count=int(data["frame_count"]),
    )


def record_check_reference(
    crash_input: str | None,
    crash_pattern: str,
) -> CheckReference:
    output_bin = os.path.join(get_work_dir(), "poc.out")
    cmd = [output_bin]
    if crash_input:
        cmd.append(crash_input)

    env = os.environ.copy()
    env["UBSAN_OPTIONS"] = "exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=1"
    env["ASAN_OPTIONS"] = "exitcode=77:symbolize=1:handle_abort=1"
    proc = run_command(
        cmd,
        env=env,
        error_prefix="Failed to execute harness for check reference extraction",
        ignore_errors=True,
    )
    output = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 77:
        raise ValueError("Check mode expected the original harness to crash with exit code 77.")

    full_stack_trace = extract_first_entire_stack_trace(output)
    if not full_stack_trace:
        raise ValueError("Check mode could not find a symbolized first stack trace.")

    reference = CheckReference(
        crash_pattern=crash_pattern,
        full_stack_trace=full_stack_trace,
        full_stack_trace_pattern=normalize_crash_signature(full_stack_trace, escape=True),
        frame_count=count_stack_trace_frames(full_stack_trace),
    )
    write_check_reference(reference)
    return reference


def _format_check_statistics_text(level_same: int, stack_same: int) -> str:
    ratio = 0.0 if level_same == 0 else stack_same / level_same
    return (
        f"level_same: {level_same}\n"
        f"stack_same: {stack_same}\n"
        f"ratio_stack_same_over_level_same: {ratio:.6f}\n"
    )


def initialize_check_statistics_file() -> str:
    path = Path(get_check_statistics_file())
    path.write_text(_format_check_statistics_text(0, 0), encoding="utf-8")
    return str(path)


def _parse_check_statistics_text(text: str) -> CheckStatistics:
    level_same = 0
    stack_same = 0
    for line in text.splitlines():
        if line.startswith("level_same:"):
            level_same = int(line.split(":", 1)[1].strip())
        elif line.startswith("stack_same:"):
            stack_same = int(line.split(":", 1)[1].strip())
    return CheckStatistics(level_same=level_same, stack_same=stack_same)


def read_check_statistics(path: str | None = None) -> CheckStatistics:
    target = Path(path or get_check_statistics_file())
    try:
        return _parse_check_statistics_text(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return CheckStatistics(level_same=0, stack_same=0)


def record_check_statistics(
    statistics_file: str,
    *,
    level_same: bool,
    stack_same: bool,
) -> None:
    path = Path(statistics_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        stats = _parse_check_statistics_text(handle.read())
        new_level_same = stats.level_same + int(level_same)
        new_stack_same = stats.stack_same + int(stack_same)
        handle.seek(0)
        handle.truncate()
        handle.write(_format_check_statistics_text(new_level_same, new_stack_same))
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def append_candidate_stack_trace(
    log_file: str,
    *,
    source_path: str,
    crash_pattern_matched: bool,
    frame_count: int,
    level_same: bool,
    stack_same: bool,
    full_stack_trace: str | None,
    compare_stack_trace: str | None,
    compile_failed: bool = False,
    uninitialized_compile_error: bool | None = False,
    compile_error: str | None = None,
    candidate_code: str | None = None,
) -> None:
    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    full_trace_text = full_stack_trace if full_stack_trace else "<no-full-stack-trace-found>"
    compare_trace_text = compare_stack_trace if compare_stack_trace else "<no-pre-harness-stack-trace-found>"
    entry = (
        "=== candidate ===\n"
        f"source: {source_path}\n"
        f"crash_pattern_matched: {crash_pattern_matched}\n"
        f"frame_count: {frame_count}\n"
        f"level_same: {level_same}\n"
        f"stack_same: {stack_same}\n"
        f"compile_failed: {compile_failed}\n"
        "full_stack_trace:\n"
        f"{full_trace_text}\n"
        "compare_stack_trace:\n"
        f"{compare_trace_text}\n"
    )
    if uninitialized_compile_error is not None:
        entry += f"uninitialized_compile_error: {uninitialized_compile_error}\n"
    if compile_error is not None:
        entry += "compile_error:\n" f"{compile_error}\n"
    if candidate_code is not None:
        entry += "candidate_code:\n" f"{candidate_code}\n"
    entry += "=== end candidate ===\n\n"
    with path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.write(entry)
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def emit_check_statistics_summary(path: str | None = None) -> CheckStatistics:
    stats = read_check_statistics(path)
    print(
        "[+] Check summary: "
        f"level_same={stats.level_same}, "
        f"stack_same={stats.stack_same}, "
        f"stack_same/level_same={stats.ratio:.6f}"
    )
    return stats


def run_treereducer_with_check(
    harness_path: str,
    fdp_trace_file: str,
    crash_pattern: str,
    compile_flags: str | None,
    link_flags: str | None,
    crash_input: str | None,
    stable: bool = False,
    phase3_mode: str = PHASE3_DIRECT,
    snapshot: bool = False,
) -> str:
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
        cmd.extend(["--stable", "--min-reduction", "1"])
    else:
        cmd.append("--fast")

    cmd.extend(
        [
            "--timeout",
            "300",
            "--interesting-exit-code",
            "77",
            "--",
            *get_check_tester_command(),
            "@@.cpp",
            crash_pattern,
            "--crash-input",
            crash_input or "",
            f"--compile-flags={compile_flags or ''}",
            f"--link-flags={link_flags or ''}",
            "--fdp-trace",
            fdp_trace_file,
            "--check-reference-file",
            get_check_reference_file(),
            "--check-statistics-file",
            initialize_check_statistics_file(),
            "--check-stack-log-file",
            get_check_candidate_stack_traces_file(),
            "--stack-trace-file",
            get_stack_trace_file(),
        ]
    )
    if snapshot:
        cmd.extend(["--last-interesting-file", get_last_interesting_file()])
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))

    proc = subprocess.run(
        cmd,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to run tree-reducer in check mode:\n{proc.stdout} {proc.stderr}")
    if not os.path.exists(reduced_harness):
        raise RuntimeError("Reduced harness file was not created as expected.")

    if pch_artifacts is not None:
        restore_pch_includes(reduced_harness, pch_artifacts)
        if snapshot:
            last_interesting_file = get_last_interesting_file()
            if os.path.exists(last_interesting_file):
                restore_pch_includes(last_interesting_file, pch_artifacts)

    return reduced_harness

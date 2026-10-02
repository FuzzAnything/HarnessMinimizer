from __future__ import annotations

import fcntl
from contextlib import nullcontext
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from harnessreducer.process_supervisor import (
    run_supervised,
)
from harnessreducer.reduction_engines import RawOutputCapture

from harnessreducer.reducer_runner import (
    DEFAULT_EXEC_TIMEOUT_MS,
    DEFAULT_TREEREDUCE_JOBS,
    MAX_TREEREDUCE_JOBS,
    PHASE3_DIRECT,
    PHASE3_PCH,
    PHASE3_SPLIT,
    PchArtifacts,
    STACK_FRAME_COUNT_PATTERN,
    StaticArchiveRootConfig,
    append_exec_timeout_tester_args,
    auto_var_init_tester_args,
    calibrate_exec_timeout_ms,
    dynamic_crash_site_tester_args,
    get_last_interesting_file,
    extract_first_sanitizer_stack_trace,
    get_project_root,
    get_work_dir,
    normalize_crash_signature,
    pch_tester_args,
    prepare_phase3_pch_harness,
    restore_pch_includes,
    run_command,
    run_amortized_reference_candidate,
    set_current_exec_timeout_ms,
    start_amortized_runner,
    get_stack_trace_file,
    validate_phase3_mode,
    runtime_library_env,
    absolutize_link_flags,
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
    full_stack_trace_symbolize_0: str = ""
    full_stack_trace_symbolize_0_pattern: str = ""
    frame_count_symbolize_0: int = 0


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
    return sum(
        1 for line in stack_trace.splitlines() if STACK_FRAME_COUNT_PATTERN.match(line)
    )


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
        full_stack_trace_symbolize_0=data.get("full_stack_trace_symbolize_0", ""),
        full_stack_trace_symbolize_0_pattern=data.get(
            "full_stack_trace_symbolize_0_pattern", ""
        ),
        frame_count_symbolize_0=int(data.get("frame_count_symbolize_0", 0)),
    )


def _run_check_reference_harness(
    crash_input: str | None,
    link_flags: str | None,
    *,
    symbolize: bool,
) -> subprocess.CompletedProcess[str]:
    output_bin = os.path.join(get_work_dir(), "poc.out")
    cmd = [output_bin]
    if crash_input:
        cmd.append(crash_input)

    env = runtime_library_env(link_flags, symbolize=symbolize)
    symbolized = "1" if symbolize else "0"
    env["UBSAN_OPTIONS"] = (
        f"exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize={symbolized}"
    )
    env["ASAN_OPTIONS"] = f"exitcode=77:symbolize={symbolized}:handle_abort=1"
    return run_command(
        cmd,
        env=env,
        error_prefix="Failed to execute harness for check reference extraction",
        ignore_errors=True,
    )


def record_check_reference(
    crash_input: str | None,
    crash_pattern: str,
    link_flags: str | None = None,
) -> CheckReference:
    proc = _run_check_reference_harness(
        crash_input,
        link_flags,
        symbolize=True,
    )
    output = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 77:
        raise ValueError("Check mode expected the original harness to crash with exit code 77.")

    full_stack_trace = extract_first_entire_stack_trace(output)
    if not full_stack_trace:
        raise ValueError("Check mode could not find a symbolized first stack trace.")

    symbolize_0_proc = _run_check_reference_harness(
        crash_input,
        link_flags,
        symbolize=False,
    )
    symbolize_0_output = symbolize_0_proc.stdout + "\n" + symbolize_0_proc.stderr
    full_stack_trace_symbolize_0 = ""
    if symbolize_0_proc.returncode == 77:
        full_stack_trace_symbolize_0 = (
            extract_first_entire_stack_trace(symbolize_0_output) or ""
        )
        if not full_stack_trace_symbolize_0:
            print(
                "[!] Warning: Check mode could not find a symbolize=0 "
                "reference stack trace; the unsymbolized reference trace will be empty."
            )
    else:
        print(
            "[!] Warning: Check mode could not reproduce the reference crash with "
            "symbolize=0; the unsymbolized reference trace will be empty."
        )

    reference = CheckReference(
        crash_pattern=crash_pattern,
        full_stack_trace=full_stack_trace,
        full_stack_trace_pattern=normalize_crash_signature(full_stack_trace, escape=True),
        frame_count=count_stack_trace_frames(full_stack_trace),
        full_stack_trace_symbolize_0=full_stack_trace_symbolize_0,
        full_stack_trace_symbolize_0_pattern=(
            normalize_crash_signature(full_stack_trace_symbolize_0, escape=True)
            if full_stack_trace_symbolize_0
            else ""
        ),
        frame_count_symbolize_0=count_stack_trace_frames(full_stack_trace_symbolize_0),
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
    full_stack_trace_symbolize_0: str | None = None,
    compile_failed: bool = False,
    uninitialized_compile_error: bool | None = False,
    compile_error: str | None = None,
    candidate_code: str | None = None,
) -> None:
    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    full_trace_text = full_stack_trace if full_stack_trace else "<no-full-stack-trace-found>"
    full_trace_symbolize_0_text = (
        full_stack_trace_symbolize_0
        if full_stack_trace_symbolize_0
        else "<no-symbolize-0-full-stack-trace-found>"
    )
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
        "full_stack_trace_symbolize_0:\n"
        f"{full_trace_symbolize_0_text}\n"
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
    fdp_trace_file: str | None,
    crash_pattern: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    crash_input: str | None,
    stable: bool = False,
    phase3_mode: str = PHASE3_SPLIT,
    snapshot: bool = False,
    amortize_link: bool = False,
    crash_pattern_symbolize_0: str | None = None,
    require_crash_pattern: bool = True,
    jobs: int = DEFAULT_TREEREDUCE_JOBS,
    tool: str = "treereduce",
    auto_var_init_pattern: bool = False,
    raw_output_capture: RawOutputCapture | None = None,
) -> str:
    from harnessreducer.reduction_engines import prepare_reducer_invocation, validate_tool

    validate_tool(tool)
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
            symbolize=True,
            static_root_config=calibration_root,
            exec_timeout_ms=DEFAULT_EXEC_TIMEOUT_MS,
            reference_executable=reference_executable,
        ) as calibration_runner:
            symbolize_1_timeout_ms = calibrate_exec_timeout_ms(
                harness_path,
                fdp_trace_file,
                compile_flags,
                link_flags,
                crash_input,
                phase3_mode=phase3_mode,
                pch_artifacts=pch_artifacts,
                symbolize=True,
                runner_socket=calibration_runner.socket_path,
                plugin_link_flags=getattr(
                    calibration_runner,
                    "plugin_link_flags",
                    (),
                ),
            )
        with start_amortized_runner(
            link_flags,
            crash_input,
            fdp_trace_file,
            symbolize=False,
            static_root_config=calibration_root,
            exec_timeout_ms=DEFAULT_EXEC_TIMEOUT_MS,
            reference_executable=reference_executable,
        ) as calibration_runner_symbolize_0:
            symbolize_0_timeout_ms = calibrate_exec_timeout_ms(
                harness_path,
                fdp_trace_file,
                compile_flags,
                link_flags,
                crash_input,
                phase3_mode=phase3_mode,
                pch_artifacts=pch_artifacts,
                symbolize=False,
                runner_socket=calibration_runner_symbolize_0.socket_path,
                plugin_link_flags=getattr(
                    calibration_runner_symbolize_0,
                    "plugin_link_flags",
                    (),
                ),
            )
        exec_timeout_ms = max(symbolize_1_timeout_ms, symbolize_0_timeout_ms)
    else:
        exec_timeout_ms = max(
            calibrate_exec_timeout_ms(
                harness_path,
                fdp_trace_file,
                compile_flags,
                link_flags,
                crash_input,
                phase3_mode=phase3_mode,
                pch_artifacts=pch_artifacts,
                symbolize=True,
            ),
            calibrate_exec_timeout_ms(
                harness_path,
                fdp_trace_file,
                compile_flags,
                link_flags,
                crash_input,
                phase3_mode=phase3_mode,
                pch_artifacts=pch_artifacts,
                symbolize=False,
            ),
        )
    set_current_exec_timeout_ms(exec_timeout_ms)
    print(f"[+] Using fixed execution timeout for check mode: {exec_timeout_ms} ms")

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
        *get_check_tester_command(),
        "@@.cpp",
        crash_pattern or ".*",
        "--crash-input",
        crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
        "--check-reference-file",
        get_check_reference_file(),
        "--check-statistics-file",
        initialize_check_statistics_file(),
        "--check-stack-log-file",
        get_check_candidate_stack_traces_file(),
        "--stack-trace-file",
        get_stack_trace_file(),
    ]
    append_exec_timeout_tester_args(cmd, exec_timeout_ms)
    if fdp_trace_file:
        cmd.extend(["--fdp-trace", fdp_trace_file])
    if snapshot:
        cmd.extend(["--last-interesting-file", get_last_interesting_file()])
    if not require_crash_pattern:
        cmd.append("--skip-crash-pattern")
    cmd.extend(pch_tester_args(pch_artifacts, phase3_mode))
    cmd.extend(auto_var_init_tester_args(auto_var_init_pattern))
    cmd.extend(dynamic_crash_site_tester_args())

    runner_context = (
        start_amortized_runner(
            link_flags,
            crash_input,
            fdp_trace_file,
            symbolize=True,
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
    runner_symbolize_0_context = (
        start_amortized_runner(
            link_flags,
            crash_input,
            fdp_trace_file,
            symbolize=False,
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
    with (
        runner_context as amortized_runner,
        runner_symbolize_0_context as amortized_runner_symbolize_0,
    ):
        if amortized_runner is not None:
            plugin_link_flags = getattr(amortized_runner, "plugin_link_flags", ())
            reference_output = run_amortized_reference_candidate(
                harness_path,
                fdp_trace_file,
                crash_pattern or ".*",
                compile_flags,
                link_flags,
                crash_input,
                phase3_mode,
                amortized_runner.socket_path,
                pch_artifacts,
                plugin_link_flags,
                symbolize=True,
                require_crash_pattern=require_crash_pattern,
                auto_var_init_pattern=auto_var_init_pattern,
            )
            full_stack_trace = extract_first_entire_stack_trace(reference_output)
            if not full_stack_trace:
                raise RuntimeError(
                    "Could not extract an amortized-link check-mode reference stack trace."
                )
            full_stack_trace_symbolize_0 = ""
            if amortized_runner_symbolize_0 is not None:
                try:
                    reference_output_symbolize_0 = run_amortized_reference_candidate(
                        harness_path,
                        fdp_trace_file,
                        crash_pattern_symbolize_0 or crash_pattern or ".*",
                        compile_flags,
                        link_flags,
                        crash_input,
                        phase3_mode,
                        amortized_runner_symbolize_0.socket_path,
                        pch_artifacts,
                        plugin_link_flags,
                        symbolize=False,
                        auto_var_init_pattern=auto_var_init_pattern,
                    )
                    full_stack_trace_symbolize_0 = (
                        extract_first_entire_stack_trace(reference_output_symbolize_0)
                        or ""
                    )
                    if not full_stack_trace_symbolize_0:
                        print(
                            "[!] Warning: Could not extract an amortized-link "
                            "symbolize=0 check-mode reference stack trace."
                        )
                except Exception as exc:
                    print(
                        "[!] Warning: Could not record the amortized-link "
                        f"symbolize=0 check-mode reference stack trace: {exc}"
                    )
            write_check_reference(
                CheckReference(
                    crash_pattern=crash_pattern or ".*",
                    full_stack_trace=full_stack_trace,
                    full_stack_trace_pattern=normalize_crash_signature(
                        full_stack_trace, escape=True
                    ),
                    frame_count=count_stack_trace_frames(full_stack_trace),
                    full_stack_trace_symbolize_0=full_stack_trace_symbolize_0,
                    full_stack_trace_symbolize_0_pattern=(
                        normalize_crash_signature(
                            full_stack_trace_symbolize_0, escape=True
                        )
                        if full_stack_trace_symbolize_0
                        else ""
                    ),
                    frame_count_symbolize_0=count_stack_trace_frames(
                        full_stack_trace_symbolize_0
                    ),
                )
            )
            cmd.extend(
                ["--amortized-runner-socket", amortized_runner.socket_path]
            )
            if amortized_runner_symbolize_0 is not None:
                cmd.extend(
                    [
                        "--amortized-runner-socket-symbolize-0",
                        amortized_runner_symbolize_0.socket_path,
                    ]
                )
            if plugin_link_flags:
                cmd.append(
                    "--amortized-plugin-fallback-link-flags="
                    + " ".join(plugin_link_flags)
                )

        invocation = prepare_reducer_invocation(
            tool=tool, source=reducer_source, output=reduced_harness,
            checker_command=cmd, stable=stable, jobs=jobs,
        )
        print(f"[+] Running reduction engine: {tool} (check mode)")
        proc = invocation.run(run_supervised)
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to run {tool} reducer in check mode:\n{proc.stdout} {proc.stderr}")
    invocation.publish_result(raw_output_capture)
    if not os.path.exists(reduced_harness):
        raise RuntimeError("Reduced harness file was not created as expected.")

    if pch_artifacts is not None:
        restore_pch_includes(reduced_harness, pch_artifacts)
        if snapshot:
            last_interesting_file = get_last_interesting_file()
            if os.path.exists(last_interesting_file):
                restore_pch_includes(last_interesting_file, pch_artifacts)

    return reduced_harness

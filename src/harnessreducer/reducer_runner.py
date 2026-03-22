from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

TREEDUCER_DIR = tempfile.mkdtemp(prefix="harness_reducer_")
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent


def cleanup() -> None:
    try:
        shutil.rmtree(TREEDUCER_DIR, ignore_errors=True)
    except OSError:
        pass


atexit.register(cleanup)


def get_project_root() -> Path:
    return PROJECT_ROOT


def get_fdp_header_dir() -> str:
    return str(get_project_root() / "include")


def get_crash_tester_path() -> str:
    return str(get_project_root() / "tests" / "crash_tester.py")


def run_command(cmd: list[str], error_prefix: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or proc.stdout.strip() or "Unknown error"
        raise RuntimeError(f"{error_prefix}: {err_msg}")
    return proc


def check_tree_reducer() -> None:
    run_command(
        ["tree-reducer-c", "--help"],
        "tree-reducer is not available. Please ensure it is installed and in your PATH",
    )


def compile_dump_mode_harness(harness_path: str, extra_flags: str | None) -> str:
    tagged_harness_bin = os.path.join(TREEDUCER_DIR, "tagged_harness.out")
    compile_cmd = [
        "clang++",
        "-DFDP_MIN_MODE_DUMP",
        f"-I{get_fdp_header_dir()}",
        "-fsanitize=address,fuzzer,undefined",
        "-g",
        "-O0",
        harness_path,
        "-o",
        tagged_harness_bin,
    ]
    if extra_flags:
        compile_cmd.extend(extra_flags.split())

    run_command(compile_cmd, "Failed to compile tagged harness with dump mode")
    return tagged_harness_bin


def dump_fdp_trace(harness_bin: str, crash_input: str | None) -> str:
    fdp_trace_file = os.path.join(TREEDUCER_DIR, "fdp_trace.log")
    env = os.environ.copy()
    env["FDP_TRACE_PATH"] = fdp_trace_file

    exec_cmd = [harness_bin, crash_input] if crash_input else [harness_bin]
    run_command(exec_cmd, "Failed to execute tagged harness in dump mode", env=env)

    if not os.path.exists(fdp_trace_file):
        raise RuntimeError("FDP trace file was not created as expected.")
    return fdp_trace_file


def run_treereducer(
    harness_path: str,
    fdp_trace_file: str,
    crash_pattern: str,
    extra_args: str | None,
    crash_input: str | None,
) -> str:
    reduced_harness = os.path.join(TREEDUCER_DIR, "reduced_harness.cpp")
    cmd = [
        "tree-reducer-c",
        "-j",
        "60",
        "-s",
        harness_path,
        "-o",
        reduced_harness,
        "--stable",
        "--min-reduction",
        "1",
        "--interesting-exit-code",
        "77",
        "--",
        get_crash_tester_path(),
        "@@.cpp",
        crash_pattern,
    ]
    env = os.environ.copy()
    env["FDP_TRACE_PATH"] = fdp_trace_file
    env["EXTRA_FLAGS"] = extra_args or ""
    env["CRASH_INPUT"] = crash_input or ""

    proc = subprocess.run(
        cmd,
        env=env,
        stdout=subprocess.STDOUT,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to run tree-reducer:\n{proc.stdout}")
    if not os.path.exists(reduced_harness):
        raise RuntimeError("Reduced harness file was not created as expected.")

    return reduced_harness


def format_reduced_harness(reduced_harness_path: str) -> None:
    print(f"Formatting reduced harness with clang-format: {reduced_harness_path}")
    run_command(
        ["clang-format", "-i", "--style=LLVM", reduced_harness_path],
        "Failed to format reduced harness with clang-format",
    )

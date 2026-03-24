from __future__ import annotations

import atexit
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

TREEDUCER_DIR: str | None = None
_IS_USER_WORK_DIR = False
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent


def cleanup() -> None:
    global TREEDUCER_DIR

    if TREEDUCER_DIR is None or _IS_USER_WORK_DIR:
        return

    try:
        shutil.rmtree(TREEDUCER_DIR, ignore_errors=True)
    except OSError:
        pass


atexit.register(cleanup)

ASAN_PATTERN = re.compile(r"(?:ERROR|SUMMARY):\s*AddressSanitizer:\s*[\w-]+")
LEAK_PATTERN = re.compile(
    r"SUMMARY: AddressSanitizer: \d+ byte\(s\) leaked in \d+ allocation\(s\)\."
)
UBSAN_PATTERN = re.compile(
    r"runtime error:\s.*"
)

def get_project_root() -> Path:
    return PROJECT_ROOT


def get_fdp_header_dir() -> str:
    return str(get_project_root() / "include")


def get_crash_tester_path() -> str:
    return str(get_project_root() / "tests" / "crash_tester.py")


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

def check_harness_compilation(harness_path: str, extra_flags: str | None) -> None:
    print("[+] Checking harness compilation...")
    work_dir = get_work_dir()
    output_bin = os.path.join(work_dir, "poc.out")
    compile_cmd = [
        "clang++",
        "-fsanitize=address,fuzzer,undefined",
        "-g",
        "-O0",
        harness_path,
        "-o",
        output_bin,
    ]
    if extra_flags:
        compile_cmd.extend(extra_flags.split())

    run_command(compile_cmd, "Failed to compile the original harness. Please fix compilation errors before reduction.")
    print("[+] Harness compiles successfully.")

def extract_crash_pattern_from_output(crash_input: str | None) -> str:
    work_dir = get_work_dir()
    output_bin = os.path.join(work_dir, "poc.out")
    cmd = [output_bin]
    if crash_input:
        cmd.append(crash_input)
    env = os.environ.copy()
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
    proc = run_command(cmd, "Failed to execute harness for crash pattern extraction", ignore_errors=True)
    output = proc.stdout + "\n" + proc.stderr

    asan_match = ASAN_PATTERN.search(output)
    if asan_match:
        return asan_match.group(0)

    leak_match = LEAK_PATTERN.search(output)
    if leak_match:
        return leak_match.group(0)

    ubsan_match = UBSAN_PATTERN.search(output)
    if ubsan_match:
        return ubsan_match.group(0)

    raise ValueError("Could not extract a crash pattern from the tester output: \n" + output)
    

def check_reducer_crash_pattern(harness_path: str, crash_pattern: str, crash_input: str | None, extra_flags: str | None) -> None:
    print("[+] Checking crash pattern validity...")
    if not crash_pattern:
        raise ValueError("Crash pattern cannot be empty.")
    cmd = [
        get_crash_tester_path(),
        harness_path,
        crash_pattern,
        "--crash-input", crash_input or "",
        "--extra-flags", extra_flags or "",
    ]
    proc = run_command(cmd, "Invalid crash pattern.", ignore_errors=True)
    if proc.returncode != 77:
        print("Tester command: " + " ".join(cmd))
        raise ValueError(f"Crash pattern did not match the crash behavior. Tester output:\n{proc.stdout}\n{proc.stderr}")
    print("[+] Crash pattern is valid.")

def compile_dump_mode_harness(harness_path: str, extra_flags: str | None) -> str:
    tagged_harness_bin = os.path.join(get_work_dir(), "tagged_harness.out")
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
    extra_args: str | None,
    crash_input: str | None,
) -> str:
    reduced_harness = os.path.join(get_work_dir(), "reduced_harness.cpp")
    cmd = [
        "treereduce-c",
        "-j",
        "60",
        "-s",
        harness_path,
        "-o",
        reduced_harness,
        #"--stable",
        #"--min-reduction",
        #"1",
        "--fast",
        "--timeout",
        "300",
        "--interesting-exit-code",
        "77",
        "--",
        get_crash_tester_path(),
        "@@.cpp",
        crash_pattern,
        "--crash-input", crash_input or "",
        "--extra-flags", extra_args or "",
        "--fdp-trace", fdp_trace_file,
    ]

    proc = subprocess.run(
        cmd,
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

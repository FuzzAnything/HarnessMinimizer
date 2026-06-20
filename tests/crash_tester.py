#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import tempfile
import argparse
from pathlib import Path

__script_dir__ = os.path.dirname(os.path.realpath(__file__))
__project_root__ = Path(__script_dir__).parent
PHASE3_SANITIZER_FLAGS = ["-fsanitize=address,fuzzer,undefined"]
PHASE3_DIRECT_OPT_FLAGS = ["-g", "-O0"]
PHASE3_PCH_OPT_FLAGS = ["-O1", "-gline-tables-only"]


def get_project_root():
    return __project_root__

def get_fdp_header_dir():
    return os.path.join(get_project_root(), "include")


def split_extra_flags(extra_flags: str | None) -> list[str]:
    return extra_flags.split() if extra_flags else []


def phase3_replay_flags(fdp_trace: str | None) -> list[str]:
    if not fdp_trace:
        return []
    return [f"-I{get_fdp_header_dir()}", "-DFDP_MIN_MODE_REPLAY"]


def compile_direct(args: argparse.Namespace, output_path: str) -> tuple[int, str | None]:
    compile_cmd = [
        "clang++",
        *phase3_replay_flags(args.fdp_trace),
        *PHASE3_SANITIZER_FLAGS,
        *PHASE3_DIRECT_OPT_FLAGS,
        args.source,
        "-o",
        output_path
    ]
    compile_cmd.extend(split_extra_flags(args.extra_flags))

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

    extra_flags = split_extra_flags(args.extra_flags)
    compile_cmd = [
        "clang++",
        "-Qunused-arguments",
        "-include-pch",
        args.pch_path,
        *phase3_replay_flags(args.fdp_trace),
        *PHASE3_SANITIZER_FLAGS,
        *PHASE3_PCH_OPT_FLAGS,
        "-c",
        args.source,
        "-o",
        object_path,
    ]
    compile_cmd.extend(extra_flags)

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
    ]
    link_cmd.extend(extra_flags)
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=str, help="Source file to compile")
    parser.add_argument("crash_pattern", type=str, help="Regex pattern to identify the crash in the output")
    parser.add_argument("--crash-input", type=str, default=None, help="Optional input to feed to the binary during execution")
    parser.add_argument("--extra-flags", type=str, default=None, help="Optional extra compiler flags to use during compilation")
    parser.add_argument("--fdp-trace", type=str, default=None, help="Optional FDP trace path used for replay-mode execution")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--direct", action="store_true", help="Use the original one-step Phase 3 compile/link command")
    mode_group.add_argument("--pch", action="store_true", help="Use PCH Phase 3 mode: compile object with -include-pch, then link")
    parser.add_argument("--pch-path", type=str, default=None, help="Path to fahm_prefix.pch when --pch is used")
    args = parser.parse_args()
    pid = os.getpid()

    with tempfile.NamedTemporaryFile(prefix=f"poc_{pid}_", suffix=".out", delete=False, dir="/tmp") as out_file:
        output_path = out_file.name
    object_path = None

    try:
        if args.pch:
            compile_status, object_path = compile_with_pch(args, output_path)
        else:
            compile_status, object_path = compile_direct(args, output_path)
        if compile_status != 0:
            return -1

        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "exitcode=77:symbolize=0"
        env["UBSAN_OPTIONS"] = "exitcode=77:symbolize=0:halt_on_error=1"
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

        # Some libFuzzer/ASAN crash paths print fatal markers but still exit 0.
        if status == 77 and re.search(args.crash_pattern, run_log) is not None:
            print("execution log: ")
            print(run_log)
            print("Crash behavior preserved.")
            return 77
        print(f"Crash pattern did not match. Exit status: {status}\n, crash pattern: {args.crash_pattern}\nExecution log:\n{run_log}")
        return 1
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

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


def get_project_root():
    return __project_root__

def get_fdp_header_dir():
    return os.path.join(get_project_root(), "include")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=str, help="Source file to compile")
    parser.add_argument("crash_pattern", type=str, help="Regex pattern to identify the crash in the output")
    parser.add_argument("--crash-input", type=str, default=None, help="Optional input to feed to the binary during execution")
    parser.add_argument("--extra-flags", type=str, default=None, help="Optional extra compiler flags to use during compilation")
    parser.add_argument("--fdp-trace", type=str, default=None, help="Optional path to write FDP trace logs during execution")  
    args = parser.parse_args()
    pid = os.getpid()

    with tempfile.NamedTemporaryFile(prefix=f"poc_{pid}_", suffix=".out", delete=False, dir="/tmp") as out_file:
        output_path = out_file.name

    try:
        compile_cmd = [
            "clang++",
            f"-I{get_fdp_header_dir()}" if args.fdp_trace else "",
            "-DFDP_MIN_MODE_REPLAY" if args.fdp_trace else "",
            "-fsanitize=address,fuzzer,undefined",
            "-g",
            "-O0",
            args.source,
            "-o",
            output_path
        ]
        if args.extra_flags:
            compile_cmd.extend(args.extra_flags.split())        

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
        if status == 77 and run_log.find(args.crash_pattern) != -1:
            print("execution log: ")
            print(run_log)
            print("Crash behavior preserved.")
            return 77
        print(f"Crash pattern did not match. Exit status: {status}\n, crash pattern: {args.crash_pattern}\nExecution log:\n{run_log}")
        return 1
    finally:
        try:
            os.remove(output_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    sys.exit(main())

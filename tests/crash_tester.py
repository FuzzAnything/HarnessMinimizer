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

CRASH_INPUT = os.getenv("CRASH_INPUT", None)
EXTRA_FLAGS = os.getenv("EXTRA_FLAGS", None)
FDP_TRACE = os.getenv("FDP_TRACE", None)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=str, help="Source file to compile")
    parser.add_argument("crash_pattern", type=str, help="Regex pattern to identify the crash in the output")
    args = parser.parse_args()
    pid = os.getpid()

    with tempfile.NamedTemporaryFile(prefix=f"poc_{pid}_", suffix=".out", delete=False, dir="/tmp") as out_file:
        output_path = out_file.name

    try:
        compile_cmd = [
            "clang++",
            f"-I{get_fdp_header_dir()}",
            "-DFDP_MIN_MODE_REPLAY",
            "-fsanitize=address,fuzzer,undefined",
            "-g",
            "-O0",
            args.source,
            "-o",
            output_path
        ]
        if EXTRA_FLAGS:
            compile_cmd.extend(EXTRA_FLAGS.split())        

        compile_proc = subprocess.run(
            compile_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if compile_proc.returncode != 0:
            err_msg = compile_proc.stderr.strip() or compile_proc.stdout.strip() or "Unknown compilation error"
            print(f"Compilation failed: {err_msg}", file=sys.stderr)
            return -1

        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "exitcode=77:symbolize=0"
        env["UBSAN_OPTIONS"] = "exitcode=77:symbolize=0:halt_on_error=1"
        env["FDP_TRACE_PATH"] = FDP_TRACE
        
        exec_cmd = [output_path, CRASH_INPUT] if CRASH_INPUT else [output_path]
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
        if status == 77 and re.search(
            args.crash_pattern,
            run_log,
        ):
            print("execution log: ")
            print(run_log)
            print("Crash behavior preserved.")
            return 77
        return 1
    finally:
        try:
            os.remove(output_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    sys.exit(main())

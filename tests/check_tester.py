#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

__script_dir__ = Path(__file__).resolve().parent
__project_root__ = __script_dir__.parent
sys.path.insert(0, str(__project_root__ / "src"))

import importlib.util

from harnessreducer.check_mode import (
    append_candidate_stack_trace,
    count_stack_trace_frames,
    extract_first_entire_stack_trace,
    load_check_reference,
    record_check_statistics,
)
from harnessreducer.reducer_runner import extract_stack_trace

_crash_tester_spec = importlib.util.spec_from_file_location(
    "crash_tester_support",
    str(__project_root__ / "tests" / "crash_tester.py"),
)
_crash_tester = importlib.util.module_from_spec(_crash_tester_spec)
_crash_tester_spec.loader.exec_module(_crash_tester)

compile_direct = _crash_tester.compile_direct
compile_split = _crash_tester.compile_split
compile_with_pch = _crash_tester.compile_with_pch


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
    parser.add_argument("--pch-path", type=str, default=None, help="Path to fahm_prefix.pch when --pch is used")
    parser.add_argument("--check-reference-file", type=str, required=True, help="Path to the stored check reference JSON")
    parser.add_argument("--check-statistics-file", type=str, required=True, help="Path to the check statistics file")
    parser.add_argument("--check-stack-log-file", type=str, required=True, help="Path to the per-candidate check stack-trace log")
    parser.add_argument("--stack-trace-file", type=str, required=True, help="Path to the stored pre-harness stack-trace pattern")
    args = parser.parse_args()

    pid = os.getpid()
    with tempfile.NamedTemporaryFile(prefix=f"poc_{pid}_", suffix=".out", delete=False, dir="/tmp") as out_file:
        output_path = out_file.name
    object_path = None

    try:
        if args.pch:
            compile_status, object_path = compile_with_pch(args, output_path)
        elif args.split:
            compile_status, object_path = compile_split(args, output_path)
        else:
            compile_status, object_path = compile_direct(args, output_path)
        if compile_status != 0:
            return -1

        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "exitcode=77:symbolize=1:handle_abort=1"
        env["UBSAN_OPTIONS"] = "exitcode=77:symbolize=1:halt_on_error=1:print_stacktrace=1"
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

        stored_compare_pattern = Path(args.stack_trace_file).read_text(encoding="utf-8").strip()
        reference = load_check_reference(args.check_reference_file)
        run_log = run_proc.stdout + run_proc.stderr
        candidate_full_trace = extract_first_entire_stack_trace(run_log)
        candidate_compare_trace = extract_stack_trace(run_log, harness_path=args.source)
        candidate_frames = count_stack_trace_frames(candidate_full_trace)
        crash_pattern_matched = run_proc.returncode == 77 and re.search(args.crash_pattern, run_log) is not None
        level_same = crash_pattern_matched and candidate_frames == reference.frame_count
        stack_same = level_same and bool(stored_compare_pattern) and candidate_compare_trace is not None and (
            re.search(stored_compare_pattern, candidate_compare_trace) is not None
        )
        append_candidate_stack_trace(
            args.check_stack_log_file,
            source_path=args.source,
            crash_pattern_matched=crash_pattern_matched,
            frame_count=candidate_frames,
            level_same=level_same,
            stack_same=stack_same,
            full_stack_trace=candidate_full_trace,
            compare_stack_trace=candidate_compare_trace,
        )

        if not crash_pattern_matched:
            return 1

        if candidate_full_trace:
            record_check_statistics(
                args.check_statistics_file,
                level_same=level_same,
                stack_same=stack_same,
            )

        return 77
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
    raise SystemExit(main())

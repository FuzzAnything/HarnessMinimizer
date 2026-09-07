#!/usr/bin/env python3
"""Compare fixed PCH/amortized/profile checks against an unmodified checkout.

All candidates are bounded synthetic programs; no reduction scheduling or
worker-count changes confound the comparison. This is an overhead experiment,
not a claim about performance on every target library.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from harnessreducer.process_supervisor import run_supervised, terminate_process_group


def build(command):
    result = run_supervised(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    with tempfile.TemporaryDirectory(prefix="hr-supervision-bench-") as directory, ExitStack() as stack:
        directory = Path(directory)
        target_source = directory / "target.cpp"
        target_source.write_text(
            '#include <cstdint>\n#include <cstddef>\n'
            'extern "C" int target(const uint8_t *data,size_t size) {'
            'volatile int *p=new int[1];int r=p[(size?data[0]:1)+1];delete[]p;return r;}\n'
        )
        target = directory / "libtarget.so"
        sanitize = ["-fsanitize=address,undefined"]
        build(["clang++", *sanitize, "-O1", "-g", "-shared", "-fPIC", str(target_source), "-o", str(target)])
        prefix = directory / "prefix.h"
        prefix.write_text('#include <cstdint>\n#include <cstddef>\nextern "C" int target(const uint8_t*,size_t);\n')
        pch = directory / "prefix.pch"
        build(["clang++", *sanitize, "-O0", "-gline-tables-only", "-fPIC", "-x", "c++-header", str(prefix), "-o", str(pch)])
        seed = directory / "seed"
        seed.write_bytes(b"x")
        candidates = {}
        for name, body, status in (("crash", "return target(data,size);", 77), ("normal", "return 0;", 1), ("compile_failure", "return undefined_name;", 255)):
            source = directory / f"{name}.cpp"
            source.write_text('extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size){'+body+'}\n')
            candidates[name] = (source, status)
        sockets = {}
        roots = {"baseline": args.baseline_root.resolve(), "patched": ROOT}
        profiles = {label: directory / f"{label}.jsonl" for label in roots}
        for label, root in roots.items():
            runner = directory / label
            build(["clang++", "-std=c++17", *sanitize, "-O1", "-gline-tables-only", "-fno-omit-frame-pointer", "-Wl,--export-dynamic", str(root / "src/harnessreducer/harness_runner.cpp"), "-ldl", "-o", str(runner)])
            sock = directory / f"{label}.sock"
            env = dict(os.environ, ASAN_OPTIONS="exitcode=77:symbolize=0:detect_odr_violation=0:handle_abort=1", UBSAN_OPTIONS="exitcode=77:halt_on_error=1:print_stacktrace=1:symbolize=0")
            process = subprocess.Popen([str(runner), str(sock), str(seed), "3", str(target)], env=env, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(terminate_process_group, process)
            deadline = time.monotonic() + 5
            while not sock.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"{label} runner failed to start")
                time.sleep(.01)
            sockets[label] = sock

        def check(label, name, record, block):
            source, status = candidates[name]
            command = [sys.executable, str(roots[label] / "tests/crash_tester.py"), str(source), "heap-buffer-overflow", "--crash-input", str(seed), "--pch", "--pch-path", str(pch), "--pch-amortized-link", "--amortized-runner-socket", str(sockets[label]), "--exec-timeout-ms=3000", "--profile-file", str(profiles[label])]
            started = time.perf_counter_ns()
            result = run_supervised(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            elapsed = time.perf_counter_ns() - started
            if result.returncode != status:
                raise RuntimeError(f"{label}/{name}: expected {status}, got {result.returncode}\n{result.stdout!r}\n{result.stderr!r}")
            if record:
                rows.append(dict(label=label, candidate=name, block=block, wall_ns=elapsed))

        for label in roots:
            for name in candidates:
                check(label, name, False, -1)
        for block in range(args.rounds):
            order = list(roots) if block % 2 == 0 else list(reversed(roots))
            for _ in range(args.repeats):
                for name in candidates:
                    for label in order:
                        check(label, name, True, block)
            print(f"completed paired block {block + 1}/{args.rounds}", flush=True)

        summary = {}
        for label in roots:
            values = [r["wall_ns"] for r in rows if r["label"] == label]
            summary[label] = dict(checks=len(values), mean_ms=statistics.mean(values)/1e6, median_ms=statistics.median(values)/1e6)
        summary["mean_change_percent"] = (summary["patched"]["mean_ms"] / summary["baseline"]["mean_ms"] - 1) * 100
        summary["per_candidate"] = {}
        for name in candidates:
            means = {label: statistics.mean(r["wall_ns"] for r in rows if r["label"] == label and r["candidate"] == name)/1e6 for label in roots}
            summary["per_candidate"][name] = means
        summary["paired_block_change_percent"] = []
        for block in range(args.rounds):
            totals = {label: sum(r["wall_ns"] for r in rows if r["block"] == block and r["label"] == label) for label in roots}
            summary["paired_block_change_percent"].append((totals["patched"]/totals["baseline"]-1)*100)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(dict(summary=summary, samples=rows), indent=2) + "\n")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

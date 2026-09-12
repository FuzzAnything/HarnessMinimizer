#!/usr/bin/env python3
"""Run HarnessReducer performance sweeps for optimized and split-symbolize modes."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time


PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
from harnessreducer.process_supervisor import run_supervised

DEFAULT_JOBS = (1, 2, 4, 8, 16, 32, 60)
LATEST_MARKER_NAME = "latest_harnessreducer_perf_run.txt"
SOURCE_TOKEN_COUNT_METHOD = "cpp_like_regex_v1"
SOURCE_TOKEN_RE = re.compile(
    r"""
    //[^\n]*
    | /\*.*?\*/
    | "(?:\\.|[^"\\])*"
    | '(?:\\.|[^'\\])*'
    | [A-Za-z_]\w*
    | 0[xX][0-9A-Fa-f]+
    | \d+(?:\.\d*)?(?:[eE][+-]?\d+)?
    | ::|->\*|->|\+\+|--|<<=|>>=|<=|>=|==|!=|&&|\|\||<<|>>|[+\-*/%&|^~!<>=?:;,.()[\]{}]
    | \S
    """,
    re.DOTALL | re.VERBOSE,
)


VARIANTS = (
    {
        "key": "optimized",
        "directory": "optimized",
        "label": "--pch --amortize-link, symbolize off",
        "extra_args": ("--pch", "--amortize-link"),
    },
    {
        "key": "split_symbolize",
        "directory": "split-symbolize",
        "label": "--split, no amortize-link, --symbolize",
        "extra_args": ("--split", "--symbolize"),
    },
)


def parse_jobs(value: str) -> list[int]:
    jobs: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            job = int(item)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid job count: {item!r}") from exc
        if job < 1:
            raise argparse.ArgumentTypeError("job counts must be positive")
        if job not in jobs:
            jobs.append(job)
    if not jobs:
        raise argparse.ArgumentTypeError("at least one job count is required")
    return jobs


def benchmark_dir(value: str) -> Path:
    raw = Path(value).expanduser()
    if raw.exists():
        return raw.resolve()
    candidate = PROJECT_ROOT / "benchmark" / "library-bug" / value
    if candidate.exists():
        return candidate.resolve()
    raise SystemExit(
        f"benchmark directory not found: {value!r} "
        f"(also tried {candidate})"
    )


def default_python() -> str:
    venv_python = PROJECT_ROOT / ".venv-host" / "bin" / "python"
    if venv_python.is_file():
        return str(venv_python)
    return sys.executable


def expand_benchmark_placeholders(value: str | None, bench_dir: Path) -> str | None:
    if value is None:
        return None
    bench = str(bench_dir)
    return (
        value.replace("$(pwd)", bench)
        .replace("${PWD}", bench)
        .replace("$PWD", bench)
        .replace("{bench_dir}", bench)
    )


def shell_command(command: list[str]) -> str:
    return shlex.join(command)


def count_source_tokens(path: Path) -> int | None:
    """Count source tokens with a lightweight C/C++-like tokenizer.

    The count is intended for consistent before/after reduction comparisons,
    not as a full replacement for a compiler lexer.
    """
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    count = 0
    for match in SOURCE_TOKEN_RE.finditer(text):
        token = match.group(0)
        if token.startswith("//") or token.startswith("/*"):
            continue
        count += 1
    return count


def token_reduction_percent(
    original_tokens: int | None,
    final_tokens: int | None,
) -> float | None:
    if original_tokens is None or final_tokens is None or original_tokens <= 0:
        return None
    return 100.0 * (1.0 - (final_tokens / original_tokens))


def source_metrics(original_path: Path, reduced_path: Path) -> dict[str, object]:
    original_tokens = count_source_tokens(original_path)
    final_tokens = count_source_tokens(reduced_path)
    return {
        "token_count_method": SOURCE_TOKEN_COUNT_METHOD,
        "original_tokens": original_tokens,
        "final_tokens": final_tokens,
        "token_reduction_percent": token_reduction_percent(
            original_tokens,
            final_tokens,
        ),
    }


def profiled_checks(profile_path: Path) -> int | None:
    if not profile_path.is_file():
        return None
    try:
        summary = json.loads(profile_path.read_text(encoding="utf-8"))
        reducer = summary.get("reducer", {})
        if not isinstance(reducer, dict):
            return None
        return int(reducer.get("profiled_checks"))  # type: ignore[arg-type]
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None


def run_case(
    *,
    python_executable: str,
    bench_dir: Path,
    harness_path: Path,
    harness: str,
    crash_input: str,
    compile_flags: str,
    link_flags: str,
    variant: dict[str, object],
    job: int,
    job_dir: Path,
    stable: bool,
) -> dict[str, object]:
    work_dir = job_dir / "work"
    output_path = job_dir / "reduced.cpp"
    job_dir.mkdir(parents=True, exist_ok=False)

    extra_args = [str(arg) for arg in variant["extra_args"]]  # type: ignore[index]
    if stable:
        extra_args.append("--stable")

    command = [
        python_executable,
        "-m",
        "harnessreducer.cli",
        harness,
        f"--compile-flags={compile_flags}",
        f"--link-flags={link_flags}",
        "--work-dir",
        str(work_dir),
        "--crash-input",
        crash_input,
        *extra_args,
        "--profile",
        "--jobs",
        str(job),
        "-o",
        str(output_path),
    ]

    env = os.environ.copy()
    src_path = str(PROJECT_ROOT / "src")
    env["PYTHONPATH"] = (
        src_path
        if not env.get("PYTHONPATH")
        else src_path + os.pathsep + env["PYTHONPATH"]
    )

    command_text = shell_command(command)
    (job_dir / "command.txt").write_text(command_text + "\n", encoding="utf-8")

    start_time = datetime.now().astimezone()
    start_ns = time.perf_counter_ns()
    with (job_dir / "command.log").open("w", encoding="utf-8", errors="replace") as log:
        log.write(command_text + "\n\n")
        log.flush()
        proc = run_supervised(
            command,
            cwd=bench_dir,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=None,
        )
    full_wall_seconds = (time.perf_counter_ns() - start_ns) / 1_000_000_000.0
    end_time = datetime.now().astimezone()

    (job_dir / "full_command_wall_seconds.txt").write_text(
        f"{full_wall_seconds:.6f}\n",
        encoding="utf-8",
    )

    total_checks = profiled_checks(job_dir / "reduction_profile.json")
    source_reduction = source_metrics(harness_path, output_path)
    source_reduction_path = job_dir / "source_reduction_metrics.json"
    source_reduction_path.write_text(
        json.dumps(source_reduction, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    run_info = {
        "variant": variant["key"],
        "variant_label": variant["label"],
        "jobs": job,
        "stable": stable,
        "benchmark_dir": str(bench_dir),
        "work_dir": str(work_dir),
        "output": str(output_path),
        "command": command,
        "started": start_time.isoformat(),
        "ended": end_time.isoformat(),
        "full_command_wall_seconds": full_wall_seconds,
        "returncode": proc.returncode,
        "total_checks": total_checks,
        "source_reduction_metrics": source_reduction,
    }
    (job_dir / "run_info.json").write_text(
        json.dumps(run_info, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return run_info


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run HarnessReducer with optimized PCH/amortized-link settings and "
            "with split/symbolized settings across a worker sweep."
        )
    )
    parser.add_argument(
        "--dir",
        required=True,
        help=(
            "Benchmark name under benchmark/library-bug, for example libaom-1, "
            "or an explicit benchmark directory path."
        ),
    )
    parser.add_argument("--compile-flags", required=True)
    parser.add_argument("--link-flags", required=True)
    parser.add_argument(
        "--jobs",
        type=parse_jobs,
        default=list(DEFAULT_JOBS),
        help="Comma-separated worker counts. Default: 1,2,4,8,16,32,60.",
    )
    parser.add_argument(
        "--harness",
        default="harness.cpp",
        help="Harness path relative to the benchmark directory. Default: harness.cpp.",
    )
    parser.add_argument(
        "--crash-input",
        default="crash-input",
        help="Crash input path relative to the benchmark directory. Default: crash-input.",
    )
    parser.add_argument(
        "--output-root",
        default=None,
        help=(
            "Directory for all results. Default: "
            "<benchmark>/harnessreducer-perf-comparison-<timestamp>."
        ),
    )
    parser.add_argument(
        "--python",
        default=default_python(),
        help="Python executable used to run harnessreducer.cli.",
    )
    parser.add_argument(
        "--no-stable",
        action="store_true",
        help="Do not pass --stable. By default --stable is used for comparability.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue the remaining jobs if one command exits nonzero.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    bench_dir = benchmark_dir(args.dir)

    harness_path = bench_dir / args.harness
    crash_input_path = bench_dir / args.crash_input
    if not harness_path.is_file():
        raise SystemExit(f"harness not found: {harness_path}")
    if not crash_input_path.is_file():
        raise SystemExit(f"crash input not found: {crash_input_path}")

    compile_flags = expand_benchmark_placeholders(args.compile_flags, bench_dir)
    link_flags = expand_benchmark_placeholders(args.link_flags, bench_dir)
    assert compile_flags is not None
    assert link_flags is not None

    timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    output_root = (
        Path(args.output_root).expanduser()
        if args.output_root
        else bench_dir / f"harnessreducer-perf-comparison-{timestamp}"
    ).resolve()
    if output_root.exists():
        raise SystemExit(f"output directory already exists: {output_root}")
    output_root.mkdir(parents=True)

    stable = not args.no_stable
    manifest: dict[str, object] = {
        "schema_version": 1,
        "created": datetime.now().astimezone().isoformat(),
        "benchmark_dir": str(bench_dir),
        "harness": args.harness,
        "crash_input": args.crash_input,
        "compile_flags": compile_flags,
        "link_flags": link_flags,
        "jobs": list(args.jobs),
        "stable": stable,
        "variants": {
            str(variant["key"]): {
                "directory": variant["directory"],
                "label": variant["label"],
                "extra_args": list(variant["extra_args"]),  # type: ignore[arg-type]
            }
            for variant in VARIANTS
        },
        "runs": [],
    }
    manifest_path = output_root / "run_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"Benchmark: {bench_dir}")
    print(f"Results:   {output_root}")
    print(f"Python:    {args.python}")
    print(f"Jobs:      {','.join(str(job) for job in args.jobs)}")

    failed = False
    for variant in VARIANTS:
        variant_dir = output_root / str(variant["directory"])
        for job in args.jobs:
            job_dir = variant_dir / f"jobs-{job}"
            print(f"[run] {variant['key']} jobs={job}")
            run_info = run_case(
                python_executable=args.python,
                bench_dir=bench_dir,
                harness_path=harness_path,
                harness=args.harness,
                crash_input=args.crash_input,
                compile_flags=compile_flags,
                link_flags=link_flags,
                variant=variant,
                job=job,
                job_dir=job_dir,
                stable=stable,
            )
            manifest["runs"].append(run_info)  # type: ignore[index]
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(
                f"[done] {variant['key']} jobs={job} "
                f"wall={run_info['full_command_wall_seconds']:.2f}s "
                f"returncode={run_info['returncode']}"
            )
            if int(run_info["returncode"]) != 0:
                failed = True
                if not args.keep_going:
                    print(f"Stopping after failure. See {job_dir / 'command.log'}")
                    break
        if failed and not args.keep_going:
            break

    (bench_dir / LATEST_MARKER_NAME).write_text(str(output_root) + "\n", encoding="utf-8")
    print(f"Latest-run marker: {bench_dir / LATEST_MARKER_NAME}")
    print("Create the TXT tables with:")
    print(f"  ./make_harnessreducer_perf_tables.py --dir {bench_dir.name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Evaluate both TSV datasets serially and generate reports for a fresh batch."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
from harnessreducer.evaluation_metrics import (
    EVALUATION_FORMAT, MEASUREMENT_STAGE, SOURCE_TOKEN_COUNT_METHOD,
    finite_number, measure_run, read_json, write_json,
)
from harnessreducer.process_supervisor import run_supervised
from harnessreducer.reduction_engines import TOOL_CHOICES

ALL_TOOLS = ("treereduce", "perses", "wdd", "cdd")
DATASETS = (("harness-bug", "harness_bug_cases.tsv"), ("library-bug", "library_bug_cases.tsv"))
VARIANTS = (
    ("optimized", ("--pch", "--amortize-link", "--no-symbolize")),
    ("split_symbolize", ("--split", "--symbolize")),
)
PLACEHOLDERS = re.compile(r"\$\(pwd\)|\$\{PWD\}|\$PWD\b|\{bench_dir\}")


def repository_path(value: str | Path) -> Path:
    return (PROJECT_ROOT / Path(value).expanduser()).resolve()


def default_python() -> str:
    for name in (".venv", ".venv-host"):
        candidate = PROJECT_ROOT / name / "bin/python"
        if candidate.is_file():
            return str(candidate)
    return sys.executable


def expand_benchmark_placeholders(value: str, bench_dir: Path) -> str:
    # Parse quoting before substitution, then quote each expanded argument. This
    # preserves paths containing spaces and treats shell syntax as ordinary text.
    return shlex.join([
        PLACEHOLDERS.sub(lambda _: str(bench_dir), token)
        for token in shlex.split(value)
    ])


def load_cases() -> list[dict]:
    cases = []
    for dataset, filename in DATASETS:
        path = PROJECT_ROOT / filename
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream, delimiter="\t")
            if reader.fieldnames != ["benchmark", "compile_flags", "link_flags"]:
                raise ValueError(f"{path}: expected benchmark, compile_flags, link_flags TSV columns")
            seen = set()
            for line, row in enumerate(reader, 2):
                name = row["benchmark"]
                if None in row or any(value is None for value in row.values()):
                    raise ValueError(f"{path}:{line}: expected three tab-separated fields")
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
                    raise ValueError(f"{path}:{line}: invalid benchmark name {name!r}")
                if name in seen:
                    raise ValueError(f"{path}:{line}: duplicate benchmark {name}")
                seen.add(name)
                bench = (PROJECT_ROOT / "benchmark" / dataset / name).resolve()
                for required in ("harness.cpp", "crash-input"):
                    if not (bench / required).is_file():
                        raise ValueError(f"Missing benchmark input: {bench / required}")
                cases.append({
                    "dataset": dataset, "case": name, "benchmark_dir": str(bench),
                    "harness": str(bench / "harness.cpp"),
                    "crash_input": str(bench / "crash-input"),
                    "compile_flags": expand_benchmark_placeholders(row["compile_flags"], bench),
                    "link_flags": expand_benchmark_placeholders(row["link_flags"], bench),
                })
            if not seen:
                raise ValueError(f"Empty evaluation dataset: {path}")
    return cases


def plan_runs(cases: list[dict], tools: tuple[str, ...], root: Path, python: str) -> list[dict]:
    runs = []
    for case in cases:
        case_dir = Path(case["dataset"]) / case["case"]
        for tool in tools:
            for configuration, flags in VARIANTS:
                run_dir = case_dir / tool / configuration
                output = run_dir / "reduced.cpp"
                work = run_dir / "work"
                command = [
                    python, "-m", "harnessreducer.cli", case["harness"], "--tool", tool,
                    f"--compile-flags={case['compile_flags']}", f"--link-flags={case['link_flags']}",
                    "--crash-input", case["crash_input"], "--work-dir", str(root / work),
                    *flags, "--stable", "--profile", "--capture-raw-output", "--protect-initializers", "--jobs", "1",
                    "-o", str(root / output),
                ]
                runs.append({
                    **case, "tool": tool, "configuration": configuration, "jobs": 1,
                    "stable": True, "protect_initializers": True, "capture_raw_output": True,
                    "status": "planned", "command": command, "returncode": None,
                    "original_source": str(case_dir / "harness.original.cpp"),
                    "directory": str(run_dir), "work_dir": str(work), "output": str(output),
                    "raw_reduced_harness": str(run_dir / "reduced.raw.cpp"),
                    "profile": str(run_dir / "reduction_profile.json"),
                    "candidate_profile": str(run_dir / "candidate_profile.jsonl"),
                    "log": str(run_dir / "command.log"),
                    "run_info": str(run_dir / "run_info.json"),
                })
    return runs


def reference_stability_wall_seconds(work_dir: Path) -> float:
    path = work_dir / "stack_depth_stability.json"
    if not path.is_file():
        return 0.0
    try:
        value = finite_number(read_json(path).get("total_wall_seconds"))
        return max(0.0, value or 0.0)
    except (OSError, ValueError):
        return 0.0


def run_case(root: Path, run: dict) -> None:
    directory = root / run["directory"]
    directory.mkdir(parents=True, exist_ok=False)
    original = root / run["original_source"]
    if not original.exists():
        shutil.copyfile(run["harness"], original)
    command_text = shlex.join(run["command"])
    (directory / "command.txt").write_text(command_text + "\n", encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT / "src") + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    run["started"] = datetime.now().astimezone().isoformat()
    start = time.perf_counter()
    errors = []
    try:
        with (root / run["log"]).open("w", encoding="utf-8") as log:
            log.write(command_text + "\n\n")
            log.flush()
            result = run_supervised(
                run["command"], cwd=Path(run["benchmark_dir"]), env=env,
                stdout=log, stderr=subprocess.STDOUT, text=True, check=False, timeout=None,
            )
        run["returncode"] = result.returncode
        if result.returncode != 0:
            errors.append(f"Reduction exited with status {result.returncode}")
    except (OSError, subprocess.SubprocessError) as exc:
        errors.append(f"Could not execute reduction: {exc}")
    run["ended"] = datetime.now().astimezone().isoformat()
    raw_wall = time.perf_counter() - start
    excluded = reference_stability_wall_seconds(root / run["work_dir"])
    run.update({
        "raw_full_command_wall_seconds": raw_wall,
        "profile_excluded_setup_wall_seconds": excluded,
        "full_command_wall_seconds": max(0.0, raw_wall - excluded),
    })
    for key in ("raw_full_command_wall_seconds", "profile_excluded_setup_wall_seconds", "full_command_wall_seconds"):
        (directory / f"{key}.txt").write_text(f"{run[key]:.9f}\n", encoding="utf-8")
    metrics, measurement_errors = measure_run(root, run)
    errors.extend(measurement_errors)
    run["metrics"] = metrics
    run["errors"] = errors
    run["status"] = "failed" if run["returncode"] != 0 else ("incomplete" if errors else "success")
    write_json(directory / "source_reduction_metrics.json", {
        key: metrics[key] for key in (
            "measurement_stage", "token_count_method", "original_tokens", "remaining_tokens",
            "token_reduction_percent", "final_output_bytes",
        )
    })
    write_json(root / run["run_info"], run)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True, choices=(*TOOL_CHOICES, "all"),
                        help="all runs treereduce, perses, wdd and cdd")
    parser.add_argument("--output-root", default="output/evaluation",
                        help="Parent of a fresh timestamped batch (relative paths use the repository)")
    parser.add_argument("--python", default=default_python(), help="Python executable for reductions")
    parser.add_argument("--dry-run", action="store_true", help="Validate both TSVs and print commands without creating results")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cases = load_cases()
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    # Preserve virtualenv executable symlinks: resolving them would select the
    # base interpreter and lose the environment's installed dependencies.
    python = shutil.which(args.python) if "/" not in args.python else str(PROJECT_ROOT / Path(args.python).expanduser())
    if not python or not os.access(python, os.X_OK):
        parser.error(f"Python executable not found: {args.python}")
    tools = ALL_TOOLS if args.tool == "all" else (args.tool,)
    root = repository_path(args.output_root) / datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")
    runs = plan_runs(cases, tools, root, python)
    print(f"{len(cases)} cases, {len(tools)} tools, 2 configurations: {len(runs)} reductions; --jobs 1, serial", flush=True)
    reporter_command = [python, str(PROJECT_ROOT / "make_harnessreducer_perf_tables.py"), "--results-dir", str(root)]
    if args.dry_run:
        for run in runs:
            print(f"[{run['dataset']}/{run['case']}/{run['tool']}/{run['configuration']}] cwd={shlex.quote(run['benchmark_dir'])}")
            print(shlex.join(run["command"]))
        print(shlex.join(reporter_command))
        return 0
    root.mkdir(parents=True, exist_ok=False)
    manifest = {
        "format": EVALUATION_FORMAT, "measurement_stage": MEASUREMENT_STAGE,
        "token_count_method": SOURCE_TOKEN_COUNT_METHOD, "jobs": 1, "tools": list(tools),
        "datasets": [{"dataset": name, "tsv": str(PROJECT_ROOT / filename)} for name, filename in DATASETS],
        "created": datetime.now().astimezone().isoformat(), "status": "running", "runs": runs,
        "report_command": reporter_command,
    }
    manifest_path = root / "run_manifest.json"
    write_json(manifest_path, manifest)
    print(f"Results: {root}", flush=True)
    for index, run in enumerate(runs, 1):
        run["status"] = "running"
        write_json(manifest_path, manifest)
        try:
            run_case(root, run)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            run.update(status="failed", errors=[str(exc)])
        write_json(manifest_path, manifest)
        print(f"[{index}/{len(runs)}] {run['dataset']}/{run['case']}/{run['tool']}/{run['configuration']}: {run['status']}", flush=True)
    # Keep evaluation and report failures independent; reporting still writes
    # partial results and never hides failed runs behind older successful data.
    from make_harnessreducer_perf_tables import generate_reports
    try:
        manifest["report_returncode"] = generate_reports(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        manifest["report_returncode"] = 1
        manifest["report_error"] = str(exc)
        print(f"Reporting failed: {exc}", file=sys.stderr)
    failed = manifest["report_returncode"] != 0 or any(run["status"] != "success" for run in runs)
    manifest["status"] = "failed" if failed else "completed"
    manifest["ended"] = datetime.now().astimezone().isoformat()
    write_json(manifest_path, manifest)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())

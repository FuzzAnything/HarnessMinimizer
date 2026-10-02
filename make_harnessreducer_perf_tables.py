#!/usr/bin/env python3
"""Generate raw-output evaluation reports using only one batch's manifest."""
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
from harnessreducer.evaluation_metrics import (
    EVALUATION_FORMAT, MEASUREMENT_STAGE, SOURCE_TOKEN_COUNT_METHOD,
    artifact_path, finite_number, measure_run, read_json,
)

TIME_METRICS = (
    "reduction_wall_seconds", "full_command_wall_seconds", "raw_full_command_wall_seconds",
    "python_setup_milliseconds", "compile_milliseconds", "link_milliseconds",
    "execute_milliseconds", "total_per_check_milliseconds",
)
FIELDS = (
    "dataset", "case", "tool", "configuration", "row_type", "status", "jobs", "returncode",
    "measurement_stage", "token_count_method", "original_tokens", "remaining_tokens",
    "token_reduction_percent", "final_output_bytes", *TIME_METRICS,
    "profile_excluded_setup_wall_seconds", "checks_per_second", "total_checks",
    "interesting_checks", "uninteresting_checks", "invalid_checks", "checker_outcomes",
    "mean_in_flight_checks", "worker_utilization", "initializer_recovery", "reduction_attempts",
    "initializer_recovery_metadata",
    "final_validated", "original_source", "raw_reduced_harness", "output", "profile",
    "candidate_profile", "log", "errors",
)


def run_row(root: Path, run: dict) -> dict:
    row = {key: run.get(key) for key in FIELDS if key in run}
    row.update(row_type="reduction", measurement_stage=MEASUREMENT_STAGE,
               token_count_method=SOURCE_TOKEN_COUNT_METHOD)
    errors = list(run.get("errors", []))
    try:
        metrics, measurement_errors = measure_run(root, run)
        row.update(metrics)
        errors.extend(measurement_errors)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"Could not measure run: {exc}")
    for key in ("full_command_wall_seconds", "raw_full_command_wall_seconds", "profile_excluded_setup_wall_seconds"):
        value = finite_number(run.get(key))
        row[key] = value
        if value is None or value < 0:
            errors.append(f"Missing or invalid {key}")
    if run.get("jobs") != 1:
        errors.append("Evaluation requires --jobs 1")
    if run.get("returncode") not in (None, 0):
        row["status"] = "failed"
    elif run.get("status") != "success" or run.get("returncode") is None or errors:
        row["status"] = "incomplete" if run.get("status") != "failed" else "failed"
    if row["status"] != "success" and not errors:
        errors.append(f"Run status: {run.get('status', 'missing')}")
    row["errors"] = "; ".join(dict.fromkeys(errors))
    return row


def safe_ratio(numerator: object, denominator: object) -> float | None:
    top, bottom = finite_number(numerator), finite_number(denominator)
    return top / bottom if top is not None and bottom is not None and bottom > 0 else None


def speedup_row(rows: list[dict]) -> dict | None:
    pair = {row["configuration"]: row for row in rows}
    optimized, baseline = pair.get("optimized"), pair.get("split_symbolize")
    if not optimized or not baseline or any(row["status"] != "success" for row in (optimized, baseline)):
        return None
    result = {key: optimized[key] for key in ("dataset", "case", "tool", "jobs")}
    result.update(configuration="optimized_speedup_x", row_type="speedup", status="success")
    for field in TIME_METRICS:
        result[field] = safe_ratio(baseline.get(field), optimized.get(field))
    result["checks_per_second"] = safe_ratio(optimized.get("checks_per_second"), baseline.get("checks_per_second"))
    return result


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def display(value: object) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


def write_text(path: Path, rows: list[dict], speedup: dict | None) -> None:
    first = rows[0]
    lines = [
        f"Dataset: {first['dataset']}    Case: {first['case']}    Tool: {first['tool']}    Jobs: 1",
        "Remaining tokens: raw_reducer_output, before macro/PCH/initializer restoration or inlining.",
        "Temporary includes count as text; external header contents are not expanded.",
        "Final-output byte size is separate from raw remaining-token size.",
        "Full command time excludes reference stack-depth stability setup; raw wall time includes it.",
        "Recovery profiles include all reduction attempts; tokens use the selected attempt/snapshot.",
        "Speedup: baseline / optimized for times, optimized / baseline for checks per second.",
        "",
    ]
    columns = [row["configuration"] for row in rows]
    values = rows + ([speedup] if speedup is not None else [])
    if speedup is not None:
        columns.append("optimized_speedup_x")
    fields = [field for field in FIELDS if field not in ("dataset", "case", "tool", "row_type")]
    data = [[field, *(display(row.get(field)) for row in values)] for field in fields]
    headers = ["metric", *columns]
    # Keep long artifact paths/errors readable without padding the entire table
    # to their length; they are listed below the numeric comparison instead.
    path_fields = {"original_source", "raw_reduced_harness", "output", "profile", "candidate_profile", "log", "errors", "initializer_recovery_metadata"}
    numeric = [row for row in data if row[0] not in path_fields]
    widths = [max(len(str(row[index])) for row in [headers, *numeric]) for index in range(len(headers))]
    lines.append(" | ".join(value.ljust(width) for value, width in zip(headers, widths)))
    lines.append("-+-".join("-" * width for width in widths))
    lines.extend(" | ".join(value.ljust(width) for value, width in zip(row, widths)) for row in numeric)
    for row in rows:
        lines.extend(["", f"{row['configuration']} artifacts / errors:"])
        lines.extend(f"  {field}: {display(row.get(field))}" for field in FIELDS if field in path_fields)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_reports(root: Path) -> int:
    root = root.resolve()
    manifest = read_json(root / "run_manifest.json")
    if manifest.get("format") != EVALUATION_FORMAT or manifest.get("measurement_stage") != MEASUREMENT_STAGE:
        raise ValueError("Expected a fresh raw-output evaluation manifest")
    runs = manifest.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("Evaluation manifest has no planned runs")
    groups = defaultdict(list)
    rows = []
    identities = set()
    for run in runs:
        identity = tuple(run[key] for key in ("dataset", "case", "tool", "configuration"))
        if identity in identities:
            raise ValueError(f"Duplicate run in evaluation manifest: {identity}")
        identities.add(identity)
        # Also validates output destinations before writing any per-case report.
        artifact_path(root, str(Path(*identity[:3])))
        row = run_row(root, run)
        rows.append(row)
        groups[identity[:3]].append(row)
    failed = any(row["status"] != "success" for row in rows)
    for identity, group in groups.items():
        directory = artifact_path(root, str(Path(*identity)))
        directory.mkdir(parents=True, exist_ok=True)
        speedup = speedup_row(group)
        tool, case = identity[2], identity[1]
        if {row["configuration"] for row in group} != {"optimized", "split_symbolize"}:
            failed = True
        write_csv(directory / f"performance_comparison_{tool}_{case}.csv", group + ([speedup] if speedup else []))
        write_text(directory / f"performance_tables_{tool}_{case}.txt", group, speedup)
    write_csv(root / "evaluation_summary.csv", rows)
    print(f"Reports: {root / 'evaluation_summary.csv'} ({len(rows)} reductions, {sum(row['status'] != 'success' for row in rows)} unsuccessful)")
    return int(failed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True, help="Fresh evaluation batch directory; relative paths use the repository")
    args = parser.parse_args(argv)
    try:
        return generate_reports((PROJECT_ROOT / Path(args.results_dir).expanduser()).resolve())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Reporting failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Create TXT and CSV HarnessReducer performance tables from profile outputs."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
import json
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parent
LATEST_MARKER_NAME = "latest_harnessreducer_perf_run.txt"
DEFAULT_VARIANT_DIRS = {
    "optimized": "optimized",
    "split_symbolize": "split-symbolize",
}
VARIANT_TITLES = {
    "optimized": "Optimized configuration: --pch --amortize-link, symbolize off",
    "split_symbolize": "Split-symbolize configuration: --split, no amortize-link, --symbolize",
}


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


def latest_results_dir(bench_dir: Path) -> Path:
    marker = bench_dir / LATEST_MARKER_NAME
    if marker.is_file():
        path = Path(marker.read_text(encoding="utf-8").strip()).expanduser()
        if path.exists():
            return path.resolve()

    candidates = sorted(
        bench_dir.glob("harnessreducer-perf-comparison-*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if candidates:
        return candidates[0].resolve()
    raise SystemExit(
        f"no performance result directory found for {bench_dir}. "
        "Run run_harnessreducer_perf_sweep.py first, or pass --results-dir."
    )


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_float(path: Path) -> float | None:
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return None
    try:
        return float(text.split()[0])
    except ValueError:
        return None


def ns_to_ms(value: object) -> float:
    try:
        return float(value) / 1_000_000.0
    except (TypeError, ValueError):
        return 0.0


def timing_mean_ms(summary: dict[str, object], field: str) -> float:
    candidate_timing = summary.get("candidate_timing", {})
    if not isinstance(candidate_timing, dict):
        return 0.0
    stats = candidate_timing.get(field, {})
    if not isinstance(stats, dict):
        return 0.0
    return ns_to_ms(stats.get("mean_ns", 0))


def format_float(value: float | None, digits: int) -> str:
    if value is None:
        return "n/a"
    return f"{value:,.{digits}f}"


def format_int(value: int | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:,}"


def format_speedup(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}x"


def ascii_table(headers: list[str], rows: Iterable[list[str]]) -> str:
    materialized_rows = [list(row) for row in rows]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in materialized_rows))
        for index in range(len(headers))
    ]

    def border(char: str = "-") -> str:
        return "+" + "+".join(char * (width + 2) for width in widths) + "+"

    def render_row(row: list[str]) -> str:
        cells: list[str] = []
        for index, cell in enumerate(row):
            if index == 0:
                cells.append(f" {cell:>{widths[index]}} ")
            else:
                cells.append(f" {cell:>{widths[index]}} ")
        return "|" + "|".join(cells) + "|"

    lines = [border("-"), render_row(headers), border("=")]
    lines.extend(render_row(row) for row in materialized_rows)
    lines.append(border("-"))
    return "\n".join(lines)


def result_counts(summary: dict[str, object]) -> dict[str, int]:
    reducer = summary.get("reducer", {})
    if not isinstance(reducer, dict):
        return {}
    counts = reducer.get("result_counts", {})
    if not isinstance(counts, dict):
        return {}
    parsed: dict[str, int] = {}
    for key, value in counts.items():
        try:
            parsed[str(key)] = int(value)
        except (TypeError, ValueError):
            parsed[str(key)] = 0
    return parsed


def load_variant(results_dir: Path, variant_key: str, directory: str) -> dict[int, dict[str, object]]:
    variant_dir = results_dir / directory
    if not variant_dir.is_dir():
        raise SystemExit(f"missing result directory for {variant_key}: {variant_dir}")

    rows: dict[int, dict[str, object]] = {}
    for job_dir in sorted(variant_dir.glob("jobs-*")):
        try:
            jobs = int(job_dir.name.removeprefix("jobs-"))
        except ValueError:
            continue
        profile_path = job_dir / "reduction_profile.json"
        if not profile_path.is_file():
            raise SystemExit(f"missing profile JSON: {profile_path}")
        summary = read_json(profile_path)
        full_wall = read_float(job_dir / "full_command_wall_seconds.txt")
        reduced_path = job_dir / "reduced.cpp"
        final_size = reduced_path.stat().st_size if reduced_path.is_file() else None
        rows[jobs] = {
            "job_dir": str(job_dir),
            "summary": summary,
            "full_wall": full_wall,
            "final_size": final_size,
        }
    if not rows:
        raise SystemExit(f"no jobs-* results found in {variant_dir}")
    return rows


def get_reducer(row: dict[str, object]) -> dict[str, object]:
    summary = row["summary"]
    assert isinstance(summary, dict)
    reducer = summary.get("reducer", {})
    return reducer if isinstance(reducer, dict) else {}


def main_rows(rows_by_job: dict[int, dict[str, object]]) -> list[list[str]]:
    table_rows: list[list[str]] = []
    for jobs in sorted(rows_by_job):
        row = rows_by_job[jobs]
        reducer = get_reducer(row)
        table_rows.append(
            [
                str(jobs),
                format_float(float(reducer.get("wall_seconds", 0.0)), 3),
                format_float(row.get("full_wall"), 2),  # type: ignore[arg-type]
                format_int(int(reducer.get("profiled_checks", 0))),
                format_float(float(reducer.get("checks_per_second", 0.0)), 3),
                format_int(row.get("final_size")),  # type: ignore[arg-type]
            ]
        )
    return table_rows


def worker_rows(rows_by_job: dict[int, dict[str, object]]) -> list[list[str]]:
    table_rows: list[list[str]] = []
    for jobs in sorted(rows_by_job):
        reducer = get_reducer(rows_by_job[jobs])
        counts = result_counts(rows_by_job[jobs]["summary"])  # type: ignore[arg-type]
        table_rows.append(
            [
                str(jobs),
                format_float(float(reducer.get("mean_in_flight_checks", 0.0)), 3),
                format_float(float(reducer.get("worker_utilization", 0.0)), 3),
                format_int(counts.get("77", 0)),
                format_int(counts.get("1", 0)),
                format_int(counts.get("-1", 0)),
            ]
        )
    return table_rows


def candidate_rows(rows_by_job: dict[int, dict[str, object]]) -> list[list[str]]:
    table_rows: list[list[str]] = []
    for jobs in sorted(rows_by_job):
        summary = rows_by_job[jobs]["summary"]
        assert isinstance(summary, dict)
        table_rows.append(
            [
                str(jobs),
                format_float(timing_mean_ms(summary, "python_import_ns"), 3),
                format_float(timing_mean_ms(summary, "compile_ns"), 3),
                format_float(timing_mean_ms(summary, "link_ns"), 3),
                format_float(timing_mean_ms(summary, "execute_ns"), 3),
                format_float(timing_mean_ms(summary, "total_ns"), 3),
            ]
        )
    return table_rows


def safe_divide(numerator: float | None, denominator: float | None) -> float | None:
    if numerator is None or denominator is None or denominator == 0:
        return None
    return numerator / denominator


def comparison_metric_values(
    optimized_row: dict[str, object],
    split_symbolize_row: dict[str, object],
) -> list[tuple[str, str, float | None, float | None, float | None]]:
    """Return raw values and speedups in one consistent representation.

    Each tuple is (metric, unit, optimized value, non-optimized value,
    optimized speedup). For times, speedup is non-optimized / optimized. For
    throughput, it is optimized / non-optimized. A result above 1.0 therefore
    always means that the optimized configuration is faster.
    """
    opt_reducer = get_reducer(optimized_row)
    split_reducer = get_reducer(split_symbolize_row)
    opt_summary = optimized_row["summary"]
    split_summary = split_symbolize_row["summary"]
    assert isinstance(opt_summary, dict)
    assert isinstance(split_summary, dict)

    opt_reduction_wall = float(opt_reducer.get("wall_seconds", 0.0))
    split_reduction_wall = float(split_reducer.get("wall_seconds", 0.0))
    opt_full_wall = optimized_row.get("full_wall")
    split_full_wall = split_symbolize_row.get("full_wall")
    assert opt_full_wall is None or isinstance(opt_full_wall, float)
    assert split_full_wall is None or isinstance(split_full_wall, float)
    opt_checks_per_second = float(opt_reducer.get("checks_per_second", 0.0))
    split_checks_per_second = float(split_reducer.get("checks_per_second", 0.0))

    values: list[tuple[str, str, float | None, float | None, float | None]] = [
        (
            "reduction_wall_time",
            "seconds",
            opt_reduction_wall,
            split_reduction_wall,
            safe_divide(split_reduction_wall, opt_reduction_wall),
        ),
        (
            "full_command_wall_time",
            "seconds",
            opt_full_wall,
            split_full_wall,
            safe_divide(split_full_wall, opt_full_wall),
        ),
        (
            "checks_per_second",
            "checks/second",
            opt_checks_per_second,
            split_checks_per_second,
            safe_divide(opt_checks_per_second, split_checks_per_second),
        ),
    ]

    for metric, field in (
        ("python_setup_time", "python_import_ns"),
        ("compile_time", "compile_ns"),
        ("link_time", "link_ns"),
        ("execute_time", "execute_ns"),
        ("total_per_check_time", "total_ns"),
    ):
        opt_value = timing_mean_ms(opt_summary, field)
        split_value = timing_mean_ms(split_summary, field)
        values.append(
            (
                metric,
                "milliseconds",
                opt_value,
                split_value,
                safe_divide(split_value, opt_value),
            )
        )
    return values


def comparison_rows(
    optimized: dict[int, dict[str, object]],
    split_symbolize: dict[int, dict[str, object]],
) -> list[list[str]]:
    rows: list[list[str]] = []
    for jobs in sorted(set(optimized) & set(split_symbolize)):
        metrics = comparison_metric_values(optimized[jobs], split_symbolize[jobs])
        rows.append(
            [
                str(jobs),
                *(format_speedup(metric[4]) for metric in metrics),
            ]
        )
    return rows


def write_comparison_csv(
    output_path: Path,
    optimized: dict[int, dict[str, object]],
    split_symbolize: dict[int, dict[str, object]],
) -> None:
    """Write three compact rows of metrics for each worker count."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            [
                "jobs",
                "result_type",
                "reduction_wall_seconds",
                "full_command_wall_seconds",
                "checks_per_second",
                "python_setup_milliseconds",
                "compile_milliseconds",
                "link_milliseconds",
                "execute_milliseconds",
                "total_per_check_milliseconds",
            ]
        )
        for jobs in sorted(set(optimized) & set(split_symbolize)):
            metrics = comparison_metric_values(
                optimized[jobs], split_symbolize[jobs]
            )
            for result_type, value_index in (
                ("optimized", 2),
                ("non_optimized_split_symbolize", 3),
                ("optimized_speedup_x", 4),
            ):
                writer.writerow(
                    [
                        jobs,
                        result_type,
                        *(
                            "" if metric[value_index] is None else repr(metric[value_index])
                            for metric in metrics
                        ),
                    ]
                )


def variant_dirs_from_manifest(results_dir: Path) -> dict[str, str]:
    manifest_path = results_dir / "run_manifest.json"
    if not manifest_path.is_file():
        return dict(DEFAULT_VARIANT_DIRS)
    manifest = read_json(manifest_path)
    variants = manifest.get("variants", {})
    if not isinstance(variants, dict):
        return dict(DEFAULT_VARIANT_DIRS)
    directories = dict(DEFAULT_VARIANT_DIRS)
    for key in directories:
        config = variants.get(key, {})
        if isinstance(config, dict) and isinstance(config.get("directory"), str):
            directories[key] = str(config["directory"])
    return directories


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render TXT and CSV tables from HarnessReducer performance sweep results."
    )
    parser.add_argument(
        "--dir",
        required=True,
        help=(
            "Benchmark name under benchmark/library-bug, for example libaom-1, "
            "or an explicit benchmark directory path."
        ),
    )
    parser.add_argument(
        "--results-dir",
        default=None,
        help=(
            "Result directory created by run_harnessreducer_perf_sweep.py. "
            "Default: latest marker under the selected benchmark."
        ),
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output TXT path. Default: <results-dir>/performance_tables.txt.",
    )
    parser.add_argument(
        "--csv-output",
        default=None,
        help="Output CSV path. Default: <results-dir>/performance_comparison.csv.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    bench_dir = benchmark_dir(args.dir)
    results_dir = (
        Path(args.results_dir).expanduser().resolve()
        if args.results_dir
        else latest_results_dir(bench_dir)
    )
    if not results_dir.is_dir():
        raise SystemExit(f"results directory not found: {results_dir}")

    variant_dirs = variant_dirs_from_manifest(results_dir)
    optimized = load_variant(results_dir, "optimized", variant_dirs["optimized"])
    split_symbolize = load_variant(
        results_dir,
        "split_symbolize",
        variant_dirs["split_symbolize"],
    )

    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else results_dir / "performance_tables.txt"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    csv_output_path = (
        Path(args.csv_output).expanduser().resolve()
        if args.csv_output
        else results_dir / "performance_comparison.csv"
    )

    lines = [
        "HarnessReducer Performance Tables",
        "=================================",
        "",
        f"Generated: {datetime.now().astimezone().isoformat()}",
        f"Benchmark: {bench_dir}",
        f"Results:   {results_dir}",
        "",
        "Speedup convention:",
        "- For time columns, speedup = split-symbolize time / optimized time.",
        "- For Checks/s, speedup = optimized Checks/s / split-symbolize Checks/s.",
        "",
    ]

    for key, rows_by_job in (
        ("optimized", optimized),
        ("split_symbolize", split_symbolize),
    ):
        lines.extend(
            [
                VARIANT_TITLES[key],
                "",
                "Main performance table",
                ascii_table(
                    [
                        "Jobs",
                        "Reduction wall (s)",
                        "Full command wall (s)",
                        "Profiled checks",
                        "Checks/s",
                        "Final size (bytes)",
                    ],
                    main_rows(rows_by_job),
                ),
                "",
                "Worker usage and checker outcomes",
                ascii_table(
                    [
                        "Jobs",
                        "Mean in-flight checks",
                        "Worker utilization",
                        "Interesting (77)",
                        "Uninteresting (1)",
                        "Compile fail (-1)",
                    ],
                    worker_rows(rows_by_job),
                ),
                "",
                "Mean time per candidate",
                ascii_table(
                    [
                        "Jobs",
                        "Python setup (ms)",
                        "Compile (ms)",
                        "Link (ms)",
                        "Execute (ms)",
                        "Total per check (ms)",
                    ],
                    candidate_rows(rows_by_job),
                ),
                "",
            ]
        )

    lines.extend(
        [
            "Comparison table: optimized speedup over split-symbolize",
            ascii_table(
                [
                    "Jobs",
                    "Reduction wall",
                    "Full command wall",
                    "Checks/s",
                    "Python setup",
                    "Compile",
                    "Link",
                    "Execute",
                    "Total per check",
                ],
                comparison_rows(optimized, split_symbolize),
            ),
            "",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")
    write_comparison_csv(csv_output_path, optimized, split_symbolize)
    print(output_path)
    print(csv_output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

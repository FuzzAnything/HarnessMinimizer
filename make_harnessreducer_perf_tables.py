#!/usr/bin/env python3
"""Create TXT and CSV HarnessReducer performance tables from profile outputs."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
import json
from pathlib import Path
import re
import sys
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parent
LATEST_MARKER_NAME = "latest_harnessreducer_perf_run.txt"
TOOL_MARKER_GLOB = "latest_harnessreducer_perf_run_*.txt"
DEFAULT_VARIANT_DIRS = {
    "optimized": "optimized",
    "split_symbolize": "split-symbolize",
}
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


def result_directories(bench_dir: Path) -> list[Path]:
    candidates = {path.resolve() for path in bench_dir.glob("harnessreducer-perf-comparison-*") if path.is_dir()}
    # Include old/global and new/per-tool markers, including custom output roots.
    for marker in [bench_dir / LATEST_MARKER_NAME, *sorted(bench_dir.glob(TOOL_MARKER_GLOB))]:
        if marker.is_file():
            value = marker.read_text(encoding="utf-8").strip()
            if not value:
                continue
            path = Path(value).expanduser()
            if not path.is_absolute():
                path = bench_dir / path
            if path.is_dir():
                candidates.add(path.resolve())
    return sorted(candidates)


def run_start_key(results_dir: Path) -> tuple[float, str]:
    """Report writes change directory mtime, so prefer the recorded run start."""
    manifest = read_json_if_exists(results_dir / "run_manifest.json")
    created = manifest.get("created")
    if isinstance(created, str):
        try:
            return datetime.fromisoformat(created).timestamp(), str(results_dir)
        except (ValueError, OverflowError):
            pass
    match = re.search(r"(\d{8}-\d{6}(?:-\d{6})?)$", results_dir.name)
    if match:
        for pattern in ("%Y%m%d-%H%M%S-%f", "%Y%m%d-%H%M%S"):
            try:
                return datetime.strptime(match[1], pattern).timestamp(), str(results_dir)
            except ValueError:
                pass
    # Last resort for old custom names without timestamps: prefer the manifest's
    # mtime, which generating a report does not change, to the directory's mtime.
    manifest_path = results_dir / "run_manifest.json"
    dated_path = manifest_path if manifest_path.is_file() else results_dir
    return dated_path.stat().st_mtime, str(results_dir)


def recorded_tool(results_dir: Path) -> str:
    manifest_path = results_dir / "run_manifest.json"
    manifest = read_json(manifest_path) if manifest_path.is_file() else {}
    if not isinstance(manifest, dict):
        raise SystemExit(f"invalid run manifest: {manifest_path}")
    # A manifest can identify an incomplete run before any profile exists.
    if manifest.get("tool") is not None:
        return infer_tool(manifest)
    # Older sweeps may record the tool only in their job metadata/profiles.
    rows = {}
    for directory in variant_dirs_from_manifest(results_dir).values():
        for job_dir in sorted((results_dir / directory).glob("jobs-*")):
            rows[len(rows)] = {
                "run_info": read_json_if_exists(job_dir / "run_info.json"),
                "summary": read_json_if_exists(job_dir / "reduction_profile.json"),
            }
    return infer_tool(manifest, rows)


def latest_results_by_tool(bench_dir: Path) -> dict[str, Path]:
    latest: dict[str, Path] = {}
    for path in sorted(result_directories(bench_dir), key=run_start_key):
        latest[recorded_tool(path)] = path
    return latest


def latest_results_dir(bench_dir: Path, tool: str | None = None) -> Path:
    if tool is None:
        candidates = result_directories(bench_dir)
        if candidates:
            return max(candidates, key=run_start_key)
    else:
        candidate = latest_results_by_tool(bench_dir).get(tool)
        if candidate is not None:
            return candidate
    raise SystemExit(
        f"no performance result directory found for {bench_dir}"
        + (f" with tool {tool}" if tool else "")
        + ". Run run_harnessreducer_perf_sweep.py first, or pass --results-dir."
    )


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_json_if_exists(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


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


def int_or_none(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def float_or_none(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def count_source_tokens(path: Path) -> int | None:
    """Count source tokens with a lightweight C/C++-like tokenizer.

    This is meant for consistent before/after reduction reporting. It is not a
    full compiler lexer.
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


def source_reduction_metrics(
    original_path: Path,
    reduced_path: Path,
) -> dict[str, object]:
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


def merge_source_reduction_metrics(
    original_path: Path,
    reduced_path: Path,
    recorded: object,
) -> dict[str, object]:
    computed = source_reduction_metrics(original_path, reduced_path)
    if not isinstance(recorded, dict):
        return computed

    original_tokens = int_or_none(recorded.get("original_tokens"))
    final_tokens = int_or_none(recorded.get("final_tokens"))
    reduction_percent = float_or_none(recorded.get("token_reduction_percent"))
    return {
        "token_count_method": str(
            recorded.get("token_count_method", SOURCE_TOKEN_COUNT_METHOD)
        ),
        "original_tokens": (
            original_tokens
            if original_tokens is not None
            else computed["original_tokens"]
        ),
        "final_tokens": (
            final_tokens if final_tokens is not None else computed["final_tokens"]
        ),
        "token_reduction_percent": (
            reduction_percent
            if reduction_percent is not None
            else computed["token_reduction_percent"]
        ),
    }


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


def format_percent(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:,.2f}%"


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


def load_variant(
    results_dir: Path,
    variant_key: str,
    directory: str,
    original_harness_path: Path,
) -> dict[int, dict[str, object]]:
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
        run_info = read_json_if_exists(job_dir / "run_info.json")
        metrics_path = job_dir / "source_reduction_metrics.json"
        metrics_record = read_json_if_exists(metrics_path)
        if not metrics_record:
            metrics_record = run_info.get("source_reduction_metrics", {})
        source_metrics = merge_source_reduction_metrics(
            original_harness_path,
            reduced_path,
            metrics_record,
        )
        rows[jobs] = {
            "job_dir": str(job_dir),
            "summary": summary,
            "full_wall": full_wall,
            "final_size": final_size,
            "run_info": run_info,
            "source_reduction_metrics": source_metrics,
        }
    if not rows:
        raise SystemExit(f"no jobs-* results found in {variant_dir}")
    return rows


def get_reducer(row: dict[str, object]) -> dict[str, object]:
    summary = row["summary"]
    assert isinstance(summary, dict)
    reducer = summary.get("reducer", {})
    return reducer if isinstance(reducer, dict) else {}


def get_source_metrics(row: dict[str, object]) -> dict[str, object]:
    metrics = row.get("source_reduction_metrics", {})
    return metrics if isinstance(metrics, dict) else {}


def main_rows(rows_by_job: dict[int, dict[str, object]]) -> list[list[str]]:
    table_rows: list[list[str]] = []
    for jobs in sorted(rows_by_job):
        row = rows_by_job[jobs]
        reducer = get_reducer(row)
        source_metrics = get_source_metrics(row)
        table_rows.append(
            [
                str(jobs),
                format_float(float(reducer.get("wall_seconds", 0.0)), 3),
                format_float(row.get("full_wall"), 2),  # type: ignore[arg-type]
                format_int(int(reducer.get("profiled_checks", 0))),
                format_float(float(reducer.get("checks_per_second", 0.0)), 3),
                format_int(row.get("final_size")),  # type: ignore[arg-type]
                format_int(int_or_none(source_metrics.get("original_tokens"))),
                format_int(int_or_none(source_metrics.get("final_tokens"))),
                format_percent(
                    float_or_none(source_metrics.get("token_reduction_percent"))
                ),
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


def csv_scalar(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return repr(value)
    return str(value)


def csv_source_metric_values(row: dict[str, object]) -> list[str]:
    reducer = get_reducer(row)
    source_metrics = get_source_metrics(row)
    return [
        csv_scalar(int_or_none(reducer.get("profiled_checks"))),
        csv_scalar(int_or_none(source_metrics.get("original_tokens"))),
        csv_scalar(int_or_none(source_metrics.get("final_tokens"))),
        csv_scalar(float_or_none(source_metrics.get("token_reduction_percent"))),
    ]


def recovery_metadata(row: dict[str, object]) -> dict:
    summary = row.get("summary", {})
    configuration = summary.get("configuration", {}) if isinstance(summary, dict) else {}
    recovery = configuration.get("initializer_recovery", {}) if isinstance(configuration, dict) else {}
    return recovery if isinstance(recovery, dict) else {}


def write_comparison_csv(
    output_path: Path,
    optimized: dict[int, dict[str, object]],
    split_symbolize: dict[int, dict[str, object]],
) -> None:
    """Write three compact rows of metrics for each worker count."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    include_recovery = any(
        recovery_metadata(row) for group in (optimized, split_symbolize) for row in group.values()
    )
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
                "total_checks",
                "original_tokens",
                "final_tokens",
                "token_reduction_percent",
                *(["initializer_recovery", "reduction_attempts"] if include_recovery else []),
            ]
        )
        for jobs in sorted(set(optimized) & set(split_symbolize)):
            metrics = comparison_metric_values(
                optimized[jobs], split_symbolize[jobs]
            )
            for result_type, value_index, row_for_metadata in (
                ("optimized", 2, optimized[jobs]),
                ("non_optimized_split_symbolize", 3, split_symbolize[jobs]),
                ("optimized_speedup_x", 4, None),
            ):
                metadata_values = (
                    ["", "", "", ""]
                    if row_for_metadata is None
                    else csv_source_metric_values(row_for_metadata)
                )
                recovery_values = []
                if include_recovery:
                    metadata = recovery_metadata(row_for_metadata) if row_for_metadata is not None else {}
                    recovery_values = (
                        ["", ""] if row_for_metadata is None
                        else [str(metadata.get("status", "disabled")), str(metadata.get("attempt_count", 1))]
                    )
                writer.writerow(
                    [
                        jobs,
                        result_type,
                        *(
                            "" if metric[value_index] is None else repr(metric[value_index])
                            for metric in metrics
                        ),
                        *metadata_values,
                        *recovery_values,
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


def infer_tool(
    manifest: dict[str, object],
    *variants: dict[int, dict[str, object]],
) -> str:
    """Use recorded engine identities, never silently compare different tools.

    Pre-engine sweep results have no tool field and used treereduce by default.
    Explicit identities from manifests, per-job commands, and profiles must agree.
    This reads metadata only; no engine installation is needed to make tables.
    """
    found: set[str] = set()

    def add(value: object) -> None:
        if value is None:
            return
        if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_-]*", value):
            raise SystemExit(f"invalid recorded tool name: {value!r}")
        found.add(value)

    def inspect(record: object) -> None:
        if not isinstance(record, dict):
            return
        add(record.get("tool"))
        command = record.get("command", [])
        if isinstance(command, list):
            for index, argument in enumerate(command):
                if argument == "--tool":
                    if index + 1 >= len(command):
                        raise SystemExit("recorded command has --tool without a value")
                    add(command[index + 1])
                elif isinstance(argument, str) and argument.startswith("--tool="):
                    add(argument.partition("=")[2])

    inspect(manifest)
    runs = manifest.get("runs", [])
    if isinstance(runs, list):
        for run in runs:
            inspect(run)
    for rows in variants:
        for row in rows.values():
            inspect(row.get("run_info"))
            summary = row.get("summary", {})
            if isinstance(summary, dict):
                configuration = summary.get("configuration", {})
                inspect(configuration)
                if isinstance(configuration, dict):
                    inspect(configuration.get("engine"))
    if len(found) > 1:
        raise SystemExit(
            "conflicting reduction tools in these results: " + ", ".join(sorted(found))
            + ". Select a single-tool sweep using --results-dir."
        )
    return next(iter(found), "treereduce")


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
            "Overrides latest-run selection; without it, select by recorded run start time."
        ),
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--tool", default=None,
        help="Report the latest sweep for this tool; with --results-dir, verify its recorded tool matches.",
    )
    selection.add_argument(
        "--all-tools", action="store_true",
        help="Report only the latest sweep for each tool available for this benchmark.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output TXT path. Default: <results-dir>/performance_tables_<tool>_<dir>.txt.",
    )
    parser.add_argument(
        "--csv-output",
        default=None,
        help="Output CSV path. Default: <results-dir>/performance_comparison_<tool>_<dir>.csv.",
    )
    return parser


def validate_sweep(
    manifest: dict[str, object],
    optimized: dict[int, dict[str, object]],
    split_symbolize: dict[int, dict[str, object]],
) -> None:
    requested_jobs = manifest.get("jobs")
    if isinstance(requested_jobs, list):
        expected = {int(job) for job in requested_jobs}
        if set(optimized) != expected or set(split_symbolize) != expected:
            raise SystemExit("incomplete sweep: not all requested worker counts have both configurations")
    policies = set()
    for rows in (optimized, split_symbolize):
        for row in rows.values():
            recovery = recovery_metadata(row)
            policies.add(bool(recovery))
            if recovery.get("final_validated") is False:
                raise SystemExit(f"unvalidated final output: {row['job_dir']}")
            run_info = row.get("run_info", {})
            for record in (run_info, get_reducer(row)):
                if isinstance(record, dict) and record.get("returncode") not in (None, 0):
                    raise SystemExit(f"failed run: {row['job_dir']}; not reporting it as a successful comparison")
            if manifest.get("status") == "completed" and row.get("final_size") is None:
                raise SystemExit(f"incomplete run: missing reduced.cpp in {row['job_dir']}")
    if len(policies) > 1 or (
        "protect_initializers" in manifest and policies
        and policies != {bool(manifest["protect_initializers"])}
    ):
        raise SystemExit("mixed initializer-recovery policies; compare runs using the same policy")


def write_reports(bench_dir: Path, results_dir: Path, args: argparse.Namespace) -> int:
    if not results_dir.is_dir():
        raise SystemExit(f"results directory not found: {results_dir}")

    manifest = read_json_if_exists(results_dir / "run_manifest.json")
    if manifest.get("status") not in (None, "completed"):
        raise SystemExit(
            f"sweep is not marked completed (status={manifest['status']}): {results_dir}. "
            "No older run has been substituted."
        )
    harness_name = str(manifest.get("harness", "harness.cpp"))
    harness_path = Path(harness_name).expanduser()
    original_harness_path = (
        harness_path.resolve()
        if harness_path.is_absolute()
        else (bench_dir / harness_path).resolve()
    )

    variant_dirs = variant_dirs_from_manifest(results_dir)
    optimized = load_variant(
        results_dir,
        "optimized",
        variant_dirs["optimized"],
        original_harness_path,
    )
    split_symbolize = load_variant(
        results_dir,
        "split_symbolize",
        variant_dirs["split_symbolize"],
        original_harness_path,
    )
    tool = infer_tool(manifest, optimized, split_symbolize)
    if args.tool is not None and args.tool != tool:
        raise SystemExit(f"requested tool {args.tool}, but results record {tool}: {results_dir}")
    validate_sweep(manifest, optimized, split_symbolize)

    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else results_dir / f"performance_tables_{tool}_{bench_dir.name}.txt"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    csv_output_path = (
        Path(args.csv_output).expanduser().resolve()
        if args.csv_output
        else results_dir / f"performance_comparison_{tool}_{bench_dir.name}.csv"
    )

    lines = [
        "HarnessReducer Performance Tables",
        "=================================",
        "",
        f"Generated: {datetime.now().astimezone().isoformat()}",
        f"Benchmark: {bench_dir}",
        f"Tool:      {tool}",
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
        if any(recovery_metadata(row) for row in rows_by_job.values()):
            lines.extend([
                f"{VARIANT_TITLES[key]} - initializer recovery",
                "Reduction times/counts pool all attempts; full command time also includes diagnosis and validation.",
                ascii_table(
                    ["Jobs", "Recovery", "Attempts", "Final validated"],
                    [[str(jobs), str(recovery_metadata(row).get("status", "disabled")),
                      str(recovery_metadata(row).get("attempt_count", 1)),
                      str(recovery_metadata(row).get("final_validated", "unknown"))]
                     for jobs, row in sorted(rows_by_job.items())],
                ),
                "",
            ])
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
                        "Total checks",
                        "Checks/s",
                        "Final size (bytes)",
                        "Original tokens",
                        "Final tokens",
                        "Token reduction",
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


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.all_tools and any((args.results_dir, args.output, args.csv_output)):
        parser.error("--all-tools cannot be combined with --results-dir, --output, or --csv-output")
    if args.tool is not None and not re.fullmatch(r"[a-z][a-z0-9_-]*", args.tool):
        parser.error("invalid --tool name")
    bench_dir = benchmark_dir(args.dir)
    if not args.all_tools:
        results_dir = (
            Path(args.results_dir).expanduser().resolve()
            if args.results_dir else latest_results_dir(bench_dir, args.tool)
        )
        return write_reports(bench_dir, results_dir, args)

    latest = latest_results_by_tool(bench_dir)
    if not latest:
        print(f"No performance sweeps found for {bench_dir}; skipped.")
        return 0
    failed = False
    for tool, results_dir in sorted(latest.items()):
        print(f"Latest {tool}: {results_dir}")
        try:
            write_reports(bench_dir, results_dir, args)
        except (SystemExit, OSError, ValueError) as exc:
            print(f"Report failed for {tool}: {exc}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

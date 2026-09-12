from __future__ import annotations

from collections import Counter
from datetime import datetime
import json
import math
from pathlib import Path
import statistics
from typing import Iterable, Sequence


PROFILE_SCHEMA_VERSION = 1

STAGE_FIELDS: tuple[tuple[str, str], ...] = (
    ("python_import_ns", "Python imports/module setup"),
    ("argument_setup_ns", "Argument parsing/candidate setup"),
    ("compile_ns", "Compile subprocess"),
    ("compile_link_ns", "Direct compile+link subprocess"),
    ("link_ns", "Link subprocess"),
    ("execute_ns", "Candidate execution region"),
    ("oracle_ns", "Crash-oracle checks"),
    ("total_ns", "Tester total before cleanup"),
)

BUILD_SUCCESS_ONLY_STAGE_FIELDS = frozenset({"compile_ns", "compile_link_ns"})


def _percentile(values: Sequence[int], percentile: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _sample_summary(values: Sequence[int]) -> dict[str, int | float]:
    if not values:
        return {
            "count": 0,
            "mean_ns": 0.0,
            "median_ns": 0.0,
            "p95_ns": 0,
            "min_ns": 0,
            "max_ns": 0,
        }
    return {
        "count": len(values),
        "mean_ns": statistics.fmean(values),
        "median_ns": statistics.median(values),
        "p95_ns": _percentile(values, 0.95),
        "min_ns": min(values),
        "max_ns": max(values),
    }


def read_profile_events(path: str | Path) -> tuple[list[dict[str, object]], int]:
    events: list[dict[str, object]] = []
    malformed_lines = 0
    profile_path = Path(path)
    if not profile_path.exists():
        return events, malformed_lines

    for line in profile_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            malformed_lines += 1
            continue
        if isinstance(event, dict):
            events.append(event)
        else:
            malformed_lines += 1
    return events, malformed_lines


def _parallelism(events: Iterable[dict[str, object]], wall_ns: int) -> tuple[float, int]:
    points: list[tuple[int, int]] = []
    accumulated_ns = 0
    for event in events:
        try:
            start_ns = int(event["start_wall_ns"])
            end_ns = int(event["end_wall_ns"])
            total_ns = int(event["durations_ns"]["total_ns"])  # type: ignore[index]
        except (KeyError, TypeError, ValueError):
            continue
        if end_ns < start_ns:
            continue
        accumulated_ns += max(0, total_ns)
        points.append((start_ns, 1))
        points.append((end_ns, -1))

    active = 0
    maximum = 0
    # Process endings before starts at the same instant.
    for _, delta in sorted(points, key=lambda point: (point[0], point[1])):
        active += delta
        maximum = max(maximum, active)

    mean = 0.0 if wall_ns <= 0 else accumulated_ns / wall_ns
    return mean, maximum


def build_profile_summary(
    events: Sequence[dict[str, object]],
    *,
    wall_ns: int,
    jobs: int,
    returncode: int,
    configuration: dict[str, object],
    malformed_lines: int = 0,
) -> dict[str, object]:
    result_counts: Counter[int] = Counter()
    stages: dict[str, list[int]] = {field: [] for field, _ in STAGE_FIELDS}
    source_sizes: list[int] = []
    child_user_ns: list[int] = []
    child_system_ns: list[int] = []

    for event in events:
        try:
            result_counts[int(event["result_code"])] += 1
        except (KeyError, TypeError, ValueError):
            pass

        duration_values = event.get("durations_ns")
        if isinstance(duration_values, dict):
            for field, _ in STAGE_FIELDS:
                if (
                    field in BUILD_SUCCESS_ONLY_STAGE_FIELDS
                    and "compile_success" in event
                    and event.get("compile_success") is not True
                ):
                    continue
                try:
                    value = int(duration_values.get(field, 0))
                except (TypeError, ValueError):
                    continue
                if value > 0:
                    stages[field].append(value)

        try:
            source_sizes.append(int(event["source_bytes"]))
        except (KeyError, TypeError, ValueError):
            pass

        cpu_values = event.get("cpu_ns")
        if isinstance(cpu_values, dict):
            try:
                child_user_ns.append(int(cpu_values.get("children_user_ns", 0)))
                child_system_ns.append(int(cpu_values.get("children_system_ns", 0)))
            except (TypeError, ValueError):
                pass

    attempts = len(events)
    wall_seconds = wall_ns / 1_000_000_000.0
    checks_per_second = 0.0 if wall_ns <= 0 else attempts / wall_seconds
    mean_parallel, max_parallel = _parallelism(events, wall_ns)

    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "generated": datetime.now().astimezone().isoformat(),
        "configuration": configuration,
        "reducer": {
            "returncode": returncode,
            "wall_ns": wall_ns,
            "wall_seconds": wall_seconds,
            "profiled_checks": attempts,
            "checks_per_second": checks_per_second,
            "result_counts": {
                str(code): count for code, count in sorted(result_counts.items())
            },
            "mean_in_flight_checks": mean_parallel,
            "max_in_flight_checks": max_parallel,
            "worker_utilization": 0.0 if jobs <= 0 else mean_parallel / jobs,
            "malformed_event_lines": malformed_lines,
        },
        "candidate_timing": {
            field: _sample_summary(values) for field, values in stages.items()
        },
        "candidate_source_bytes": _sample_summary(source_sizes),
        "child_cpu": {
            "user_ns": _sample_summary(child_user_ns),
            "system_ns": _sample_summary(child_system_ns),
        },
    }


def _ms(value: object) -> str:
    try:
        return f"{float(value) / 1_000_000.0:.3f}"
    except (TypeError, ValueError):
        return "0.000"


def render_profile_text(summary: dict[str, object]) -> str:
    configuration = summary["configuration"]
    reducer = summary["reducer"]
    timing = summary["candidate_timing"]
    assert isinstance(configuration, dict)
    assert isinstance(reducer, dict)
    assert isinstance(timing, dict)

    lines = [
        "HARNESSREDUCER TREE-REDUCTION PROFILE",
        "=====================================",
        "",
        "Reducer throughput",
        "------------------",
        f"tool: {configuration.get('tool', 'treereduce')}",
        f"jobs: {configuration.get('jobs')}",
        f"phase3_mode: {configuration.get('phase3_mode')}",
        f"amortize_link: {configuration.get('amortize_link')}",
        f"symbolize: {configuration.get('symbolize')}",
        f"stable: {configuration.get('stable')}",
        f"wall_seconds: {float(reducer.get('wall_seconds', 0.0)):.6f}",
        f"profiled_checks: {reducer.get('profiled_checks', 0)}",
        f"checks_per_second: {float(reducer.get('checks_per_second', 0.0)):.3f}",
        f"mean_in_flight_checks: {float(reducer.get('mean_in_flight_checks', 0.0)):.3f}",
        f"max_in_flight_checks: {reducer.get('max_in_flight_checks', 0)}",
        f"worker_utilization: {float(reducer.get('worker_utilization', 0.0)):.3f}",
        f"result_counts: {json.dumps(reducer.get('result_counts', {}), sort_keys=True)}",
        f"malformed_event_lines: {reducer.get('malformed_event_lines', 0)}",
        "",
        "Per-check timing",
        "----------------",
        "Stage                               N    Mean ms  Median ms  P95 ms   Min ms   Max ms",
        "----------------------------------  ---  -------  ---------  -------  -------  -------",
    ]
    labels = dict(STAGE_FIELDS)
    for field, _ in STAGE_FIELDS:
        stats = timing.get(field, {})
        assert isinstance(stats, dict)
        lines.append(
            f"{labels[field]:34}  "
            f"{str(stats.get('count', 0)):>3}  "
            f"{_ms(stats.get('mean_ns', 0)):>7}  "
            f"{_ms(stats.get('median_ns', 0)):>9}  "
            f"{_ms(stats.get('p95_ns', 0)):>7}  "
            f"{_ms(stats.get('min_ns', 0)):>7}  "
            f"{_ms(stats.get('max_ns', 0)):>7}"
        )

    lines.extend(
        [
            "",
            "Notes",
            "-----",
            "- Profiled checks include the selected engine's initial verification checks; cached candidates not executed are excluded.",
            "- Reduction wall time includes engine startup and test-adapter overhead; per-check times are measured inside the checker.",
            "- Compile-related rows use only candidates with compile_success=yes when that field is recorded.",
            "- Python startup before the first executed module statement is not observable here.",
            "- Candidate execution can overlap a fallback plugin link when fallback is triggered.",
            "- Profiling appends one small JSON record per check without fsync.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_profile_summary(
    events_path: str | Path,
    json_path: str | Path,
    text_path: str | Path,
    *,
    wall_ns: int,
    jobs: int,
    returncode: int,
    configuration: dict[str, object],
) -> dict[str, object]:
    events, malformed_lines = read_profile_events(events_path)
    summary = build_profile_summary(
        events,
        wall_ns=wall_ns,
        jobs=jobs,
        returncode=returncode,
        configuration=configuration,
        malformed_lines=malformed_lines,
    )
    Path(json_path).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(text_path).write_text(render_profile_text(summary), encoding="utf-8")
    return summary

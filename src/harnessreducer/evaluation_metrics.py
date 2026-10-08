"""Measurements shared by the evaluation runner and batch report generator."""
from __future__ import annotations

import json
import math
from pathlib import Path
import re

EVALUATION_FORMAT = "harnessreducer-evaluation-v1"
MEASUREMENT_STAGE = "raw_reducer_output"
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


def count_source_tokens(path: Path) -> int | None:
    """Count the file text, without expanding or normalizing any includes."""
    if not path.is_file():
        return None
    return sum(
        1 for match in SOURCE_TOKEN_RE.finditer(path.read_text(encoding="utf-8", errors="replace"))
        if not match.group(0).startswith(("//", "/*"))
    )


def token_reduction_percent(original: int | None, remaining: int | None) -> float | None:
    if original is None or remaining is None or original <= 0:
        return None
    return 100.0 * (1.0 - remaining / original)


def source_metrics(original: Path, raw: Path, final: Path) -> dict:
    original_tokens = count_source_tokens(original)
    remaining_tokens = count_source_tokens(raw)
    return {
        "measurement_stage": MEASUREMENT_STAGE,
        "token_count_method": SOURCE_TOKEN_COUNT_METHOD,
        "original_tokens": original_tokens,
        "remaining_tokens": remaining_tokens,
        "token_reduction_percent": token_reduction_percent(original_tokens, remaining_tokens),
        "final_output_bytes": final.stat().st_size if final.is_file() else None,
    }


def read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return data


def write_json(path: Path, data: dict) -> None:
    # Readers can regenerate a partial report even while the batch is running.
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def artifact_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if Path(relative).is_absolute() or not path.is_relative_to(root.resolve()):
        raise ValueError(f"Artifact is outside the evaluation batch: {relative}")
    return path


def finite_number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def measure_run(root: Path, run: dict) -> tuple[dict, list[str]]:
    """Read only this run's manifest-listed artifacts; never use cached counts."""
    paths = {key: artifact_path(root, run[key]) for key in (
        "original_source", "raw_reduced_harness", "output", "profile",
    )}
    metrics = source_metrics(paths["original_source"], paths["raw_reduced_harness"], paths["output"])
    errors = [f"Missing {key}: {path}" for key, path in paths.items() if not path.is_file()]
    if not paths["profile"].is_file():
        return metrics, errors
    try:
        summary = read_json(paths["profile"])
        reducer = summary["reducer"]
        config = summary["configuration"]
        recovery = config["initializer_recovery"]
        if config["tool"] != run["tool"]:
            errors.append("Profile tool differs from manifest tool")
        if recovery.get("final_validated") is not True:
            errors.append("Initializer recovery did not produce a validated final result")
        wall = finite_number(reducer.get("wall_seconds"))
        checks = reducer.get("profiled_checks")
        if wall is None or wall < 0 or type(checks) is not int or checks < 0:
            raise ValueError("Missing or invalid reduction wall time / check count")
        metrics.update({
            "reduction_wall_seconds": wall,
            "total_checks": checks,
            "checks_per_second": checks / wall if wall > 0 else None,
            "mean_in_flight_checks": finite_number(reducer.get("mean_in_flight_checks")),
            "worker_utilization": finite_number(reducer.get("worker_utilization")),
            "initializer_recovery": recovery.get("status"),
            "initializer_recovery_metadata": json.dumps(recovery, sort_keys=True),
            "reduction_attempts": recovery.get("attempt_count"),
            "final_validated": recovery.get("final_validated"),
            "checker_outcomes": json.dumps(reducer.get("result_counts", {}), sort_keys=True),
        })
        counts = reducer.get("result_counts", {})
        for key, code in (("interesting_checks", "77"), ("uninteresting_checks", "1"), ("invalid_checks", "-1")):
            metrics[key] = counts.get(code, 0)
        for name, field in (
            ("python_setup_milliseconds", "python_import_ns"),
            ("compile_milliseconds", "compile_ns"),
            ("link_milliseconds", "link_ns"),
            ("execute_milliseconds", "execute_ns"),
            ("total_per_check_milliseconds", "total_ns"),
        ):
            mean = finite_number(summary.get("candidate_timing", {}).get(field, {}).get("mean_ns"))
            metrics[name] = mean / 1_000_000 if mean is not None else None
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        errors.append(f"Invalid profile: {exc}")
    return metrics, errors

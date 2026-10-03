"""Rebuild replay and one-way oracle reports from selected experiment runs."""
from __future__ import annotations

from pathlib import Path

from harnessreducer.evaluation_common import (
    EXPERIMENT_FORMAT, atomic_text, case_key, collection_lock, mean, percent,
    read_json, read_jsonl, relative, selected_runs, write_csv, write_json,
)
from harnessreducer.evaluation_metrics import (
    MEASUREMENT_STAGE, SOURCE_TOKEN_COUNT_METHOD, artifact_path,
    count_source_tokens, token_reduction_percent,
)
from harnessreducer.evaluation_source import count_calls
from harnessreducer.oracle_evaluation import (
    CATEGORIES, classify_query, process_observations, query_categories,
)

REPLAY_CONFIGS = ("with_replay", "without_replay")
REPLAY_CASE_FIELDS = ("dataset", "case", "run_id", "status", "uses_fdp", "measurement_stage", "original_tokens", "original_fdp_calls",
    "with_replay_valid", "with_replay_status", "with_replay_reason", "with_replay_remaining_tokens",
    "with_replay_remaining_fdp_calls", "with_replay_token_reduction_percent", "with_replay_final_output_bytes",
    "without_replay_valid", "without_replay_status", "without_replay_reason", "without_replay_remaining_tokens",
    "without_replay_remaining_fdp_calls", "without_replay_token_reduction_percent", "without_replay_final_output_bytes",
    "token_delta", "token_relation", "fdp_call_delta", "fdp_call_relation")
REPLAY_SUMMARY_FIELDS = ("configuration", "case_count", "mean_original_tokens", "mean_remaining_tokens",
    "mean_token_reduction_percent", "mean_original_fdp_calls", "mean_remaining_fdp_calls", "measurement_stage")
ORACLE_CASE_FIELDS = ("dataset", "case", "run_id", "run_status", "final_validation_passed", "measurement_errors",
    "fs_compared_queries", "fs_agree_queries", "fs_disagree_queries", "fs_agreement_percent",
    "ds_compared_queries", "ds_agree_queries", "ds_disagree_queries", "ds_agreement_percent")
ORACLE_SUMMARY_FIELDS = ("case_count", "fs_compared_queries", "fs_agree_queries", "fs_disagree_queries",
    "mean_fs_agreement_percent", "pooled_fs_agreement_percent", "ds_compared_queries", "ds_agree_queries",
    "ds_disagree_queries", "mean_ds_agreement_percent", "pooled_ds_agreement_percent")


def _required_files(run, manifest, config):
    errors = []
    for name in ("reference/original.cpp", "reference/crash-input", "reference/build.json",
                 config.get("output"), config.get("command"), *config.get("generated_headers", [])):
        if not name:
            errors.append("Missing artifact path in manifest")
        elif not artifact_path(run, name).is_file():
            errors.append(f"Missing artifact: {name}")
    return errors


def replay_measurements(run: Path, manifest: dict, configuration: str):
    config = manifest.get("configurations", {}).get(configuration, {})
    errors = _required_files(run, manifest, config)
    raw_name = config.get("raw_reduced_harness")
    # Missing paths are errors, never a request to discover another source.
    raw = artifact_path(run, raw_name) if raw_name else None
    final = artifact_path(run, config["output"]) if config.get("output") else None
    original = run / "reference" / "original.cpp"
    original_tokens = count_source_tokens(original)
    remaining_tokens = count_source_tokens(raw) if raw is not None else None
    measurements = {"original_tokens": original_tokens, "remaining_tokens": remaining_tokens,
        "token_reduction_percent": token_reduction_percent(original_tokens, remaining_tokens),
        "final_output_bytes": final.stat().st_size if final is not None and final.is_file() else None,
        "measurement_stage": MEASUREMENT_STAGE}
    if raw is None or not raw.is_file():
        errors.append("Missing selected raw reducer output")
    if manifest["settings"].get("measurement_stage") != MEASUREMENT_STAGE:
        errors.append("Unexpected token measurement stage")
    if not measurements["original_tokens"]:
        errors.append("Original source tokens unavailable or empty")
    for name, path in (("original_fdp_calls", original), ("remaining_fdp_calls", raw)):
        measurements[name] = None
        if path is not None and path.is_file():
            try:
                measurements[name] = count_calls(path.read_text(encoding="utf-8", errors="replace"))
            except ValueError as exc:
                errors.append(f"{name}: {exc}")
    passed = config.get("final_validation_passed") is True
    if not passed:
        errors.append("Final pipeline validation did not pass")
    measurements.update(final_validation_passed=passed, raw_reduced_harness=raw_name,
                        token_count_method=SOURCE_TOKEN_COUNT_METHOD, errors=errors)
    return measurements


def _selection_manifest(destination, experiment, selections):
    write_json(destination / "collection_manifest.json", {"format": EXPERIMENT_FORMAT, "experiment": experiment,
        "selected_runs": {case_key(m["dataset"], m["case"]): m["run_id"] for _, m in selections},
        "publication": "Atomic file replacement under .collection.lock; read under that lock for a consistent snapshot."})


def _destination(root, case, selections):
    return root if case is None else selections[0][0].parents[1] / "reports"


def collect_replay(root: Path, case: str | None = None):
    with collection_lock(root):
        selections = list(selected_runs(root, case))
        cases, configuration_rows = [], {}
        for run, manifest in selections:
            if manifest["experiment"] != "replay":
                raise ValueError(f"Not a replay run: {run}")
            rows = []
            for config in REPLAY_CONFIGS:
                metrics = replay_measurements(run, manifest, config)
                recorded = manifest.get("configurations", {}).get(config, {})
                status = recorded.get("status", "not_started")
                if status == "completed" and metrics["errors"]:
                    status = "incomplete"
                row = {**metrics, "dataset": manifest["dataset"], "case": manifest["case"],
                    "run_id": manifest["run_id"], "configuration": config, "status": status,
                    "reason": "; ".join(dict.fromkeys([*metrics["errors"], *([recorded["reason"]] if recorded.get("reason") else [])])),
                    "artifact_dir": relative(run / config, root)}
                rows.append(row)
            original_calls = rows[0]["original_fdp_calls"]
            item = {"dataset": manifest["dataset"], "case": manifest["case"], "run_id": manifest["run_id"],
                "status": manifest["status"], "uses_fdp": original_calls > 0 if original_calls is not None else None,
                "original_tokens": rows[0]["original_tokens"], "original_fdp_calls": original_calls,
                "measurement_stage": MEASUREMENT_STAGE}
            for config, row in zip(REPLAY_CONFIGS, rows):
                item[f"{config}_valid"] = manifest["status"] != "running" and row["status"] == "completed" and not row["errors"]
                for field in ("remaining_tokens", "remaining_fdp_calls", "token_reduction_percent", "final_output_bytes", "status", "reason"):
                    item[f"{config}_{field}"] = row[field]
            paired = all(item[f"{config}_valid"] for config in REPLAY_CONFIGS)
            for field, stem in (("remaining_tokens", "token"), ("remaining_fdp_calls", "fdp_call")):
                delta = rows[0][field] - rows[1][field] if paired else None
                item[f"{stem}_delta"] = delta
                item[f"{stem}_relation"] = "unavailable" if delta is None else "smaller" if delta < 0 else "larger" if delta > 0 else "equal"
            cases.append(item)
            configuration_rows[case_key(item["dataset"], item["case"])] = rows
        destination = _destination(root, case, selections)
        summary = []
        for index, config in enumerate(REPLAY_CONFIGS):
            rows = [configuration_rows[case_key(c["dataset"], c["case"])][index]
                    for c in cases if c["uses_fdp"] and c[f"{config}_valid"]]
            summary.append({"configuration": config, "case_count": len(rows), "measurement_stage": MEASUREMENT_STAGE, **{
                "mean_" + field: mean([r[field] for r in rows]) for field in (
                    "original_tokens", "remaining_tokens", "token_reduction_percent", "original_fdp_calls", "remaining_fdp_calls")}})
        write_csv(destination / "cases.csv", cases, REPLAY_CASE_FIELDS)
        write_csv(destination / "successful_cases.csv", [c for c in cases if c["with_replay_valid"]], REPLAY_CASE_FIELDS)
        write_csv(destination / "summary.csv", summary, REPLAY_SUMMARY_FIELDS)
        for metric, stem in (("tokens", "token"), ("fdp_calls", "fdp_call")):
            for relation in ("smaller", "equal", "larger"):
                names = sorted(case_key(c["dataset"], c["case"]) for c in cases if c[f"{stem}_relation"] == relation)
                atomic_text(destination / f"{metric}_{relation}.txt", "".join(n + "\n" for n in names))
        _selection_manifest(destination, "replay", selections)
        return bool(cases) and all(c["status"] == "completed" and all(c[f"{config}_valid"] for config in REPLAY_CONFIGS) for c in cases)


def oracle_artifact_errors(run: Path, manifest: dict):
    config = manifest.get("configurations", {}).get("oracle", {})
    errors = _required_files(run, manifest, config)
    required = ["reference/runs.csv", "reference/traces.json", "reduction_completed.json", "final/validation.json", "summary.json"]
    if manifest["settings"]["symbolized_comparison"] == "paired-execution":
        required.append("paired_execution.json")
    for name in required:
        if not (run / name).is_file():
            errors.append(f"Missing artifact: {name}")
    references = read_json(run / "reference" / "traces.json", {})
    if not references.get("frozen") or not references.get("usable_symbolized_samples"):
        errors.append("No usable frozen symbolized reference")
    summary = read_json(run / "summary.json", {})
    starts = list((run / "observations").glob("query-*/started.json"))
    results = list((run / "observations").glob("query-*/result.json"))
    if not starts or not summary.get("total_queries"):
        errors.append("No recorded oracle queries")
    if len(results) != summary.get("total_queries") or len(results) != len(starts):
        errors.append("Oracle query artifacts are incomplete")
    if summary.get("incomplete_queries") or summary.get("observer_errors"):
        errors.append("Incomplete oracle observations")
    for started in starts:
        if not (started.parent / "result.json").is_file():
            errors.append(f"Missing query result: {started.parent.name}")
    if manifest.get("final_validation_passed") is not True:
        errors.append("Final pipeline validation did not pass")
    return errors


def oracle_case(root, run, manifest):
    if manifest["experiment"] != "oracle":
        raise ValueError(f"Not an oracle run: {run}")
    with collection_lock(run / "observations"):
        process_observations(run)
    queries = []
    for path in sorted((run / "observations").glob("query-*/result.json")):
        query = read_json(path)
        before = dict(query)
        classify_query(query)
        if before != query:
            write_json(path, query)
        queries.append(query)
    for started in sorted((run / "observations").glob("query-*/started.json")):
        if (started.parent / "result.json").exists():
            continue
        record = read_json(started)
        queries.append(classify_query({"dataset": manifest["dataset"], "case": manifest["case"], "run_id": manifest["run_id"],
            "query_id": record["query_id"], "candidate_hash": record["candidate_hash"], "build_status": "unknown",
            "execution_status": "unknown", "query_status": "incomplete", "d_verdict": "unavailable",
            "f_verdict": "unavailable", "s_verdict": "unavailable", "attempts": [], "artifact_dir": ""}))
    queries.sort(key=lambda q: q["query_id"])
    refs = read_json(run / "reference" / "traces.json", {})
    modes = sorted({q["fast_oracle_mode"] for q in queries if q.get("fast_oracle_mode")})
    summary = {"dataset": manifest["dataset"], "case": manifest["case"], "run_id": manifest["run_id"],
        "run_status": manifest["status"], "reduction_completed": manifest.get("reduction_completed", False),
        "final_validation_passed": manifest.get("final_validation_passed"), "artifact_dir": relative(run, root),
        "fast_oracle_mode": modes[0] if len(modes) == 1 else "mixed" if modes else "unavailable",
        "strict_depth_configured": refs.get("strict_depth_configured"), "planned_symbolized_samples": 20,
        "usable_symbolized_samples": refs.get("usable_symbolized_samples", 0), "unique_reference_traces": len(refs.get("traces", [])),
        "total_queries": len(queries), "build_rejected_queries": sum(q["build_status"] == "rejected" for q in queries),
        "incomplete_queries": sum(q["query_status"] != "completed" for q in queries),
        "execution_error_queries": sum(any(a["returncode"] in (None, 125) for a in q["attempts"]) or q.get("fast_reject_reason") == "execution_error" for q in queries),
        "timeout_queries": sum(any(a["returncode"] == 124 for a in q["attempts"]) for q in queries),
        "unavailable_s_queries": sum(q["s_verdict"] == "unavailable" for q in queries),
        "unavailable_d_queries": sum(q["d_verdict"] == "unavailable" for q in queries),
        "observer_errors": len(read_jsonl(run / "observer-errors.jsonl")),
        **{f"{c}_queries": sum(c in query_categories(q) for q in queries) for c in CATEGORIES}}
    for stem in ("fs", "ds"):
        agree = sum(q[f"{stem}_outcome"] == "agreement" for q in queries)
        disagree = sum(q[f"{stem}_outcome"] == "disagreement" for q in queries)
        summary.update({f"{stem}_compared_queries": agree + disagree, f"{stem}_agree_queries": agree,
                        f"{stem}_disagree_queries": disagree, f"{stem}_agreement_percent": percent(agree, agree + disagree)})
    write_json(run / "summary.json", summary)
    summary["measurement_errors"] = "; ".join(oracle_artifact_errors(run, manifest))
    write_json(run / "summary.json", summary)
    return summary, queries


def collect_oracle(root: Path, case: str | None = None):
    # Process queries without holding the batch publication lock while cases run.
    for run, manifest in list(selected_runs(root, case)):
        oracle_case(root, run, manifest)
    with collection_lock(root):
        selections = list(selected_runs(root, case))
        cases, queries = [], []
        for run, manifest in selections:
            item = read_json(run / "summary.json")
            if item is None:
                # A newly selected concurrent attempt has not been collected yet.
                item, _ = oracle_case(root, run, manifest)
            cases.append(item)
            queries.extend(read_json(p) for p in sorted((run / "observations").glob("query-*/result.json")))
        destination = _destination(root, case, selections)
        sums = {name: sum(c[name] for c in cases) for name in (
            "fs_compared_queries", "fs_agree_queries", "fs_disagree_queries",
            "ds_compared_queries", "ds_agree_queries", "ds_disagree_queries")}
        summary = [{"case_count": len(cases), **sums,
            "mean_fs_agreement_percent": mean([c["fs_agreement_percent"] for c in cases]),
            "pooled_fs_agreement_percent": percent(sums["fs_agree_queries"], sums["fs_compared_queries"]),
            "mean_ds_agreement_percent": mean([c["ds_agreement_percent"] for c in cases]),
            "pooled_ds_agreement_percent": percent(sums["ds_agree_queries"], sums["ds_compared_queries"])}]
        write_csv(destination / "cases.csv", cases, ORACLE_CASE_FIELDS)
        write_csv(destination / "summary.csv", summary, ORACLE_SUMMARY_FIELDS)
        for category in CATEGORIES:
            names = sorted({case_key(q["dataset"], q["case"]) for q in queries if category in query_categories(q)})
            atomic_text(destination / f"{category}.txt", "".join(name + "\n" for name in names))
        _selection_manifest(destination, "oracle", selections)
        return bool(cases) and all(c["run_status"] == "completed" and not c["measurement_errors"] for c in cases)

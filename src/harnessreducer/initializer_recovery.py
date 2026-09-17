"""Bounded, opt-in recovery around whole reduction attempts, never candidates."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from harnessreducer.initializer_analysis import analyze_uninitialized
from harnessreducer.initializer_protection import (
    prepare_initializer_protection, preparation_compile_flags, verify_preparation,
)
from harnessreducer.reduction_profile import combine_attempt_profiles
from harnessreducer.reducer_runner import get_work_dir, isolated_attempt_work_dir, reset_poc_runtime_args


_PROFILE_FILES = ("candidate_profile.jsonl", "reduction_profile.json", "reduction_profile.txt")
_REFERENCE_FILES = (
    "poc.out", "stack_trace.pattern", "crash_pattern.symbolize0", "crash_pattern.symbolize1",
    "dynamic_crash_site.json", "symbolized_crash_location.pattern",
    "check_reference.json",
)


def _merge_statistics(attempts: list[dict], root: Path) -> None:
    from harnessreducer.reducer_runner import _format_statistics_text
    counts = {"count_77": 0, "count_1": 0, "count_-1": 0}
    found = False
    for attempt in attempts:
        path = Path(attempt["directory"]) / "statistics.txt"
        if not path.is_file():
            continue
        found = True
        for line in path.read_text().splitlines():
            key, _, value = line.partition(":")
            if key in counts:
                counts[key] += int(value.strip())
    if found:
        (root / "statistics.txt").write_text(_format_statistics_text(*counts.values()))


def _merge_check_statistics(attempts: list[dict], root: Path) -> None:
    from harnessreducer.check_mode import read_check_statistics, _format_check_statistics_text
    paths = [Path(a["directory"]) / "check_statistics.txt" for a in attempts]
    stats = [read_check_statistics(str(path)) for path in paths if path.is_file()]
    if stats:
        (root / "check_statistics.txt").write_text(_format_check_statistics_text(
            sum(item.level_same for item in stats), sum(item.stack_same for item in stats),
        ))


def reduce_with_initializer_recovery(
    attempt, tagged_source: str, compile_flags: str | None, *,
    replay: bool, plugin: bool, profile: bool, statistics: bool, jobs: int,
):
    """Run normally, diagnose only an unvalidated result, retry no more than once."""
    root = Path(get_work_dir()).resolve()
    metadata = {
        "policy": "on-validation-failure-v1", "status": "normal",
        "triggered": False, "attempt_count": 1, "diagnosis_ns": 0,
        "final_validated": False,
    }
    attempts = []
    original_source = str(Path(tagged_source).resolve())
    first = attempt(original_source, compile_flags)
    metadata["final_validated"] = bool(getattr(first, "validated", True))
    if metadata["final_validated"]:
        # No analyzer, source parsing, or attempt-directory work on success.
        metadata["status"] = "not-needed"
        if profile:
            summary_path = root / "reduction_profile.json"
            if summary_path.is_file():
                from harnessreducer.reduction_profile import render_profile_text
                summary = json.loads(summary_path.read_text())
                summary["configuration"]["initializer_recovery"] = metadata
                summary_path.write_text(json.dumps(summary, indent=2) + "\n")
                (root / "reduction_profile.txt").write_text(render_profile_text(summary))
        (root / "initializer_recovery.json").write_text(json.dumps(metadata, indent=2) + "\n")
        return first

    # The normal attempt retains its original paths. Archive its reports before
    # replacing the top-level reports with aggregate data.
    recovery_root = Path(tempfile.mkdtemp(prefix="initializer-recovery-", dir=root))
    normal = recovery_root / "attempt-1-normal"
    normal.mkdir()
    for name in (*_PROFILE_FILES, "statistics.txt", "check_statistics.txt", "reduction_engine.json"):
        source = root / name
        if source.is_file():
            shutil.copy2(source, normal / name)
    attempts.append({"directory": str(normal), "mode": "normal", "validated": False, "output": first[0]})
    result = first
    try:
        if getattr(first, "stage", "") == "missing-input":
            metadata["status"] = "missing-input"
            return first
        print("[+] Diagnosing unsuccessful final validation for uninitialized uses (once).")
        diagnosis = analyze_uninitialized(first[0], recovery_root / "diagnosis", compile_flags)
        metadata["diagnosis"] = asdict(diagnosis)
        metadata["diagnosis_ns"] = diagnosis.wall_ns
        if diagnosis.status != "uninitialized-use":
            metadata["status"] = diagnosis.status
            print(f"[!] No protected retry: {diagnosis.status}. Diagnosis: {diagnosis.log}")
            return first
        protected_dir = recovery_root / "attempt-2-protected"
        protected_dir.mkdir()
        protection = prepare_initializer_protection(Path(original_source), protected_dir)
        metadata["protection"] = protection.metadata()
        if not protection.declarations:
            metadata["status"] = "no-supported-initializers"
            print("[!] No supported original initialized declarations; protected retry was not started.")
            return first
        for name in _REFERENCE_FILES:
            source = root / name
            if source.is_file():
                shutil.copy2(source, protected_dir / name)
        with preparation_compile_flags(compile_flags, Path(original_source), protected_dir) as prepared_flags:
            check_started = time.perf_counter_ns()
            verify_preparation(protection, prepared_flags, replay=replay, plugin=plugin)
            metadata["preparation_check_ns"] = time.perf_counter_ns() - check_started
            metadata["compile_flags_response_file"] = str(protected_dir / "compile_flags.rsp")
            metadata.update(triggered=True, attempt_count=2, status="retrying")
            print(
                f"[+] Retrying the same engine from the original tagged source with "
                f"{len(protection.declarations)} protected declarations "
                f"({len(protection.skipped)} unsupported declarations skipped)."
            )
            attempts.append({"directory": str(protected_dir), "mode": "protected", "validated": False})
            with isolated_attempt_work_dir(protected_dir):
                reset_poc_runtime_args()
                result = attempt(str(protection.source), prepared_flags, protection)
        validated = bool(getattr(result, "validated", True))
        attempts[-1].update(validated=validated, output=result[0])
        metadata["final_validated"] = validated
        metadata["status"] = "recovered" if validated else "retry-validation-failed"
        return result
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        # Keep diagnostic artifacts but never publish this unvalidated result as
        # successful. No recursive retry and no weaker oracle.
        metadata["status"] = "recovery-error"
        metadata["error"] = str(exc)
        print(f"[-] Initializer recovery did not complete: {exc}")
        return first
    finally:
        metadata["attempts"] = attempts
        (root / "initializer_recovery.json").write_text(json.dumps(metadata, indent=2) + "\n")
        if profile:
            combine_attempt_profiles(attempts, root, metadata, jobs=jobs)
        if statistics:
            _merge_statistics(attempts, root)
        _merge_check_statistics(attempts, root)

#!/usr/bin/env bash
# Usage: bash run_crash_triage_parallel_hku.sh [jobs=4] [--resume] [--dry-run]
set -euo pipefail

# Change this to low, high, or max; it overrides the Python default.
export HR_TRIAGE_REASONING_EFFORT=high
# Run these tools sequentially for each benchmark.
export HR_TRIAGE_TOOLS="none treereduce cdd wdd perses"

HR_TRIAGE_JOBS=${1:-4}
if [[ $# -gt 0 ]]; then shift; fi
export HR_TRIAGE_DRY_RUN=
export HR_TRIAGE_RESUME=0
hr_usage() {
    printf 'Usage: bash run_crash_triage_parallel_hku.sh [positive job count] [--resume] [--dry-run]\n' >&2
}
if [[ ! "$HR_TRIAGE_JOBS" =~ ^[1-9][0-9]*$ ]]; then
    hr_usage
    exit 2
fi
for option in "$@"; do
    case "$option" in
        --dry-run) export HR_TRIAGE_DRY_RUN=--dry-run ;;
        --resume) export HR_TRIAGE_RESUME=1 ;;
        *) hr_usage; exit 2 ;;
    esac
done

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
export HR_TRIAGE_CSV=${HR_TRIAGE_CSV:-crash_triage_results_new_hku_5.3${HR_TRIAGE_REASONING_EFFORT}.csv}
export HR_TRIAGE_LOG_DIR=${HR_TRIAGE_LOG_DIR:-triage-logs-hku-${HR_TRIAGE_REASONING_EFFORT}/$(date +%Y%m%d-%H%M%S)-$$}

hr_emit_cases() {
    python3 - <<'PY'
import csv
import fcntl
import os
from pathlib import Path
import sys

with open("harness_bug_cases.tsv", newline="", encoding="utf-8") as handle:
    cases = list(csv.DictReader(handle, delimiter="\t"))
tools = os.environ["HR_TRIAGE_TOOLS"].split()
completed = set()
if os.environ["HR_TRIAGE_RESUME"] == "1":
    csv_path = Path(os.environ["HR_TRIAGE_CSV"]).expanduser()
    try:
        handle = csv_path.open(newline="", encoding="utf-8")
    except FileNotFoundError:
        pass
    else:
        with handle:
            # Coordinate with the exclusive lock used when results are appended.
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            reader = csv.DictReader(handle)
            if reader.fieldnames is not None and not {
                "dir", "tool", "triage result"
            }.issubset(reader.fieldnames):
                raise SystemExit(f"Cannot resume: unexpected CSV header in {csv_path}")
            completed = {
                (row["dir"], row["tool"])
                for row in reader
                if row.get("triage result") in {"library-bug", "harness-bug"}
            }

arguments = []
skipped = remaining = 0
for case in cases:
    pending = [tool for tool in tools if (case["benchmark"], tool) not in completed]
    skipped += len(tools) - len(pending)
    remaining += len(pending)
    if pending:
        arguments.extend(case[column] for column in ("benchmark", "compile_flags", "link_flags"))
        arguments.append(" ".join(pending))
if os.environ["HR_TRIAGE_RESUME"] == "1":
    print(
        f"[RESUME] Skipping {skipped} completed example/tool pairs; "
        f"{remaining} pairs remain. CSV: {csv_path}",
        file=sys.stderr,
    )
sys.stdout.buffer.write(b"".join(value.encode("utf-8") + b"\0" for value in arguments))
PY
}

hr_run_case() {
    local benchmark=$1 compile_flags=$2 link_flags=$3
    local tool log quoted exit_status result=0
    local -a command pending_tools
    read -r -a pending_tools <<< "$4"
    # Keep the two tools for a benchmark sequential: both harnesses use the
    # same benchmark working directory. Different benchmarks run in parallel.
    for tool in "${pending_tools[@]}"; do
        command=(
            python3 -u crash_triage_new_hku.py
            --tool "$tool" --dir "$benchmark"
            "--compile-flags=$compile_flags" "--link-flags=$link_flags"
            --csv "$HR_TRIAGE_CSV" --llm-reasoning-effort "$HR_TRIAGE_REASONING_EFFORT"
        )
        if [[ "$HR_TRIAGE_DRY_RUN" == --dry-run ]]; then
            printf -v quoted '%q ' "${command[@]}"
            printf '%s\n' "$quoted"
            continue
        fi
        log="$HR_TRIAGE_LOG_DIR/$tool-$benchmark.log"
        printf '[START] %s / %s\n' "$benchmark" "$tool"
        if "${command[@]}" >"$log" 2>&1; then
            printf '[DONE]  %s / %s\n' "$benchmark" "$tool"
        else
            exit_status=$?
            printf '[FAIL]  %s / %s (exit %s); see %s\n' \
                "$benchmark" "$tool" "$exit_status" "$log" >&2
            result=1
        fi
    done
    return "$result"
}
export -f hr_run_case

if [[ "$HR_TRIAGE_DRY_RUN" != --dry-run ]]; then
    mkdir -p -- "$HR_TRIAGE_LOG_DIR"
    printf 'Concurrent benchmarks: %s\nReasoning effort: %s\nCSV: %s\nLogs: %s\n' \
        "$HR_TRIAGE_JOBS" "$HR_TRIAGE_REASONING_EFFORT" "$HR_TRIAGE_CSV" "$HR_TRIAGE_LOG_DIR"
fi

# Continue independent cases after a failed job; xargs returns a nonzero batch
# status if any worker fails. NUL-separated arguments preserve literal $(pwd).
hr_emit_cases | xargs -0 -r -n 4 -P "$HR_TRIAGE_JOBS" bash -c 'hr_run_case "$@"' hr-triage

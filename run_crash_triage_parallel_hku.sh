#!/usr/bin/env bash
# Usage: bash run_crash_triage_parallel_hku.sh [jobs=4] [--dry-run]
set -euo pipefail

# Change this to low, high, or max; it overrides the Python default.
export HR_TRIAGE_REASONING_EFFORT=high

HR_TRIAGE_JOBS=${1:-4}
export HR_TRIAGE_DRY_RUN=${2:-}
if [[ $# -gt 2 || ! "$HR_TRIAGE_JOBS" =~ ^[1-9][0-9]*$ ||
      ( -n "$HR_TRIAGE_DRY_RUN" && "$HR_TRIAGE_DRY_RUN" != --dry-run ) ]]; then
    printf 'Usage: bash run_crash_triage_parallel_hku.sh [positive job count] [--dry-run]\n' >&2
    exit 2
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
export HR_TRIAGE_CSV=${HR_TRIAGE_CSV:-crash_triage_results_new_hku_5.3${HR_TRIAGE_REASONING_EFFORT}.csv}
export HR_TRIAGE_LOG_DIR=${HR_TRIAGE_LOG_DIR:-triage-logs-hku-${HR_TRIAGE_REASONING_EFFORT}/$(date +%Y%m%d-%H%M%S)-$$}

hr_emit_cases() {
    python3 - <<'PY'
import csv
import sys

with open("crash_triage_cases.tsv", newline="", encoding="utf-8") as handle:
    cases = list(csv.DictReader(handle, delimiter="\t"))
arguments = [
    case[column]
    for case in cases
    for column in ("benchmark", "compile_flags", "link_flags")
]
sys.stdout.buffer.write(b"".join(value.encode("utf-8") + b"\0" for value in arguments))
PY
}

hr_run_case() {
    local benchmark=$1 compile_flags=$2 link_flags=$3
    local tool log quoted exit_status result=0
    local -a command
    # Keep the two tools for a benchmark sequential: both harnesses use the
    # same benchmark working directory. Different benchmarks run in parallel.
    for tool in none treereduce; do
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
hr_emit_cases | xargs -0 -r -n 3 -P "$HR_TRIAGE_JOBS" bash -c 'hr_run_case "$@"' hr-triage

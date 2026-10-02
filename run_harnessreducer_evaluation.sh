#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${HARNESSREDUCER_PYTHON:-}" ]]; then
    evaluation_python="$HARNESSREDUCER_PYTHON"
elif [[ -x "$repo_dir/.venv/bin/python" ]]; then
    evaluation_python="$repo_dir/.venv/bin/python"
elif [[ -x "$repo_dir/.venv-host/bin/python" ]]; then
    evaluation_python="$repo_dir/.venv-host/bin/python"
else
    evaluation_python=python3
fi
exec "$evaluation_python" "$repo_dir/run_harnessreducer_perf_sweep.py" "$@"

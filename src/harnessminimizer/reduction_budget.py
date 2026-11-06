"""Bound tree reduction while leaving time to finalize and validate its result."""

from __future__ import annotations

import math
import os
from pathlib import Path
import shutil
import subprocess
import time

from harnessminimizer.process_supervisor import run_supervised


CHECKPOINT_WINDOW_SECONDS = 4 * 60
CHECKPOINT_START_ENV = "HARNESSMINIMIZER_CHECKPOINT_START_MONOTONIC"


def run_bounded_reduction(
    command: list[str], output: str, timeout_seconds: float, snapshot: str,
    *, env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Reduction timeout must be finite and positive.")
    candidate = Path(output)
    # A previous invocation's output cannot qualify as this run's progress.
    candidate.unlink(missing_ok=True)
    checkpoint = Path(snapshot)
    checkpoint.unlink(missing_ok=True)
    # All tester processes share this cutoff, measured from the actual search
    # launch rather than harness preparation. Do not seed an initial snapshot.
    environment = dict(os.environ if env is None else env)
    environment[CHECKPOINT_START_ENV] = str(
        time.monotonic() + max(0, timeout_seconds - CHECKPOINT_WINDOW_SECONDS)
    )
    try:
        return run_supervised(
            command, stderr=subprocess.STDOUT, text=True,
            timeout=timeout_seconds, private_tmpdir=True, env=environment,
        )
    except subprocess.TimeoutExpired:
        # The existing supervisor has stopped the reducer and its descendants
        # before returning control, including testers with their own groups.
        # treereduce writes its -o file only at completion. The tester's
        # atomic snapshot is what survives an interrupted reduction.
        if not checkpoint.is_symlink() and checkpoint.is_file() and checkpoint.stat().st_size:
            shutil.copyfile(checkpoint, candidate)
        if candidate.is_symlink() or not candidate.is_file() or not candidate.stat().st_size:
            raise RuntimeError("Reduction budget exhausted without a candidate.")
        print(
            f"[+] Reduction budget exhausted after {timeout_seconds:g} seconds; "
            "finalizing the current candidate. Crash validation is still required.",
            flush=True,
        )
        return subprocess.CompletedProcess(command, 0)

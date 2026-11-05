"""Bound tree reduction while leaving time to finalize and validate its result."""

from __future__ import annotations

import math
import os
from pathlib import Path
import signal
import shutil
import subprocess


def _stop_process_group(process: subprocess.Popen) -> None:
    # Testers and compilers belong to this group too. Reap them before the
    # caller restores PCH includes or reads the reduced source.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_bounded_reduction(
    command: list[str], output: str, timeout_seconds: float, snapshot: str
) -> subprocess.CompletedProcess:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Reduction timeout must be finite and positive.")
    candidate = Path(output)
    # A previous invocation's output cannot qualify as this run's progress.
    candidate.unlink(missing_ok=True)
    checkpoint = Path(snapshot)
    checkpoint.unlink(missing_ok=True)
    process = subprocess.Popen(
        command, stderr=subprocess.STDOUT, text=True, start_new_session=True
    )
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _stop_process_group(process)
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
    except BaseException:
        _stop_process_group(process)
        raise
    return subprocess.CompletedProcess(command, returncode)

"""Bound tree reduction while leaving time to finalize and validate its result."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import math
import os
from pathlib import Path
import subprocess
import time
from typing import TYPE_CHECKING

from harnessminimizer.safe_files import copy_regular_file
from harnessminimizer.process_supervisor import run_supervised

if TYPE_CHECKING:
    from harnessminimizer.reduction_engines import ReducerInvocation


CHECKPOINT_WINDOW_SECONDS = 4 * 60
CHECKPOINT_START_ENV = "HARNESSMINIMIZER_CHECKPOINT_START_MONOTONIC"
_search_deadline: ContextVar[float | None] = ContextVar("search_deadline", default=None)


@contextmanager
def search_budget(timeout_seconds: float | None):
    """Share one optional budget across reference preparation and search."""
    if timeout_seconds is not None and (
        not math.isfinite(timeout_seconds) or timeout_seconds <= 0
    ):
        raise ValueError("Search timeout must be finite and positive.")
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
    token = _search_deadline.set(deadline)
    try:
        yield
    finally:
        _search_deadline.reset(token)


def run_bounded_reduction(
    command: list[str], output: str, timeout_seconds: float, snapshot: str,
    *, env: dict[str, str] | None = None,
    invocation: ReducerInvocation | None = None,
) -> subprocess.CompletedProcess:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Reduction timeout must be finite and positive.")
    deadline = _search_deadline.get()
    if deadline is not None:
        timeout_seconds = min(timeout_seconds, deadline - time.monotonic())
        if timeout_seconds <= 0:
            raise RuntimeError("Search budget exhausted during harness preparation.")
    candidate = Path(output)
    # A previous invocation's output cannot qualify as this run's progress.
    candidate.unlink(missing_ok=True)
    checkpoint = Path(snapshot)
    checkpoint.unlink(missing_ok=True)
    # All tester processes share this cutoff, measured from the actual search
    # launch rather than harness preparation. Do not seed an initial snapshot.
    checkpoint_start = str(
        time.monotonic() + max(0, timeout_seconds - CHECKPOINT_WINDOW_SECONDS)
    )

    def supervise(command, **kwargs):
        # Keep the engine's cwd, log redirection and trace environment. Perses
        # runs in its own input directory and publishes from a separate output.
        environment = dict(kwargs.get("env", os.environ if env is None else env))
        environment[CHECKPOINT_START_ENV] = checkpoint_start
        kwargs.update(timeout=timeout_seconds, env=environment)
        return run_supervised(command, **kwargs)

    try:
        if invocation is not None:
            return invocation.run(supervise)
        return supervise(
            command, stderr=subprocess.STDOUT, text=True,
            private_tmpdir=True,
        )
    except subprocess.TimeoutExpired:
        # The existing supervisor has stopped the reducer and its descendants
        # before returning control, including testers with their own groups.
        # Perses may have written an initial or intermediate result already;
        # only a tester checkpoint qualifies for timeout recovery.
        if not copy_regular_file(checkpoint, candidate, skip_empty=True, create_parent=True):
            raise RuntimeError("Reduction budget exhausted without a candidate.")
        print(
            f"[+] Reduction budget exhausted after {timeout_seconds:g} seconds; "
            "finalizing the current candidate. Crash validation is still required.",
            flush=True,
        )
        return subprocess.CompletedProcess(command, 0)

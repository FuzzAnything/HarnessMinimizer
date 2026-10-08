"""Bounded subprocess I/O and process-group cleanup without watcher threads.

Linux pidfds make child exit observable even when a descendant holds a pipe.
Other POSIX kernels use a short wait only when pidfds are unavailable. Groups
are not a sandbox: a descendant can escape by creating another session.
"""
from __future__ import annotations

from contextlib import contextmanager
import locale
import math
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import tempfile
import threading
import time


DEFAULT_COMMAND_TIMEOUT = 300.0
MAX_OUTPUT_BYTES = int(os.environ.get("HARNESSMINIMIZER_MAX_OUTPUT_BYTES", 64 * 1024 * 1024))
if MAX_OUTPUT_BYTES <= 0:
    raise ValueError("HARNESSMINIMIZER_MAX_OUTPUT_BYTES must be positive")


class OutputLimitExceeded(subprocess.SubprocessError):
    """The subprocess exceeded the configured captured-output budget."""


@contextmanager
def termination_guard():
    """Let normal finally blocks run on TERM/HUP; preserve custom handlers."""
    previous = {}
    if threading.current_thread() is threading.main_thread():
        def terminate(signum, _frame):
            raise SystemExit(128 + signum)

        for sig in (signal.SIGTERM, signal.SIGHUP):
            handler = signal.getsignal(sig)
            if handler == signal.SIG_DFL:
                previous[sig] = handler
                signal.signal(sig, terminate)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _signal_group(pgid: int, sig: int) -> None:
    if pgid <= 0 or pgid == os.getpgrp():
        raise ValueError("refusing to signal the supervisor's process group")
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass


def _descendant_groups(pid: int) -> set[int]:
    """Failure/shutdown path only: include nested groups before parents exit."""
    groups = set()
    pending = [pid]
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        try:
            group = os.getpgid(current)
            if group != os.getpgrp():
                groups.add(group)
            for task in Path(f"/proc/{current}/task").iterdir():
                try:
                    pending.extend(map(int, (task / "children").read_text().split()))
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    pass
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    return groups


def terminate_process_group(process: subprocess.Popen, grace: float = 1.0) -> None:
    """Terminate owned groups even when their leader has already exited.

    Call only for children launched in their own session/group. Descendant
    enumeration is restricted to this shutdown path, never normal I/O.
    """
    groups = _descendant_groups(process.pid) | {process.pid}
    for group in groups:
        _signal_group(group, signal.SIGTERM)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    finally:
        # Leader exit does not imply descendant exit. No fixed grace sleep on
        # the fast path; stubborn descendants receive KILL before returning.
        for group in groups:
            _signal_group(group, signal.SIGKILL)
    process.wait(timeout=5)


def treereduce_binary() -> str:
    override = os.environ.get("HARNESSMINIMIZER_TREEREDUCE")
    if override:
        return override
    local = Path(__file__).resolve().parents[2] / ".tools/bin/treereduce-c"
    return str(local) if local.is_file() else "treereduce-c"


def runner_request(socket_path, plugin_path, timeout=305.0):
    """Read either runner protocol using one absolute request deadline."""
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(max(0.001, deadline - time.monotonic()))
        client.connect(str(socket_path))
        client.sendall(os.fsencode(os.path.abspath(plugin_path)) + b"\n")
        data = bytearray()
        header = None
        size = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Persistent runner response timed out")
            client.settimeout(remaining)
            chunk = client.recv(65536)
            if not chunk:
                raise RuntimeError("Persistent runner returned an incomplete response")
            data.extend(chunk)
            if header is None:
                newline = data.find(b"\n")
                if newline < 0:
                    if len(data) > 1024:
                        raise RuntimeError("Persistent runner response header is too large")
                    continue
                if newline > 1024:
                    raise RuntimeError("Persistent runner response header is too large")
                try:
                    header = bytes(data[:newline]).decode("ascii").split()
                    size = int(header[1])
                except (UnicodeDecodeError, ValueError, IndexError) as exc:
                    raise RuntimeError("Invalid persistent runner response header") from exc
                if size < 0 or size > MAX_OUTPUT_BYTES + 1024:
                    raise OutputLimitExceeded("Persistent runner response exceeds output budget")
                del data[:newline + 1]
            if len(data) == size:
                return header, bytes(data)
            if len(data) > size:
                raise RuntimeError("Persistent runner returned an oversized response")


@termination_guard()
def run_supervised(
    args, *, stdout=None, stderr=None, text=False, env=None, cwd=None,
    check=False, timeout=DEFAULT_COMMAND_TIMEOUT, max_output_bytes=MAX_OUTPUT_BYTES,
    private_tmpdir=False, **kwargs,
):
    """The subprocess.run subset used by the reducer, with tree cleanup.

    Preserve CompletedProcess/TimeoutExpired and stdout/stderr semantics so
    profiling stays around the same compile/link/execute regions. stdout and
    stderr limits apply only to PIPEs, not inherited output or caller files.
    """
    if private_tmpdir:
        with tempfile.TemporaryDirectory(prefix="harnessminimizer_checks_") as tmp:
            child_env = dict(os.environ if env is None else env)
            child_env.update(TMPDIR=tmp, HARNESSMINIMIZER_TMPDIR=tmp)
            return run_supervised(
                args, stdout=stdout, stderr=stderr, text=text, env=child_env,
                cwd=cwd, check=check, timeout=timeout,
                max_output_bytes=max_output_bytes, **kwargs,
            )
    encoding = kwargs.pop("encoding", None) or locale.getpreferredencoding(False)
    errors = kwargs.pop("errors", None) or "strict"
    kwargs.setdefault("start_new_session", True)
    started = time.monotonic()
    deadline = None if timeout is None else started + timeout
    process = subprocess.Popen(
        args, stdout=stdout, stderr=stderr, env=env, cwd=cwd, **kwargs,
    )
    poller = select.poll()
    streams = {}
    output = bytearray() if stdout == subprocess.PIPE else None
    error = bytearray() if stderr == subprocess.PIPE else None
    pidfd = None
    total = 0
    exited = False
    try:
        for stream, storage in ((process.stdout, output), (process.stderr, error)):
            if stream is not None:
                fd = stream.fileno()
                os.set_blocking(fd, False)
                streams[fd] = (stream, storage)
                poller.register(fd, select.POLLIN)
        try:
            pidfd = os.pidfd_open(process.pid)
            poller.register(pidfd, select.POLLIN)
        except (AttributeError, OSError):
            pidfd = None
        while streams or not exited:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise subprocess.TimeoutExpired(
                    args, timeout, output=bytes(output) if output is not None else None,
                    stderr=bytes(error) if error is not None else None,
                )
            wait_ms = None if remaining is None else max(1, math.ceil(remaining * 1000))
            if pidfd is None and not exited:
                wait_ms = min(wait_ms, 50) if wait_ms is not None else 50
            events = poller.poll(wait_ms)
            child_ready = any(fd == pidfd for fd, _ in events) if pidfd is not None else False
            if child_ready or (pidfd is None and process.poll() is not None):
                # With pidfd the child has not been reaped yet, retaining its
                # PID while we terminate anything left in its process group.
                _signal_group(process.pid, signal.SIGKILL)
                process.wait()
                exited = True
                if pidfd is not None:
                    poller.unregister(pidfd)
                drain_deadline = time.monotonic() + 1.0
                deadline = min(deadline, drain_deadline) if deadline is not None else drain_deadline
            for fd, _ in events:
                if fd not in streams:
                    continue
                stream, storage = streams[fd]
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    poller.unregister(fd)
                    stream.close()
                    del streams[fd]
                    continue
                total += len(chunk)
                if total > max_output_bytes:
                    raise OutputLimitExceeded(
                        f"Command exceeded {max_output_bytes} captured output bytes: {args[0]}"
                    )
                storage.extend(chunk)
    except BaseException:
        terminate_process_group(process)
        raise
    finally:
        if pidfd is not None:
            os.close(pidfd)
        for stream, _ in streams.values():
            stream.close()

    def convert(data):
        if data is None:
            return None
        value = bytes(data)
        return value.decode(encoding, errors).replace("\r\n", "\n").replace("\r", "\n") if text else value

    result = subprocess.CompletedProcess(args, process.returncode, convert(output), convert(error))
    if check:
        result.check_returncode()
    return result

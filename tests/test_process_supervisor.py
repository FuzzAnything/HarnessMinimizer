"""Bounded lifecycle regressions: sleepers, never a host-load/fork-bomb test."""
import ctypes
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager

import pytest

from harnessreducer.process_supervisor import (
    OutputLimitExceeded, run_supervised, runner_request, terminate_process_group,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def reap_orphans():
    # Scoped to these tests so deliberately orphaned sleepers never burden PID 1.
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    owned = []
    yield owned
    for pid in owned:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    assert libc.prctl(36, previous.value, 0, 0, 0) == 0


def wait_file(path):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if path.exists() and path.read_text().strip():
            return int(path.read_text())
        time.sleep(0.01)
    raise AssertionError(f"child did not write {path}")


def assert_terminated(pid):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            return
        if stat[stat.rfind(")") + 2:].startswith("Z"):
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            else:
                return
        time.sleep(0.01)
    raise AssertionError(f"process {pid} survived or was not reaped")


def test_run_preserves_output_and_exit_status():
    result = run_supervised(
        [sys.executable, "-c", "import sys;print('out');print('err',file=sys.stderr);sys.exit(77)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert (result.returncode, result.stdout, result.stderr) == (77, "out\n", "err\n")


@pytest.mark.parametrize("timeout", [True, False])
def test_python_descendants_are_cleaned_on_timeout_and_normal_exit(tmp_path, reap_orphans, timeout):
    pidfile = tmp_path / "child.pid"
    code = (
        "import os,pathlib,time;child=os.fork();"
        f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())) if child==0 else None;"
        f"time.sleep(8) if child==0 or {timeout!r} else None"
    )
    started = time.monotonic()
    try:
        if timeout:
            with pytest.raises(subprocess.TimeoutExpired):
                run_supervised([sys.executable, "-c", code], stdout=subprocess.PIPE, timeout=0.3)
        else:
            assert run_supervised([sys.executable, "-c", code], stdout=subprocess.PIPE, timeout=2).returncode == 0
    finally:
        if pidfile.exists():
            reap_orphans.append(wait_file(pidfile))
    assert time.monotonic() - started < 2
    assert_terminated(reap_orphans[-1])


def test_python_closed_output_still_times_out():
    with pytest.raises(subprocess.TimeoutExpired):
        run_supervised(
            [sys.executable, "-c", "import os,time;os.close(1);os.close(2);time.sleep(8)"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=0.2,
        )


def test_output_is_bounded():
    with pytest.raises(OutputLimitExceeded):
        run_supervised(
            [sys.executable, "-c", "import os,time;os.write(1,b'x'*100000);time.sleep(8)"],
            stdout=subprocess.PIPE, timeout=2, max_output_bytes=1024,
        )


def test_cleanup_after_leader_exit_kills_stubborn_child(tmp_path, reap_orphans):
    pidfile = tmp_path / "child.pid"
    code = (
        "import os,pathlib,signal,time;child=os.fork();"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN) if child==0 else None;"
        f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())) if child==0 else None;"
        "time.sleep(8) if child==0 else None"
    )
    process = subprocess.Popen([sys.executable, "-c", code], start_new_session=True)
    try:
        child = wait_file(pidfile)
        reap_orphans.append(child)
        process.wait(timeout=2)
        terminate_process_group(process)
        assert_terminated(child)
    finally:
        terminate_process_group(process)


@pytest.fixture(scope="module")
def runner_binaries(tmp_path_factory):
    directory = tmp_path_factory.mktemp("runner-supervision")
    from measure_time import TIMING_RUNNER_SOURCE
    timing_source = directory / "timing.cpp"
    timing_source.write_text(TIMING_RUNNER_SOURCE)
    binaries = {}
    for kind, source in (("production", ROOT / "src/harnessreducer/harness_runner.cpp"), ("timing", timing_source)):
        binary = directory / kind
        subprocess.run([
            "clang++", "-std=c++17", "-O1", "-I" + str(ROOT / "src/harnessreducer"),
            str(source), "-ldl", "-o", str(binary),
        ], check=True, timeout=30)
        binaries[kind] = binary
    return binaries


def compile_plugin(tmp_path, body):
    source = tmp_path / "plugin.cpp"
    source.write_text(
        '#include <cstdint>\n#include <cstddef>\n#include <unistd.h>\n#include <cstdio>\n#include <csignal>\n'
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t*,size_t) {' + body + '}\n'
    )
    plugin = tmp_path / "plugin.so"
    subprocess.run(["clang++", "-shared", "-fPIC", str(source), "-o", str(plugin)], check=True, timeout=15)
    return plugin


@contextmanager
def running_runner(binary, tmp_path, kind, env=None):
    sock = tmp_path / "runner.sock"
    command = [str(binary), str(sock), ""]
    if kind == "timing":
        command.append(str(tmp_path / "startup.txt"))
    command.append("1")
    process = subprocess.Popen(command, start_new_session=True, env=env)
    try:
        deadline = time.monotonic() + 3
        while not sock.exists() and time.monotonic() < deadline:
            assert process.poll() is None
            time.sleep(0.01)
        assert sock.exists()
        yield process, sock
    finally:
        terminate_process_group(process)


@pytest.mark.parametrize("kind", ["production", "timing"])
@pytest.mark.parametrize("body,status", [
    ("return 77;", 77),
    ("close(1);close(2);sleep(8);return 0;", 124),
    ("if(fork()==0){sleep(8);_exit(0);}sleep(8);return 0;", 124),
    ("if(fork()==0){sleep(8);_exit(0);}return 77;", 77),
])
def test_runner_deadlines_and_descendant_cleanup(runner_binaries, tmp_path, kind, body, status):
    plugin = compile_plugin(tmp_path, body)
    with running_runner(runner_binaries[kind], tmp_path, kind) as (process, sock):
        started = time.monotonic()
        header, _output = runner_request(sock, plugin, timeout=3)
        assert int(header[0]) == status
        assert time.monotonic() - started < 2.5
        assert len(header) == (10 if kind == "timing" else 2)
        if kind == "timing":
            assert all(int(value) >= 0 for value in header[2:])
            assert int(header[5]) >= 0  # dlsym and execution fields still present
        # Server ignores SIGCHLD, and each monitor reaps its own executor and
        # orphan descendants before returning. No monitors should accumulate.
        children = Path(f"/proc/{process.pid}/task/{process.pid}/children")
        deadline = time.monotonic() + 1
        while children.read_text().strip() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not children.read_text().strip()


def test_runner_disconnect_cancels_execution(runner_binaries, tmp_path):
    pidfile = tmp_path / "executor.pid"
    plugin = compile_plugin(tmp_path, f'FILE *f=fopen("{pidfile}","w");fprintf(f,"%d",getpid());fclose(f);sleep(8);return 0;')
    with running_runner(runner_binaries["production"], tmp_path, "production") as (_, sock):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(sock))
            client.sendall(os.fsencode(plugin) + b"\n")
            child = wait_file(pidfile)
        assert_terminated(child)


@pytest.mark.parametrize("kind", ["production", "timing"])
def test_runner_owner_death_cleans_active_request(runner_binaries, tmp_path, reap_orphans, kind):
    pidfile = tmp_path / "executor.pid"
    plugin = compile_plugin(tmp_path, f'FILE *f=fopen("{pidfile}","w");fprintf(f,"%d",getpid());fclose(f);sleep(8);return 0;')
    sock = tmp_path / "runner.sock"
    command = [str(runner_binaries[kind]), str(sock), ""]
    if kind == "timing":
        command.append(str(tmp_path / "startup.txt"))
    command.append("8")
    runner_pidfile = tmp_path / "runner.pid"
    code = (
        "import os,pathlib,subprocess\n"
        f"runner=subprocess.Popen({command!r},start_new_session=True,"
        "env=dict(os.environ,HARNESSREDUCER_RUNNER_PARENT_PID=str(os.getpid())))\n"
        f"pathlib.Path({str(runner_pidfile)!r}).write_text(str(runner.pid))\n"
        "runner.wait(timeout=10)\n"
    )
    owner = subprocess.Popen([sys.executable, "-c", code], start_new_session=True)
    try:
        runner = wait_file(runner_pidfile)
        reap_orphans.append(runner)
        deadline = time.monotonic() + 3
        while not sock.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(sock))
            client.sendall(os.fsencode(plugin) + b"\n")
            executor = wait_file(pidfile)
            monitors = list(map(int, Path(f"/proc/{runner}/task/{runner}/children").read_text().split()))
            assert len(monitors) == 1
            reap_orphans.extend([*monitors, executor])
            # Keep the client connected: this specifically tests owner death,
            # rather than the disconnect or execution-deadline paths.
            owner.kill()
            owner.wait(timeout=2)
            assert_terminated(executor)
            assert_terminated(monitors[0])
            assert_terminated(runner)
    finally:
        terminate_process_group(owner)


def test_runner_output_limit(runner_binaries, tmp_path):
    plugin = compile_plugin(tmp_path, 'char data[8192]={};write(1,data,sizeof(data));sleep(8);return 0;')
    env = dict(os.environ, HARNESSREDUCER_MAX_OUTPUT_BYTES="1024")
    with running_runner(runner_binaries["production"], tmp_path, "production", env) as (_, sock):
        header, output = runner_request(sock, plugin, timeout=3)
        assert int(header[0]) == 125
        assert b"output limit" in output


def test_real_checker_preserves_profile_fields_and_crash(tmp_path):
    source = tmp_path / "harness.cpp"
    source.write_text(
        '#include <cstddef>\n#include <cstdint>\n'
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t*,size_t) {'
        'volatile int *p=new int[1];int x=p[2];delete[]p;return x;}\n'
    )
    seed = tmp_path / "seed"
    seed.write_bytes(b"x")
    profile = tmp_path / "profile.jsonl"
    command = [sys.executable, str(ROOT / "tests/crash_tester.py"), str(source),
               "heap-buffer-overflow", "--crash-input", str(seed), "--exec-timeout-ms=5000"]
    plain = run_supervised(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    profiled = run_supervised(command + ["--profile-file", str(profile)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    assert plain.returncode == profiled.returncode == 77, (plain.stderr, profiled.stderr)
    event = json.loads(profile.read_text())
    assert event["result_code"] == 77
    assert event["compile_success"] is True
    durations = event["durations_ns"]
    assert durations["compile_link_ns"] > 0
    assert durations["execute_ns"] > 0
    assert durations["oracle_ns"] > 0
    assert durations["total_ns"] >= durations["execute_ns"] + durations["compile_link_ns"]


def test_patched_treereduce_reaps_timed_out_checkers(tmp_path, reap_orphans):
    from harnessreducer.process_supervisor import treereduce_binary
    binary = treereduce_binary()
    probe = subprocess.run([binary, "--harnessreducer-supervisor-version"], capture_output=True)
    if probe.returncode != 0:
        pytest.skip("install the pinned treereduce patch to run its integration regression")
    source = tmp_path / "source.cpp"
    source.write_text("int f(int x) { int a = x+1; int b = a+2; return b; }\n")
    checker = tmp_path / "checker.py"
    entries = tmp_path / "pids.jsonl"
    checker.write_text(
        "import os,pathlib,subprocess,sys,time,json\n"
        f"initial=pathlib.Path({str(tmp_path / 'initial')!r})\n"
        "if not initial.exists():\n initial.touch();sys.exit(77)\n"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(8)'],start_new_session=True)\n"
        f"with open({str(entries)!r},'a') as f:f.write(json.dumps([os.getpid(),child.pid])+'\\n')\n"
        "time.sleep(8)\n"
    )
    process = subprocess.Popen([
        binary, "-j", "1", "-s", str(source), "-o", str(tmp_path / "reduced.cpp"),
        "--timeout", "1", "--interesting-exit-code", "77", "--", sys.executable, str(checker), "@@.cpp",
    ], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 4
        rows = []
        while time.monotonic() < deadline:
            if entries.exists():
                rows = [json.loads(line) for line in entries.read_text().splitlines()]
                if len(rows) >= 3:
                    break
            time.sleep(0.02)
        assert len(rows) >= 3
        assert process.poll() is None
        # Unlike the unpatched dependency, earlier checkers have been reaped
        # while the reducer remains alive; nested executor groups are dead too.
        for checker_pid, child_pid in rows[:-1]:
            assert not Path(f"/proc/{checker_pid}").exists()
            assert_terminated(child_pid)
    finally:
        terminate_process_group(process)
        if entries.exists():
            for row in entries.read_text().splitlines():
                reap_orphans.extend(json.loads(row))


def test_sigterm_unwinds_python_supervisor(tmp_path, reap_orphans):
    pidfile = tmp_path / "child.pid"
    script = tmp_path / "supervisor.py"
    script.write_text(
        "import sys\n"
        f"sys.path.insert(0,{str(ROOT / 'src')!r})\n"
        "from harnessreducer.process_supervisor import run_supervised\n"
        "import subprocess\n"
        f"code=\"import pathlib,os,time;pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()));time.sleep(8)\"\n"
        "run_supervised([sys.executable,'-c',code],stdout=subprocess.PIPE)\n"
    )
    process = subprocess.Popen([sys.executable, str(script)], start_new_session=True)
    try:
        child = wait_file(pidfile)
        reap_orphans.append(child)
        process.terminate()
        assert process.wait(timeout=3) == 143
        assert_terminated(child)
    finally:
        terminate_process_group(process)

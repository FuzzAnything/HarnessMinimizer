#!/usr/bin/env python3
"""Benchmark HarnessReducer's compile, link, load, and execution stages."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import platform
import re
import shlex
import signal
import socket
import statistics
import subprocess
import sys
import time
from typing import Iterable, Sequence


PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from harnessreducer import reducer_runner as rr  # noqa: E402


AMORTIZED_UNDEFINED_SYMBOL_LOAD_PATTERN = re.compile(
    rb"dlopen candidate failed: .*undefined symbol:"
)


TIMING_RUNNER_SOURCE = r'''
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

using RunOneFn = int (*)(const uint8_t *, size_t);
using Clock = std::chrono::steady_clock;

volatile sig_atomic_t TimedChild = -1;
volatile sig_atomic_t ChildTimedOut = 0;

uint64_t NowNs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now().time_since_epoch()).count());
}

void HandleTimeout(int) {
  ChildTimedOut = 1;
  if (TimedChild > 0)
    kill(static_cast<pid_t>(TimedChild), SIGKILL);
}

bool WriteAll(int fd, const void *raw_data, size_t size) {
  const char *data = static_cast<const char *>(raw_data);
  while (size != 0) {
    const ssize_t written = write(fd, data, size);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    data += written;
    size -= static_cast<size_t>(written);
  }
  return true;
}

bool ReadAll(int fd, void *raw_data, size_t size) {
  char *data = static_cast<char *>(raw_data);
  while (size != 0) {
    const ssize_t count = read(fd, data, size);
    if (count == 0)
      return false;
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    data += count;
    size -= static_cast<size_t>(count);
  }
  return true;
}

std::string ReadPluginPath(int fd) {
  std::string path;
  char ch = '\0';
  while (path.size() < 65536) {
    const ssize_t count = read(fd, &ch, 1);
    if (count == 0)
      break;
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return {};
    }
    if (ch == '\n')
      break;
    path.push_back(ch);
  }
  return path;
}

int WaitStatusToExitCode(int status) {
  if (WIFEXITED(status))
    return WEXITSTATUS(status);
  if (WIFSIGNALED(status))
    return 128 + WTERMSIG(status);
  return 1;
}

void CloseHandles(std::vector<void *> &handles) {
  for (void *handle : handles) {
    if (handle != nullptr)
      dlclose(handle);
  }
  handles.clear();
}

bool LoadTargetLibraries(
    const std::vector<std::string> &paths,
    const char *order_name,
    std::vector<void *> &handles,
    std::vector<std::pair<std::string, uint64_t>> &target_times,
    uint64_t &target_dlopen_total_ns,
    std::string &error) {
  target_times.clear();
  target_dlopen_total_ns = 0;
  for (const std::string &path : paths) {
    const uint64_t before_ns = NowNs();
    void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL);
    const uint64_t elapsed_ns = NowNs() - before_ns;
    if (handle == nullptr) {
      error = std::string("dlopen target failed during ") + order_name +
              " order for " + path + ": " + dlerror();
      return false;
    }
    target_times.emplace_back(path, elapsed_ns);
    target_dlopen_total_ns += elapsed_ns;
    handles.push_back(handle);
  }
  return true;
}

bool LoadTargetLibrariesWithRetry(
    const std::vector<std::string> &paths,
    std::vector<void *> &handles,
    std::vector<std::pair<std::string, uint64_t>> &target_times,
    uint64_t &target_dlopen_total_ns) {
  std::string forward_error;
  if (LoadTargetLibraries(paths, "original", handles, target_times,
                          target_dlopen_total_ns, forward_error))
    return true;

  CloseHandles(handles);
  if (paths.size() <= 1) {
    std::fprintf(stderr, "%s\n", forward_error.c_str());
    std::fprintf(stderr,
                 "Amortized-link runner could not load the target shared "
                 "library. Try rerunning without --amortize-link.\n");
    return false;
  }

  std::vector<std::string> reversed_paths = paths;
  std::reverse(reversed_paths.begin(), reversed_paths.end());
  std::fprintf(stderr, "%s\n", forward_error.c_str());
  std::fprintf(stderr, "Retrying target dlopen in reverse order.\n");

  std::string reverse_error;
  if (LoadTargetLibraries(reversed_paths, "reverse", handles, target_times,
                          target_dlopen_total_ns, reverse_error))
    return true;

  CloseHandles(handles);
  std::fprintf(stderr, "%s\n", reverse_error.c_str());
  std::fprintf(stderr,
               "Amortized-link runner could not load target shared libraries "
               "in original or reverse order. This usually means a target "
               "shared library has unresolved dynamic dependencies that are "
               "not available to the persistent runner. Try rerunning without "
               "--amortize-link.\n");
  return false;
}

struct PluginMetrics {
  uint64_t dlopen_ns = 0;
  uint64_t dlsym_ns = 0;
  uint64_t execute_start_ns = 0;
};

void HandleRequest(int connection, int listen_fd,
                   const std::vector<uint8_t> &crash_data,
                   uint64_t monitor_fork_start_ns,
                   unsigned int timeout_seconds) {
  const uint64_t request_start_ns = NowNs();
  const uint64_t monitor_fork_ns = request_start_ns - monitor_fork_start_ns;
  close(listen_fd);
  const std::string plugin_path = ReadPluginPath(connection);
  if (plugin_path.empty()) {
    const std::string response = "1 0 0 0 0 0 0 0 0 0\n";
    WriteAll(connection, response.data(), response.size());
    close(connection);
    _exit(0);
  }

  int output_pipe[2];
  int metrics_pipe[2];
  if (pipe(output_pipe) != 0 || pipe(metrics_pipe) != 0) {
    const std::string message = std::string("pipe failed: ") + strerror(errno) + "\n";
    const std::string header = "1 " + std::to_string(message.size()) +
        " 0 0 0 0 0 0 0 0\n";
    WriteAll(connection, header.data(), header.size());
    WriteAll(connection, message.data(), message.size());
    close(connection);
    _exit(0);
  }

  signal(SIGCHLD, SIG_DFL);
  const uint64_t executor_fork_start_ns = NowNs();
  const pid_t child = fork();
  if (child == 0) {
    close(output_pipe[0]);
    close(metrics_pipe[0]);
    dup2(output_pipe[1], STDOUT_FILENO);
    dup2(output_pipe[1], STDERR_FILENO);
    close(output_pipe[1]);
    close(connection);

    PluginMetrics metrics;
    const uint64_t dlopen_start_ns = NowNs();
    void *plugin = dlopen(plugin_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    metrics.dlopen_ns = NowNs() - dlopen_start_ns;
    if (plugin == nullptr) {
      WriteAll(metrics_pipe[1], &metrics, sizeof(metrics));
      close(metrics_pipe[1]);
      std::fprintf(stderr, "dlopen candidate failed: %s\n", dlerror());
      _exit(125);
    }

    dlerror();
    const uint64_t dlsym_start_ns = NowNs();
    auto run_one = reinterpret_cast<RunOneFn>(
        dlsym(plugin, "LLVMFuzzerTestOneInput"));
    metrics.dlsym_ns = NowNs() - dlsym_start_ns;
    if (const char *error = dlerror()) {
      WriteAll(metrics_pipe[1], &metrics, sizeof(metrics));
      close(metrics_pipe[1]);
      std::fprintf(stderr, "dlsym LLVMFuzzerTestOneInput failed: %s\n", error);
      _exit(125);
    }

    metrics.execute_start_ns = NowNs();
    WriteAll(metrics_pipe[1], &metrics, sizeof(metrics));
    close(metrics_pipe[1]);
    const uint8_t *data = crash_data.empty() ? nullptr : crash_data.data();
    const int result = run_one(data, crash_data.size());
    _exit(result & 0xff);
  }

  const uint64_t executor_fork_ns = NowNs() - executor_fork_start_ns;
  close(output_pipe[1]);
  close(metrics_pipe[1]);

  TimedChild = child;
  ChildTimedOut = 0;
  signal(SIGALRM, HandleTimeout);
  alarm(timeout_seconds);

  PluginMetrics metrics;
  if (!ReadAll(metrics_pipe[0], &metrics, sizeof(metrics)))
    metrics = PluginMetrics{};
  close(metrics_pipe[0]);

  const uint64_t output_start_ns = NowNs();
  std::string output;
  char buffer[16384];
  while (true) {
    const ssize_t count = read(output_pipe[0], buffer, sizeof(buffer));
    if (count == 0)
      break;
    if (count < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    output.append(buffer, static_cast<size_t>(count));
  }
  close(output_pipe[0]);
  const uint64_t output_pipe_ns = NowNs() - output_start_ns;
  alarm(0);

  const uint64_t wait_start_ns = NowNs();
  int wait_status = 0;
  if (child < 0 || waitpid(child, &wait_status, 0) < 0)
    wait_status = 1 << 8;
  const uint64_t waitpid_ns = NowNs() - wait_start_ns;
  const uint64_t child_end_ns = NowNs();
  const int exit_code = ChildTimedOut ? 124 : WaitStatusToExitCode(wait_status);
  const uint64_t execute_to_exit_ns = metrics.execute_start_ns == 0
      ? 0 : child_end_ns - metrics.execute_start_ns;
  const uint64_t monitor_total_ns = child_end_ns - request_start_ns;

  const std::string header =
      std::to_string(exit_code) + " " + std::to_string(output.size()) + " " +
      std::to_string(monitor_fork_ns) + " " +
      std::to_string(executor_fork_ns) + " " +
      std::to_string(metrics.dlopen_ns) + " " +
      std::to_string(metrics.dlsym_ns) + " " +
      std::to_string(execute_to_exit_ns) + " " +
      std::to_string(output_pipe_ns) + " " +
      std::to_string(waitpid_ns) + " " +
      std::to_string(monitor_total_ns) + "\n";
  WriteAll(connection, header.data(), header.size());
  WriteAll(connection, output.data(), output.size());
  close(connection);
  _exit(0);
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 5) {
    std::fprintf(stderr,
                 "usage: timing_runner SOCKET CRASH_INPUT STARTUP_FILE "
                 "TIMEOUT [TARGET_SO...]\n");
    return 2;
  }

  char *timeout_end = nullptr;
  const unsigned long parsed_timeout = std::strtoul(argv[4], &timeout_end, 10);
  if (timeout_end == argv[4] || *timeout_end != '\0' || parsed_timeout == 0) {
    std::fprintf(stderr, "invalid execution timeout: %s\n", argv[4]);
    return 2;
  }
  const unsigned int timeout_seconds =
      static_cast<unsigned int>(parsed_timeout);

  const uint64_t startup_begin_ns = NowNs();
  std::vector<std::string> target_paths;
  for (int index = 5; index < argc; ++index) {
    target_paths.emplace_back(argv[index]);
  }
  std::vector<void *> target_handles;
  std::vector<std::pair<std::string, uint64_t>> target_times;
  uint64_t target_dlopen_total_ns = 0;
  if (!LoadTargetLibrariesWithRetry(target_paths, target_handles, target_times,
                                    target_dlopen_total_ns))
    return 2;

  const uint64_t input_start_ns = NowNs();
  std::vector<uint8_t> crash_data;
  if (argv[2][0] != '\0') {
    std::ifstream input(argv[2], std::ios::binary);
    if (!input) {
      std::fprintf(stderr, "failed to open crash input: %s\n", argv[2]);
      return 2;
    }
    crash_data.assign(std::istreambuf_iterator<char>(input),
                      std::istreambuf_iterator<char>());
  }
  const uint64_t crash_input_read_ns = NowNs() - input_start_ns;

  const uint64_t socket_start_ns = NowNs();
  const int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    std::perror("socket");
    return 2;
  }
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  const std::string socket_path = argv[1];
  if (socket_path.size() >= sizeof(address.sun_path)) {
    std::fprintf(stderr, "runner socket path is too long\n");
    return 2;
  }
  std::strncpy(address.sun_path, socket_path.c_str(), sizeof(address.sun_path) - 1);
  unlink(socket_path.c_str());
  if (bind(listen_fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
    std::perror("bind");
    return 2;
  }
  if (listen(listen_fd, 128) != 0) {
    std::perror("listen");
    return 2;
  }
  const uint64_t socket_setup_ns = NowNs() - socket_start_ns;
  const uint64_t startup_internal_total_ns = NowNs() - startup_begin_ns;

  {
    std::ofstream startup(argv[3], std::ios::trunc);
    startup << "target_dlopen_total_ns\t" << target_dlopen_total_ns << "\n";
    for (const auto &entry : target_times)
      startup << "target_dlopen_ns\t" << entry.first << "\t" << entry.second << "\n";
    startup << "crash_input_read_ns\t" << crash_input_read_ns << "\n";
    startup << "crash_input_size_bytes\t" << crash_data.size() << "\n";
    startup << "socket_setup_ns\t" << socket_setup_ns << "\n";
    startup << "startup_internal_total_ns\t" << startup_internal_total_ns << "\n";
  }

  struct sigaction action {};
  action.sa_handler = SIG_IGN;
  action.sa_flags = SA_NOCLDWAIT;
  sigemptyset(&action.sa_mask);
  sigaction(SIGCHLD, &action, nullptr);

  while (true) {
    const int connection = accept(listen_fd, nullptr, nullptr);
    if (connection < 0) {
      if (errno == EINTR)
        continue;
      std::perror("accept");
      break;
    }
    const uint64_t monitor_fork_start_ns = NowNs();
    const pid_t monitor = fork();
    if (monitor == 0)
      HandleRequest(connection, listen_fd, crash_data, monitor_fork_start_ns,
                    timeout_seconds);
    close(connection);
  }

  close(listen_fd);
  unlink(socket_path.c_str());
  return 0;
}
'''


@dataclass(frozen=True)
class SampleStats:
    count: int
    mean_ns: float
    median_ns: float
    stddev_ns: float
    min_ns: int
    max_ns: int


def calculate_stats(values: Sequence[int]) -> SampleStats:
    if not values:
        return SampleStats(0, 0.0, 0.0, 0.0, 0, 0)
    return SampleStats(
        count=len(values),
        mean_ns=statistics.fmean(values),
        median_ns=statistics.median(values),
        stddev_ns=statistics.pstdev(values) if len(values) > 1 else 0.0,
        min_ns=min(values),
        max_ns=max(values),
    )


def ns_to_ms(value: float | int) -> float:
    return float(value) / 1_000_000.0


def ns_to_us(value: float | int) -> float:
    return float(value) / 1_000.0


def format_command(command: Sequence[str]) -> str:
    return shlex.join(str(part) for part in command)


def run_checked(
    command: Sequence[str],
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        output = (proc.stderr or proc.stdout).strip()
        raise RuntimeError(
            f"Command failed with exit code {proc.returncode}:\n"
            f"{format_command(command)}\n{output}"
        )
    return proc


def measure_checked_command(
    command: Sequence[str],
    iterations: int,
    *,
    env: dict[str, str] | None = None,
) -> list[int]:
    samples: list[int] = []
    for _ in range(iterations):
        start_ns = time.perf_counter_ns()
        run_checked(command, env=env)
        samples.append(time.perf_counter_ns() - start_ns)
    return samples


def measure_checked_once(
    command: Sequence[str],
    *,
    env: dict[str, str] | None = None,
) -> int:
    start_ns = time.perf_counter_ns()
    run_checked(command, env=env)
    return time.perf_counter_ns() - start_ns


def read_exact(stream, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) != size:
        raise RuntimeError(f"Truncated runner output: expected {size}, got {len(data)}")
    return data


def sanitizer_env(
    link_flags: str | None,
    symbolize: bool,
    *,
    detect_odr_violation: bool = True,
) -> dict[str, str]:
    env = rr.runtime_library_env(link_flags)
    value = "1" if symbolize else "0"
    env["ASAN_OPTIONS"] = rr.sanitizer_asan_options(
        symbolize=symbolize,
        detect_odr_violation=detect_odr_violation,
    )
    env["UBSAN_OPTIONS"] = (
        f"exitcode=77:symbolize={value}:halt_on_error=1:print_stacktrace=1"
    )
    return env


def measure_standalone_execution(
    executable: Path,
    crash_input: Path,
    iterations: int,
    link_flags: str | None,
    symbolize: bool,
    timeout_seconds: int,
) -> tuple[list[int], Counter[int]]:
    samples: list[int] = []
    statuses: Counter[int] = Counter()
    env = sanitizer_env(link_flags, symbolize)
    command = [str(executable), str(crash_input)]
    for _ in range(iterations):
        start_ns = time.perf_counter_ns()
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
                timeout=timeout_seconds,
            )
            status = proc.returncode
        except subprocess.TimeoutExpired:
            status = 124
        samples.append(time.perf_counter_ns() - start_ns)
        statuses[status] += 1
    return samples, statuses


def parse_startup_file(path: Path) -> dict[str, object]:
    result: dict[str, object] = {"target_dlopen_ns": []}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if parts[0] == "target_dlopen_ns":
            target_values = result["target_dlopen_ns"]
            assert isinstance(target_values, list)
            target_values.append({"path": parts[1], "ns": int(parts[2])})
        else:
            result[parts[0]] = int(parts[1])
    return result


def start_timing_runner(
    runner_binary: Path,
    socket_path: Path,
    crash_input: Path,
    startup_file: Path,
    shared_libraries: Sequence[str],
    link_flags: str | None,
    symbolize: bool,
    timeout_seconds: int,
) -> tuple[subprocess.Popen[bytes], int, dict[str, object]]:
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    try:
        startup_file.unlink()
    except FileNotFoundError:
        pass

    env = sanitizer_env(link_flags, symbolize, detect_odr_violation=False)
    command = [
        str(runner_binary),
        str(socket_path),
        str(crash_input),
        str(startup_file),
        str(timeout_seconds),
        *shared_libraries,
    ]
    start_ns = time.perf_counter_ns()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    deadline = time.monotonic() + 15.0
    while not socket_path.exists() or not startup_file.exists():
        return_code = process.poll()
        if return_code is not None:
            stdout, stderr = process.communicate()
            raise RuntimeError(
                "Timing runner failed during startup:\n"
                + stdout.decode(errors="replace")
                + stderr.decode(errors="replace")
            )
        if time.monotonic() >= deadline:
            stop_runner(process, socket_path)
            raise RuntimeError("Timed out waiting for the timing runner")
        time.sleep(0.002)
    wall_ns = time.perf_counter_ns() - start_ns
    return process, wall_ns, parse_startup_file(startup_file)


def stop_runner(process: subprocess.Popen[bytes], socket_path: Path) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass


RUNNER_METRIC_NAMES = (
    "monitor_fork_ns",
    "executor_fork_ns",
    "candidate_dlopen_ns",
    "dlsym_ns",
    "execute_to_exit_ns",
    "output_pipe_ns",
    "waitpid_ns",
    "monitor_total_ns",
)


def timing_runner_request(
    socket_path: Path,
    plugin_path: Path,
) -> tuple[int, bytes, list[int], int]:
    start_ns = time.perf_counter_ns()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(socket_path))
        client.sendall(str(plugin_path).encode("utf-8") + b"\n")
        stream = client.makefile("rb")
        header = stream.readline()
        if not header:
            raise RuntimeError("Timing runner closed the connection")
        fields = header.decode("ascii").strip().split()
        if len(fields) != 10:
            raise RuntimeError(f"Invalid timing runner response: {header!r}")
        status = int(fields[0])
        output_size = int(fields[1])
        metric_values = [int(value) for value in fields[2:]]
        output = read_exact(stream, output_size)
    elapsed_ns = time.perf_counter_ns() - start_ns
    return status, output, metric_values, elapsed_ns


def should_retry_timing_plugin_with_fallback(status: int, output: bytes) -> bool:
    return status == 125 and bool(AMORTIZED_UNDEFINED_SYMBOL_LOAD_PATTERN.search(output))


def measure_runner_requests(
    socket_path: Path,
    plugin_path: Path,
    iterations: int,
    fallback_plugin_path: Path | None = None,
) -> tuple[dict[str, list[int]], Counter[int], bytes | None, bool]:
    samples = {"end_to_end_ns": [], "fallback_trigger_request_ns": []}
    samples.update({name: [] for name in RUNNER_METRIC_NAMES})
    statuses: Counter[int] = Counter()
    representative_output: bytes | None = None
    fallback_needed = False

    for _ in range(iterations):
        total_start_ns = time.perf_counter_ns()
        status, output, metric_values, initial_elapsed_ns = timing_runner_request(
            socket_path,
            plugin_path,
        )
        if (
            fallback_plugin_path is not None
            and should_retry_timing_plugin_with_fallback(status, output)
        ):
            fallback_needed = True
            samples["fallback_trigger_request_ns"].append(initial_elapsed_ns)
            status, output, metric_values, _ = timing_runner_request(
                socket_path,
                fallback_plugin_path,
            )
        if representative_output is None:
            representative_output = output
        samples["end_to_end_ns"].append(time.perf_counter_ns() - total_start_ns)
        statuses[status] += 1
        for name, value in zip(RUNNER_METRIC_NAMES, metric_values, strict=True):
            samples[name].append(value)
    return samples, statuses, representative_output, fallback_needed


def output_text(output: bytes | None) -> str | None:
    if output is None:
        return None
    return output.decode("utf-8", errors="replace")


def crash_pattern_from_output(output: bytes | None) -> str | None:
    text = output_text(output)
    if text is None:
        return None
    return rr._extract_crash_signature_from_output(text)


def stack_trace_pattern_from_output(
    output: bytes | None,
    *,
    harness_path: str,
) -> str | None:
    text = output_text(output)
    if text is None:
        return None
    trace = rr.extract_stack_trace(text, harness_path=harness_path)
    if not trace:
        return None
    return rr.normalize_crash_signature(trace, escape=True)


def measure_oracle_checks(
    output: bytes | None,
    iterations: int,
    link_flags: str | None,
    *,
    crash_pattern: str | None,
    stack_trace_pattern: str | None,
    stack_trace_harness_path: str,
    check_dynamic_site: bool,
) -> tuple[dict[str, list[int]], rr.DynamicCrashSite | None, int]:
    samples: dict[str, list[int]] = {
        "crash_pattern_ns": [],
        "stack_depth_ns": [],
        "dynamic_crash_site_ns": [],
        "stack_trace_pattern_ns": [],
        "combined_ns": [],
    }
    if output is None:
        return samples, None, 0

    text = output.decode("utf-8", errors="replace")
    expected_depth = rr.count_first_stack_trace_frames(text)
    expected_site = (
        rr.extract_first_dynamic_library_crash_site(text, link_flags)
        if check_dynamic_site
        else None
    )

    for _ in range(iterations):
        if crash_pattern is not None:
            start_ns = time.perf_counter_ns()
            _ = re.search(crash_pattern, text) is not None
            samples["crash_pattern_ns"].append(time.perf_counter_ns() - start_ns)

        start_ns = time.perf_counter_ns()
        rr.count_first_stack_trace_frames(text)
        samples["stack_depth_ns"].append(time.perf_counter_ns() - start_ns)

        if expected_site is not None:
            start_ns = time.perf_counter_ns()
            site = rr.extract_first_dynamic_library_crash_site(
                text,
                expected_library=expected_site.library_path,
            )
            _ = site is not None and site.offset == expected_site.offset
            samples["dynamic_crash_site_ns"].append(time.perf_counter_ns() - start_ns)

        if stack_trace_pattern is not None:
            start_ns = time.perf_counter_ns()
            trace = rr.extract_stack_trace(text, harness_path=stack_trace_harness_path)
            _ = trace is not None and re.search(stack_trace_pattern, trace) is not None
            samples["stack_trace_pattern_ns"].append(time.perf_counter_ns() - start_ns)

        start_ns = time.perf_counter_ns()
        if crash_pattern is not None:
            _ = re.search(crash_pattern, text) is not None
        rr.count_first_stack_trace_frames(text)
        if expected_site is not None:
            site = rr.extract_first_dynamic_library_crash_site(
                text,
                expected_library=expected_site.library_path,
            )
            _ = site is not None and site.offset == expected_site.offset
        if stack_trace_pattern is not None:
            trace = rr.extract_stack_trace(text, harness_path=stack_trace_harness_path)
            _ = trace is not None and re.search(stack_trace_pattern, trace) is not None
        samples["combined_ns"].append(time.perf_counter_ns() - start_ns)

    return samples, expected_site, expected_depth


def measure_two_stage_validation_checks(
    fast_output: bytes | None,
    symbolized_output: bytes | None,
    iterations: int,
    link_flags: str | None,
    *,
    crash_pattern_symbolize_0: str | None,
    crash_pattern_symbolize_1: str | None,
    stack_trace_pattern: str | None,
    stack_trace_harness_path: str,
) -> tuple[dict[str, list[int]], dict[str, object]]:
    samples: dict[str, list[int]] = {"combined_ns": []}
    fast_text = output_text(fast_output)
    symbolized_text = output_text(symbolized_output)
    if fast_text is None or symbolized_text is None or crash_pattern_symbolize_0 is None:
        return samples, {
            "active": False,
            "reason": "missing representative output or symbolize=0 crash pattern",
        }

    expected_site = rr.extract_first_dynamic_library_crash_site(fast_text, link_flags)
    fast_depth = rr.count_first_stack_trace_frames(fast_text)
    symbolized_depth = rr.count_first_stack_trace_frames(symbolized_text)

    for _ in range(iterations):
        start_ns = time.perf_counter_ns()
        _ = re.search(crash_pattern_symbolize_0, fast_text) is not None
        rr.count_first_stack_trace_frames(fast_text)
        if expected_site is not None:
            site = rr.extract_first_dynamic_library_crash_site(
                fast_text,
                expected_library=expected_site.library_path,
            )
            _ = site is not None and site.offset == expected_site.offset
        if crash_pattern_symbolize_1 is not None:
            _ = re.search(crash_pattern_symbolize_1, symbolized_text) is not None
        rr.count_first_stack_trace_frames(symbolized_text)
        if stack_trace_pattern is not None:
            trace = rr.extract_stack_trace(
                symbolized_text,
                harness_path=stack_trace_harness_path,
            )
            _ = trace is not None and re.search(stack_trace_pattern, trace) is not None
        samples["combined_ns"].append(time.perf_counter_ns() - start_ns)

    return samples, {
        "active": True,
        "expected_fast_stack_depth": fast_depth,
        "expected_symbolized_stack_depth": symbolized_depth,
        "dynamic_crash_site": (
            {
                "library_path": expected_site.library_path,
                "library_name": expected_site.library_name,
                "offset": expected_site.offset,
            }
            if expected_site is not None
            else None
        ),
        "crash_pattern_symbolize_0": crash_pattern_symbolize_0,
        "crash_pattern_symbolize_1": crash_pattern_symbolize_1,
        "symbolized_crash_pattern_required": crash_pattern_symbolize_1 is not None,
        "stack_trace_pattern": stack_trace_pattern,
        "stack_trace_pattern_active": stack_trace_pattern is not None,
    }


class Report:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def title(self, text: str) -> None:
        self.lines.extend(["=" * 79, text, "=" * 79, ""])

    def section(self, letter: str, text: str) -> None:
        self.lines.extend(["", "=" * 79, f"{letter}. {text}", "=" * 79, ""])

    def subsection(self, text: str) -> None:
        self.lines.extend([text, "-" * len(text), ""])

    def add(self, text: str = "") -> None:
        self.lines.append(text)

    def table(self, headers: Sequence[str], rows: Iterable[Sequence[object]]) -> None:
        rendered = [[str(value) for value in row] for row in rows]
        widths = [len(header) for header in headers]
        for row in rendered:
            for index, value in enumerate(row):
                widths[index] = max(widths[index], len(value))
        self.lines.append("  ".join(header.ljust(widths[i]) for i, header in enumerate(headers)))
        self.lines.append("  ".join("-" * width for width in widths))
        for row in rendered:
            self.lines.append("  ".join(value.ljust(widths[i]) for i, value in enumerate(row)))
        self.lines.append("")

    def write(self, path: Path) -> None:
        path.write_text("\n".join(self.lines).rstrip() + "\n", encoding="utf-8")


def stats_row(label: str, values: Sequence[int], unit: str = "ms") -> list[str]:
    stats = calculate_stats(values)
    convert = ns_to_us if unit == "us" else ns_to_ms
    return [
        label,
        str(stats.count),
        f"{convert(stats.mean_ns):.3f}",
        f"{convert(stats.median_ns):.3f}",
        f"{convert(stats.stddev_ns):.3f}",
        f"{convert(stats.min_ns):.3f}",
        f"{convert(stats.max_ns):.3f}",
    ]


def speedup(baseline: Sequence[int], improved: Sequence[int]) -> str:
    baseline_mean = calculate_stats(baseline).mean_ns
    improved_mean = calculate_stats(improved).mean_ns
    if improved_mean == 0:
        return "n/a"
    return f"{baseline_mean / improved_mean:.2f}x"


def status_text(statuses: Counter[int]) -> str:
    return ", ".join(f"{code}:{count}" for code, count in sorted(statuses.items()))


def clang_version() -> str:
    proc = subprocess.run(
        ["clang++", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return proc.stdout.splitlines()[0] if proc.stdout else "unknown"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Measure HarnessReducer's normal, PCH, and linkage-amortized build "
            "and execution stages without running reduction."
        )
    )
    parser.add_argument("harness", help="Input C/C++ fuzz harness")
    parser.add_argument("--compile-flags", default=None, help="Compilation/preprocessor flags")
    parser.add_argument("--link-flags", required=True, help="Static/dynamic target link flags")
    parser.add_argument("--crash-input", required=True, help="Input passed to the harness")
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Name of the representative standalone executable created in the timing directory",
    )
    parser.add_argument(
        "--suffix",
        default=None,
        help="Use time-SUFFIX instead of time for the timing directory",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="Repetitions for each repeated measurement (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Per-execution timeout in seconds (default: 300)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.iterations <= 0:
        raise SystemExit("--iterations must be positive")
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")

    harness = Path(args.harness).expanduser().resolve()
    crash_input = Path(args.crash_input).expanduser().resolve()
    if not harness.is_file():
        raise SystemExit(f"Harness does not exist: {harness}")
    if not crash_input.is_file():
        raise SystemExit(f"Crash input does not exist: {crash_input}")

    if args.suffix is not None:
        if (
            not args.suffix
            or args.suffix in {".", ".."}
            or Path(args.suffix).name != args.suffix
            or "/" in args.suffix
            or "\\" in args.suffix
        ):
            raise SystemExit("--suffix must be a non-empty directory-name suffix")
        output_dir_name = f"time-{args.suffix}"
    else:
        output_dir_name = "time"

    output_dir = harness.parent / output_dir_name
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "time.txt"
    raw_path = output_dir / "raw_samples.json"
    output_name = Path(args.output).name
    if not output_name:
        raise SystemExit("-o must contain a file name")
    if output_name in {"time.txt", "raw_samples.json"}:
        raise SystemExit("-o conflicts with a timing report filename")

    commands: dict[str, list[str]] = {}
    samples: dict[str, list[int]] = {}
    execution_statuses: dict[str, Counter[int]] = {}
    one_time: dict[str, int] = {}
    startup_metrics: dict[str, object] = {}
    runner_request_samples: dict[str, dict[str, list[int]]] = {}
    runner_representative_outputs: dict[str, bytes | None] = {}
    runner_fallback_needed: dict[str, bool] = {}
    oracle_check_samples: dict[str, dict[str, list[int]]] = {}
    oracle_references: dict[str, object] = {}

    try:
        compile_flags = rr._split_flags(args.compile_flags)
        link_flags = rr._split_flags(args.link_flags)

        classification_start_ns = time.perf_counter_ns()
        link_inputs = rr.resolve_amortized_link_inputs(args.link_flags)
        one_time["link_classification_ns"] = time.perf_counter_ns() - classification_start_ns
        if link_inputs.static_libraries and link_inputs.shared_libraries:
            library_kind = "mixed"
        elif link_inputs.static_libraries:
            library_kind = "static"
        else:
            library_kind = "dynamic"

        source_start_ns = time.perf_counter_ns()
        source = harness.read_text(encoding="utf-8", errors="ignore")
        pch_prefix, _, body = rr._split_source_for_pch(source, harness.parent)
        prefix_header = output_dir / "harness_prefix.h"
        body_source = output_dir / f"{harness.stem}.harness_body{harness.suffix or '.cpp'}"
        prefix_header.write_text(pch_prefix, encoding="utf-8")
        body_source.write_text(body, encoding="utf-8")
        one_time["source_split_and_write_ns"] = time.perf_counter_ns() - source_start_ns

        normal_pch = output_dir / "harness_prefix.normal.pch"
        amortized_pch = output_dir / "harness_prefix.amortized.pch"
        commands["normal_pch_build"] = rr._build_pch_compile_command(
            str(prefix_header),
            str(normal_pch),
            args.compile_flags,
            use_replay=False,
            amortize_link=False,
        )
        commands["amortized_pch_build"] = rr._build_pch_compile_command(
            str(prefix_header),
            str(amortized_pch),
            args.compile_flags,
            use_replay=False,
            amortize_link=True,
        )
        one_time["normal_pch_build_ns"] = measure_checked_once(commands["normal_pch_build"])
        one_time["amortized_pch_build_ns"] = measure_checked_once(
            commands["amortized_pch_build"]
        )

        normal_split_object = output_dir / "normal_split.o"
        normal_pch_object = output_dir / "normal_pch.o"
        plugin_split_object = output_dir / "plugin_split.o"
        plugin_pch_object = output_dir / "plugin_pch.o"

        commands["normal_split_compile"] = [
            "clang++",
            "-Qunused-arguments",
            *rr.PHASE3_SANITIZER_FLAGS,
            *rr.PHASE3_SPLIT_OPT_FLAGS,
            *rr.PHASE3_WARNING_FLAGS,
            "-c",
            *compile_flags,
            str(harness),
            "-o",
            str(normal_split_object),
        ]
        commands["normal_pch_compile"] = [
            "clang++",
            "-Qunused-arguments",
            "-include-pch",
            str(normal_pch),
            *rr.PHASE3_SANITIZER_FLAGS,
            *rr.PHASE3_PCH_OPT_FLAGS,
            *rr.PHASE3_WARNING_FLAGS,
            "-c",
            *compile_flags,
            str(body_source),
            "-o",
            str(normal_pch_object),
        ]
        commands["plugin_split_compile"] = [
            "clang++",
            "-Qunused-arguments",
            *rr.PHASE3_PLUGIN_SANITIZER_FLAGS,
            *rr.PHASE3_SPLIT_OPT_FLAGS,
            *rr.PHASE3_WARNING_FLAGS,
            "-fPIC",
            "-c",
            *compile_flags,
            str(harness),
            "-o",
            str(plugin_split_object),
        ]
        commands["plugin_pch_compile"] = [
            "clang++",
            "-Qunused-arguments",
            "-include-pch",
            str(amortized_pch),
            *rr.PHASE3_PLUGIN_SANITIZER_FLAGS,
            *rr.PHASE3_PCH_OPT_FLAGS,
            *rr.PHASE3_WARNING_FLAGS,
            "-fPIC",
            "-c",
            *compile_flags,
            str(body_source),
            "-o",
            str(plugin_pch_object),
        ]

        for key in (
            "normal_split_compile",
            "normal_pch_compile",
            "plugin_split_compile",
            "plugin_pch_compile",
        ):
            samples[key] = measure_checked_command(commands[key], args.iterations)

        standalone = output_dir / output_name
        plugin = output_dir / "candidate.so"
        fallback_plugin = output_dir / "candidate.fallback.so"
        commands["normal_executable_link"] = [
            "clang++",
            "-Qunused-arguments",
            *rr.PHASE3_SANITIZER_FLAGS,
            str(normal_split_object),
            "-o",
            str(standalone),
            *link_flags,
        ]
        commands["candidate_plugin_link"] = [
            "clang++",
            "-Qunused-arguments",
            "-shared",
            *rr.PHASE3_PLUGIN_SANITIZER_FLAGS,
            str(plugin_pch_object),
            "-o",
            str(plugin),
        ]
        if link_inputs.plugin_link_flags:
            commands["candidate_plugin_fallback_link"] = [
                "clang++",
                "-Qunused-arguments",
                "-shared",
                *rr.PHASE3_PLUGIN_SANITIZER_FLAGS,
                str(plugin_pch_object),
                *link_inputs.plugin_link_flags,
                "-o",
                str(fallback_plugin),
            ]
        samples["normal_executable_link"] = measure_checked_command(
            commands["normal_executable_link"], args.iterations
        )
        samples["candidate_plugin_link"] = measure_checked_command(
            commands["candidate_plugin_link"], args.iterations
        )
        if "candidate_plugin_fallback_link" in commands:
            samples["candidate_plugin_fallback_link"] = measure_checked_command(
                commands["candidate_plugin_fallback_link"], args.iterations
            )

        runner_source = PROJECT_ROOT / "src" / "harnessreducer" / "harness_runner.cpp"
        production_runner = output_dir / "harness_runner"
        timing_source = output_dir / "timing_runner.cpp"
        timing_runner = output_dir / "timing_runner"
        timing_source.write_text(TIMING_RUNNER_SOURCE, encoding="utf-8")
        static_root_object = plugin_pch_object if link_inputs.static_libraries else None
        static_plan_start_ns = time.perf_counter_ns()
        static_link_plan = rr.plan_static_archive_runner_link(
            link_inputs,
            static_root_object,
            export_dir=output_dir,
        )
        one_time["static_archive_link_plan_ns"] = (
            time.perf_counter_ns() - static_plan_start_ns
        )
        link_tail = [
            *static_link_plan.flags,
            *rr.runner_dynamic_dependency_link_flags(link_inputs),
        ]
        common_runner_prefix = [
            "clang++",
            "-std=c++17",
            *rr.PHASE3_PLUGIN_SANITIZER_FLAGS,
            "-O1",
            "-gline-tables-only",
            "-fno-omit-frame-pointer",
        ]
        commands["production_runner_build"] = [
            *common_runner_prefix,
            str(runner_source),
            *link_tail,
            "-ldl",
            "-o",
            str(production_runner),
        ]
        commands["timing_runner_build"] = [
            *common_runner_prefix,
            str(timing_source),
            *link_tail,
            "-ldl",
            "-o",
            str(timing_runner),
        ]
        one_time["production_runner_build_ns"] = measure_checked_once(
            commands["production_runner_build"]
        )
        one_time["timing_runner_build_ns"] = measure_checked_once(
            commands["timing_runner_build"]
        )

        for symbolize in (False, True):
            label = f"symbolize_{int(symbolize)}"
            socket_path = output_dir / f"timing_runner_{int(symbolize)}.sock"
            startup_file = output_dir / f"runner_startup_{int(symbolize)}.txt"
            process, startup_wall_ns, current_startup = start_timing_runner(
                timing_runner,
                socket_path,
                crash_input,
                startup_file,
                link_inputs.shared_libraries,
                args.link_flags,
                symbolize,
                args.timeout,
            )
            try:
                (
                    current_samples,
                    statuses,
                    representative_output,
                    fallback_needed,
                ) = measure_runner_requests(
                    socket_path,
                    plugin,
                    args.iterations,
                    (
                        fallback_plugin
                        if "candidate_plugin_fallback_link" in commands
                        else None
                    ),
                )
            finally:
                stop_runner(process, socket_path)
            runner_request_samples[label] = current_samples
            runner_representative_outputs[label] = representative_output
            runner_fallback_needed[label] = fallback_needed
            execution_statuses[f"amortized_{label}"] = statuses
            if not symbolize:
                one_time["runner_startup_wall_ns"] = startup_wall_ns
                startup_metrics = current_startup

        oracle_crash_patterns = {
            label: crash_pattern_from_output(runner_representative_outputs.get(label))
            for label in ("symbolize_0", "symbolize_1")
        }
        oracle_stack_trace_pattern = stack_trace_pattern_from_output(
            runner_representative_outputs.get("symbolize_1"),
            harness_path=str(body_source),
        )

        for symbolize in (False, True):
            label = f"symbolize_{int(symbolize)}"
            current_samples, expected_site, expected_depth = measure_oracle_checks(
                runner_representative_outputs.get(label),
                args.iterations,
                args.link_flags,
                crash_pattern=oracle_crash_patterns.get(label),
                stack_trace_pattern=(
                    oracle_stack_trace_pattern if symbolize else None
                ),
                stack_trace_harness_path=str(body_source),
                check_dynamic_site=not symbolize,
            )
            oracle_check_samples[label] = current_samples
            oracle_references[label] = {
                "crash_pattern": oracle_crash_patterns.get(label),
                "crash_pattern_active": oracle_crash_patterns.get(label) is not None,
                "expected_stack_depth": expected_depth,
                "stack_trace_pattern": (
                    oracle_stack_trace_pattern if symbolize else None
                ),
                "stack_trace_pattern_active": (
                    symbolize and oracle_stack_trace_pattern is not None
                ),
                "dynamic_crash_site": (
                    {
                        "library_path": expected_site.library_path,
                        "library_name": expected_site.library_name,
                        "offset": expected_site.offset,
                    }
                    if expected_site is not None
                    else None
                ),
            }
        two_stage_samples, two_stage_reference = measure_two_stage_validation_checks(
            runner_representative_outputs.get("symbolize_0"),
            runner_representative_outputs.get("symbolize_1"),
            args.iterations,
            args.link_flags,
            crash_pattern_symbolize_0=oracle_crash_patterns.get("symbolize_0"),
            crash_pattern_symbolize_1=oracle_crash_patterns.get("symbolize_1"),
            stack_trace_pattern=oracle_stack_trace_pattern,
            stack_trace_harness_path=str(body_source),
        )
        oracle_check_samples["two_stage_slice_inline"] = two_stage_samples
        oracle_references["two_stage_slice_inline"] = two_stage_reference

        for symbolize in (False, True):
            label = f"symbolize_{int(symbolize)}"
            current_samples, statuses = measure_standalone_execution(
                standalone,
                crash_input,
                args.iterations,
                args.link_flags,
                symbolize,
                args.timeout,
            )
            samples[f"standalone_{label}"] = current_samples
            execution_statuses[f"standalone_{label}"] = statuses

        report = Report()
        report.title("HARNESSREDUCER TIMING BENCHMARK")
        report.subsection("Benchmark configuration")
        report.table(
            ["Field", "Value"],
            [
                ("Generated", datetime.now().astimezone().isoformat()),
                ("Harness", harness),
                ("Crash input", crash_input),
                ("Crash input bytes", crash_input.stat().st_size),
                ("Iterations", args.iterations),
                ("Suffix", args.suffix or "(none)"),
                ("Output directory", output_dir),
                ("Representative executable", standalone),
                ("Compile flags", args.compile_flags or "(none)"),
                ("Link flags", args.link_flags),
                ("Library configuration", library_kind),
                ("Platform", platform.platform()),
                ("Python", platform.python_version()),
                ("Compiler", clang_version()),
                ("Clock", "time.perf_counter_ns / C++ steady_clock"),
            ],
        )

        report.section("A", "LIBRARY CLASSIFICATION")
        report.subsection("Resolved target inputs")
        library_rows: list[tuple[str, str]] = []
        library_rows.extend(("Static target", path) for path in link_inputs.static_libraries)
        library_rows.extend(("Dynamic target", path) for path in link_inputs.shared_libraries)
        if not library_rows:
            library_rows.append(("Target", "(none)"))
        report.table(["Kind", "Resolved path"], library_rows)
        report.subsection("Normal one-time runner dependencies")
        report.add(format_command(link_inputs.runner_link_flags) or "(none)")
        if link_inputs.static_libraries:
            report.subsection("Static archive runner extraction")
            extraction_mode = (
                "whole-archive fallback"
                if static_link_plan.uses_whole_archive
                else "rooted undefined-symbol closure"
            )
            report.table(
                ["Field", "Value"],
                [
                    ("Mode", extraction_mode),
                    ("Root symbol count", len(static_link_plan.root_symbols)),
                    (
                        "Static archives copied for export fix",
                        len(static_link_plan.visibility_exported_libraries),
                    ),
                    (
                        "Static symbols made exportable",
                        static_link_plan.visibility_exported_symbol_count,
                    ),
                    (
                        "Root symbols",
                        (
                            ", ".join(static_link_plan.root_symbols[:20])
                            + (
                                " ..."
                                if len(static_link_plan.root_symbols) > 20
                                else ""
                            )
                        )
                        or "(none)",
                    ),
                ],
            )

        report.section("B", "ONE-TIME PREPARATION")
        if link_inputs.static_libraries:
            static_build_note = (
                " (rooted static archive extraction)"
                if not static_link_plan.uses_whole_archive
                else " (whole-archive static fallback)"
            )
        else:
            static_build_note = ""
        one_time_rows = [
            ("Classify link flags", ns_to_ms(one_time["link_classification_ns"])),
            ("Split source and write PCH inputs", ns_to_ms(one_time["source_split_and_write_ns"])),
            ("Build normal PCH", ns_to_ms(one_time["normal_pch_build_ns"])),
            ("Build amortized PCH", ns_to_ms(one_time["amortized_pch_build_ns"])),
            (
                "Plan static archive runner link",
                ns_to_ms(one_time["static_archive_link_plan_ns"]),
            ),
            (
                "Build production harness_runner" + static_build_note,
                ns_to_ms(one_time["production_runner_build_ns"]),
            ),
            (
                "Build instrumented timing runner" + static_build_note,
                ns_to_ms(one_time["timing_runner_build_ns"]),
            ),
            ("Start timing runner until ready", ns_to_ms(one_time["runner_startup_wall_ns"])),
        ]
        report.table(
            ["Operation", "Time (ms)"],
            [(name, f"{value:.3f}") for name, value in one_time_rows],
        )
        report.subsection("Runner-internal startup breakdown (symbolize=0)")
        if link_inputs.shared_libraries:
            target_dlopen_ns = int(
                startup_metrics.get("target_dlopen_total_ns", 0)
            )
            target_dlopen_result = f"{ns_to_ms(target_dlopen_ns):.3f}"
        else:
            target_dlopen_result = "N/A (static targets are linked into the runner)"
        startup_rows = [
            ("All dynamic-target dlopen calls", target_dlopen_result),
            (
                "Read crash input",
                f"{ns_to_ms(int(startup_metrics.get('crash_input_read_ns', 0))):.3f}",
            ),
            (
                "Create/bind/listen socket",
                f"{ns_to_ms(int(startup_metrics.get('socket_setup_ns', 0))):.3f}",
            ),
            (
                "Internal startup total",
                f"{ns_to_ms(int(startup_metrics.get('startup_internal_total_ns', 0))):.3f}",
            ),
        ]
        report.table(
            ["Operation", "Time (ms) or status"],
            startup_rows,
        )
        target_timings = startup_metrics.get("target_dlopen_ns", [])
        if isinstance(target_timings, list) and target_timings:
            report.subsection("Individual dynamic-target dlopen calls")
            report.table(
                ["Target", "Time (ms)"],
                [
                    (entry["path"], f"{ns_to_ms(entry['ns']):.3f}")
                    for entry in target_timings
                ],
            )

        report.section("C", f"OBJECT COMPILATION — {args.iterations} ITERATIONS")
        report.table(
            ["Path", "Headers", "Output", "N", "Mean ms", "Median", "Stddev", "Min", "Max"],
            [
                ["Normal", "Split", "Executable .o", *stats_row("", samples["normal_split_compile"])[1:]],
                ["Normal", "PCH", "Executable .o", *stats_row("", samples["normal_pch_compile"])[1:]],
                ["Amortized", "Split", "Plugin .o", *stats_row("", samples["plugin_split_compile"])[1:]],
                ["Amortized", "PCH", "Plugin .o", *stats_row("", samples["plugin_pch_compile"])[1:]],
            ],
        )
        report.subsection("Compilation comparisons")
        report.table(
            ["Comparison", "Speedup"],
            [
                ("PCH benefit for normal compilation", speedup(samples["normal_split_compile"], samples["normal_pch_compile"])),
                ("PCH benefit for amortized compilation", speedup(samples["plugin_split_compile"], samples["plugin_pch_compile"])),
                ("Plugin split versus normal split", speedup(samples["normal_split_compile"], samples["plugin_split_compile"])),
                ("Plugin PCH versus normal PCH", speedup(samples["normal_pch_compile"], samples["plugin_pch_compile"])),
            ],
        )

        report.section("D", f"OUTPUT LINKING — {args.iterations} ITERATIONS")
        link_rows = [
            stats_row("Normal executable", samples["normal_executable_link"]),
            stats_row("Candidate plugin.so", samples["candidate_plugin_link"]),
        ]
        if "candidate_plugin_fallback_link" in samples:
            link_rows.append(
                stats_row(
                    "Candidate plugin fallback.so",
                    samples["candidate_plugin_fallback_link"],
                )
            )
        report.table(
            ["Output", "N", "Mean ms", "Median", "Stddev", "Min", "Max"],
            link_rows,
        )
        report.add(
            "Plugin-link speedup over normal executable link: "
            + speedup(samples["normal_executable_link"], samples["candidate_plugin_link"])
        )
        if "candidate_plugin_fallback_link" in samples:
            report.subsection("Fallback use during candidate execution")
            fallback_rows: list[list[str]] = []
            for symbolize in (0, 1):
                label = f"symbolize_{symbolize}"
                fallback_rows.append(
                    [
                        f"symbolize={symbolize}",
                        "yes" if runner_fallback_needed.get(label, False) else "no",
                    ]
                )
            report.table(
                [
                    "Mode",
                    "Fallback needed?",
                ],
                fallback_rows,
            )
            report.add(
                "Fallback is needed when the lightweight candidate plugin fails "
                "to load with an unresolved symbol."
            )
        else:
            report.add("No candidate plugin fallback link was configured.")

        report.section("E", f"END-TO-END EXECUTION — {args.iterations} ITERATIONS")
        execution_rows: list[list[str]] = []
        for path_label, sample_key, status_key in (
            ("Standalone", "standalone_symbolize_0", "standalone_symbolize_0"),
            ("Standalone", "standalone_symbolize_1", "standalone_symbolize_1"),
            ("Amortized", "symbolize_0", "amortized_symbolize_0"),
            ("Amortized", "symbolize_1", "amortized_symbolize_1"),
        ):
            symbolize_value = sample_key.rsplit("_", 1)[-1]
            values = (
                runner_request_samples[sample_key]["end_to_end_ns"]
                if path_label == "Amortized"
                else samples[sample_key]
            )
            stats = calculate_stats(values)
            execution_rows.append(
                [
                    path_label,
                    symbolize_value,
                    str(stats.count),
                    f"{ns_to_ms(stats.mean_ns):.3f}",
                    f"{ns_to_ms(stats.median_ns):.3f}",
                    f"{ns_to_ms(stats.stddev_ns):.3f}",
                    f"{ns_to_ms(stats.min_ns):.3f}",
                    f"{ns_to_ms(stats.max_ns):.3f}",
                    status_text(execution_statuses[status_key]),
                ]
            )
        report.table(
            ["Path", "Symbolize", "N", "Mean ms", "Median", "Stddev", "Min", "Max", "Statuses code:count"],
            execution_rows,
        )
        report.subsection("Execution comparisons")
        report.table(
            ["Comparison", "Speedup"],
            [
                (
                    "Amortization, symbolize=0",
                    speedup(samples["standalone_symbolize_0"], runner_request_samples["symbolize_0"]["end_to_end_ns"]),
                ),
                (
                    "Amortization, symbolize=1",
                    speedup(samples["standalone_symbolize_1"], runner_request_samples["symbolize_1"]["end_to_end_ns"]),
                ),
                (
                    "symbolize=0 versus 1, standalone",
                    speedup(samples["standalone_symbolize_1"], samples["standalone_symbolize_0"]),
                ),
                (
                    "symbolize=0 versus 1, amortized",
                    speedup(runner_request_samples["symbolize_1"]["end_to_end_ns"], runner_request_samples["symbolize_0"]["end_to_end_ns"]),
                ),
            ],
        )
        report.subsection("Python-side candidate oracle parsing")
        oracle_rows: list[list[str]] = []
        for label in ("symbolize_0", "symbolize_1"):
            reference = oracle_references.get(label, {})
            expected_depth = (
                reference.get("expected_stack_depth", 0)
                if isinstance(reference, dict)
                else 0
            )
            dynamic_site = (
                reference.get("dynamic_crash_site")
                if isinstance(reference, dict)
                else None
            )
            crash_pattern_active = bool(
                reference.get("crash_pattern_active")
                if isinstance(reference, dict)
                else False
            )
            stack_trace_pattern_active = bool(
                reference.get("stack_trace_pattern_active")
                if isinstance(reference, dict)
                else False
            )
            current = oracle_check_samples[label]
            oracle_rows.append(
                [
                    label,
                    (
                        "crash regex match"
                        if crash_pattern_active
                        else "crash regex match (not active)"
                    ),
                    *stats_row("", current["crash_pattern_ns"], "us")[1:],
                ]
            )
            oracle_rows.append(
                [
                    label,
                    f"stack-depth check (expected {expected_depth})",
                    *stats_row("", current["stack_depth_ns"], "us")[1:],
                ]
            )
            oracle_rows.append(
                [
                    label,
                    (
                        "dynamic .so offset check"
                        if dynamic_site is not None
                        else "dynamic .so offset check (not active)"
                    ),
                    *stats_row("", current["dynamic_crash_site_ns"], "us")[1:],
                ]
            )
            oracle_rows.append(
                [
                    label,
                    (
                        "pre-harness stack-trace regex"
                        if stack_trace_pattern_active
                        else "pre-harness stack-trace regex (not active)"
                    ),
                    *stats_row("", current["stack_trace_pattern_ns"], "us")[1:],
                ]
            )
            oracle_rows.append(
                [
                    label,
                    "combined active checks",
                    *stats_row("", current["combined_ns"], "us")[1:],
                ]
            )
        two_stage_reference = oracle_references.get("two_stage_slice_inline", {})
        two_stage_symbolized_required = (
            two_stage_reference.get("symbolized_crash_pattern_required", False)
            if isinstance(two_stage_reference, dict)
            else False
        )
        oracle_rows.append(
            [
                "two_stage_slice_inline",
                (
                    "symbolize=0 crash + symbolize=1 crash/depth/stack"
                    if two_stage_symbolized_required
                    else "symbolize=0 crash + symbolize=1 depth/stack"
                ),
                *stats_row(
                    "",
                    oracle_check_samples["two_stage_slice_inline"]["combined_ns"],
                    "us",
                )[1:],
            ]
        )
        report.table(
            ["Output", "Check", "N", "Mean us", "Median", "Stddev", "Min", "Max"],
            oracle_rows,
        )
        dynamic_reference = oracle_references.get("symbolize_0", {})
        dynamic_site = (
            dynamic_reference.get("dynamic_crash_site")
            if isinstance(dynamic_reference, dict)
            else None
        )
        if isinstance(dynamic_site, dict):
            report.add(
                "Recorded dynamic crash-site used for timing: "
                f"{dynamic_site['library_path']}+{dynamic_site['offset']}"
            )
        report.add(
            "These rows measure Python parsing of already captured output. They are "
            "not extra harness executions."
        )
        report.add(
            "The two-stage row mirrors slicing/inline validation: first the "
            "symbolize=0 crash-pattern check, then the symbolize=1 stack/depth "
            "check; a symbolize=1 crash regex is included only when one was "
            "extracted."
        )

        report.section("F", f"AMORTIZED REQUEST BREAKDOWN — {args.iterations} ITERATIONS")
        for symbolize in (0, 1):
            key = f"symbolize_{symbolize}"
            report.subsection(f"symbolize={symbolize}")
            current = runner_request_samples[key]
            report.table(
                ["Stage", "N", "Mean us", "Median", "Stddev", "Min", "Max"],
                [
                    stats_row("Socket + complete request", current["end_to_end_ns"], "us"),
                    *(
                        [
                            stats_row(
                                "Failed fast-path request before fallback",
                                current["fallback_trigger_request_ns"],
                                "us",
                            )
                        ]
                        if current["fallback_trigger_request_ns"]
                        else []
                    ),
                    stats_row("Monitor fork", current["monitor_fork_ns"], "us"),
                    stats_row("Executor fork", current["executor_fork_ns"], "us"),
                    stats_row("dlopen(candidate.so)", current["candidate_dlopen_ns"], "us"),
                    stats_row("dlsym(callback)", current["dlsym_ns"], "us"),
                    stats_row("Call to child termination", current["execute_to_exit_ns"], "us"),
                    stats_row("Output-pipe interval (overlaps call)", current["output_pipe_ns"], "us"),
                    stats_row("waitpid after pipe EOF", current["waitpid_ns"], "us"),
                    stats_row("Monitor internal total", current["monitor_total_ns"], "us"),
                ],
            )
        report.add(
            "Note: 'Call to child termination' includes target execution and sanitizer crash "
            "reporting. The output-pipe interval overlaps that time and must not be added to it."
        )
        report.add(
            "If fallback is triggered, the request end-to-end row includes the failed "
            "fast-path load request plus the successful fallback load request. The fallback "
            "plugin link itself is measured in section D."
        )

        report.section("G", "COMMANDS USED")
        for name, command in commands.items():
            report.subsection(name.replace("_", " ").title())
            report.add(format_command(command))
            report.add()

        report.section("H", "ARTIFACTS")
        artifact_rows = [
            ("Human-readable report", report_path),
            ("Raw timing samples", raw_path),
            ("PCH prefix header", prefix_header),
            ("Normal PCH", normal_pch),
            ("Amortized PCH", amortized_pch),
            ("Include-free harness body", body_source),
            ("Representative executable", standalone),
            ("Candidate plugin", plugin),
            *(
                [("Fallback candidate plugin", fallback_plugin)]
                if "candidate_plugin_fallback_link" in commands
                else []
            ),
            *(
                [
                    (f"Temporary fixed static archive {index}", path)
                    for index, path in enumerate(
                        static_link_plan.visibility_exported_libraries,
                        start=1,
                    )
                ]
                if static_link_plan.visibility_exported_libraries
                else []
            ),
            ("Production runner", production_runner),
            ("Instrumented runner", timing_runner),
        ]
        report.table(["Artifact", "Path"], artifact_rows)
        report.write(report_path)

        raw_data = {
            "configuration": {
                "harness": str(harness),
                "crash_input": str(crash_input),
                "iterations": args.iterations,
                "suffix": args.suffix,
                "output_directory": str(output_dir),
                "compile_flags": args.compile_flags,
                "link_flags": args.link_flags,
                "library_kind": library_kind,
                "static_libraries": list(link_inputs.static_libraries),
                "shared_libraries": list(link_inputs.shared_libraries),
                "runner_link_flags": list(link_inputs.runner_link_flags),
                "plugin_fallback_link_flags": list(link_inputs.plugin_link_flags),
                "static_archive_link_plan": {
                    "uses_whole_archive": static_link_plan.uses_whole_archive,
                    "root_symbols": list(static_link_plan.root_symbols),
                    "visibility_exported_libraries": list(
                        static_link_plan.visibility_exported_libraries
                    ),
                    "visibility_exported_symbol_count": (
                        static_link_plan.visibility_exported_symbol_count
                    ),
                    "flags": list(static_link_plan.flags),
                },
            },
            "one_time_ns": one_time,
            "startup_metrics": startup_metrics,
            "repeated_samples_ns": samples,
            "runner_request_samples_ns": runner_request_samples,
            "runner_fallback_needed": runner_fallback_needed,
            "oracle_check_samples_ns": oracle_check_samples,
            "oracle_references": oracle_references,
            "execution_statuses": {
                key: dict(value) for key, value in execution_statuses.items()
            },
            "commands": commands,
        }
        raw_path.write_text(json.dumps(raw_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[+] Timing report: {report_path}")
        print(f"[+] Raw samples:  {raw_path}")
        return 0
    except Exception as exc:
        report_path.write_text(
            "HARNESSREDUCER TIMING BENCHMARK FAILED\n"
            "======================================\n\n"
            f"{type(exc).__name__}: {exc}\n",
            encoding="utf-8",
        )
        print(f"[-] Measurement failed: {exc}", file=sys.stderr)
        print(f"[-] Failure report: {report_path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

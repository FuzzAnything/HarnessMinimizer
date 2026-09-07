#ifndef HARNESSREDUCER_PROCESS_SUPERVISOR_H
#define HARNESSREDUCER_PROCESS_SUPERVISOR_H

// Shared by the production and measurement runners. The existing monitor
// blocks in ppoll: no watcher process/thread and no periodic wakeups.
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace hrprocess {
inline volatile sig_atomic_t Stopping = 0;
inline sigset_t WaitMask;
inline uint64_t NowNs() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
}
inline void Stop(int) { Stopping = 1; }
inline void ChildExited(int) {}

inline bool FollowOwner() {
  const char *owner = std::getenv("HARNESSREDUCER_RUNNER_PARENT_PID");
  if (!owner) return true; // Also support directly launched standalone runners.
  pid_t expected = static_cast<pid_t>(std::strtol(owner, nullptr, 10));
  return expected > 0 && prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && getppid() == expected;
}

inline bool PrepareMonitor(pid_t server) {
  struct sigaction action {};
  sigemptyset(&action.sa_mask);
  action.sa_handler = ChildExited;
  if (sigaction(SIGCHLD, &action, nullptr) < 0) return false;
  action.sa_handler = Stop;
  if (sigaction(SIGTERM, &action, nullptr) < 0 ||
      sigaction(SIGHUP, &action, nullptr) < 0 ||
      sigaction(SIGINT, &action, nullptr) < 0) return false;
  // Block CHLD before checking child state. ppoll atomically unmasks it,
  // avoiding the exit-between-waitpid-and-poll lost-wakeup race.
  sigset_t blocked;
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGCHLD);
  sigaddset(&blocked, SIGTERM);
  sigaddset(&blocked, SIGHUP);
  sigaddset(&blocked, SIGINT);
  if (sigprocmask(SIG_BLOCK, &blocked, &WaitMask) < 0) return false;
  sigdelset(&WaitMask, SIGCHLD);
  sigdelset(&WaitMask, SIGTERM);
  sigdelset(&WaitMask, SIGHUP);
  sigdelset(&WaitMask, SIGINT);
  if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0 ||
      prctl(PR_SET_PDEATHSIG, SIGTERM) < 0) return false;
  if (getppid() != server) Stopping = 1;
  return true;
}

inline void PrepareExecutor(pid_t monitor) {
  if (setpgid(0, 0) < 0) _exit(125);
  signal(SIGCHLD, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGHUP, SIG_DFL);
  signal(SIGINT, SIG_DFL);
  sigprocmask(SIG_SETMASK, &WaitMask, nullptr);
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != monitor)
    _exit(125);
}

inline size_t OutputLimit() {
  const char *value = std::getenv("HARNESSREDUCER_MAX_OUTPUT_BYTES");
  if (value && *value) {
    char *end = nullptr;
    unsigned long long limit = std::strtoull(value, &end, 10);
    if (end != value && *end == '\0' && limit > 0) return limit;
  }
  return 64U * 1024U * 1024U;
}

inline int Poll(pollfd *fds, nfds_t count, uint64_t deadline) {
  uint64_t now = NowNs();
  if (now >= deadline) return 0;
  uint64_t left = deadline - now;
  timespec duration {static_cast<time_t>(left / 1000000000),
                     static_cast<long>(left % 1000000000)};
  return ppoll(fds, count, &duration, &WaitMask);
}

inline std::string ReadRequest(int fd, uint64_t deadline) {
  std::string path;
  while (!Stopping && path.size() < 65536) {
    pollfd event {fd, POLLIN, 0};
    int ready = Poll(&event, 1, deadline);
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0) return {};
    char buffer[4096];
    ssize_t size = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
    if (size < 0 && (errno == EINTR || errno == EAGAIN)) continue;
    if (size <= 0) return {};
    path.append(buffer, size);
    size_t newline = path.find('\n');
    if (newline != std::string::npos) {
      path.resize(newline);
      return path;
    }
  }
  return {};
}

inline bool Send(int fd, const std::string &data, uint64_t deadline) {
  size_t offset = 0;
  while (offset < data.size() && !Stopping) {
    ssize_t size = send(fd, data.data() + offset, data.size() - offset,
                        MSG_DONTWAIT | MSG_NOSIGNAL);
    if (size > 0) { offset += size; continue; }
    if (size < 0 && errno == EINTR) continue;
    if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      pollfd event {fd, POLLOUT, 0};
      int ready = Poll(&event, 1, deadline);
      if (ready < 0 && errno == EINTR) continue;
      if (ready > 0 && !(event.revents & (POLLERR | POLLHUP | POLLNVAL))) continue;
    }
    return false;
  }
  return offset == data.size();
}

struct Result {
  std::string output;
  std::string auxiliary;
  int status = 1;
  uint64_t child_end_ns = 0;
  uint64_t output_pipe_ns = 0;
  uint64_t waitpid_ns = 0;
};

inline void KillGroup(pid_t child) {
  if (child > 0) kill(-child, SIGKILL);
}

inline Result Supervise(pid_t child, int output_fd, int connection,
                        uint64_t deadline, int auxiliary_fd = -1,
                        size_t auxiliary_limit = 0) {
  Result result;
  const uint64_t started = NowNs();
  uint64_t auxiliary_end = auxiliary_fd < 0 ? started : 0;
  uint64_t output_end = 0;
  uint64_t cleanup_deadline = 0;
  const size_t output_limit = OutputLimit();
  bool reaped = child < 0;
  bool children_remain = false;
  bool failed = child < 0;
  bool connected = true;
  if (child > 0) setpgid(child, child); // Pair with child-side setpgid to close the race.
  fcntl(output_fd, F_SETFL, fcntl(output_fd, F_GETFL) | O_NONBLOCK);
  if (auxiliary_fd >= 0)
    fcntl(auxiliary_fd, F_SETFL, fcntl(auxiliary_fd, F_GETFL) | O_NONBLOCK);

  auto fail = [&](int status, const char *message) {
    if (!failed) {
      failed = true;
      result.status = status;
      result.output.append(message);
      cleanup_deadline = NowNs() + 1000000000;
    }
    KillGroup(child);
  };

  while (true) {
    if (Stopping) fail(125, "Execution cancelled.\n");
    if (!failed && NowNs() >= deadline)
      fail(124, "Execution timed out.\n");
    if (!reaped) {
      siginfo_t info {};
      if (waitid(P_PID, child, &info, WEXITED | WNOHANG | WNOWAIT) == 0 && info.si_pid) {
        // Retain the leader PID until group cleanup has been signaled.
        KillGroup(child);
        int status = 0;
        uint64_t wait_start = NowNs();
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        result.waitpid_ns = NowNs() - wait_start;
        result.child_end_ns = NowNs();
        reaped = true;
        if (!failed && waited == child)
          result.status = WIFEXITED(status) ? WEXITSTATUS(status) :
                          WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1;
        if (!cleanup_deadline) cleanup_deadline = NowNs() + 1000000000;
      }
    }
    if (reaped) {
      pid_t waited;
      do { waited = waitpid(-1, nullptr, WNOHANG); } while (waited > 0 || (waited < 0 && errno == EINTR));
      children_remain = waited == 0;
    }
    if (reaped && !children_remain && output_fd < 0 && auxiliary_fd < 0) break;
    if (cleanup_deadline && NowNs() >= cleanup_deadline) {
      if (!failed) fail(125, "Execution cleanup did not finish.\n");
      break;
    }
    pollfd events[3] {{output_fd, POLLIN, 0}, {auxiliary_fd, POLLIN, 0},
                      {connected ? connection : -1, POLLIN, 0}};
    uint64_t until = cleanup_deadline ? cleanup_deadline : deadline;
    int ready = Poll(events, 3, until);
    if (ready < 0) {
      if (errno == EINTR) continue;
      fail(125, "Execution poll failed.\n");
      continue;
    }
    if (events[2].revents) {
      char byte;
      ssize_t size = recv(connection, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
      if (size == 0 || size > 0 || (size < 0 && errno != EAGAIN && errno != EINTR)) {
        connected = false;
        fail(125, "Execution client disconnected.\n");
      }
    }
    for (int index = 0; index < 2; ++index) {
      int &fd = index == 0 ? output_fd : auxiliary_fd;
      if (fd < 0 || !events[index].revents) continue;
      char buffer[16384];
      ssize_t size = read(fd, buffer, sizeof(buffer));
      if (size < 0 && (errno == EAGAIN || errno == EINTR)) continue;
      if (size <= 0) {
        close(fd); fd = -1;
        if (index == 0) output_end = NowNs(); else auxiliary_end = NowNs();
        continue;
      }
      std::string &target = index == 0 ? result.output : result.auxiliary;
      size_t limit = index == 0 ? output_limit : auxiliary_limit;
      if (target.size() + static_cast<size_t>(size) > limit) {
        fail(125, "Execution output limit exceeded.\n");
        close(fd); fd = -1;
      } else {
        target.append(buffer, size);
      }
    }
  }
  if (output_fd >= 0) close(output_fd);
  if (auxiliary_fd >= 0) close(auxiliary_fd);
  if (!reaped) KillGroup(child);
  result.output_pipe_ns = output_end > auxiliary_end && auxiliary_end ? output_end - auxiliary_end : 0;
  return result;
}
} // namespace hrprocess
#endif

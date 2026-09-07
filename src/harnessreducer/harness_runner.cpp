#include "process_supervisor.h"
#include <cerrno>
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
#include <vector>

namespace {

using RunOneFn = int (*)(const uint8_t *, size_t);

void CloseHandles(std::vector<void *> &handles) {
  for (void *handle : handles) {
    if (handle != nullptr)
      dlclose(handle);
  }
  handles.clear();
}

bool LoadTargetLibraries(const std::vector<std::string> &paths,
                         const char *order_name,
                         std::vector<void *> &handles, std::string &error) {
  for (const std::string &path : paths) {
    void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (handle == nullptr) {
      error = std::string("dlopen target failed during ") + order_name +
              " order for " + path + ": " + dlerror();
      return false;
    }
    handles.push_back(handle);
  }
  return true;
}

bool LoadTargetLibrariesWithRetry(const std::vector<std::string> &paths,
                                  std::vector<void *> &handles) {
  std::string forward_error;
  if (LoadTargetLibraries(paths, "original", handles, forward_error))
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
  if (LoadTargetLibraries(reversed_paths, "reverse", handles, reverse_error))
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

void HandleRequest(int connection, int listen_fd,
                   const std::vector<uint8_t> &crash_data,
                   int exec_timeout_seconds) {
  close(listen_fd);
  const uint64_t deadline = hrprocess::NowNs() + uint64_t(exec_timeout_seconds) * 1000000000;
  const std::string plugin_path = hrprocess::ReadRequest(connection, deadline);
  if (plugin_path.empty()) {
    const std::string response = "1 0\n";
    hrprocess::Send(connection, response, deadline);
    close(connection);
    _exit(0);
  }

  int output_pipe[2];
  if (pipe(output_pipe) != 0) {
    const std::string message = std::string("pipe failed: ") + strerror(errno) + "\n";
    const std::string header = "1 " + std::to_string(message.size()) + "\n";
    hrprocess::Send(connection, header, deadline);
    hrprocess::Send(connection, message, deadline);
    close(connection);
    _exit(0);
  }

  // The main server ignores SIGCHLD to avoid monitor zombies. The monitor must
  // restore normal handling so it can wait for the candidate executor.
  const pid_t monitor = getpid();
  const pid_t child = fork();
  if (child == 0) {
    hrprocess::PrepareExecutor(monitor);
    close(output_pipe[0]);
    dup2(output_pipe[1], STDOUT_FILENO);
    dup2(output_pipe[1], STDERR_FILENO);
    close(output_pipe[1]);
    close(connection);

    void *plugin = dlopen(plugin_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (plugin == nullptr) {
      std::fprintf(stderr, "dlopen candidate failed: %s\n", dlerror());
      _exit(125);
    }
    dlerror();
    auto run_one = reinterpret_cast<RunOneFn>(
        dlsym(plugin, "LLVMFuzzerTestOneInput"));
    if (const char *error = dlerror()) {
      std::fprintf(stderr, "dlsym LLVMFuzzerTestOneInput failed: %s\n", error);
      _exit(125);
    }

    const uint8_t *data = crash_data.empty() ? nullptr : crash_data.data();
    const int result = run_one(data, crash_data.size());
    _exit(result & 0xff);
  }

  close(output_pipe[1]);
  auto result = hrprocess::Supervise(child, output_pipe[0], connection, deadline);
  const std::string header = std::to_string(result.status) + " " +
                             std::to_string(result.output.size()) + "\n";
  const uint64_t reply_deadline = hrprocess::NowNs() + 1000000000;
  hrprocess::Send(connection, header, reply_deadline);
  hrprocess::Send(connection, result.output, reply_deadline);
  close(connection);
  _exit(0);
}

} // namespace

int main(int argc, char **argv) {
  if (!hrprocess::FollowOwner()) return 125;
  if (argc < 4) {
    std::fprintf(stderr,
                 "usage: harness_runner SOCKET CRASH_INPUT EXEC_TIMEOUT_SECS "
                 "[TARGET_SO...]\n");
    return 2;
  }

  char *timeout_end = nullptr;
  const unsigned long parsed_timeout = std::strtoul(argv[3], &timeout_end, 10);
  if (timeout_end == nullptr || *timeout_end != '\0' || parsed_timeout == 0UL) {
    std::fprintf(stderr, "invalid execution timeout: %s\n", argv[3]);
    return 2;
  }
  const int exec_timeout_seconds = static_cast<int>(parsed_timeout);

  std::vector<std::string> target_paths;
  for (int index = 4; index < argc; ++index) {
    target_paths.emplace_back(argv[index]);
  }
  std::vector<void *> target_handles;
  if (!LoadTargetLibrariesWithRetry(target_paths, target_handles))
    return 2;

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

  struct sigaction action {};
  action.sa_handler = SIG_IGN;
  action.sa_flags = SA_NOCLDWAIT;
  sigemptyset(&action.sa_mask);
  sigaction(SIGCHLD, &action, nullptr);

  const pid_t server = getpid();
  while (true) {
    const int connection = accept(listen_fd, nullptr, nullptr);
    if (connection < 0) {
      if (errno == EINTR)
        continue;
      std::perror("accept");
      break;
    }
    const pid_t monitor = fork();
    if (monitor == 0) {
      if (!hrprocess::PrepareMonitor(server)) _exit(125);
      HandleRequest(connection, listen_fd, crash_data, exec_timeout_seconds);
    }
    close(connection);
  }

  close(listen_fd);
  unlink(socket_path.c_str());
  return 0;
}

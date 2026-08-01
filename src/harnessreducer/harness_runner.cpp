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
volatile sig_atomic_t TimedChild = -1;
volatile sig_atomic_t ChildTimedOut = 0;

void HandleTimeout(int) {
  ChildTimedOut = 1;
  if (TimedChild > 0)
    kill(static_cast<pid_t>(TimedChild), SIGKILL);
}

bool WriteAll(int fd, const char *data, size_t size) {
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
  const std::string plugin_path = ReadPluginPath(connection);
  if (plugin_path.empty()) {
    const std::string response = "1 0\n";
    WriteAll(connection, response.data(), response.size());
    close(connection);
    _exit(0);
  }

  int output_pipe[2];
  if (pipe(output_pipe) != 0) {
    const std::string message = std::string("pipe failed: ") + strerror(errno) + "\n";
    const std::string header = "1 " + std::to_string(message.size()) + "\n";
    WriteAll(connection, header.data(), header.size());
    WriteAll(connection, message.data(), message.size());
    close(connection);
    _exit(0);
  }

  // The main server ignores SIGCHLD to avoid monitor zombies. The monitor must
  // restore normal handling so it can wait for the candidate executor.
  signal(SIGCHLD, SIG_DFL);
  const pid_t child = fork();
  if (child == 0) {
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

  TimedChild = child;
  ChildTimedOut = 0;
  signal(SIGALRM, HandleTimeout);
  alarm(static_cast<unsigned int>(exec_timeout_seconds));
  close(output_pipe[1]);
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
  alarm(0);
  if (ChildTimedOut) {
    output.append("Execution timed out after ");
    output.append(std::to_string(exec_timeout_seconds));
    output.append(" seconds.\n");
  }

  int wait_status = 0;
  if (child < 0 || waitpid(child, &wait_status, 0) < 0)
    wait_status = 1 << 8;
  const int exit_code = ChildTimedOut ? 124 : WaitStatusToExitCode(wait_status);
  const std::string header =
      std::to_string(exit_code) + " " + std::to_string(output.size()) + "\n";
  WriteAll(connection, header.data(), header.size());
  WriteAll(connection, output.data(), output.size());
  close(connection);
  _exit(0);
}

} // namespace

int main(int argc, char **argv) {
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

  while (true) {
    const int connection = accept(listen_fd, nullptr, nullptr);
    if (connection < 0) {
      if (errno == EINTR)
        continue;
      std::perror("accept");
      break;
    }
    const pid_t monitor = fork();
    if (monitor == 0)
      HandleRequest(connection, listen_fd, crash_data, exec_timeout_seconds);
    close(connection);
  }

  close(listen_fd);
  unlink(socket_path.c_str());
  return 0;
}

#include "fuzzer/FuzzedDataProviderReplayRuntime.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

const std::string &GetTracePath() {
  static const std::string path = [] {
    const char *env = std::getenv("FDP_TRACE_PATH");
    if (env != nullptr && env[0] != '\0')
      return std::string(env);
    return std::string("fdp_trace.log");
  }();
  return path;
}

class ReplayTraceStore {
 public:
  static ReplayTraceStore &Instance() {
    static ReplayTraceStore store;
    return store;
  }

  long double ReplayScalarValue(int line) {
    auto it = scalar_streams_.find(line);
    if (it == scalar_streams_.end() || it->second.empty())
      std::abort();
    long double value = it->second.front();
    it->second.pop_front();
    return value;
  }

  size_t ReplayRemainingValue(int line) {
    auto it = remaining_streams_.find(line);
    if (it == remaining_streams_.end() || it->second.empty())
      std::abort();
    size_t value = it->second.front();
    it->second.pop_front();
    return value;
  }

  std::vector<uint8_t> ReplayBytesValue(int line, size_t wanted_size) {
    auto it = bytes_streams_.find(line);
    if (it == bytes_streams_.end() || it->second.empty())
      std::abort();

    std::vector<uint8_t> value = std::move(it->second.front());
    it->second.pop_front();

    if (wanted_size != static_cast<size_t>(-1)) {
      if (value.size() < wanted_size)
        value.resize(wanted_size, 0);
      if (value.size() > wanted_size)
        value.resize(wanted_size);
    }
    return value;
  }

 private:
  ReplayTraceStore() {
    std::ifstream in(GetTracePath());
    if (!in)
      return;

    std::string line;
    while (std::getline(in, line)) {
      if (line.empty())
        continue;
      std::istringstream iss(line);
      char tag = '\0';
      iss >> tag;
      if (!iss)
        continue;

      if (tag == 'S') {
        int call_line = 0;
        long double value = 0;
        iss >> call_line >> value;
        if (iss)
          scalar_streams_[call_line].push_back(value);
      } else if (tag == 'R') {
        int call_line = 0;
        size_t value = 0;
        iss >> call_line >> value;
        if (iss)
          remaining_streams_[call_line].push_back(value);
      } else if (tag == 'B') {
        int call_line = 0;
        size_t count = 0;
        iss >> call_line >> count;
        if (!iss)
          continue;

        std::vector<uint8_t> bytes;
        bytes.reserve(count);
        for (size_t index = 0; index < count; ++index) {
          unsigned int entry = 0;
          if (!(iss >> entry))
            break;
          bytes.push_back(static_cast<uint8_t>(entry & 0xffu));
        }
        if (bytes.size() < count)
          bytes.resize(count, 0);
        bytes_streams_[call_line].push_back(std::move(bytes));
      }
    }
  }

  std::map<int, std::deque<long double>> scalar_streams_;
  std::map<int, std::deque<size_t>> remaining_streams_;
  std::map<int, std::deque<std::vector<uint8_t>>> bytes_streams_;
};

} // namespace

namespace fdp_min_internal {

void EnsureReplayTraceLoaded() {
  (void)ReplayTraceStore::Instance();
}

long double ReplayScalarValue(int line) {
  return ReplayTraceStore::Instance().ReplayScalarValue(line);
}

size_t ReplayRemainingValue(int line) {
  return ReplayTraceStore::Instance().ReplayRemainingValue(line);
}

std::vector<uint8_t> ReplayBytesValue(int line, size_t wanted_size) {
  return ReplayTraceStore::Instance().ReplayBytesValue(line, wanted_size);
}

std::string ReplayStringValue(int line, size_t wanted_size) {
  std::vector<uint8_t> bytes =
      ReplayTraceStore::Instance().ReplayBytesValue(line, wanted_size);
  if (bytes.empty())
    return {};
  return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
}

} // namespace fdp_min_internal

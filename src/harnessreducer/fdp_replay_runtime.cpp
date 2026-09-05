#include "fuzzer/FuzzedDataProviderReplayRuntime.h"

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <type_traits>
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

void NativeAdvance(const uint8_t *&data_ptr, size_t &remaining_bytes,
                   size_t num_bytes) {
  if (num_bytes > remaining_bytes)
    std::abort();
  data_ptr += num_bytes;
  remaining_bytes -= num_bytes;
}

void NativeCopyAndAdvance(void *destination, size_t num_bytes,
                          const uint8_t *&data_ptr, size_t &remaining_bytes) {
  std::memcpy(destination, data_ptr, num_bytes);
  NativeAdvance(data_ptr, remaining_bytes, num_bytes);
}

template <typename TS, typename TU> TS NativeConvertUnsignedToSigned(TU value) {
  if (std::numeric_limits<TS>::is_modulo)
    return static_cast<TS>(value);
  if (value <= std::numeric_limits<TS>::max())
    return static_cast<TS>(value);
  constexpr auto min = std::numeric_limits<TS>::min();
  return min + static_cast<TS>(value - min);
}

uint64_t NativeConsumeIntegralInRangeImpl(uint64_t min, uint64_t max,
                                          size_t value_bits,
                                          const uint8_t *&data_ptr,
                                          size_t &remaining_bytes) {
  uint64_t range = max - min;
  uint64_t result = 0;
  size_t offset = 0;
  while (offset < value_bits && (range >> offset) > 0 && remaining_bytes != 0) {
    --remaining_bytes;
    result = (result << CHAR_BIT) | data_ptr[remaining_bytes];
    offset += CHAR_BIT;
  }
  if (range != std::numeric_limits<decltype(range)>::max())
    result = result % (range + 1);
  return min + result;
}

template <typename T> T ClampReplayScalar(long double value) {
  if constexpr (std::is_integral_v<T>) {
    const long double lo =
        static_cast<long double>(std::numeric_limits<T>::lowest());
    const long double hi =
        static_cast<long double>(std::numeric_limits<T>::max());
    if (value < lo)
      value = lo;
    if (value > hi)
      value = hi;
  } else if constexpr (std::is_enum_v<T>) {
    using UT = std::underlying_type_t<T>;
    const long double lo =
        static_cast<long double>(std::numeric_limits<UT>::lowest());
    const long double hi =
        static_cast<long double>(std::numeric_limits<UT>::max());
    if (value < lo)
      value = lo;
    if (value > hi)
      value = hi;
  }
  return static_cast<T>(value);
}

template <typename T> T ReplayTypedScalar(int line) {
  return ClampReplayScalar<T>(
      ReplayTraceStore::Instance().ReplayScalarValue(line));
}

template <typename T>
T NativeConsumeProbabilityImpl(const uint8_t *&data_ptr,
                               size_t &remaining_bytes) {
  using IntegralType =
      typename std::conditional_t<(sizeof(T) <= sizeof(uint32_t)), uint32_t,
                                  uint64_t>;
  T result = static_cast<T>(NativeConsumeIntegralInRangeImpl(
      static_cast<uint64_t>(std::numeric_limits<IntegralType>::min()),
      static_cast<uint64_t>(std::numeric_limits<IntegralType>::max()),
      sizeof(IntegralType) * CHAR_BIT, data_ptr, remaining_bytes));
  result /= static_cast<T>(std::numeric_limits<IntegralType>::max());
  return result;
}

template <typename T>
T NativeConsumeFloatingPointInRangeImpl(T min, T max, const uint8_t *&data_ptr,
                                        size_t &remaining_bytes) {
  if (min > max)
    std::abort();
  T range = .0;
  T result = min;
  constexpr T zero(.0);
  if (max > zero && min < zero && max > min + std::numeric_limits<T>::max()) {
    range = (max / 2.0) - (min / 2.0);
    if (NativeConsumeIntegralInRangeImpl(
            static_cast<uint64_t>(std::numeric_limits<uint8_t>::min()),
            static_cast<uint64_t>(std::numeric_limits<uint8_t>::max()),
            sizeof(uint8_t) * CHAR_BIT, data_ptr, remaining_bytes) &
        1u) {
      result += range;
    }
  } else {
    range = max - min;
  }
  return result +
         range * NativeConsumeProbabilityImpl<T>(data_ptr, remaining_bytes);
}

} // namespace

namespace fdp_min_internal {

void EnsureReplayTraceLoaded() { (void)ReplayTraceStore::Instance(); }

long double ReplayScalarValue(int line) {
  return ReplayTraceStore::Instance().ReplayScalarValue(line);
}

bool ReplayBoolValue(int line) { return ReplayTypedScalar<bool>(line); }

char ReplayCharValue(int line) { return ReplayTypedScalar<char>(line); }

signed char ReplaySignedCharValue(int line) {
  return ReplayTypedScalar<signed char>(line);
}

unsigned char ReplayUnsignedCharValue(int line) {
  return ReplayTypedScalar<unsigned char>(line);
}

short ReplayShortValue(int line) { return ReplayTypedScalar<short>(line); }

unsigned short ReplayUnsignedShortValue(int line) {
  return ReplayTypedScalar<unsigned short>(line);
}

int ReplayIntValue(int line) { return ReplayTypedScalar<int>(line); }

unsigned int ReplayUnsignedIntValue(int line) {
  return ReplayTypedScalar<unsigned int>(line);
}

long ReplayLongValue(int line) { return ReplayTypedScalar<long>(line); }

unsigned long ReplayUnsignedLongValue(int line) {
  return ReplayTypedScalar<unsigned long>(line);
}

long long ReplayLongLongValue(int line) {
  return ReplayTypedScalar<long long>(line);
}

unsigned long long ReplayUnsignedLongLongValue(int line) {
  return ReplayTypedScalar<unsigned long long>(line);
}

float ReplayFloatValue(int line) { return ReplayTypedScalar<float>(line); }

double ReplayDoubleValue(int line) { return ReplayTypedScalar<double>(line); }

long double ReplayLongDoubleValue(int line) {
  return ReplayTypedScalar<long double>(line);
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
  return std::string(reinterpret_cast<const char *>(bytes.data()),
                     bytes.size());
}

size_t ReplayBytesToBuffer(int line, void *destination) {
  std::vector<uint8_t> bytes = ReplayTraceStore::Instance().ReplayBytesValue(
      line, static_cast<size_t>(-1));
  if (!bytes.empty())
    std::memcpy(destination, bytes.data(), bytes.size());
  return bytes.size();
}

std::vector<uint8_t> NativeConsumeBytesValue(size_t num_bytes,
                                             const uint8_t *&data_ptr,
                                             size_t &remaining_bytes) {
  num_bytes = std::min(num_bytes, remaining_bytes);
  std::vector<uint8_t> result(num_bytes);
  if (num_bytes != 0)
    NativeCopyAndAdvance(result.data(), num_bytes, data_ptr, remaining_bytes);
  return result;
}

std::vector<uint8_t>
NativeConsumeBytesWithTerminatorValue(size_t num_bytes, uint8_t terminator,
                                      const uint8_t *&data_ptr,
                                      size_t &remaining_bytes) {
  num_bytes = std::min(num_bytes, remaining_bytes);
  std::vector<uint8_t> result(num_bytes + 1, terminator);
  if (num_bytes != 0)
    NativeCopyAndAdvance(result.data(), num_bytes, data_ptr, remaining_bytes);
  return result;
}

std::string NativeConsumeBytesAsStringValue(size_t num_bytes,
                                            const uint8_t *&data_ptr,
                                            size_t &remaining_bytes) {
  num_bytes = std::min(num_bytes, remaining_bytes);
  std::string result(
      reinterpret_cast<const std::string::value_type *>(data_ptr), num_bytes);
  NativeAdvance(data_ptr, remaining_bytes, num_bytes);
  return result;
}

std::string NativeConsumeRandomLengthStringValue(size_t max_length,
                                                 const uint8_t *&data_ptr,
                                                 size_t &remaining_bytes) {
  std::string result;
  result.reserve(std::min(max_length, remaining_bytes));
  for (size_t index = 0; index < max_length && remaining_bytes != 0; ++index) {
    char next = NativeConvertUnsignedToSigned<char>(data_ptr[0]);
    NativeAdvance(data_ptr, remaining_bytes, 1);
    if (next == '\\' && remaining_bytes != 0) {
      next = NativeConvertUnsignedToSigned<char>(data_ptr[0]);
      NativeAdvance(data_ptr, remaining_bytes, 1);
      if (next != '\\')
        break;
    }
    result += next;
  }
  result.shrink_to_fit();
  return result;
}

uint64_t NativeConsumeIntegralInRangeValue(uint64_t min, uint64_t max,
                                           size_t value_bits,
                                           const uint8_t *&data_ptr,
                                           size_t &remaining_bytes) {
  return NativeConsumeIntegralInRangeImpl(min, max, value_bits, data_ptr,
                                          remaining_bytes);
}

bool NativeConsumeBoolValue(const uint8_t *&data_ptr, size_t &remaining_bytes) {
  return 1u & NativeConsumeIntegralInRangeImpl(
                  static_cast<uint64_t>(std::numeric_limits<uint8_t>::min()),
                  static_cast<uint64_t>(std::numeric_limits<uint8_t>::max()),
                  sizeof(uint8_t) * CHAR_BIT, data_ptr, remaining_bytes);
}

float NativeConsumeProbabilityFloat(const uint8_t *&data_ptr,
                                    size_t &remaining_bytes) {
  return NativeConsumeProbabilityImpl<float>(data_ptr, remaining_bytes);
}

double NativeConsumeProbabilityDouble(const uint8_t *&data_ptr,
                                      size_t &remaining_bytes) {
  return NativeConsumeProbabilityImpl<double>(data_ptr, remaining_bytes);
}

long double NativeConsumeProbabilityLongDouble(const uint8_t *&data_ptr,
                                               size_t &remaining_bytes) {
  return NativeConsumeProbabilityImpl<long double>(data_ptr, remaining_bytes);
}

float NativeConsumeFloatingPointInRangeFloat(float min, float max,
                                             const uint8_t *&data_ptr,
                                             size_t &remaining_bytes) {
  return NativeConsumeFloatingPointInRangeImpl<float>(min, max, data_ptr,
                                                      remaining_bytes);
}

double NativeConsumeFloatingPointInRangeDouble(double min, double max,
                                               const uint8_t *&data_ptr,
                                               size_t &remaining_bytes) {
  return NativeConsumeFloatingPointInRangeImpl<double>(min, max, data_ptr,
                                                       remaining_bytes);
}

long double
NativeConsumeFloatingPointInRangeLongDouble(long double min, long double max,
                                            const uint8_t *&data_ptr,
                                            size_t &remaining_bytes) {
  return NativeConsumeFloatingPointInRangeImpl<long double>(min, max, data_ptr,
                                                            remaining_bytes);
}

} // namespace fdp_min_internal

//===- FuzzedDataProvider.h - Utility header for fuzz targets ---*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// A single header library providing an utility class to break up an array of
// bytes. Whenever run on the same input, provides the same output, as long as
// its methods are called in the same order, with the same arguments.
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_
#define LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_

#include <algorithm>
#include <array>
#include <climits>
#if !defined(FDP_MIN_MODE_REPLAY) || !defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME)
#include <cmath>
#endif
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#if defined(FDP_MIN_MODE_DUMP) || (defined(FDP_MIN_MODE_REPLAY) &&             \
                                   !defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME))
#include <fstream>
#include <iomanip>
#include <mutex>
#endif

#if defined(FDP_MIN_MODE_DUMP) || (defined(FDP_MIN_MODE_REPLAY) &&             \
                                   !defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME))
#include <deque>
#include <map>
#include <sstream>
#endif

#if defined(FDP_MIN_MODE_REPLAY) && defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME)
#include "fuzzer/FuzzedDataProviderReplayRuntime.h"
#endif

#if defined(FDP_MIN_MODE_DUMP) && defined(FDP_MIN_MODE_REPLAY)
#error "FDP_MIN_MODE_DUMP and FDP_MIN_MODE_REPLAY are mutually exclusive"
#endif

#if defined(__has_builtin)
#if __has_builtin(__builtin_COLUMN)
#define FDP_MIN_DEFAULT_SITE_ID ((__builtin_LINE() << 12) ^ __builtin_COLUMN())
#else
#define FDP_MIN_DEFAULT_SITE_ID (__builtin_LINE())
#endif
#else
#define FDP_MIN_DEFAULT_SITE_ID (__builtin_LINE())
#endif

namespace fdp_min_internal {

enum class Mode {
  kNative,
  kDump,
  kReplay,
};

#if defined(FDP_MIN_MODE_DUMP)
inline constexpr Mode kMode = Mode::kDump;
#elif defined(FDP_MIN_MODE_REPLAY)
inline constexpr Mode kMode = Mode::kReplay;
#else
inline constexpr Mode kMode = Mode::kNative;
#endif

inline const std::string &GetTracePath() {
  static const std::string path = [] {
    const char *env = std::getenv("FDP_TRACE_PATH");
    if (env != nullptr && env[0] != '\0')
      return std::string(env);
    return std::string("fdp_trace.log");
  }();
  return path;
}

inline const std::string &GetWideTracePath() {
  static const std::string path = [] {
    const char *env = std::getenv("FDP_WIDE_TRACE_PATH");
    if (env != nullptr && env[0] != '\0')
      return std::string(env);
    return GetTracePath() + ".wide";
  }();
  return path;
}

template <typename T>
inline constexpr bool kUseWideIntegralVectorTrace =
    std::is_integral_v<T> && sizeof(T) > 1 && sizeof(T) <= sizeof(uint64_t);

#if defined(FDP_MIN_MODE_DUMP) || (defined(FDP_MIN_MODE_REPLAY) &&             \
                                   !defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME))

struct WideVectorRecord {
  bool is_signed = false;
  size_t value_bits = 0;
  std::vector<int64_t> signed_values;
  std::vector<uint64_t> unsigned_values;
};

class TraceStore {
public:
  static TraceStore &Instance() {
    static TraceStore store;
    return store;
  }

  void DumpScalar(int line, long double value) {
    if (line == -1)
      return;
    std::lock_guard<std::mutex> lock(mu_);
    std::ofstream out(GetTracePath(), std::ios::app);
    if (!out)
      return;
    out << "S " << line << " ";
    if (std::isfinite(value) && std::truncl(value) == value) {
      out << std::fixed << std::setprecision(0) << value;
    } else {
      out << std::setprecision(std::numeric_limits<long double>::max_digits10)
          << value;
    }
    out << "\n";
  }

  void DumpRemaining(int line, size_t value) {
    if (line == -1)
      return;
    std::lock_guard<std::mutex> lock(mu_);
    std::ofstream out(GetTracePath(), std::ios::app);
    if (!out)
      return;
    out << "R " << line << " " << value << "\n";
  }

  void DumpBytes(int line, const uint8_t *bytes, size_t size) {
    if (line == -1)
      return;
    std::lock_guard<std::mutex> lock(mu_);
    std::ofstream out(GetTracePath(), std::ios::app);
    if (!out)
      return;
    out << "B " << line << " " << size;
    for (size_t i = 0; i < size; ++i)
      out << " " << static_cast<unsigned>(bytes[i]);
    out << "\n";
  }

  template <typename T>
  void DumpWideIntegralVector(int line, const T *values, size_t count) {
    if (line == -1)
      return;
    std::lock_guard<std::mutex> lock(mu_);
    std::ofstream out(GetWideTracePath(), std::ios::app);
    if (!out)
      return;
    out << "V " << line << " " << (std::is_signed_v<T> ? "S" : "U") << " "
        << (sizeof(T) * CHAR_BIT) << " " << count;
    for (size_t i = 0; i < count; ++i) {
      if constexpr (std::is_signed_v<T>) {
        out << " " << static_cast<long long>(values[i]);
      } else {
        out << " " << static_cast<unsigned long long>(values[i]);
      }
    }
    out << "\n";
  }

  template <typename T> T ReplayScalar(int line, T fallback) {
    auto it = scalar_streams_.find(line);
    if (it == scalar_streams_.end() || it->second.empty())
      abort();
    long double value = it->second.front();
    it->second.pop_front();

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

  size_t ReplayRemaining(int line, size_t fallback) {
    auto it = remaining_streams_.find(line);
    if (it == remaining_streams_.end() || it->second.empty())
      abort();
    size_t value = it->second.front();
    it->second.pop_front();
    return value;
  }

  std::vector<uint8_t> ReplayBytes(int line, size_t wanted_size) {
    auto it = bytes_streams_.find(line);
    if (it == bytes_streams_.end() || it->second.empty())
      abort();

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

  template <typename T> std::vector<T> ReplayWideIntegralVector(int line) {
    LoadWideTraces();

    auto it = wide_vector_streams_.find(line);
    if (it == wide_vector_streams_.end() || it->second.empty())
      abort();

    WideVectorRecord value = std::move(it->second.front());
    it->second.pop_front();

    if (value.is_signed != std::is_signed_v<T> ||
        value.value_bits != sizeof(T) * CHAR_BIT) {
      abort();
    }

    std::vector<T> result;
    if constexpr (std::is_signed_v<T>) {
      result.reserve(value.signed_values.size());
      for (int64_t entry : value.signed_values) {
        if (entry < static_cast<int64_t>(std::numeric_limits<T>::lowest()) ||
            entry > static_cast<int64_t>(std::numeric_limits<T>::max())) {
          abort();
        }
        result.push_back(static_cast<T>(entry));
      }
    } else {
      result.reserve(value.unsigned_values.size());
      for (uint64_t entry : value.unsigned_values) {
        if (entry > static_cast<uint64_t>(std::numeric_limits<T>::max()))
          abort();
        result.push_back(static_cast<T>(entry));
      }
    }
    return result;
  }

private:
  TraceStore() {
    if (kMode != Mode::kReplay)
      return;

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
        for (size_t i = 0; i < count; ++i) {
          unsigned int v = 0;
          if (!(iss >> v))
            break;
          bytes.push_back(static_cast<uint8_t>(v & 0xffu));
        }
        if (bytes.size() < count)
          bytes.resize(count, 0);
        bytes_streams_[call_line].push_back(std::move(bytes));
      }
    }
  }

  void LoadWideTraces() {
    if (wide_traces_loaded_)
      return;
    wide_traces_loaded_ = true;
    if (kMode != Mode::kReplay)
      return;

    std::ifstream in(GetWideTracePath());
    if (!in)
      return;

    std::string line;
    while (std::getline(in, line)) {
      if (line.empty())
        continue;
      std::istringstream iss(line);
      char tag = '\0';
      int call_line = 0;
      char signedness = '\0';
      size_t value_bits = 0;
      size_t count = 0;
      iss >> tag >> call_line >> signedness >> value_bits >> count;
      if (!iss || tag != 'V' || (signedness != 'S' && signedness != 'U'))
        continue;

      WideVectorRecord record;
      record.is_signed = signedness == 'S';
      record.value_bits = value_bits;
      if (record.is_signed) {
        record.signed_values.reserve(count);
        for (size_t i = 0; i < count; ++i) {
          int64_t entry = 0;
          if (!(iss >> entry))
            break;
          record.signed_values.push_back(entry);
        }
        if (record.signed_values.size() != count)
          continue;
      } else {
        record.unsigned_values.reserve(count);
        for (size_t i = 0; i < count; ++i) {
          uint64_t entry = 0;
          if (!(iss >> entry))
            break;
          record.unsigned_values.push_back(entry);
        }
        if (record.unsigned_values.size() != count)
          continue;
      }
      wide_vector_streams_[call_line].push_back(std::move(record));
    }
  }

  std::mutex mu_;
  bool wide_traces_loaded_ = false;
  std::map<int, std::deque<long double>> scalar_streams_;
  std::map<int, std::deque<size_t>> remaining_streams_;
  std::map<int, std::deque<std::vector<uint8_t>>> bytes_streams_;
  std::map<int, std::deque<WideVectorRecord>> wide_vector_streams_;
};

inline void InitializeReplayStore() {
  if (kMode == Mode::kReplay)
    (void)TraceStore::Instance();
}

inline void DumpScalar(int line, long double value) {
  TraceStore::Instance().DumpScalar(line, value);
}

inline void DumpRemaining(int line, size_t value) {
  TraceStore::Instance().DumpRemaining(line, value);
}

inline void DumpBytes(int line, const uint8_t *bytes, size_t size) {
  TraceStore::Instance().DumpBytes(line, bytes, size);
}

template <typename T>
inline void DumpVector(int line, const std::vector<T> &values) {
  if constexpr (kUseWideIntegralVectorTrace<T>) {
    TraceStore::Instance().DumpWideIntegralVector(line, values.data(),
                                                  values.size());
  } else {
    TraceStore::Instance().DumpBytes(
        line, reinterpret_cast<const uint8_t *>(values.data()),
        values.size() * sizeof(T));
  }
}

template <typename T> T ReplayScalar(int line, T fallback) {
  return TraceStore::Instance().ReplayScalar<T>(line, fallback);
}

inline size_t ReplayRemaining(int line, size_t fallback) {
  return TraceStore::Instance().ReplayRemaining(line, fallback);
}

inline std::vector<uint8_t> ReplayBytes(int line, size_t wanted_size) {
  return TraceStore::Instance().ReplayBytes(line, wanted_size);
}

template <typename T>
inline std::vector<T> ReplayVector(int line, size_t wanted_size) {
  if constexpr (kUseWideIntegralVectorTrace<T>) {
    (void)wanted_size;
    return TraceStore::Instance().ReplayWideIntegralVector<T>(line);
  } else {
    auto bytes = ReplayBytes(line, wanted_size);
    return std::vector<T>(bytes.begin(), bytes.end());
  }
}

#elif defined(FDP_MIN_MODE_REPLAY) && defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME)

inline void InitializeReplayStore() { EnsureReplayTraceLoaded(); }

inline void DumpScalar(int, long double) {}

inline void DumpRemaining(int, size_t) {}

inline void DumpBytes(int, const uint8_t *, size_t) {}

template <typename T>
inline void DumpVector(int, const std::vector<T> &) {}

template <typename T> T ReplayScalar(int line, T fallback) {
  (void)fallback;
  if constexpr (std::is_same_v<T, bool>) {
    return ReplayBoolValue(line);
  } else if constexpr (std::is_same_v<T, char>) {
    return ReplayCharValue(line);
  } else if constexpr (std::is_same_v<T, signed char>) {
    return ReplaySignedCharValue(line);
  } else if constexpr (std::is_same_v<T, unsigned char>) {
    return ReplayUnsignedCharValue(line);
  } else if constexpr (std::is_same_v<T, short>) {
    return ReplayShortValue(line);
  } else if constexpr (std::is_same_v<T, unsigned short>) {
    return ReplayUnsignedShortValue(line);
  } else if constexpr (std::is_same_v<T, int>) {
    return ReplayIntValue(line);
  } else if constexpr (std::is_same_v<T, unsigned int>) {
    return ReplayUnsignedIntValue(line);
  } else if constexpr (std::is_same_v<T, long>) {
    return ReplayLongValue(line);
  } else if constexpr (std::is_same_v<T, unsigned long>) {
    return ReplayUnsignedLongValue(line);
  } else if constexpr (std::is_same_v<T, long long>) {
    return ReplayLongLongValue(line);
  } else if constexpr (std::is_same_v<T, unsigned long long>) {
    return ReplayUnsignedLongLongValue(line);
  } else if constexpr (std::is_same_v<T, float>) {
    return ReplayFloatValue(line);
  } else if constexpr (std::is_same_v<T, double>) {
    return ReplayDoubleValue(line);
  } else if constexpr (std::is_same_v<T, long double>) {
    return ReplayLongDoubleValue(line);
  } else {
    long double value = ReplayScalarValue(line);

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
}

inline size_t ReplayRemaining(int line, size_t fallback) {
  (void)fallback;
  return ReplayRemainingValue(line);
}

inline std::vector<uint8_t> ReplayBytes(int line, size_t wanted_size) {
  return ReplayBytesValue(line, wanted_size);
}

template <typename T, typename U>
inline std::vector<T> ConvertReplayVector(std::vector<U> &&values) {
  if constexpr (std::is_same_v<T, U>) {
    return std::move(values);
  } else {
    return std::vector<T>(values.begin(), values.end());
  }
}

template <typename T>
inline std::vector<T> ReplayVector(int line, size_t wanted_size) {
  if constexpr (kUseWideIntegralVectorTrace<T>) {
    (void)wanted_size;
    if constexpr (std::is_signed_v<T>) {
      if constexpr (sizeof(T) == 2) {
        return ConvertReplayVector<T>(ReplaySigned16VectorValue(line));
      } else if constexpr (sizeof(T) == 4) {
        return ConvertReplayVector<T>(ReplaySigned32VectorValue(line));
      } else if constexpr (sizeof(T) == 8) {
        return ConvertReplayVector<T>(ReplaySigned64VectorValue(line));
      }
    } else {
      if constexpr (sizeof(T) == 2) {
        return ConvertReplayVector<T>(ReplayUnsigned16VectorValue(line));
      } else if constexpr (sizeof(T) == 4) {
        return ConvertReplayVector<T>(ReplayUnsigned32VectorValue(line));
      } else if constexpr (sizeof(T) == 8) {
        return ConvertReplayVector<T>(ReplayUnsigned64VectorValue(line));
      }
    }
    abort();
  } else {
    auto bytes = ReplayBytes(line, wanted_size);
    if constexpr (std::is_same_v<T, uint8_t>) {
      return bytes;
    } else {
      return std::vector<T>(bytes.begin(), bytes.end());
    }
  }
}

#else

inline void InitializeReplayStore() {}

inline void DumpScalar(int, long double) {}

inline void DumpRemaining(int, size_t) {}

inline void DumpBytes(int, const uint8_t *, size_t) {}

template <typename T>
inline void DumpVector(int, const std::vector<T> &) {}

template <typename T> T ReplayScalar(int, T fallback) { return fallback; }

inline size_t ReplayRemaining(int, size_t fallback) { return fallback; }

inline std::vector<uint8_t> ReplayBytes(int, size_t) { return {}; }

template <typename T>
inline std::vector<T> ReplayVector(int, size_t) {
  return {};
}

#endif

} // namespace fdp_min_internal

class FuzzedDataProvider {
public:
  FuzzedDataProvider(const uint8_t *data, size_t size)
      : data_ptr_(data), remaining_bytes_(size) {
    if (fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
      remaining_bytes_ = std::numeric_limits<size_t>::max() / 4;
      fdp_min_internal::InitializeReplayStore();
    }
  }
  ~FuzzedDataProvider() = default;

  template <typename T>
  std::vector<T> ConsumeBytes(size_t num_bytes,
                              int line = FDP_MIN_DEFAULT_SITE_ID);
  template <typename T>
  std::vector<T> ConsumeBytesWithTerminator(size_t num_bytes, T terminator = 0,
                                            int line = FDP_MIN_DEFAULT_SITE_ID);
  template <typename T>
  std::vector<T> ConsumeRemainingBytes(int line = FDP_MIN_DEFAULT_SITE_ID);

  std::string ConsumeBytesAsString(size_t num_bytes,
                                   int line = FDP_MIN_DEFAULT_SITE_ID);
  std::string ConsumeRandomLengthString(size_t max_length,
                                        int line = FDP_MIN_DEFAULT_SITE_ID);
  std::string ConsumeRandomLengthString(int line = FDP_MIN_DEFAULT_SITE_ID);
  std::string ConsumeRemainingBytesAsString(int line = FDP_MIN_DEFAULT_SITE_ID);

  template <typename T> T ConsumeIntegral(int line = FDP_MIN_DEFAULT_SITE_ID);
  template <typename T>
  T ConsumeIntegralInRange(T min, T max, int line = FDP_MIN_DEFAULT_SITE_ID);

  template <typename T>
  T ConsumeFloatingPoint(int line = FDP_MIN_DEFAULT_SITE_ID);
  template <typename T>
  T ConsumeFloatingPointInRange(T min, T max,
                                int line = FDP_MIN_DEFAULT_SITE_ID);

  template <typename T>
  T ConsumeProbability(int line = FDP_MIN_DEFAULT_SITE_ID);
  bool ConsumeBool(int line = FDP_MIN_DEFAULT_SITE_ID);
  template <typename T> T ConsumeEnum(int line = FDP_MIN_DEFAULT_SITE_ID);

  template <typename T, size_t size>
  T PickValueInArray(const T (&array)[size],
                     int line = FDP_MIN_DEFAULT_SITE_ID);
  template <typename T, size_t size>
  T PickValueInArray(const std::array<T, size> &array,
                     int line = FDP_MIN_DEFAULT_SITE_ID);
  template <typename T>
  T PickValueInArray(std::initializer_list<const T> list,
                     int line = FDP_MIN_DEFAULT_SITE_ID);

  size_t ConsumeData(void *destination, size_t num_bytes,
                     int line = FDP_MIN_DEFAULT_SITE_ID);

  size_t remaining_bytes(int line = FDP_MIN_DEFAULT_SITE_ID) {
    if (line != -1) {
      if (fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay)
        return fdp_min_internal::ReplayRemaining(line, remaining_bytes_);
      if (fdp_min_internal::kMode == fdp_min_internal::Mode::kDump)
        fdp_min_internal::DumpRemaining(line, remaining_bytes_);
    }
    return remaining_bytes_;
  }

private:
  FuzzedDataProvider(const FuzzedDataProvider &) = delete;
  FuzzedDataProvider &operator=(const FuzzedDataProvider &) = delete;

  void CopyAndAdvance(void *destination, size_t num_bytes);
  void Advance(size_t num_bytes);
  template <typename T>
  std::vector<T> ConsumeBytesIter(size_t size, size_t num_bytes);
  template <typename TS, typename TU> TS ConvertUnsignedToSigned(TU value);

  const uint8_t *data_ptr_;
  size_t remaining_bytes_;
};

#if defined(FDP_MIN_MODE_REPLAY) && defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME)
#define FDP_REPLAY_BYTES(wanted_size)                                          \
  if (line != -1 &&                                                            \
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {            \
    return fdp_min_internal::ReplayVector<T>(line, wanted_size);               \
  }

#define FDP_REPLAY_STR(wanted_size)                                            \
  if (line != -1 &&                                                            \
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {            \
    return fdp_min_internal::ReplayStringValue(line, wanted_size);             \
  }
#else
#define FDP_REPLAY_BYTES(wanted_size)                                          \
  if (line != -1 &&                                                            \
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {            \
    return fdp_min_internal::ReplayVector<T>(line, wanted_size);               \
  }

#define FDP_REPLAY_STR(wanted_size)                                            \
  if (line != -1 &&                                                            \
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {            \
    auto bs = fdp_min_internal::ReplayBytes(line, wanted_size);                \
    return std::string((const char *)bs.data(), bs.size());                    \
  }
#endif

#define FDP_REPLAY_SCALAR(type)                                                \
  if (line != -1 &&                                                            \
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {            \
    return fdp_min_internal::ReplayScalar<type>(line, static_cast<type>(0));   \
  }

template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeBytes(size_t num_bytes, int line) {
  FDP_REPLAY_BYTES((size_t)-1);
  num_bytes = std::min(num_bytes, remaining_bytes_);
  auto res = ConsumeBytesIter<T>(num_bytes, num_bytes);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpVector(line, res);
  }
  return res;
}

template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeBytesWithTerminator(size_t num_bytes,
                                                              T terminator,
                                                              int line) {
  FDP_REPLAY_BYTES((size_t)-1);
  num_bytes = std::min(num_bytes, remaining_bytes_);
  std::vector<T> result = ConsumeBytesIter<T>(num_bytes + 1, num_bytes);
  result.back() = terminator;
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpVector(line, result);
  }
  return result;
}

template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeRemainingBytes(int line) {
  FDP_REPLAY_BYTES(-1);
  auto res = ConsumeBytes<T>(remaining_bytes_, -1);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpVector(line, res);
  }
  return res;
}

#if defined(FDP_MIN_MODE_REPLAY) && defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME)
inline std::string FuzzedDataProvider::ConsumeBytesAsString(size_t num_bytes,
                                                            int line) {
  if (line != -1 &&
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
    return fdp_min_internal::ReplayStringValue(line, static_cast<size_t>(-1));
  }
  return fdp_min_internal::NativeConsumeBytesAsStringValue(num_bytes, data_ptr_,
                                                           remaining_bytes_);
}

inline std::string
FuzzedDataProvider::ConsumeRandomLengthString(size_t max_length, int line) {
  if (line != -1 &&
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
    return fdp_min_internal::ReplayStringValue(line, static_cast<size_t>(-1));
  }
  return fdp_min_internal::NativeConsumeRandomLengthStringValue(
      max_length, data_ptr_, remaining_bytes_);
}

inline std::string FuzzedDataProvider::ConsumeRandomLengthString(int line) {
  if (line != -1 &&
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
    return fdp_min_internal::ReplayStringValue(line, static_cast<size_t>(-1));
  }
  return fdp_min_internal::NativeConsumeRandomLengthStringValue(
      remaining_bytes_, data_ptr_, remaining_bytes_);
}

inline std::string FuzzedDataProvider::ConsumeRemainingBytesAsString(int line) {
  if (line != -1 &&
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
    return fdp_min_internal::ReplayStringValue(line, static_cast<size_t>(-1));
  }
  return fdp_min_internal::NativeConsumeBytesAsStringValue(
      remaining_bytes_, data_ptr_, remaining_bytes_);
}
#else
inline std::string FuzzedDataProvider::ConsumeBytesAsString(size_t num_bytes,
                                                            int line) {
  FDP_REPLAY_STR((size_t)-1);
  num_bytes = std::min(num_bytes, remaining_bytes_);
  std::string result(
      reinterpret_cast<const std::string::value_type *>(data_ptr_), num_bytes);
  Advance(num_bytes);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpBytes(line, (const uint8_t *)result.data(),
                                result.size());
  }
  return result;
}

inline std::string
FuzzedDataProvider::ConsumeRandomLengthString(size_t max_length, int line) {
  FDP_REPLAY_STR(-1);
  std::string result;
  result.reserve(std::min(max_length, remaining_bytes_));
  for (size_t i = 0; i < max_length && remaining_bytes_ != 0; ++i) {
    char next = ConvertUnsignedToSigned<char>(data_ptr_[0]);
    Advance(1);
    if (next == '\\' && remaining_bytes_ != 0) {
      next = ConvertUnsignedToSigned<char>(data_ptr_[0]);
      Advance(1);
      if (next != '\\')
        break;
    }
    result += next;
  }
  result.shrink_to_fit();
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpBytes(line, (const uint8_t *)result.data(),
                                result.size());
  }
  return result;
}

inline std::string FuzzedDataProvider::ConsumeRandomLengthString(int line) {
  FDP_REPLAY_STR(-1);
  auto res = ConsumeRandomLengthString(remaining_bytes_, -1);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpBytes(line, (const uint8_t *)res.data(), res.size());
  }
  return res;
}

inline std::string FuzzedDataProvider::ConsumeRemainingBytesAsString(int line) {
  FDP_REPLAY_STR(-1);
  auto res = ConsumeBytesAsString(remaining_bytes_, -1);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpBytes(line, (const uint8_t *)res.data(), res.size());
  }
  return res;
}
#endif

template <typename T> T FuzzedDataProvider::ConsumeIntegral(int line) {
  FDP_REPLAY_SCALAR(T);
  auto res = ConsumeIntegralInRange<T>(std::numeric_limits<T>::min(),
                                       std::numeric_limits<T>::max(), -1);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpScalar(line, static_cast<long double>(res));
  }
  return res;
}

template <typename T>
T FuzzedDataProvider::ConsumeIntegralInRange(T min, T max, int line) {
  if (min > max)
    abort();
  FDP_REPLAY_SCALAR(T);
  uint64_t range = static_cast<uint64_t>(max) - static_cast<uint64_t>(min);
  uint64_t result = 0;
  size_t offset = 0;
  while (offset < sizeof(T) * CHAR_BIT && (range >> offset) > 0 &&
         remaining_bytes_ != 0) {
    --remaining_bytes_;
    result = (result << CHAR_BIT) | data_ptr_[remaining_bytes_];
    offset += CHAR_BIT;
  }
  if (range != std::numeric_limits<decltype(range)>::max())
    result = result % (range + 1);
  T final = static_cast<T>(static_cast<uint64_t>(min) + result);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpScalar(line, static_cast<long double>(final));
  }
  return final;
}

template <typename T> T FuzzedDataProvider::ConsumeFloatingPoint(int line) {
  FDP_REPLAY_SCALAR(T);
  auto res = ConsumeFloatingPointInRange<T>(std::numeric_limits<T>::lowest(),
                                            std::numeric_limits<T>::max(), -1);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpScalar(line, static_cast<long double>(res));
  }
  return res;
}

template <typename T>
T FuzzedDataProvider::ConsumeFloatingPointInRange(T min, T max, int line) {
  if (min > max)
    abort();
  FDP_REPLAY_SCALAR(T);
  T range = .0;
  T result = min;
  constexpr T zero(.0);
  if (max > zero && min < zero && max > min + std::numeric_limits<T>::max()) {
    range = (max / 2.0) - (min / 2.0);
    if (ConsumeBool(-1))
      result += range;
  } else {
    range = max - min;
  }
  T final = result + range * ConsumeProbability<T>(-1);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpScalar(line, static_cast<long double>(final));
  }
  return final;
}

template <typename T> T FuzzedDataProvider::ConsumeProbability(int line) {
  FDP_REPLAY_SCALAR(T);
  using IntegralType =
      typename std::conditional_t<(sizeof(T) <= sizeof(uint32_t)), uint32_t,
                                  uint64_t>;
  T result = static_cast<T>(ConsumeIntegral<IntegralType>(-1));
  result /= static_cast<T>(std::numeric_limits<IntegralType>::max());
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpScalar(line, static_cast<long double>(result));
  }
  return result;
}

#if defined(FDP_MIN_MODE_REPLAY) && defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME)
#define FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(Type)                        \
  template <>                                                                  \
  inline Type FuzzedDataProvider::ConsumeIntegral<Type>(int line) {            \
    if (line != -1 &&                                                          \
        fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {          \
      return fdp_min_internal::ReplayScalar<Type>(line, static_cast<Type>(0)); \
    }                                                                          \
    uint64_t raw = fdp_min_internal::NativeConsumeIntegralInRangeValue(        \
        static_cast<uint64_t>(std::numeric_limits<Type>::min()),               \
        static_cast<uint64_t>(std::numeric_limits<Type>::max()),               \
        sizeof(Type) * CHAR_BIT, data_ptr_, remaining_bytes_);                 \
    return static_cast<Type>(raw);                                             \
  }                                                                            \
  template <>                                                                  \
  inline Type FuzzedDataProvider::ConsumeIntegralInRange<Type>(                \
      Type min, Type max, int line) {                                          \
    if (min > max)                                                             \
      abort();                                                                 \
    if (line != -1 &&                                                          \
        fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {          \
      return fdp_min_internal::ReplayScalar<Type>(line, static_cast<Type>(0)); \
    }                                                                          \
    uint64_t raw = fdp_min_internal::NativeConsumeIntegralInRangeValue(        \
        static_cast<uint64_t>(min), static_cast<uint64_t>(max),                \
        sizeof(Type) * CHAR_BIT, data_ptr_, remaining_bytes_);                 \
    return static_cast<Type>(raw);                                             \
  }

FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(char)
FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(signed char)
FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(unsigned char)
FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(short)
FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(unsigned short)
FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(int)
FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(unsigned int)
FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(long)
FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(unsigned long)
FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(long long)
FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION(unsigned long long)

#undef FDP_DEFINE_INTEGRAL_REPLAY_SPECIALIZATION

#define FDP_DEFINE_FLOATING_REPLAY_SPECIALIZATION(Type, Suffix)                \
  template <>                                                                  \
  inline Type FuzzedDataProvider::ConsumeFloatingPoint<Type>(int line) {       \
    if (line != -1 &&                                                          \
        fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {          \
      return fdp_min_internal::ReplayScalar<Type>(line, static_cast<Type>(0)); \
    }                                                                          \
    return fdp_min_internal::NativeConsumeFloatingPointInRange##Suffix(        \
        std::numeric_limits<Type>::lowest(), std::numeric_limits<Type>::max(), \
        data_ptr_, remaining_bytes_);                                          \
  }                                                                            \
  template <>                                                                  \
  inline Type FuzzedDataProvider::ConsumeFloatingPointInRange<Type>(           \
      Type min, Type max, int line) {                                          \
    if (min > max)                                                             \
      abort();                                                                 \
    if (line != -1 &&                                                          \
        fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {          \
      return fdp_min_internal::ReplayScalar<Type>(line, static_cast<Type>(0)); \
    }                                                                          \
    return fdp_min_internal::NativeConsumeFloatingPointInRange##Suffix(        \
        min, max, data_ptr_, remaining_bytes_);                                \
  }                                                                            \
  template <>                                                                  \
  inline Type FuzzedDataProvider::ConsumeProbability<Type>(int line) {         \
    if (line != -1 &&                                                          \
        fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {          \
      return fdp_min_internal::ReplayScalar<Type>(line, static_cast<Type>(0)); \
    }                                                                          \
    return fdp_min_internal::NativeConsumeProbability##Suffix(                 \
        data_ptr_, remaining_bytes_);                                          \
  }

FDP_DEFINE_FLOATING_REPLAY_SPECIALIZATION(float, Float)
FDP_DEFINE_FLOATING_REPLAY_SPECIALIZATION(double, Double)
FDP_DEFINE_FLOATING_REPLAY_SPECIALIZATION(long double, LongDouble)

#undef FDP_DEFINE_FLOATING_REPLAY_SPECIALIZATION
#endif

#if defined(FDP_MIN_MODE_REPLAY) && defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME)
inline bool FuzzedDataProvider::ConsumeBool(int line) {
  if (line != -1 &&
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
    return fdp_min_internal::ReplayScalar<bool>(line, false);
  }
  return fdp_min_internal::NativeConsumeBoolValue(data_ptr_, remaining_bytes_);
}
#else
inline bool FuzzedDataProvider::ConsumeBool(int line) {
  FDP_REPLAY_SCALAR(bool);
  bool res = 1 & ConsumeIntegral<uint8_t>(-1);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpScalar(line, static_cast<long double>(res));
  }
  return res;
}
#endif

template <typename T> T FuzzedDataProvider::ConsumeEnum(int line) {
  FDP_REPLAY_SCALAR(T);
  T res = static_cast<T>(ConsumeIntegralInRange<uint32_t>(
      0, static_cast<uint32_t>(T::kMaxValue), -1));
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpScalar(line, static_cast<long double>(res));
  }
  return res;
}

template <typename T, size_t size>
T FuzzedDataProvider::PickValueInArray(const T (&array)[size], int line) {
  FDP_REPLAY_SCALAR(T);
  T res = array[ConsumeIntegralInRange<size_t>(0, size - 1, -1)];
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpScalar(line, static_cast<long double>(res));
  }
  return res;
}

template <typename T, size_t size>
T FuzzedDataProvider::PickValueInArray(const std::array<T, size> &array,
                                       int line) {
  FDP_REPLAY_SCALAR(T);
  T res = array[ConsumeIntegralInRange<size_t>(0, size - 1, -1)];
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpScalar(line, static_cast<long double>(res));
  }
  return res;
}

template <typename T>
T FuzzedDataProvider::PickValueInArray(std::initializer_list<const T> list,
                                       int line) {
  if (!list.size())
    abort();
  FDP_REPLAY_SCALAR(T);
  T res =
      *(list.begin() + ConsumeIntegralInRange<size_t>(0, list.size() - 1, -1));
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpScalar(line, static_cast<long double>(res));
  }
  return res;
}

inline size_t FuzzedDataProvider::ConsumeData(void *destination,
                                              size_t num_bytes, int line) {
#if defined(FDP_MIN_MODE_REPLAY) && defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME)
  if (line != -1 &&
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
    return fdp_min_internal::ReplayBytesToBuffer(line, destination);
  }
#else
  if (line != -1 &&
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
    auto bs = fdp_min_internal::ReplayBytes(line, (size_t)-1);
    std::memcpy(destination, bs.data(), bs.size());
    return bs.size();
  }
#endif
  num_bytes = std::min(num_bytes, remaining_bytes_);
  CopyAndAdvance(destination, num_bytes);
  if (line != -1 && fdp_min_internal::kMode == fdp_min_internal::Mode::kDump) {
    fdp_min_internal::DumpBytes(line, (const uint8_t *)destination, num_bytes);
  }
  return num_bytes;
}

inline void FuzzedDataProvider::CopyAndAdvance(void *destination,
                                               size_t num_bytes) {
  std::memcpy(destination, data_ptr_, num_bytes);
  Advance(num_bytes);
}

inline void FuzzedDataProvider::Advance(size_t num_bytes) {
  if (num_bytes > remaining_bytes_)
    abort();
  data_ptr_ += num_bytes;
  remaining_bytes_ -= num_bytes;
}

template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeBytesIter(size_t size,
                                                    size_t num_bytes) {
  std::vector<T> result(size);
  if (size == 0) {
    if (num_bytes != 0)
      abort();
    return result;
  }
  CopyAndAdvance(result.data(), num_bytes);
  result.shrink_to_fit();
  return result;
}

#if defined(FDP_MIN_MODE_REPLAY) && defined(FDP_MIN_EXTERNAL_REPLAY_RUNTIME)
template <>
inline std::vector<uint8_t>
FuzzedDataProvider::ConsumeBytes<uint8_t>(size_t num_bytes, int line) {
  if (line != -1 &&
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
    return fdp_min_internal::ReplayBytes(line, static_cast<size_t>(-1));
  }
  return fdp_min_internal::NativeConsumeBytesValue(num_bytes, data_ptr_,
                                                   remaining_bytes_);
}

template <>
inline std::vector<uint8_t>
FuzzedDataProvider::ConsumeBytesWithTerminator<uint8_t>(size_t num_bytes,
                                                        uint8_t terminator,
                                                        int line) {
  if (line != -1 &&
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
    return fdp_min_internal::ReplayBytes(line, static_cast<size_t>(-1));
  }
  return fdp_min_internal::NativeConsumeBytesWithTerminatorValue(
      num_bytes, terminator, data_ptr_, remaining_bytes_);
}

template <>
inline std::vector<uint8_t>
FuzzedDataProvider::ConsumeRemainingBytes<uint8_t>(int line) {
  if (line != -1 &&
      fdp_min_internal::kMode == fdp_min_internal::Mode::kReplay) {
    return fdp_min_internal::ReplayBytes(line, static_cast<size_t>(-1));
  }
  return fdp_min_internal::NativeConsumeBytesValue(remaining_bytes_, data_ptr_,
                                                   remaining_bytes_);
}
#endif

template <typename TS, typename TU>
TS FuzzedDataProvider::ConvertUnsignedToSigned(TU value) {
  if (std::numeric_limits<TS>::is_modulo)
    return static_cast<TS>(value);
  if (value <= std::numeric_limits<TS>::max())
    return static_cast<TS>(value);
  constexpr auto TS_min = std::numeric_limits<TS>::min();
  return TS_min + static_cast<TS>(value - TS_min);
}

#endif // LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_

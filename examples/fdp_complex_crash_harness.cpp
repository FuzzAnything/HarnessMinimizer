#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

namespace {

struct Header {
  std::string magic;
  uint8_t opcode;
  uint8_t guard;
  uint16_t version;
};

struct Record {
  uint32_t id;
  uint8_t kind;
  std::string name;
  std::vector<uint8_t> payload;
};

static Header ParseHeader(FuzzedDataProvider &fdp) {
  Header h;
  h.magic.reserve(8);
  for (int i = 0; i < 8 && fdp.remaining_bytes() > 0; ++i) {
    h.magic.push_back(static_cast<char>(fdp.ConsumeIntegral<uint8_t>()));
  }
  h.opcode = fdp.ConsumeIntegral<uint8_t>();
  h.guard = fdp.ConsumeIntegral<uint8_t>();
  h.version = fdp.ConsumeIntegral<uint16_t>();
  return h;
}

static std::vector<Record> ParseRecords(FuzzedDataProvider &fdp) {
  std::vector<Record> records;
  const uint8_t raw_count = fdp.ConsumeIntegral<uint8_t>();
  const size_t count = static_cast<size_t>(raw_count % 6U);
  records.reserve(count);

  for (size_t i = 0; i < count && fdp.remaining_bytes() > 0; ++i) {
    Record rec;
    rec.id = fdp.ConsumeIntegral<uint32_t>();
    rec.kind = fdp.ConsumeIntegral<uint8_t>();
    rec.name = fdp.ConsumeRandomLengthString(24);

    const size_t payload_len =
        static_cast<size_t>(fdp.ConsumeIntegral<uint8_t>() % 32U);
    rec.payload = fdp.ConsumeBytes<uint8_t>(payload_len);
    records.push_back(std::move(rec));
  }
  return records;
}

static std::unordered_map<std::string, double> BuildMetrics(
    FuzzedDataProvider &fdp, const std::vector<Record> &records) {
  std::unordered_map<std::string, double> metrics;
  for (const auto &rec : records) {
    const double weight = fdp.ConsumeFloatingPoint<double>();
    const bool enable = fdp.ConsumeBool();
    if (!enable) {
      continue;
    }

    double payload_score = 0.0;
    for (uint8_t b : rec.payload) {
      payload_score += static_cast<double>(b);
    }

    std::ostringstream key;
    key << rec.name << "#" << std::hex << rec.id;
    metrics[key.str()] = payload_score + weight;
  }
  return metrics;
}

static void MaybeCrash(bool gate_open,
                       const std::unordered_map<std::string, double> &metrics,
                       FuzzedDataProvider &fdp) {
  if (!gate_open) {
    return;
  }

  volatile uint32_t checksum = 0;
  for (const auto &it : metrics) {
    checksum ^= static_cast<uint32_t>(it.first.size());
    checksum += static_cast<uint32_t>(it.second);
  }

  if ((checksum & 1U) == 0U && fdp.remaining_bytes() > 0) {
    (void)fdp.ConsumeIntegral<uint32_t>();
  }

  volatile int *p = nullptr;
  *p = 0x1337;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const bool crash_gate =
      size >= 10 && std::string(reinterpret_cast<const char *>(data), 8) == "FDPDEMO!" &&
      data[8] == 0x42 && data[9] == 0x99;

  FuzzedDataProvider fdp(data, size);

  Header h = ParseHeader(fdp);
  std::vector<Record> records = ParseRecords(fdp);
  std::unordered_map<std::string, double> metrics = BuildMetrics(fdp, records);
  (void)h;
  MaybeCrash(crash_gate, metrics, fdp);

  return 0;
}

#ifndef LLVM_FUZZER_FUZZED_DATA_PROVIDER_REPLAY_RUNTIME_H_
#define LLVM_FUZZER_FUZZED_DATA_PROVIDER_REPLAY_RUNTIME_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace fdp_min_internal {

void EnsureReplayTraceLoaded();
long double ReplayScalarValue(int line);
bool ReplayBoolValue(int line);
char ReplayCharValue(int line);
signed char ReplaySignedCharValue(int line);
unsigned char ReplayUnsignedCharValue(int line);
short ReplayShortValue(int line);
unsigned short ReplayUnsignedShortValue(int line);
int ReplayIntValue(int line);
unsigned int ReplayUnsignedIntValue(int line);
long ReplayLongValue(int line);
unsigned long ReplayUnsignedLongValue(int line);
long long ReplayLongLongValue(int line);
unsigned long long ReplayUnsignedLongLongValue(int line);
float ReplayFloatValue(int line);
double ReplayDoubleValue(int line);
long double ReplayLongDoubleValue(int line);
size_t ReplayRemainingValue(int line);
std::vector<uint8_t> ReplayBytesValue(int line, size_t wanted_size);
std::vector<int16_t> ReplaySigned16VectorValue(int line);
std::vector<uint16_t> ReplayUnsigned16VectorValue(int line);
std::vector<int32_t> ReplaySigned32VectorValue(int line);
std::vector<uint32_t> ReplayUnsigned32VectorValue(int line);
std::vector<int64_t> ReplaySigned64VectorValue(int line);
std::vector<uint64_t> ReplayUnsigned64VectorValue(int line);
std::string ReplayStringValue(int line, size_t wanted_size);
size_t ReplayBytesToBuffer(int line, void *destination);

std::vector<uint8_t> NativeConsumeBytesValue(size_t num_bytes,
                                             const uint8_t *&data_ptr,
                                             size_t &remaining_bytes);
std::vector<uint8_t>
NativeConsumeBytesWithTerminatorValue(size_t num_bytes, uint8_t terminator,
                                      const uint8_t *&data_ptr,
                                      size_t &remaining_bytes);
std::string NativeConsumeBytesAsStringValue(size_t num_bytes,
                                            const uint8_t *&data_ptr,
                                            size_t &remaining_bytes);
std::string NativeConsumeRandomLengthStringValue(size_t max_length,
                                                 const uint8_t *&data_ptr,
                                                 size_t &remaining_bytes);
uint64_t NativeConsumeIntegralInRangeValue(uint64_t min, uint64_t max,
                                           size_t value_bits,
                                           const uint8_t *&data_ptr,
                                           size_t &remaining_bytes);
bool NativeConsumeBoolValue(const uint8_t *&data_ptr, size_t &remaining_bytes);
float NativeConsumeProbabilityFloat(const uint8_t *&data_ptr,
                                    size_t &remaining_bytes);
double NativeConsumeProbabilityDouble(const uint8_t *&data_ptr,
                                      size_t &remaining_bytes);
long double NativeConsumeProbabilityLongDouble(const uint8_t *&data_ptr,
                                               size_t &remaining_bytes);
float NativeConsumeFloatingPointInRangeFloat(float min, float max,
                                             const uint8_t *&data_ptr,
                                             size_t &remaining_bytes);
double NativeConsumeFloatingPointInRangeDouble(double min, double max,
                                               const uint8_t *&data_ptr,
                                               size_t &remaining_bytes);
long double
NativeConsumeFloatingPointInRangeLongDouble(long double min, long double max,
                                            const uint8_t *&data_ptr,
                                            size_t &remaining_bytes);

} // namespace fdp_min_internal

#endif // LLVM_FUZZER_FUZZED_DATA_PROVIDER_REPLAY_RUNTIME_H_

#ifndef LLVM_FUZZER_FUZZED_DATA_PROVIDER_REPLAY_RUNTIME_H_
#define LLVM_FUZZER_FUZZED_DATA_PROVIDER_REPLAY_RUNTIME_H_

#include <cstddef>
#include <cstdint>
#include <vector>

namespace fdp_min_internal {

void EnsureReplayTraceLoaded();
long double ReplayScalarValue(int line);
size_t ReplayRemainingValue(int line);
std::vector<uint8_t> ReplayBytesValue(int line, size_t wanted_size);

} // namespace fdp_min_internal

#endif // LLVM_FUZZER_FUZZED_DATA_PROVIDER_REPLAY_RUNTIME_H_

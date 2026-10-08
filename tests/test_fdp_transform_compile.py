"""Compile the generated expressions in type-sensitive C++ contexts."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from harnessminimizer.fdp_transform import inject_ids, inline_source_with_report, load_trace


@pytest.fixture(scope="module")
def compiler() -> str:
    path = shutil.which("clang++")
    if path is None:
        pytest.skip("clang++ is required to check generated C++")
    return path


def compile_program(compiler: str, source: Path, *flags: str) -> Path:
    binary = source.with_suffix(".out")
    result = subprocess.run(
        [compiler, "-std=c++17", "-O1", "-I", str(Path(__file__).resolve().parents[1] / "include"),
         *flags, str(source), "-o", str(binary)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return binary


def run_program(binary: Path, trace: Path) -> str:
    result = subprocess.run(
        [str(binary)],
        env={
            **os.environ,
            "FDP_TRACE_PATH": str(trace),
            "FDP_WIDE_TRACE_PATH": f"{trace}.wide",
        },
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


PROGRAM = r"""
#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <type_traits>
#include <vector>
#include "fuzzer/FuzzedDataProvider.h"

template <typename Expected, typename Actual>
void scalar(Actual&& value) {
    // A const array element or a different arithmetic type must not silently
    // change overload resolution after inlining.
    static_assert(std::is_same_v<Expected, Actual>);
    if constexpr (std::is_enum_v<Actual>)
        std::cout << static_cast<unsigned long long>(value);
    else if constexpr (std::is_floating_point_v<Actual>)
        std::cout << std::hexfloat << value;
    else
        std::cout << +value;
    std::cout << '\n';
}

template <typename Expected, typename Actual>
void bytes(Actual&& value) {
    static_assert(std::is_same_v<Expected, Actual>);
    for (auto byte : value)
        std::cout << static_cast<unsigned>(static_cast<unsigned char>(byte)) << ',';
    std::cout << '\n';
}

void mutate(unsigned char *data) {
    *data ^= 0xff;
    std::cout << static_cast<unsigned>(*data) << '\n';
}

template <typename Byte>
void templated_bytes(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    for (int i = 0; i < ITERATIONS; ++i)
        bytes<std::vector<Byte>>(fdp.ConsumeBytes<Byte>(3));
}

int main() {
    uint8_t data[4096];
    for (size_t i = 0; i < sizeof(data); ++i)
        data[i] = static_cast<uint8_t>(i * 37 + 129);
    FuzzedDataProvider fdp(data, sizeof(data));
    using Byte = signed char;
    using Real = long double;
    enum class Choice : unsigned short { First, Second, kMaxValue = Second };
    const short low = -20, high = 20;
    const float flow = -1.0f, fhigh = 1.0f;
    const double floating_choices[] = {-1e308, 1e308};
    const std::array<short, 2> integer_choices = {-2, 4};
    const Choice enum_choices[] = {Choice::First, Choice::Second};
    for (int i = 0; i < ITERATIONS; ++i) {
        scalar<size_t>(fdp.ConsumeIntegral<size_t>());
        scalar<short>(fdp.ConsumeIntegralInRange(low, high));
        scalar<Choice>(fdp.ConsumeEnum<Choice>());
        scalar<bool>(fdp.ConsumeBool());
        scalar<long long>(fdp.ConsumeIntegralInRange<long long>(
            std::numeric_limits<long long>::min(), std::numeric_limits<long long>::min()));
        scalar<unsigned long long>(fdp.ConsumeIntegralInRange<unsigned long long>(
            std::numeric_limits<unsigned long long>::max(), std::numeric_limits<unsigned long long>::max()));
        scalar<double>(fdp.ConsumeFloatingPoint<double>());
        scalar<float>(fdp.ConsumeFloatingPointInRange(flow, fhigh));
        scalar<Real>(fdp.ConsumeProbability<Real>());
        scalar<double>(fdp.ConsumeFloatingPointInRange<double>(1e308, 1e308));
        scalar<double>(fdp.PickValueInArray(floating_choices));
        scalar<short>(fdp.PickValueInArray(integer_choices));
        scalar<Choice>(fdp.PickValueInArray<Choice>(enum_choices));
        scalar<double>(fdp.PickValueInArray({1e100, 2e100}));
        bytes<std::vector<Byte>>(fdp.ConsumeBytes<Byte>(3));
        bytes<std::vector<Byte>>(fdp.ConsumeBytes<Byte>(70));
        bytes<std::vector<unsigned char>>(fdp.ConsumeBytes<unsigned char>(70));
        bytes<std::vector<Byte>>(fdp.ConsumeBytesWithTerminator(3, Byte(-1)));
        bytes<std::string>(fdp.ConsumeBytesAsString(3));
        bytes<std::string>(fdp.ConsumeBytesAsString(70));
        bytes<std::string>(fdp.ConsumeRandomLengthString(5));
        mutate(fdp.ConsumeBytes<unsigned char>(1).data());
        mutate(fdp.ConsumeBytes<uint8_t>(1).data());
        fdp.ConsumeBytes<Byte>(3).clear();
        fdp.ConsumeBytesAsString(3).clear();
        unsigned char buffer[70] = {};
        scalar<size_t>(fdp.ConsumeData(buffer, 3));
        bytes<std::vector<unsigned char>>(std::vector<unsigned char>(buffer, buffer + 3));
        scalar<size_t>(fdp.ConsumeData(buffer, 70));
        bytes<std::vector<unsigned char>>(std::vector<unsigned char>(buffer, buffer + 70));
        scalar<size_t>(fdp.ConsumeData(buffer, 0));
        scalar<size_t>(fdp.remaining_bytes());
        scalar<size_t>(size_t(std::min(sizeof(data), fdp.ConsumeIntegral<size_t>())));
        scalar<size_t>(size_t(std::min(sizeof(data), fdp.ConsumeData(buffer, 3))));
    }
    bytes<std::vector<Byte>>(fdp.ConsumeRemainingBytes<Byte>());
    bytes<std::string>(fdp.ConsumeRemainingBytesAsString());
    templated_bytes<Byte>(data, sizeof(data));
}
"""


@pytest.mark.parametrize("iterations", [1, 2])
def test_native_dump_and_inlined_program_agree(compiler, tmp_path, iterations):
    # One iteration exercises literals/large arrays; two exercises the same
    # API/type combinations through sequence storage in the generated header.
    source, detected = inject_ids(PROGRAM.replace("ITERATIONS", str(iterations)), 100000, "FDP_ID")
    original = tmp_path / "original.cpp"
    original.write_text(source)
    trace = tmp_path / "trace.log"
    native = compile_program(compiler, original, "-DFDP_MIN_MODE_DUMP")
    expected = run_program(native, trace)

    result = inline_source_with_report(source, load_trace(trace))
    assert result.replaced == detected
    assert not result.skipped
    assert "FDP_ID" not in result.source
    (tmp_path / result.header_name).write_text(result.header_source)
    translated = tmp_path / "inlined.cpp"
    translated.write_text(result.source)
    binary = compile_program(compiler, translated)
    assert run_program(binary, trace) == expected

    # Compile the header by itself to detect dependencies on include ordering
    # or declarations that only exist in the harness's local scope.
    header_check = tmp_path / "header.cpp"
    header_check.write_text('#include "harness_values.h"\nint main() {}\n')
    compile_program(compiler, header_check)


@pytest.mark.parametrize("iterations", [1, 2])
def test_pick_value_in_array_replays_non_numeric_choices_by_index(
    compiler, tmp_path, iterations
):
    source_text = r"""
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"

struct Token {
    int value;
};

int main() {
    uint8_t data[64];
    for (size_t i = 0; i < sizeof(data); ++i)
        data[i] = static_cast<uint8_t>(i * 29 + 7);
    FuzzedDataProvider fdp(data, sizeof(data));

    const char* c_array[] = {"array-0", "array-1", "array-2"};
    const std::array<const char*, 3> std_array = {
        "std-array-0", "std-array-1", "std-array-2"
    };
    Token tokens[] = {{10}, {20}, {30}};
    std::string suffix = "-object";
    int numbers[] = {101, 202, 303};

    for (int iteration = 0; iteration < ITERATIONS; ++iteration) {
        std::cout
            << fdp.PickValueInArray(c_array, /*FDP_ID:100301*/ 100301) << '|'
            << fdp.PickValueInArray(std_array, /*FDP_ID:100302*/ 100302) << '|'
            << fdp.PickValueInArray<const char*>(
                   {"list-0", "list-1", "list-2"},
                   /*FDP_ID:100303*/ 100303)
            << '|'
            << fdp.PickValueInArray(tokens, /*FDP_ID:100304*/ 100304).value
            << '|'
            << fdp.PickValueInArray<std::string>(
                   {"string-0", std::string("string-1") + suffix},
                   /*FDP_ID:100306*/ 100306)
            << '|'
            << fdp.PickValueInArray(numbers, /*FDP_ID:100305*/ 100305)
            << '\n';
    }
}
""".replace("ITERATIONS", str(iterations))
    source = tmp_path / "pick_non_numeric.cpp"
    source.write_text(source_text, encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"

    dump_binary = compile_program(compiler, source, "-DFDP_MIN_MODE_DUMP")
    expected = run_program(dump_binary, trace)
    trace_text = trace.read_text(encoding="utf-8")
    for key in (*range(100301, 100305), 100306):
        assert trace_text.count(f"P {key} ") == iterations
    assert trace_text.count("S 100305 ") == iterations

    header_replay = compile_program(compiler, source, "-DFDP_MIN_MODE_REPLAY")
    assert run_program(header_replay, trace) == expected

    runtime_source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "harnessminimizer"
        / "fdp_replay_runtime.cpp"
    )
    external_replay = compile_program(
        compiler,
        source,
        "-DFDP_MIN_MODE_REPLAY",
        "-DFDP_MIN_EXTERNAL_REPLAY_RUNTIME",
        str(runtime_source),
    )
    assert run_program(external_replay, trace) == expected

    result = inline_source_with_report(source_text, load_trace(trace))
    assert result.replaced == 6
    assert not result.skipped
    assert "FDP_ID" not in result.source
    assert "PickValueInArray" not in result.source
    if result.header_name:
        (tmp_path / result.header_name).write_text(result.header_source, encoding="utf-8")
    inlined = tmp_path / "pick_non_numeric_inlined.cpp"
    inlined.write_text(result.source, encoding="utf-8")
    assert run_program(compile_program(compiler, inlined), trace) == expected


@pytest.mark.parametrize("iterations", [1, 2])
def test_floating_trace_boundaries_compile_and_preserve_values(compiler, tmp_path, iterations):
    trace = tmp_path / "trace.log"
    values = ["-0", "inf", "-inf", "nan", "1.00000000000000000010842", "1e4000"]
    trace.write_text("".join(
        f"S {100000 + index} {value}\n"
        for index, value in enumerate(values) for _ in range(iterations)
    ))
    source = r"""
#include <cassert>
#include <cmath>
#include <type_traits>
int main() {
    using Real = long double;
    for (int i = 0; i < ITERATIONS; ++i) {
        auto zero = fdp.ConsumeFloatingPoint<Real>(100000);
        auto positive = fdp.ConsumeFloatingPoint<Real>(100001);
        auto negative = fdp.ConsumeFloatingPoint<Real>(100002);
        auto nan = fdp.ConsumeFloatingPoint<Real>(100003);
        auto precise = fdp.ConsumeFloatingPoint<Real>(100004);
        auto huge = fdp.ConsumeFloatingPoint<Real>(100005);
        static_assert(std::is_same_v<decltype(precise), Real>);
        assert(zero == 0 && std::signbit(zero));
        assert(std::isinf(positive) && !std::signbit(positive));
        assert(std::isinf(negative) && std::signbit(negative));
        assert(std::isnan(nan));
        assert(precise == 1.00000000000000000010842L);
        assert(huge == 1e4000L);
    }
}
""".replace("ITERATIONS", str(iterations))
    result = inline_source_with_report(source, load_trace(trace))
    assert result.replaced == len(values)
    if result.header_name:
        (tmp_path / result.header_name).write_text(result.header_source)
    translated = tmp_path / "floating.cpp"
    translated.write_text(result.source)
    run_program(compile_program(compiler, translated), trace)


@pytest.mark.parametrize("iterations,size", [(1, 3), (1, 70), (2, 3)])
def test_scoped_byte_types_keep_values_and_mutability(compiler, tmp_path, iterations, size):
    # Exercise the explicit byte conversion path as well as integral aliases.
    trace = tmp_path / "trace.log"
    trace.write_text((f"B 100000 {size} " + " ".join(["255"] * size) + "\n") * iterations)
    source = r"""
#include <cassert>
#include <cstddef>
#include <type_traits>
#include <vector>
int main() {
    using Byte = std::byte;
    for (int i = 0; i < ITERATIONS; ++i) {
        auto value = fdp.ConsumeBytes<Byte>(SIZE, 100000);
        static_assert(std::is_same_v<decltype(value), std::vector<Byte>>);
        assert(value.size() == SIZE && value.back() == Byte{255});
        value.data()[0] = Byte{1};
    }
}
""".replace("ITERATIONS", str(iterations)).replace("SIZE", str(size))
    result = inline_source_with_report(source, load_trace(trace))
    assert result.replaced == 1
    if result.header_name:
        (tmp_path / result.header_name).write_text(result.header_source)
    translated = tmp_path / "bytes.cpp"
    translated.write_text(result.source)
    run_program(compile_program(compiler, translated), trace)


def test_wide_integer_vectors_use_sidecar_for_replay_and_inlining(compiler, tmp_path):
    source_text = r"""
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <type_traits>
#include <vector>
#include "fuzzer/FuzzedDataProvider.h"

template <typename T>
void print_vector(const char *name, const std::vector<T>& values) {
    std::cout << name << ':' << values.size() << ':';
    for (T value : values) {
        if constexpr (std::is_signed_v<T>)
            std::cout << static_cast<long long>(value);
        else
            std::cout << static_cast<unsigned long long>(value);
        std::cout << ',';
    }
    std::cout << '\n';
}

int main() {
    uint8_t data[] = {7, 8, 9, 10, 11, 12, 13};
    FuzzedDataProvider fdp(data, sizeof(data));
    auto half_words = fdp.ConsumeBytes<uint16_t>(3, /*FDP_ID:100101*/ 100101);
    auto terminated = fdp.ConsumeBytesWithTerminator<int32_t>(
        2, -7, /*FDP_ID:100102*/ 100102);
    auto remaining = fdp.ConsumeRemainingBytes<uint64_t>(
        /*FDP_ID:100103*/ 100103);
    print_vector("u16", half_words);
    print_vector("i32", terminated);
    print_vector("u64", remaining);
}
"""
    source = tmp_path / "wide_vectors.cpp"
    source.write_text(source_text, encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"
    sidecar = Path(f"{trace}.wide")

    native = compile_program(compiler, source, "-DFDP_MIN_MODE_DUMP")
    expected = run_program(native, trace)

    assert sidecar.exists()
    sidecar_text = sidecar.read_text(encoding="utf-8")
    assert "V 100101 U 16" in sidecar_text
    assert "V 100102 S 32" in sidecar_text
    assert "V 100103 U 64" in sidecar_text
    assert not trace.exists() or "B " not in trace.read_text(encoding="utf-8")

    header_replay = compile_program(compiler, source, "-DFDP_MIN_MODE_REPLAY")
    assert run_program(header_replay, trace) == expected

    runtime_source = Path(__file__).resolve().parents[1] / "src" / "harnessminimizer" / "fdp_replay_runtime.cpp"
    external_replay = compile_program(
        compiler,
        source,
        "-DFDP_MIN_MODE_REPLAY",
        "-DFDP_MIN_EXTERNAL_REPLAY_RUNTIME",
        str(runtime_source),
    )
    assert run_program(external_replay, trace) == expected

    result = inline_source_with_report(source_text, load_trace(trace))
    assert result.replaced == 3
    assert "FDP_ID" not in result.source
    if result.header_name:
        (tmp_path / result.header_name).write_text(result.header_source, encoding="utf-8")
    translated = tmp_path / "wide_vectors_inlined.cpp"
    translated.write_text(result.source, encoding="utf-8")
    assert run_program(compile_program(compiler, translated), trace) == expected


def test_uint8_byte_vectors_stay_on_primary_trace(compiler, tmp_path):
    source_text = r"""
#include <cstdint>
#include <vector>
#include "fuzzer/FuzzedDataProvider.h"

int main() {
    uint8_t data[] = {1, 2, 3, 4};
    FuzzedDataProvider fdp(data, sizeof(data));
    auto bytes = fdp.ConsumeBytes<uint8_t>(3, /*FDP_ID:100201*/ 100201);
    return bytes.size() == 3 ? 0 : 1;
}
"""
    source = tmp_path / "byte_vectors.cpp"
    source.write_text(source_text, encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"
    sidecar = Path(f"{trace}.wide")

    binary = compile_program(compiler, source, "-DFDP_MIN_MODE_DUMP")
    run_program(binary, trace)

    assert trace.exists()
    assert "B 100201 3 1 2 3" in trace.read_text(encoding="utf-8")
    assert not sidecar.exists()

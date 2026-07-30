from collections import defaultdict, deque

from harnessreducer.fdp_transform import (
    MAX_INLINE_BUFFER_BYTES,
    inline_source,
    inline_source_with_report,
)


def test_inline_bytes_uses_vector_literal_for_data_calls() -> None:
    source = """
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, int size) {
  FuzzedDataProvider fdp(data, size);
  auto bytes = fdp.ConsumeBytes<uint8_t>(8, /*FDP_ID:100000*/ 100000);
  memcpy(data, bytes.data(), bytes.size());
  return 0;
}
"""

    streams = defaultdict(deque)
    streams[100000].append(("B", [0x89, 0x50, 0x4E, 0x47]))

    transformed, replaced = inline_source(source, streams)

    assert replaced == 1
    assert "std::vector<uint8_t>{0x89, 0x50, 0x4e, 0x47}" in transformed
    assert "bytes.data()" in transformed


def test_inline_empty_bytes_keeps_vector_type() -> None:
    source = """
void f(uint8_t* data, int size) {
  FuzzedDataProvider fdp(data, size);
  auto bytes = fdp.ConsumeRemainingBytes(/*FDP_ID:100001*/ 100001);
}
"""

    streams = defaultdict(deque)
    streams[100001].append(("S", 7))

    transformed, replaced = inline_source(source, streams)

    assert replaced == 1
    assert "std::vector<unsigned char>{}" in transformed


def test_inline_remaining_bytes_casts_to_size_t() -> None:
    source = """
size_t g(size_t colormap_size, uint8_t* data, int size) {
  FuzzedDataProvider fdp(data, size);
  size_t bytes_to_fill = std::min((size_t)colormap_size, fdp.remaining_bytes(/*FDP_ID:100002*/ 100002));
  return bytes_to_fill;
}
"""

    streams = defaultdict(deque)
    streams[100002].append(("R", 6731))

    transformed, replaced = inline_source(source, streams)

    assert replaced == 1
    assert "std::min((size_t)colormap_size, static_cast<size_t>(6731))" in transformed


def test_inline_repeated_bytes_id_uses_header_values() -> None:
    source = """
void f(uint8_t* data, int size, size_t length) {
  FuzzedDataProvider fdp(data, size);
  auto bytes = fdp.ConsumeBytes<uint8_t>(length, /*FDP_ID:100003*/ 100003);
}
"""

    streams = defaultdict(deque)
    streams[100003].append(("B", [0x01, 0x02]))
    streams[100003].append(("B", [0x03, 0x04]))

    result = inline_source_with_report(source, streams)

    assert result.replaced == 1
    assert result.loop_replaced == 1
    assert result.header_replaced == 1
    assert "auto bytes = fuzz_values_100003[fuzz_index_100003++];" in result.source
    assert "static const std::vector<uint8_t> fuzz_values_100003[]" in result.header_source
    assert "std::vector<uint8_t>{0x01, 0x02}" in result.header_source


def test_inline_repeated_remaining_bytes_id_uses_header_values() -> None:
    source = """
size_t g(uint8_t* data, int size) {
  FuzzedDataProvider fdp(data, size);
  return fdp.remaining_bytes(/*FDP_ID:100004*/ 100004);
}
"""

    streams = defaultdict(deque)
    streams[100004].append(("R", 128))
    streams[100004].append(("R", 0))

    result = inline_source_with_report(source, streams)

    assert result.replaced == 1
    assert result.loop_replaced == 1
    assert "return fuzz_values_100004[fuzz_index_100004++];" in result.source
    assert "static const size_t fuzz_values_100004[]" in result.header_source


def test_inline_repeated_signed_min_uses_valid_cpp_literal() -> None:
    source = """
void f(uint8_t* data, int size) {
  FuzzedDataProvider fdp(data, size);
  auto pts = fdp.ConsumeIntegral<long long>(/*FDP_ID:100008*/ 100008);
}
"""

    streams = defaultdict(deque)
    streams[100008].append(("S", -(2**63)))
    streams[100008].append(("S", -(2**63)))

    result = inline_source_with_report(source, streams)

    assert result.replaced == 1
    assert "static const long long fuzz_values_100008[]" in result.header_source
    assert "(-9223372036854775807LL - 1)" in result.header_source
    assert "-9223372036854775808" not in result.header_source


def test_inline_repeated_unsigned_values_use_unsigned_literals() -> None:
    source = """
void f(uint8_t* data, int size) {
  FuzzedDataProvider fdp(data, size);
  auto pts = fdp.ConsumeIntegral<unsigned long long>(/*FDP_ID:100009*/ 100009);
}
"""

    streams = defaultdict(deque)
    streams[100009].append(("S", 2**63))
    streams[100009].append(("S", 2**64 - 1))

    result = inline_source_with_report(source, streams)

    assert result.replaced == 1
    assert "static const unsigned long long fuzz_values_100009[]" in result.header_source
    assert "9223372036854775808ULL" in result.header_source
    assert "18446744073709551615ULL" in result.header_source


def test_inline_nested_fdp_call_keeps_outer_replay_replacement() -> None:
    source = """
void f(uint8_t* data, int size) {
  FuzzedDataProvider fdp(data, size);
  int bytes_to_fill = fdp.ConsumeIntegralInRange<size_t>(
      0, fdp.remaining_bytes(/*FDP_ID:100029*/ 100029), /*FDP_ID:100028*/ 100028);
}
"""

    streams = defaultdict(deque)
    streams[100028].append(("S", 172))
    streams[100028].append(("S", 172))
    streams[100029].append(("R", 362))
    streams[100029].append(("R", 362))

    result = inline_source_with_report(source, streams)

    assert result.replaced == 1
    assert result.loop_replaced == 1
    assert "int bytes_to_fill = fuzz_values_100028[fuzz_index_100028++];" in result.source
    assert "remaining_bytes" not in result.source
    assert "100029" not in result.source
    assert "fuzz_values_100028" in result.header_source
    assert "fuzz_values_100029" not in result.header_source


def test_inline_nested_inner_call_still_replays_when_outer_has_no_trace() -> None:
    source = """
void f(uint8_t* data, int size) {
  FuzzedDataProvider fdp(data, size);
  int bytes_to_fill = fdp.ConsumeIntegralInRange<size_t>(
      0, fdp.remaining_bytes(/*FDP_ID:100029*/ 100029));
}
"""

    streams = defaultdict(deque)
    streams[100029].append(("R", 362))

    transformed, replaced = inline_source(source, streams)

    assert replaced == 1
    assert "fdp.ConsumeIntegralInRange<size_t>(" in transformed
    assert "static_cast<size_t>(362)" in transformed
    assert "remaining_bytes" not in transformed


def test_large_single_byte_vector_moves_to_values_header() -> None:
    source = """
void f(uint8_t* data, int size) {
  FuzzedDataProvider fdp(data, size);
  auto bytes = fdp.ConsumeBytes<uint8_t>(100, /*FDP_ID:100005*/ 100005);
}
"""

    streams = defaultdict(deque)
    streams[100005].append(("B", list(range(MAX_INLINE_BUFFER_BYTES + 1))))

    result = inline_source_with_report(source, streams)

    assert result.replaced == 1
    assert result.large_buffer_replaced == 1
    assert result.header_replaced == 1
    assert "std::vector<uint8_t>(fuzz_bytes_100005, fuzz_bytes_100005 + fuzz_bytes_100005_size)" in result.source
    assert "static const uint8_t fuzz_bytes_100005[]" in result.header_source
    assert "static const size_t fuzz_bytes_100005_size" in result.header_source
    assert "0x40" in result.header_source


def test_large_single_string_moves_to_values_header() -> None:
    source = """
void f(uint8_t* data, int size) {
  FuzzedDataProvider fdp(data, size);
  auto s = fdp.ConsumeBytesAsString(100, /*FDP_ID:100006*/ 100006);
}
"""

    streams = defaultdict(deque)
    streams[100006].append(("B", [ord("A")] * (MAX_INLINE_BUFFER_BYTES + 1)))

    result = inline_source_with_report(source, streams)

    assert result.replaced == 1
    assert result.large_buffer_replaced == 1
    assert "std::string(fuzz_string_100006, fuzz_string_100006_size)" in result.source
    assert "static const char fuzz_string_100006[]" in result.header_source
    assert "sizeof(fuzz_string_100006) - 1" in result.header_source


def test_inline_preserves_non_ascii_text_before_callsite() -> None:
    source = """
// café
void f(uint8_t* data, int size) {
  FuzzedDataProvider fdp(data, size);
  auto enabled = fdp.ConsumeBool(/*FDP_ID:100007*/ 100007);
}
"""

    streams = defaultdict(deque)
    streams[100007].append(("S", 1))

    transformed, replaced = inline_source(source, streams)

    assert replaced == 1
    assert "// café" in transformed
    assert "auto enabled = true;" in transformed
    assert "ConsumeBool" not in transformed

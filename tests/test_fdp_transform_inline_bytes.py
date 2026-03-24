from collections import defaultdict, deque

from harnessreducer.fdp_transform import inline_source


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
    assert "std::vector<unsigned char>{0x89, 0x50, 0x4e, 0x47}" in transformed
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

from harnessreducer.fdp_transform import inject_ids


def test_inject_ids_handles_nested_fdp_calls_without_breaking_syntax() -> None:
    source = """
void f(uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  size_t io_buffer_size = fdp.ConsumeIntegralInRange<size_t>(1, std::min<size_t>(fdp.remaining_bytes(), 1024));
}
"""

    transformed, count = inject_ids(source, 100011, "FDP_ID")

    assert count == 2
    assert "fdp.remaining_bytes(/*FDP_ID:100012*/ 100012)" in transformed
    assert (
        "fdp.ConsumeIntegralInRange<size_t>(1, "
        "std::min<size_t>(fdp.remaining_bytes(/*FDP_ID:100012*/ 100012), 1024), "
        "/*FDP_ID:100011*/ 100011)"
    ) in transformed

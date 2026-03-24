from harnessreducer.fdp_transform import strip_injected_ids


def test_strip_injected_ids_removes_marker_and_numeric_id() -> None:
    source = """
void f(FuzzedDataProvider* fdp, size_t length) {
  auto bytes = fdp->ConsumeBytes<uint8_t>(length, /*FDP_ID:100001*/ 100001);
}
"""

    cleaned, removed = strip_injected_ids(source)

    assert removed == 1
    assert "ConsumeBytes<uint8_t>(length)" in cleaned
    assert "100001" not in cleaned
    assert "FDP_ID" not in cleaned


def test_strip_injected_ids_removes_numeric_id_without_marker() -> None:
    source = """
void f(FuzzedDataProvider* fdp, size_t length) {
  auto bytes = fdp->ConsumeBytes<uint8_t>(length, 100001);
}
"""

    cleaned, removed = strip_injected_ids(source)

    assert removed == 1
    assert "ConsumeBytes<uint8_t>(length)" in cleaned
    assert "100001" not in cleaned

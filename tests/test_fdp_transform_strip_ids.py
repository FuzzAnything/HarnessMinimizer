from harnessminimizer.fdp_transform import strip_injected_ids


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


def test_strip_injected_ids_removes_ids_beyond_first_hundred() -> None:
    source = """
void f(FuzzedDataProvider* fdp) {
  auto value = fdp->ConsumeBool(/*FDP_ID:100100*/ 100100);
}
"""

    cleaned, removed = strip_injected_ids(source)

    assert removed == 1
    assert "ConsumeBool()" in cleaned
    assert "100100" not in cleaned
    assert "FDP_ID" not in cleaned


def test_strip_injected_ids_preserves_non_ascii_text_before_callsite() -> None:
    source = """
// café
void f(FuzzedDataProvider* fdp) {
  auto value = fdp->ConsumeBool(/*FDP_ID:100001*/ 100001);
}
"""

    cleaned, removed = strip_injected_ids(source)

    assert removed == 1
    assert "// café" in cleaned
    assert "ConsumeBool()" in cleaned


def test_strip_injected_ids_removes_reducer_mutated_range_id() -> None:
    source = """
void f(FuzzedDataProvider* fdp) {
  auto value = fdp->ConsumeIntegralInRange<int>(1, 0, 0);
}
"""

    cleaned, removed = strip_injected_ids(source)

    assert removed == 1
    assert "ConsumeIntegralInRange<int>(1, 0)" in cleaned
    assert "ConsumeIntegralInRange<int>(1, 0, 0)" not in cleaned


def test_strip_injected_ids_removes_reducer_mutated_zero_arg_id() -> None:
    source = """
void f(FuzzedDataProvider* fdp) {
  auto value = fdp->ConsumeBool(1);
  auto remaining = fdp->remaining_bytes(0);
}
"""

    cleaned, removed = strip_injected_ids(source)

    assert removed == 2
    assert "ConsumeBool()" in cleaned
    assert "remaining_bytes()" in cleaned


def test_strip_injected_ids_removes_reducer_mutated_id_after_optional_argument() -> None:
    source = """
void f(FuzzedDataProvider* fdp) {
  auto bytes = fdp->ConsumeBytesWithTerminator<uint8_t>(3, 99, 0);
}
"""

    cleaned, removed = strip_injected_ids(source)

    assert removed == 1
    assert "ConsumeBytesWithTerminator<uint8_t>(3, 99)" in cleaned


def test_strip_injected_ids_preserves_legal_optional_numeric_arguments() -> None:
    source = """
void f(FuzzedDataProvider* fdp, uint8_t* buffer, size_t size) {
  auto bytes = fdp->ConsumeBytesWithTerminator<uint8_t>(3, 99);
  auto token = fdp->ConsumeRandomLengthString(10);
  auto copied = fdp->ConsumeData(buffer, size);
}
"""

    cleaned, removed = strip_injected_ids(source)

    assert removed == 0
    assert cleaned == source

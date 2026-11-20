import pytest

from harnessreducer.fdp_transform import inject_ids, strip_injected_ids


@pytest.mark.parametrize("call", [
    "fdp.ConsumeBytes<uint8_t>(100001)",
    "fdp.ConsumeBytesWithTerminator<uint8_t>(100001)",
    "fdp.ConsumeBytesWithTerminator<uint8_t>(8, 200)",
    "fdp.ConsumeBytesAsString(100001)",
    "fdp.ConsumeRandomLengthString(100001)",
    "fdp.ConsumeIntegralInRange<int>(0, 100001)",
    "fdp.ConsumeFloatingPointInRange<double>(0, 100001)",
    "fdp.ConsumeData(buffer, 100001)",
])
@pytest.mark.parametrize("start_id", [100, 100000])
def test_strip_injected_ids_preserves_native_arguments_after_repeated_cleanup(call, start_id) -> None:
    source = f"void f() {{ {call}; }}"
    assert strip_injected_ids(source, start_id=start_id) == (source, 0)

    tagged, injected = inject_ids(source, start_id, "FDP_ID")
    assert injected == 1
    cleaned, removed = strip_injected_ids(tagged, start_id=start_id)
    assert (cleaned, removed) == (source, 1)
    assert strip_injected_ids(cleaned, start_id=start_id) == (source, 0)


@pytest.mark.parametrize("call", [
    "fdp.ConsumeBytes<uint8_t>(100001)",
    "fdp.ConsumeRandomLengthString(100001)",
    "fdp.ConsumeIntegralInRange<int>(0, 100001)",
])
def test_strip_unmarked_extra_id_preserves_the_remaining_numeric_argument(call) -> None:
    source = f"void f() {{ {call}; }}"
    tagged, _ = inject_ids(source, 100100, "FDP_ID")
    tagged = tagged.replace("/*FDP_ID:100100*/ ", "")
    cleaned, removed = strip_injected_ids(tagged)
    assert (cleaned, removed) == (source, 1)
    assert strip_injected_ids(cleaned) == (source, 0)


@pytest.mark.parametrize("marker", ["FDP_ID", "CUSTOM.ID+"])
@pytest.mark.parametrize("value", ["0", "-1", "100001"])
@pytest.mark.parametrize("call", [
    "fdp.ConsumeBool()",
    "fdp.ConsumeRandomLengthString()",
    "fdp.ConsumeBytesWithTerminator<uint8_t>(8)",
])
def test_strip_marked_id_after_reduction_preserves_optional_arguments(marker, value, call) -> None:
    source = f"void f() {{ {call}; }}"
    tagged, _ = inject_ids(source, 100100, marker)
    tagged = tagged.replace(f"/*{marker}:100100*/ 100100", f"/*{marker}:100100*/ {value}")
    assert strip_injected_ids(tagged, marker=marker) == (source, 1)


@pytest.mark.parametrize("comment", [
    "/* remember FDP_ID:100001 */",
    "/*NOT_FDP_ID:100001*/",
    "/*FDP_ID:invalid*/",
])
def test_strip_injected_ids_preserves_arguments_with_unrelated_comments(comment) -> None:
    source = f"void f() {{ fdp.ConsumeRandomLengthString({comment} 100001); }}"
    assert strip_injected_ids(source) == (source, 0)


def test_strip_injected_ids_preserves_required_arguments_even_with_marker() -> None:
    source = "void f() { fdp.ConsumeBytesAsString(/*FDP_ID:100001*/ 100001); }"
    assert strip_injected_ids(source) == (source, 0)


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

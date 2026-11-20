import pytest

from harnessreducer.fdp_transform import _find_fdp_calls_for_inline, inject_ids, strip_injected_ids


@pytest.mark.parametrize("call", [
    "fdp.ConsumeBytes<uint8_t>(100001)",
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
@pytest.mark.parametrize(("method", "args"), [
    ("fdp.ConsumeBool", ""),
    ("fdp.ConsumeRandomLengthString", ""),
    ("fdp.ConsumeBytesWithTerminator<uint8_t>", "8"),
])
def test_strip_legacy_marked_id_preserves_optional_arguments(marker, value, method, args) -> None:
    source = f"void f() {{ {method}({args}); }}"
    site = f"/*{marker}:100100*/ {value}"
    tagged_args = f"{args}, {site}" if args else site
    tagged = f"void f() {{ {method}({tagged_args}); }}"
    assert strip_injected_ids(tagged, marker=marker) == (source, 1)


@pytest.mark.parametrize("call", [
    "fdp.ConsumeBytesAsString(prefix..., 200000)",
    "fdp.ConsumeRandomLengthString()",
    "fdp.ConsumeBytesWithTerminator<uint8_t>(100001)",
])
def test_unverified_argument_count_leaves_the_call_intact(call) -> None:
    source = f"void f() {{ {call}; fdp.ConsumeBool(); }}"
    tagged, count = inject_ids(source, 100100, "FDP_ID")
    assert count == 1
    assert call in tagged
    without_comment = tagged.replace("/*FDP_ID:100100*/ ", "")
    assert strip_injected_ids(without_comment) == (source, 1)
    assert strip_injected_ids(source) == (source, 0)
    with pytest.raises(ValueError, match="none can be tagged"):
        inject_ids(f"void f() {{ {call}; }}", 100100, "FDP_ID")


def test_legacy_marked_argument_pack_is_rejected_before_cleanup() -> None:
    source = "void f() { fdp.ConsumeBytesAsString(prefix..., 200000, /*FDP_ID:100100*/ 100100); }"
    with pytest.raises(ValueError, match="parameter pack"):
        strip_injected_ids(source)


@pytest.mark.parametrize(("call", "native_args"), [
    ("ConsumeIntegralInRange<int>(0, 200000)", ["0", "200000"]),
    ("ConsumeIntegralInRange<unsigned>(0, 200000u)", ["0", "200000u"]),
    ("ConsumeIntegralInRange<int>(0, (200000))", ["0", "(200000)"]),
    ("ConsumeRandomLengthString(100100)", ["100100"]),
    ("ConsumeBytesAsString(prefix..., 200000)", ["prefix...", "200000"]),
    ("ConsumeBytesWithTerminator<uint8_t>(size)", ["size"]),
])
def test_native_arguments_supply_no_inline_lookup_keys(call, native_args) -> None:
    site, = _find_fdp_calls_for_inline(f"void f() {{ fdp.{call}; }}")
    assert site.arg_texts == native_args
    assert site.key is None
    assert site.fallback_keys == []


def test_native_optional_value_with_unrelated_marker_is_ignored() -> None:
    source = "void f() { fdp.ConsumeRandomLengthString(/*OTHER:7*/ 100100); }"
    site, = _find_fdp_calls_for_inline(source, marker="SITE")
    assert site.key is None
    assert site.arg_texts == ["100100"]


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

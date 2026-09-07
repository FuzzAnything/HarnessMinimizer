from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Deque

import tree_sitter_cpp as ts_cpp
from tree_sitter import Language, Node, Parser

SUPPORTED_FDP_APIS = {
    "ConsumeBytes",
    "ConsumeBytesWithTerminator",
    "ConsumeRemainingBytes",
    "ConsumeBytesAsString",
    "ConsumeRandomLengthString",
    "ConsumeRemainingBytesAsString",
    "ConsumeIntegral",
    "ConsumeIntegralInRange",
    "ConsumeFloatingPoint",
    "ConsumeFloatingPointInRange",
    "ConsumeProbability",
    "ConsumeBool",
    "ConsumeEnum",
    "PickValueInArray",
    "ConsumeData",
    "remaining_bytes",
}

CPP_LANGUAGE = Language(ts_cpp.language())
PARSER = Parser(CPP_LANGUAGE)
VALUES_HEADER_NAME = "harness_values.h"
MAX_INLINE_BUFFER_BYTES = 64   # threshold for large buffers that should be moved to a header instead of inlined as literals
_HEADER_BYTES_PER_LINE = 16
_STRING_LITERAL_CHUNK_BYTES = 64
_LLONG_MIN = -(2**63)
_LLONG_MAX = 2**63 - 1
_ULLONG_MAX = 2**64 - 1

_BOOL_METHODS = {"ConsumeBool"}
_STRING_METHODS = {
    "ConsumeBytesAsString",
    "ConsumeRandomLengthString",
    "ConsumeRemainingBytesAsString",
}
_BYTES_METHODS = {
    "ConsumeBytes",
    "ConsumeBytesWithTerminator",
    "ConsumeRemainingBytes",
}
_BUFFER_METHODS = _STRING_METHODS | _BYTES_METHODS | {"ConsumeData"}
_FLOAT_METHODS = {
    "ConsumeFloatingPoint",
    "ConsumeFloatingPointInRange",
    "ConsumeProbability",
}
_SCALAR_METHODS = _FLOAT_METHODS | {
    "ConsumeIntegral",
    "ConsumeIntegralInRange",
    "ConsumeEnum",
    "PickValueInArray",
}


@dataclass
class CallSite:
    start: int
    end: int
    method: str
    key: int | None
    fallback_keys: list[int]
    arg_texts: list[str]
    template_arg: str | None = None


@dataclass(frozen=True)
class InlineSkip:
    key: int
    method: str
    reason: str
    record_count: int


@dataclass(frozen=True)
class InlineResult:
    source: str
    replaced: int
    skipped: tuple[InlineSkip, ...] = ()
    header_name: str | None = None
    header_source: str = ""
    detected_calls: int = 0
    loop_replaced: int = 0
    header_replaced: int = 0
    large_buffer_replaced: int = 0


@dataclass(frozen=True)
class ValuesHeaderEntry:
    key: int
    method: str
    declaration: str
    includes: tuple[str, ...] = ()
    helpers: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScalarResultType:
    """Type of the replacement expression, independent of trace storage."""

    cpp_type: str
    floating_storage: bool = False
    includes: tuple[str, ...] = ()

    def expression(self, value: str) -> str:
        # A cast also restores a value expression when storage is a const lvalue.
        return f"static_cast<{self.cpp_type}>({value})"


def _iter_nodes(root: Node) -> list[Node]:
    nodes: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        nodes.append(node)
        for child in reversed(node.children):
            stack.append(child)
    return nodes


def _node_text(source_bytes: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _extract_method_name(field_node: Node, source_bytes: bytes) -> str:
    if field_node.type == "field_identifier":
        return _node_text(source_bytes, field_node)
    if field_node.type == "template_method":
        for child in field_node.children:
            if child.type == "field_identifier":
                return _node_text(source_bytes, child)
    return ""


def _normalize_type_text(type_text: str) -> str:
    return " ".join(type_text.strip().split())


def _extract_first_template_argument(field_node: Node, source_bytes: bytes) -> str | None:
    if field_node.type != "template_method":
        return None

    for child in field_node.children:
        if child.type != "template_argument_list":
            continue
        named_children = [named for named in child.named_children if named.type != "comment"]
        if named_children:
            return _normalize_type_text(_node_text(source_bytes, named_children[0]))

        text = _node_text(source_bytes, child).strip()
        if text.startswith("<") and text.endswith(">"):
            return _normalize_type_text(text[1:-1])
    return None


def _is_supported_fdp_call(call_node: Node, source_bytes: bytes) -> bool:
    function_node = call_node.child_by_field_name("function")
    if function_node is None or function_node.type != "field_expression":
        return False

    receiver = function_node.child_by_field_name("argument")
    field = function_node.child_by_field_name("field")

    if _node_text(source_bytes, receiver).strip() != "fdp":
        return False
    if field is None:
        return False

    method_name = _extract_method_name(field, source_bytes)
    return method_name in SUPPORTED_FDP_APIS


def _parse_int_literal(token: str) -> int | None:
    text = token.strip()
    if not text:
        return None
    if text.startswith("+"):
        text = text[1:]
    try:
        return int(text, 0)
    except ValueError:
        return None


def _extract_explicit_id(args_node: Node, source_bytes: bytes) -> int | None:
    arg_nodes = list(args_node.named_children)
    if not arg_nodes:
        return None
    last = arg_nodes[-1]
    if last.type not in {"number_literal", "unary_expression"}:
        return None
    return _parse_int_literal(_node_text(source_bytes, last))


def _extract_call_arg_texts(args_node: Node, source_bytes: bytes) -> list[str]:
    return [
        _node_text(source_bytes, child).strip()
        for child in args_node.named_children
        if child.type != "comment"
    ]


def _default_site_id_candidates(call_node: Node, field_node: Node | None) -> list[int]:
    row0, col0 = call_node.start_point
    if field_node is not None:
        _, col0 = field_node.start_point
    line = row0 + 1
    return [((line << 12) ^ (col0 + 1)), ((line << 12) ^ col0), line]


def _find_fdp_calls_for_inline(source: str) -> list[CallSite]:
    source_bytes = source.encode("utf-8")
    tree = PARSER.parse(source_bytes)
    calls: list[CallSite] = []

    for node in _iter_nodes(tree.root_node):
        if node.type != "call_expression":
            continue

        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "field_expression":
            continue

        recv = fn.child_by_field_name("argument")
        field = fn.child_by_field_name("field")
        if _node_text(source_bytes, recv).strip() != "fdp" or field is None:
            continue

        method = _extract_method_name(field, source_bytes)
        if method not in SUPPORTED_FDP_APIS:
            continue
        template_arg = _extract_first_template_argument(field, source_bytes)

        args = node.child_by_field_name("arguments")
        if args is None:
            continue

        arg_texts = _extract_call_arg_texts(args, source_bytes)
        key = _extract_explicit_id(args, source_bytes)
        original_arg_texts = arg_texts
        if key is not None and arg_texts:
            last_arg_value = _parse_int_literal(arg_texts[-1])
            if last_arg_value == key:
                original_arg_texts = arg_texts[:-1]

        fallback_keys: list[int] = []
        if key is None:
            fallback_keys = _default_site_id_candidates(node, field)
            if fallback_keys:
                key = fallback_keys[0]

        calls.append(
            CallSite(
                start=node.start_byte,
                end=node.end_byte,
                method=method,
                key=key,
                fallback_keys=fallback_keys,
                arg_texts=original_arg_texts,
                template_arg=template_arg,
            )
        )

    return calls


def _find_argument_list_ranges(source_bytes: bytes) -> list[tuple[int, int]]:
    tree = PARSER.parse(source_bytes)
    ranges: list[tuple[int, int]] = []

    for node in _iter_nodes(tree.root_node):
        if node.type != "call_expression":
            continue
        if not _is_supported_fdp_call(node, source_bytes):
            continue

        args = node.child_by_field_name("arguments")
        if args is None or args.type != "argument_list":
            continue

        ranges.append((args.start_byte + 1, args.end_byte - 1))

    return ranges


def inject_ids(src: str, start_id: int, marker: str) -> tuple[str, int]:
    source_bytes = src.encode("utf-8")
    arg_ranges = _find_argument_list_ranges(source_bytes)
    if not arg_ranges:
        return src, 0

    planned_inserts: list[tuple[int, bytes]] = []
    next_id = start_id
    marker_bytes = marker.encode("utf-8")

    # Assign IDs in source order for determinism, then insert from back to front
    # so nested argument ranges never invalidate each other.
    for start, end in sorted(arg_ranges, key=lambda item: item[0]):
        args = source_bytes[start:end]
        if marker_bytes in args:
            continue

        id_payload = f"/*{marker}:{next_id}*/ {next_id}".encode("utf-8")
        insert_text = b", " + id_payload if args.strip() else id_payload
        planned_inserts.append((end, insert_text))
        next_id += 1

    if not planned_inserts:
        return src, 0

    changed = source_bytes
    for pos, insert_text in sorted(planned_inserts, key=lambda item: item[0], reverse=True):
        changed = changed[:pos] + insert_text + changed[pos:]

    return changed.decode("utf-8"), len(planned_inserts)


def load_trace(trace_path: Path) -> dict[int, Deque[tuple[str, Any]]]:
    streams: dict[int, Deque[tuple[str, Any]]] = defaultdict(deque)
    lines = trace_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    for line in lines:
        parts = line.strip().split()
        if not parts:
            continue

        try:
            key = int(parts[1], 0)
        except (ValueError, IndexError):
            continue

        record_type = parts[0]
        if record_type == "S":
            # Parse via Decimal to preserve large integer precision even in scientific notation.
            value_str = parts[2]
            val: Any
            try:
                val = int(value_str, 0)
                if val == 0 and value_str.startswith("-"):
                    val = Decimal("-0")
            except ValueError:
                try:
                    dec = Decimal(value_str)
                except (InvalidOperation, ValueError):
                    val = float(value_str)
                else:
                    if dec.is_finite() and not (dec.is_zero() and dec.is_signed()) and dec == dec.to_integral_value():
                        val = int(dec)
                    else:
                        # Retain precision for long double and signed zero.
                        # The consuming FDP call, not the spelling of the
                        # trace number, determines its eventual C++ type.
                        val = dec
            streams[key].append(("S", val))
        elif record_type == "R":
            streams[key].append(("R", int(parts[2], 0)))
        elif record_type == "B":
            count = int(parts[2], 0)
            bytes_list: list[int] = []
            for i in range(count):
                bytes_list.append(int(parts[3 + i]) if 3 + i < len(parts) else 0)
            streams[key].append(("B", bytes_list))

    return streams


def _cpp_string_literal(bytes_list: list[int]) -> str:
    chars: list[str] = []
    for value in bytes_list:
        b = value & 0xFF
        if b == ord('"'):
            chars.append('\\"')
        elif b == ord("\\"):
            chars.append('\\\\')
        elif b == ord("\n"):
            chars.append('\\n')
        elif b == ord("\r"):
            chars.append('\\r')
        elif b == ord("\t"):
            chars.append('\\t')
        elif 32 <= b <= 126:
            chars.append(chr(b))
        else:
            chars.append(f"\\{b:03o}")
    return '"' + "".join(chars) + '"'


def _cpp_byte_literal(value: int) -> str:
    return f"0x{value & 0xFF:02x}"


def _vector_element_type_for_call(call: CallSite) -> str:
    if call.method in _BYTES_METHODS and call.template_arg:
        return _normalize_type_text(call.template_arg)
    if call.method == "ConsumeBytesWithTerminator" and len(call.arg_texts) >= 2:
        return f"std::decay_t<decltype(({call.arg_texts[1]}))>"
    return "unsigned char"


# Byte headers store exactly the trace bytes. Element types (including local
# aliases and template parameters) are only named at the original call site.
# The normal arithmetic path uses the same range construction as FDP replay.
_BYTE_COPY_HELPER = """namespace harnessreducer_inline_detail {
template <typename T>
std::vector<T> copy_bytes(const unsigned char *data, size_t size) {
    if (size == 0)
        return {};
    if constexpr (std::is_convertible_v<unsigned char, T>) {
        return std::vector<T>(data, data + size);
    } else {
        std::vector<T> result(size);
        for (size_t i = 0; i < size; ++i)
            result[i] = static_cast<T>(data[i]);
        return result;
    }
}
template <typename T>
std::vector<T> copy_bytes(const std::vector<unsigned char>& data) {
    return copy_bytes<T>(data.data(), data.size());
}
} // namespace harnessreducer_inline_detail"""


def _vector_type_includes(element_type: str) -> tuple[str, ...]:
    normalized = _normalize_type_text(element_type)
    if normalized in {"uint8_t", "int8_t"}:
        return ("<stdint.h>",)
    if "std::uint8_t" in normalized or "std::int8_t" in normalized:
        return ("<cstdint>",)
    if "std::byte" in normalized:
        return ("<cstddef>",)
    return ()


def _cpp_byte_literal_for_type(value: int, element_type: str) -> str:
    normalized = _normalize_type_text(element_type)
    b = value & 0xFF

    if normalized == "std::byte":
        return f"std::byte{{0x{b:02x}}}"
    if normalized in {"unsigned char", "uint8_t", "std::uint8_t"}:
        return _cpp_byte_literal(b)
    # Local aliases may denote signed bytes or enums; list initialization must
    # not infer their signedness from the spelling of the type name.
    return f"static_cast<{element_type}>(0x{b:02x})"


def _cpp_vector_literal(bytes_list: list[int], element_type: str = "unsigned char") -> str:
    vector_type = f"std::vector<{element_type}>"
    if not bytes_list:
        return f"{vector_type}{{}}"
    byte_text = ", ".join(_cpp_byte_literal_for_type(b, element_type) for b in bytes_list)
    return f"{vector_type}{{{byte_text}}}"


def _format_wrapped_items(items: list[str], per_line: int = _HEADER_BYTES_PER_LINE) -> str:
    if not items:
        return "{}"

    lines = ["{"]
    for start in range(0, len(items), per_line):
        chunk = items[start : start + per_line]
        suffix = "," if start + per_line < len(items) else ""
        lines.append("    " + ", ".join(chunk) + suffix)
    lines.append("}")
    return "\n".join(lines)


def _cpp_byte_array_initializer(bytes_list: list[int], element_type: str) -> str:
    items = [_cpp_byte_literal_for_type(value, element_type) for value in bytes_list]
    return _format_wrapped_items(items)


def _cpp_chunked_string_initializer(bytes_list: list[int]) -> str:
    if len(bytes_list) <= _STRING_LITERAL_CHUNK_BYTES:
        return _cpp_string_literal(bytes_list)

    chunks = [
        bytes_list[start : start + _STRING_LITERAL_CHUNK_BYTES]
        for start in range(0, len(bytes_list), _STRING_LITERAL_CHUNK_BYTES)
    ]
    return "\n".join(f"    {_cpp_string_literal(chunk)}" for chunk in chunks)


def _scalar_result_type(call: CallSite) -> ScalarResultType | None:
    if call.method in _BOOL_METHODS:
        return ScalarResultType("bool")
    if call.method in {"remaining_bytes", "ConsumeData"}:
        return ScalarResultType("size_t", includes=("<cstddef>",))
    if call.method not in _SCALAR_METHODS:
        return None

    # PickValueInArray can return floating values, including values whose trace
    # spelling is integral. Long double matches the scalar replay storage and
    # avoids guessing the category of a local alias or deduced element type.
    floating_storage = call.method in _FLOAT_METHODS or call.method == "PickValueInArray"
    if call.template_arg:
        return ScalarResultType(call.template_arg, floating_storage)
    if call.method in {"ConsumeIntegralInRange", "ConsumeFloatingPointInRange"} and call.arg_texts:
        # Arithmetic would promote narrow integers. Deduction from either bound
        # strips cv/reference qualifiers while retaining the original width.
        return ScalarResultType(
            f"std::decay_t<decltype(({call.arg_texts[0]}))>",
            floating_storage, ("<type_traits>",),
        )
    if call.method == "PickValueInArray" and call.arg_texts:
        array = call.arg_texts[0]
        # std::begin handles C arrays, std::array and braced initializer lists.
        argument = array if array.startswith("{") else f"({array})"
        return ScalarResultType(
            f"std::decay_t<decltype(*std::begin({argument}))>",
            True, ("<iterator>", "<type_traits>"),
        )
    return None


def _format_cpp_floating(value: Any, cpp_type: str) -> str:
    # Replay reads S records as long double and then converts to the FDP
    # return type. Emit the same conversion as a constant expression, without
    # routing through Python's binary64 float or an oversized integer token.
    number = value if isinstance(value, Decimal) else Decimal(value)
    if number.is_nan():
        literal = "std::numeric_limits<long double>::quiet_NaN()"
    elif number.is_infinite():
        literal = "std::numeric_limits<long double>::infinity()"
    else:
        mantissa, exponent = format(number, "e").split("e")
        if "." in mantissa:
            mantissa = mantissa.rstrip("0").rstrip(".")
        if "." not in mantissa:
            mantissa += ".0"
        literal = f"{mantissa}e{exponent}L"
    if not number.is_finite() and number.is_signed():
        literal = "-" + literal
    return f"static_cast<{cpp_type}>({literal})"


def _format_cpp_number(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Decimal):
        return _format_cpp_floating(value, "double")
    if isinstance(value, float):
        if math.isnan(value):
            return "std::numeric_limits<double>::quiet_NaN()"
        if math.isinf(value):
            prefix = "-" if value < 0 else ""
            return f"{prefix}std::numeric_limits<double>::infinity()"
        text = repr(value)
        if "." not in text and "e" not in text.lower():
            text += ".0"
        return text
    ivalue = int(value)
    # -9223372036854775808 (LLONG_MIN) cannot be written as a C++ integer
    # literal: the magnitude 9223372036854775808 exceeds LLONG_MAX, so the
    # compiler interprets it as unsigned and rejects the narrowing to long
    # long.  Express it as -(LLONG_MAX) - 1, which keeps every literal token
    # representable while producing the same final value.
    if ivalue == _LLONG_MIN:
        return f"(-{_LLONG_MAX}LL - 1)"
    if _LLONG_MAX < ivalue <= _ULLONG_MAX:
        return f"{ivalue}ULL"
    return str(ivalue)


def _numeric_array_type(values: list[Any]) -> str:
    if any(isinstance(value, (float, Decimal)) for value in values):
        return "double"

    ints = [int(value) for value in values]
    if all(-(2**31) <= value <= 2**31 - 1 for value in ints):
        return "int"
    if all(value >= 0 for value in ints) and any(value > _LLONG_MAX for value in ints):
        return "unsigned long long"
    return "long long"


def _needs_numeric_limits(values: list[Any]) -> bool:
    return any(
        (isinstance(value, float) and not math.isfinite(value))
        or (isinstance(value, Decimal) and not value.is_finite())
        for value in values
    )


def _literal_for_single_record(
    call: CallSite, record_type: str, value: Any,
    result_type: ScalarResultType | None,
) -> str | None:
    method = call.method
    if method in _SCALAR_METHODS:
        if record_type != "S":
            return None
        if result_type is None:
            return None
        if result_type.floating_storage:
            return _format_cpp_floating(value, result_type.cpp_type)
        return result_type.expression(_format_cpp_number(value))
    if method == "ConsumeBool":
        return "true" if value != 0 else "false"
    if method in _STRING_METHODS:
        if record_type == "B":
            return f"std::string({_cpp_string_literal(value)}, {len(value)})"
        return 'std::string("")'
    if method in _BYTES_METHODS:
        element_type = _vector_element_type_for_call(call)
        if record_type == "B":
            return _cpp_vector_literal(value, element_type)
        return f"std::vector<{element_type}>{{}}"
    if method == "ConsumeData":
        size = f"static_cast<size_t>({len(value) if record_type == 'B' else 0})"
        if record_type != "B" or not value:
            return size
        if not call.arg_texts:
            return size
        destination = call.arg_texts[0]
        byte_vector = _cpp_vector_literal(value)
        return f"(std::memcpy({destination}, {byte_vector}.data(), {len(value)}), {size})"
    if method == "remaining_bytes":
        if isinstance(value, int):
            return f"static_cast<size_t>({value})"
        return "static_cast<size_t>(0)"
    return _format_cpp_number(value)


def _value_names(key: int) -> tuple[str, str]:
    return f"fuzz_values_{key}", f"fuzz_index_{key}"


def _byte_buffer_names(key: int) -> tuple[str, str]:
    values_name = f"fuzz_bytes_{key}"
    return values_name, f"{values_name}_size"


def _string_buffer_names(key: int) -> tuple[str, str]:
    values_name = f"fuzz_string_{key}"
    return values_name, f"{values_name}_size"


def _extract_record_values(records: list[tuple[str, Any]], expected_type: str) -> list[Any] | None:
    values: list[Any] = []
    for record_type, value in records:
        if record_type != expected_type:
            return None
        values.append(value)
    return values


def _make_bool_header_entry(key: int, method: str, values: list[Any]) -> ValuesHeaderEntry:
    values_name, index_name = _value_names(key)
    value_text = ", ".join("true" if value else "false" for value in values)
    declaration = (
        f"static const bool {values_name}[] = {{{value_text}}};\n"
        f"static size_t {index_name} = 0;"
    )
    return ValuesHeaderEntry(key=key, method=method, declaration=declaration)


def _make_numeric_header_entry(
    key: int, call: CallSite, values: list[Any], result_type: ScalarResultType,
) -> ValuesHeaderEntry:
    values_name, index_name = _value_names(key)
    if result_type.floating_storage:
        value_type = result_type.cpp_type
        if value_type not in {"float", "double", "long double"}:
            # Aliases, template parameters, and deduced types can be local to
            # the harness. Keep them out of the global generated header and
            # apply their conversion at the original call site instead.
            value_type = "long double"
        value_text = ", ".join(_format_cpp_floating(value, value_type) for value in values)
    else:
        value_type = _numeric_array_type(values)
        value_text = ", ".join(_format_cpp_number(value) for value in values)
    declaration = (
        f"static const {value_type} {values_name}[] = {{{value_text}}};\n"
        f"static size_t {index_name} = 0;"
    )
    includes = ("<limits>",) if _needs_numeric_limits(values) else ()
    return ValuesHeaderEntry(key=key, method=call.method, declaration=declaration, includes=includes)


def _make_size_t_header_entry(key: int, method: str, values: list[Any]) -> ValuesHeaderEntry:
    values_name, index_name = _value_names(key)
    value_text = ", ".join(f"static_cast<size_t>({int(value)})" for value in values)
    declaration = (
        f"static const size_t {values_name}[] = {{{value_text}}};\n"
        f"static size_t {index_name} = 0;"
    )
    return ValuesHeaderEntry(key=key, method=method, declaration=declaration)


def _make_string_header_entry(key: int, method: str, byte_values: list[list[int]]) -> ValuesHeaderEntry:
    values_name, index_name = _value_names(key)
    entries = [
        f"    std::string({_cpp_string_literal(bytes_list)}, {len(bytes_list)})"
        for bytes_list in byte_values
    ]
    declaration = (
        f"static const std::string {values_name}[] = {{\n"
        + ",\n".join(entries)
        + f"\n}};\nstatic size_t {index_name} = 0;"
    )
    return ValuesHeaderEntry(key=key, method=method, declaration=declaration, includes=("<string>",))


def _make_vector_header_entry(
    key: int,
    method: str,
    byte_values: list[list[int]],
) -> ValuesHeaderEntry:
    values_name, index_name = _value_names(key)
    entries = [f"    {_cpp_vector_literal(bytes_list)}" for bytes_list in byte_values]
    declaration = (
        f"static const std::vector<unsigned char> {values_name}[] = {{\n"
        + ",\n".join(entries)
        + f"\n}};\nstatic size_t {index_name} = 0;"
    )
    includes = ("<vector>",)
    helpers = ()
    if method in _BYTES_METHODS:
        includes += ("<type_traits>",)
        helpers = (_BYTE_COPY_HELPER,)
    return ValuesHeaderEntry(
        key=key, method=method, declaration=declaration, includes=includes, helpers=helpers,
    )


def _make_large_byte_header_entry(
    key: int,
    method: str,
    bytes_list: list[int],
    extra_includes: tuple[str, ...] = (),
) -> ValuesHeaderEntry:
    values_name, size_name = _byte_buffer_names(key)
    declaration = (
        f"static const unsigned char {values_name}[] = "
        f"{_cpp_byte_array_initializer(bytes_list, 'unsigned char')};\n"
        f"static const size_t {size_name} = "
        f"sizeof({values_name}) / sizeof({values_name}[0]);"
    )
    includes = extra_includes
    helpers = ()
    if method in _BYTES_METHODS:
        includes += ("<vector>", "<type_traits>")
        helpers = (_BYTE_COPY_HELPER,)
    return ValuesHeaderEntry(
        key=key, method=method, declaration=declaration, includes=includes, helpers=helpers,
    )


def _make_large_string_header_entry(
    key: int,
    method: str,
    bytes_list: list[int],
) -> ValuesHeaderEntry:
    values_name, size_name = _string_buffer_names(key)
    initializer = _cpp_chunked_string_initializer(bytes_list)
    if "\n" in initializer:
        declaration = f"static const char {values_name}[] =\n{initializer};\n"
    else:
        declaration = f"static const char {values_name}[] = {initializer};\n"
    declaration += (
        f"static const size_t {size_name} = sizeof({values_name}) - 1;"
        "  // exclude the trailing '\\0'"
    )
    return ValuesHeaderEntry(key=key, method=method, declaration=declaration)


def _large_single_record_replacement_for_call(
    call: CallSite,
    matched_key: int,
    record_type: str,
    value: Any,
) -> tuple[str, ValuesHeaderEntry] | None:
    if (
        call.method not in _BUFFER_METHODS
        or record_type != "B"
        or not isinstance(value, list)
        or len(value) <= MAX_INLINE_BUFFER_BYTES
    ):
        return None

    if call.method in _STRING_METHODS:
        values_name, size_name = _string_buffer_names(matched_key)
        replacement = f"std::string({values_name}, {size_name})"
        return replacement, _make_large_string_header_entry(matched_key, call.method, value)

    if call.method in _BYTES_METHODS:
        element_type = _vector_element_type_for_call(call)
        values_name, size_name = _byte_buffer_names(matched_key)
        replacement = (
            f"harnessreducer_inline_detail::copy_bytes<{element_type}>"
            f"({values_name}, {size_name})"
        )
        return replacement, _make_large_byte_header_entry(matched_key, call.method, value)

    if call.method == "ConsumeData":
        if not call.arg_texts:
            return None
        values_name, size_name = _byte_buffer_names(matched_key)
        destination = call.arg_texts[0]
        replacement = (
            f"(std::memcpy({destination}, {values_name}, {size_name}), "
            f"static_cast<size_t>({size_name}))"
        )
        return replacement, _make_large_byte_header_entry(
            matched_key, call.method, value, extra_includes=("<cstring>",)
        )

    return None


def _repeated_replacement_for_call(
    call: CallSite,
    matched_key: int,
    records: list[tuple[str, Any]],
    result_type: ScalarResultType | None,
) -> tuple[str, ValuesHeaderEntry] | None:
    values_name, index_name = _value_names(matched_key)
    indexed_value = f"{values_name}[{index_name}++]"

    if call.method in _BOOL_METHODS:
        values = _extract_record_values(records, "S")
        if values is None:
            return None
        return f"static_cast<bool>({indexed_value})", _make_bool_header_entry(matched_key, call.method, values)

    if call.method in _STRING_METHODS:
        byte_values = _extract_record_values(records, "B")
        if byte_values is None:
            return None
        return f"std::string({indexed_value})", _make_string_header_entry(matched_key, call.method, byte_values)

    if call.method in _BYTES_METHODS:
        byte_values = _extract_record_values(records, "B")
        if byte_values is None:
            return None
        element_type = _vector_element_type_for_call(call)
        replacement = f"harnessreducer_inline_detail::copy_bytes<{element_type}>({indexed_value})"
        return replacement, _make_vector_header_entry(matched_key, call.method, byte_values)

    if call.method == "ConsumeData":
        byte_values = _extract_record_values(records, "B")
        if byte_values is None or not call.arg_texts:
            return None
        entry = _make_vector_header_entry(matched_key, call.method, byte_values)
        destination = call.arg_texts[0]
        replacement = (
            f"(std::memcpy({destination}, {values_name}[{index_name}].data(), "
            f"{values_name}[{index_name}].size()), "
            f"{values_name}[{index_name}++].size())"
        )
        return replacement, entry

    if call.method == "remaining_bytes":
        values = _extract_record_values(records, "R")
        if values is None:
            return None
        return f"static_cast<size_t>({indexed_value})", _make_size_t_header_entry(matched_key, call.method, values)

    if call.method in _SCALAR_METHODS:
        values = _extract_record_values(records, "S")
        if values is None or result_type is None:
            return None
        return result_type.expression(indexed_value), _make_numeric_header_entry(
            matched_key, call, values, result_type,
        )

    return None


def _build_values_header(entries: list[ValuesHeaderEntry]) -> str:
    if not entries:
        return ""

    include_set = {"<cstddef>"}
    for entry in entries:
        include_set.update(entry.includes)

    include_order = ["<cstddef>", "<cstring>", "<limits>", "<string>", "<vector>"]
    ordered_includes = [include for include in include_order if include in include_set]
    ordered_includes.extend(sorted(include_set - set(ordered_includes)))

    lines = ["#pragma once"]
    lines.extend(f"#include {include}" for include in ordered_includes)
    lines.append("")

    for helper in dict.fromkeys(helper for entry in entries for helper in entry.helpers):
        lines.extend((helper, ""))

    for entry in entries:
        lines.append(f"// Values recorded from FDP_ID {entry.key} ({entry.method}).")
        lines.append(entry.declaration)
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _ensure_values_header_include(source: str, header_name: str) -> str:
    include_line = f'#include "{header_name}"'
    if include_line in source:
        return source
    return include_line + "\n" + source


def _range_overlaps_any(
    start: int,
    end: int,
    ranges: list[tuple[int, int]],
) -> bool:
    return any(start < range_end and range_start < end for range_start, range_end in ranges)


def inline_source_with_report(
    source: str,
    streams: dict[int, Deque[tuple[str, Any]]],
    header_name: str = VALUES_HEADER_NAME,
) -> InlineResult:
    calls = _find_fdp_calls_for_inline(source)
    if not calls:
        return InlineResult(source=source, replaced=0, detected_calls=0)

    replacements: list[tuple[int, int, str]] = []
    source_includes: set[str] = set()
    skipped: list[InlineSkip] = []
    header_entries: list[ValuesHeaderEntry] = []
    header_keys: set[int] = set()
    replaced = 0
    loop_replaced = 0
    header_replaced = 0
    large_buffer_replaced = 0
    replaced_ranges: list[tuple[int, int]] = []

    # Nested FDP expressions can produce overlapping source ranges, for example:
    #
    #   fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes(...), ...)
    #   └────────────── outer replacement range ───────────────┘
    #                                      └─ inner range ─┘
    #
    # If the outer call is replayed, replacing the inner call separately is both
    # unnecessary and unsafe for textual rewriting: the stale inner replacement
    # offsets can corrupt the already-replaced outer text. Process outer calls
    # first, then skip any later call whose range overlaps an accepted replay.
    for call in sorted(calls, key=lambda item: (item.start, -item.end)):
        if _range_overlaps_any(call.start, call.end, replaced_ranges):
            continue

        matched_key: int | None = None
        candidate_keys: list[int] = []
        if call.key is not None:
            candidate_keys.append(call.key)
        candidate_keys.extend(call.fallback_keys)

        for candidate in candidate_keys:
            if candidate not in streams or not streams[candidate]:
                continue
            matched_key = candidate
            break

        if matched_key is None:
            continue

        result_type = _scalar_result_type(call)
        if call.method in _SCALAR_METHODS and result_type is None:
            skipped.append(InlineSkip(
                key=matched_key, method=call.method, reason="unsupported-result-type",
                record_count=len(streams[matched_key]),
            ))
            continue
        if result_type is not None:
            source_includes.update(result_type.includes)
        if call.method in _STRING_METHODS:
            source_includes.add("<string>")
        if call.method in _BYTES_METHODS:
            source_includes.add("<vector>")
            source_includes.update(_vector_type_includes(_vector_element_type_for_call(call)))
            if call.method == "ConsumeBytesWithTerminator" and not call.template_arg:
                source_includes.add("<type_traits>")
        if call.method == "ConsumeData":
            source_includes.update(("<cstring>", "<vector>"))

        record_count = len(streams[matched_key])
        if record_count == 1:
            record_type, value = streams[matched_key].popleft()
            large_buffer = _large_single_record_replacement_for_call(
                call, matched_key, record_type, value
            )
            if large_buffer is not None:
                literal, header_entry = large_buffer
                replacements.append((call.start, call.end, literal))
                replaced_ranges.append((call.start, call.end))
                replaced += 1
                header_replaced += 1
                large_buffer_replaced += 1
                if header_entry.key not in header_keys:
                    header_entries.append(header_entry)
                    header_keys.add(header_entry.key)
                continue

            literal = _literal_for_single_record(call, record_type, value, result_type)
            if literal is None:
                continue
            if record_type == "S" and _needs_numeric_limits([value]):
                source_includes.add("<limits>")
            replacements.append((call.start, call.end, literal))
            replaced_ranges.append((call.start, call.end))
            replaced += 1
            continue

        records = [streams[matched_key].popleft() for _ in range(record_count)]
        repeated = _repeated_replacement_for_call(call, matched_key, records, result_type)
        if repeated is None:
            skipped.append(
                InlineSkip(
                    key=matched_key,
                    method=call.method,
                    reason="unsupported-repeated-trace-id",
                    record_count=record_count,
                )
            )
            continue

        literal, header_entry = repeated
        replacements.append((call.start, call.end, literal))
        replaced_ranges.append((call.start, call.end))
        replaced += 1
        loop_replaced += 1
        header_replaced += 1
        if header_entry.key not in header_keys:
            header_entries.append(header_entry)
            header_keys.add(header_entry.key)

    if not replacements:
        return InlineResult(
            source=source,
            replaced=0,
            skipped=tuple(skipped),
            detected_calls=len(calls),
        )

    output = source.encode("utf-8")
    for start, end, literal in sorted(replacements, key=lambda item: item[0], reverse=True):
        output = output[:start] + literal.encode("utf-8") + output[end:]

    output_text = output.decode("utf-8")
    missing_includes = [
        f"#include {include}\n" for include in sorted(source_includes)
        if f"#include {include}" not in output_text
    ]
    output_text = "".join(missing_includes) + output_text

    header_source = ""
    result_header_name: str | None = None
    if header_entries:
        header_source = _build_values_header(header_entries)
        output_text = _ensure_values_header_include(output_text, header_name)
        result_header_name = header_name

    return InlineResult(
        source=output_text,
        replaced=replaced,
        skipped=tuple(skipped),
        header_name=result_header_name,
        header_source=header_source,
        detected_calls=len(calls),
        loop_replaced=loop_replaced,
        header_replaced=header_replaced,
        large_buffer_replaced=large_buffer_replaced,
    )


def inline_source(source: str, streams: dict[int, Deque[tuple[str, Any]]]) -> tuple[str, int]:
    result = inline_source_with_report(source, streams)
    return result.source, result.replaced


def strip_injected_ids(source: str, start_id: int = 100000) -> tuple[str, int]:
    """Remove numeric callsite IDs from a source instrumented by ``inject_ids``.

    Injected IDs are sequential and may exceed ``start_id + 99`` when a
    harness has more than 100 supported FDP callsites. This function is used
    only on pipeline-instrumented sources, so every final integer argument at
    or above ``start_id`` is treated as an injected ID.
    """
    source_bytes = source.encode("utf-8")
    tree = PARSER.parse(source_bytes)
    replacements: list[tuple[int, int, str]] = []
    removed = 0

    for node in _iter_nodes(tree.root_node):
        if node.type != "call_expression":
            continue
        if not _is_supported_fdp_call(node, source_bytes):
            continue

        args = node.child_by_field_name("arguments")
        if args is None or args.type != "argument_list":
            continue

        arg_nodes = [child for child in args.named_children if child.type != "comment"]
        if not arg_nodes:
            continue

        last = arg_nodes[-1]
        last_value = _parse_int_literal(_node_text(source_bytes, last))
        if last_value is None or last_value < start_id:
            continue

        arg_start = args.start_byte + 1
        arg_end = args.end_byte - 1
        if len(arg_nodes) == 1:
            replacements.append((arg_start, arg_end, ""))
            removed += 1
            continue

        prev = arg_nodes[-2]
        remove_start = prev.end_byte
        remove_end = last.end_byte

        for child in args.children:
            if child.type != ",":
                continue
            if child.start_byte >= prev.end_byte and child.end_byte <= last.start_byte:
                remove_start = child.start_byte

        replacements.append((remove_start, remove_end, ""))
        removed += 1

    if not replacements:
        return source, 0

    output = source.encode("utf-8")
    for start, end, replacement in sorted(replacements, key=lambda item: item[0], reverse=True):
        output = output[:start] + replacement.encode("utf-8") + output[end:]

    return output.decode("utf-8"), removed

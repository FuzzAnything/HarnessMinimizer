from __future__ import annotations

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


@dataclass
class CallSite:
    start: int
    end: int
    method: str
    key: int | None
    fallback_keys: list[int]


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

        args = node.child_by_field_name("arguments")
        if args is None:
            continue

        key = _extract_explicit_id(args, source_bytes)
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
            except ValueError:
                try:
                    dec = Decimal(value_str)
                except (InvalidOperation, ValueError):
                    val = float(value_str)
                else:
                    if dec == dec.to_integral_value():
                        val = int(dec)
                    else:
                        val = float(dec)
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


def inline_source(source: str, streams: dict[int, Deque[tuple[str, Any]]]) -> tuple[str, int]:
    calls = _find_fdp_calls_for_inline(source)
    if not calls:
        return source, 0

    replacements: list[tuple[int, int, str]] = []
    replaced = 0

    for call in calls:
        record = None
        if call.key is not None and call.key in streams and streams[call.key]:
            record = streams[call.key].popleft()
        else:
            for candidate in call.fallback_keys:
                if candidate in streams and streams[candidate]:
                    record = streams[candidate].popleft()
                    break

        if record is None:
            continue

        record_type, value = record
        literal = ""
        if call.method == "ConsumeBool":
            literal = "true" if value != 0 else "false"
        elif call.method in (
            "ConsumeBytesAsString",
            "ConsumeRandomLengthString",
            "ConsumeRemainingBytesAsString",
        ):
            if record_type == "B":
                hex_str = "".join(f"\\x{b:02x}" for b in value)
                literal = f'std::string("{hex_str}", {len(value)})'
            else:
                literal = 'std::string("")'
        elif call.method in (
            "ConsumeBytes",
            "ConsumeBytesWithTerminator",
            "ConsumeRemainingBytes",
        ):
            if record_type == "B":
                hex_list = ", ".join(f"0x{b:02x}" for b in value)
                literal = f"std::vector<unsigned char>{{{hex_list}}}"
            else:
                literal = "std::vector<unsigned char>{}"
        elif call.method == "ConsumeData":
            literal = str(len(value)) if record_type == "B" else "0"
        elif call.method == "remaining_bytes":
            if isinstance(value, int):
                literal = f"static_cast<size_t>({value})"
            else:
                literal = "static_cast<size_t>(0)"
        else:
            literal = str(value)

        replacements.append((call.start, call.end, literal))
        replaced += 1

    if not replacements:
        return source, 0

    output = source
    for start, end, literal in sorted(replacements, key=lambda item: item[0], reverse=True):
        output = output[:start] + literal + output[end:]

    return output, replaced


def strip_injected_ids(source: str, start_id: int = 100000) -> tuple[str, int]:
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
        if last_value is None or last_value < start_id or last_value >= start_id + 100:
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

    output = source
    for start, end, replacement in sorted(replacements, key=lambda item: item[0], reverse=True):
        output = output[:start] + replacement + output[end:]

    return output, removed

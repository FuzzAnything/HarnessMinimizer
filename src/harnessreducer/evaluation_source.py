"""Count FDP callsites without rewriting raw reducer output or tool transforms."""
from __future__ import annotations

from functools import lru_cache
import re
from tree_sitter import Node
from harnessreducer.fdp_transform import (
    PARSER, SUPPORTED_FDP_APIS, _iter_nodes, _extract_method_name, _node_text,
)

FDP_ERROR_MARKERS = tuple(sorted(SUPPORTED_FDP_APIS)) + ("FuzzedDataProvider", "FDP_ID")


@lru_cache(maxsize=16)
def _fdp_receiver_bindings(source_bytes: bytes) -> tuple:
    """Track typed declarations in lexical scopes, including shadowing."""
    root = PARSER.parse(source_bytes).root_node
    bindings = []
    for node in _iter_nodes(root):
        if node.type not in {"declaration", "parameter_declaration", "field_declaration"}:
            continue
        type_node = node.child_by_field_name("type")
        is_fdp = bool(re.search(r"\bFuzzedDataProvider\b", _node_text(source_bytes, type_node)))
        scope = node.parent
        while scope is not None and scope.type not in {"compound_statement", "function_definition", "translation_unit", "field_declaration_list"}:
            scope = scope.parent
        if scope is None:
            continue
        for child in node.children_by_field_name("declarator"):
            while child is not None and child.type not in {"identifier", "field_identifier"}:
                child = child.child_by_field_name("declarator") or (child.named_children[-1] if child.type == "reference_declarator" and child.named_children else None)
            if child is not None:
                bindings.append((_node_text(source_bytes, child), is_fdp, scope.start_byte, scope.end_byte, node.start_byte))
    return tuple(bindings)


def _fdp_receiver_matches(receiver: Node | None, source_bytes: bytes) -> bool:
    text = _node_text(source_bytes, receiver).strip()
    position = receiver.start_byte if receiver is not None else 0
    bindings = [b for b in _fdp_receiver_bindings(source_bytes) if b[0] == text and b[2] <= position < b[3] and b[4] < position]
    if bindings:
        return max(bindings, key=lambda b: (b[2], b[4]))[1]
    # PCH output can be a fragment without the frozen declaration.
    return text == "fdp"


def _is_supported_fdp_call(call_node: Node, source_bytes: bytes) -> bool:
    function_node = call_node.child_by_field_name("function")
    if function_node is None or function_node.type != "field_expression":
        return False

    receiver = function_node.child_by_field_name("argument")
    field = function_node.child_by_field_name("field")

    if not _fdp_receiver_matches(receiver, source_bytes):
        return False
    if field is None:
        return False

    method_name = _extract_method_name(field, source_bytes)
    return method_name in SUPPORTED_FDP_APIS



def _blocking_parse_error(data: bytes, root) -> str | None:
    for node in _iter_nodes(root):
        if node.type == "ERROR" or getattr(node, "is_missing", False):
            start = max(0, node.start_byte - 200)
            end = min(len(data), node.end_byte + 200)
            text = data[start:end].decode(errors="replace")
            if any(marker in text for marker in FDP_ERROR_MARKERS):
                return text[:160]
    return None


def calls(source: str):
    data = source.encode()
    root = PARSER.parse(data).root_node
    if root.has_error:
        blocked = _blocking_parse_error(data, root)
        if blocked:
            raise ValueError(f"C++ source analysis is incomplete near FDP syntax: {blocked}")
    found = []
    for node in _iter_nodes(root):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "field_expression":
            continue
        field = fn.child_by_field_name("field")
        method = _extract_method_name(field, data) if field is not None else ""
        if method not in SUPPORTED_FDP_APIS:
            continue
        if not _is_supported_fdp_call(node, data):
            raise ValueError(f"Cannot establish the type of FDP-like receiver: {_node_text(data, fn)}")
        found.append((node, method))
    return data, found


def count_calls(source: str) -> int:
    return len(calls(source)[1])


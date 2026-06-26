from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_cpp as ts_cpp
from tree_sitter import Language, Node, Parser

CPP_LANGUAGE = Language(ts_cpp.language())
PARSER = Parser(CPP_LANGUAGE)


@dataclass(frozen=True)
class CoverageMap:
    all_point_lines: frozenset[int]
    covered_lines: frozenset[int]

    def has_point_on_line(self, line: int) -> bool:
        return line in self.all_point_lines

    def has_point_in_range(self, start_line: int, end_line: int) -> bool:
        return any(line in self.all_point_lines for line in range(start_line, end_line + 1))

    def has_covered_point_in_range(self, start_line: int, end_line: int) -> bool:
        return any(line in self.covered_lines for line in range(start_line, end_line + 1))


@dataclass(frozen=True)
class SliceEdit:
    start: int
    end: int
    replacement: str
    priority: int


@dataclass(frozen=True)
class SliceResult:
    source: str
    removed_nodes: int


def parse_symbolized_sancov_json(report_text: str, source_path: str) -> CoverageMap:
    payload = json.loads(report_text)
    source_realpath = str(Path(source_path).resolve())
    all_lines: set[int] = set()
    covered_lines: set[int] = set()

    for entry in payload.get("data", []):
        covered_addrs = set(entry.get("covered-points", []))
        point_info = entry.get("point-symbol-info", {})
        for filename, functions in point_info.items():
            if str(Path(filename).resolve()) != source_realpath:
                continue
            for points in functions.values():
                for address, location in points.items():
                    try:
                        line_text, _ = location.split(":", 1)
                        line = int(line_text)
                    except ValueError:
                        continue
                    all_lines.add(line)
                    if address in covered_addrs:
                        covered_lines.add(line)

    return CoverageMap(
        all_point_lines=frozenset(all_lines),
        covered_lines=frozenset(covered_lines),
    )


def _iter_nodes(root: Node) -> list[Node]:
    nodes: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        nodes.append(node)
        for child in reversed(node.children):
            stack.append(child)
    return nodes


def _node_line_range(node: Node) -> tuple[int, int]:
    return node.start_point[0] + 1, node.end_point[0] + 1


def _node_uncovered(node: Node, coverage: CoverageMap) -> bool:
    start_line, end_line = _node_line_range(node)
    return not coverage.has_covered_point_in_range(start_line, end_line)


def _node_has_point(node: Node, coverage: CoverageMap) -> bool:
    start_line, end_line = _node_line_range(node)
    return coverage.has_point_in_range(start_line, end_line)


def _node_text(source: str, node: Node) -> str:
    return source[node.start_byte : node.end_byte]


def _extract_function_name(node: Node, source: str) -> str:
    declarator = node.child_by_field_name("declarator")
    if declarator is None:
        return ""
    stack = [declarator]
    while stack:
        current = stack.pop()
        if current.type in {"identifier", "field_identifier", "operator_name"}:
            return _node_text(source, current).strip()
        child_decl = current.child_by_field_name("declarator")
        if child_decl is not None:
            stack.append(child_decl)
            continue
        for child in reversed(current.children):
            stack.append(child)
    return ""


def _statement_delete_edit(source: str, node: Node) -> SliceEdit:
    end = node.end_byte
    while end < len(source) and source[end] in " \t":
        end += 1
    if end < len(source) and source[end] == "\r":
        end += 1
    if end < len(source) and source[end] == "\n":
        end += 1
    return SliceEdit(node.start_byte, end, "", 70)


def _collect_slice_edits(source: str, coverage: CoverageMap) -> list[SliceEdit]:
    source_bytes = source.encode("utf-8")
    tree = PARSER.parse(source_bytes)
    edits: list[SliceEdit] = []
    removable_statement_types = {
        "expression_statement",
        "declaration",
        "compound_statement",
    }

    for node in _iter_nodes(tree.root_node):
        if node.type == "function_definition":
            fn_name = _extract_function_name(node, source)
            if fn_name == "LLVMFuzzerTestOneInput":
                continue
            if _node_has_point(node, coverage) and _node_uncovered(node, coverage):
                edits.append(_statement_delete_edit(source, node))
            continue

        if node.type == "if_statement":
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")

            if alternative is not None and _node_has_point(alternative, coverage) and _node_uncovered(alternative, coverage):
                edits.append(SliceEdit(alternative.start_byte, alternative.end_byte, "", 90))

            if consequence is not None and _node_has_point(consequence, coverage) and _node_uncovered(consequence, coverage):
                edits.append(SliceEdit(consequence.start_byte, consequence.end_byte, "{}", 80))
            continue

        if node.type not in removable_statement_types:
            continue
        if node.parent is None or node.parent.type != "compound_statement":
            continue
        if node.type == "compound_statement" and node.parent.parent is not None and node.parent.parent.type == "if_statement":
            continue
        start_line, _ = _node_line_range(node)
        if coverage.has_point_on_line(start_line) and _node_uncovered(node, coverage):
            edits.append(_statement_delete_edit(source, node))

    return edits


def _select_non_overlapping_edits(edits: list[SliceEdit]) -> list[SliceEdit]:
    chosen: list[SliceEdit] = []
    for edit in sorted(edits, key=lambda item: (-item.priority, -(item.end - item.start), item.start)):
        overlap = False
        for current in chosen:
            if not (edit.end <= current.start or edit.start >= current.end):
                overlap = True
                break
        if not overlap:
            chosen.append(edit)
    return chosen


def slice_source_by_coverage(source: str, coverage: CoverageMap) -> SliceResult:
    edits = _select_non_overlapping_edits(_collect_slice_edits(source, coverage))
    if not edits:
        return SliceResult(source=source, removed_nodes=0)

    transformed = source
    for edit in sorted(edits, key=lambda item: item.start, reverse=True):
        transformed = transformed[: edit.start] + edit.replacement + transformed[edit.end :]
    return SliceResult(source=transformed, removed_nodes=len(edits))

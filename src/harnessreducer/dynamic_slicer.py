from __future__ import annotations

from dataclasses import dataclass

import tree_sitter_cpp as ts_cpp
from tree_sitter import Language, Node, Parser

CPP_LANGUAGE = Language(ts_cpp.language())
PARSER = Parser(CPP_LANGUAGE)


@dataclass(frozen=True)
class CoverageMap:
    executable_lines: frozenset[int]
    covered_lines: frozenset[int]

    def __init__(
        self,
        executable_lines: frozenset[int] | set[int] | None = None,
        covered_lines: frozenset[int] | set[int] | None = None,
        *,
        all_point_lines: frozenset[int] | set[int] | None = None,
    ) -> None:
        if executable_lines is None and all_point_lines is not None:
            executable_lines = all_point_lines
        if executable_lines is None:
            executable_lines = frozenset()
        if covered_lines is None:
            covered_lines = frozenset()
        object.__setattr__(self, "executable_lines", frozenset(executable_lines))
        object.__setattr__(self, "covered_lines", frozenset(covered_lines))

    @property
    def all_point_lines(self) -> frozenset[int]:
        """Backward-compatible alias for older tests/scripts."""
        return self.executable_lines

    @property
    def uncovered_lines(self) -> frozenset[int]:
        return frozenset(line for line in self.executable_lines if line not in self.covered_lines)

    def has_executable_on_line(self, line: int) -> bool:
        return line in self.executable_lines

    def has_executable_in_range(self, start_line: int, end_line: int) -> bool:
        return any(line in self.executable_lines for line in range(start_line, end_line + 1))

    def has_covered_point_in_range(self, start_line: int, end_line: int) -> bool:
        return any(line in self.covered_lines for line in range(start_line, end_line + 1))


@dataclass(frozen=True)
class SliceEdit:
    start: int
    end: int
    replacement: str
    priority: int
    kind: str = "generic"
    names: tuple[str, ...] = ()


@dataclass(frozen=True)
class SliceResult:
    source: str
    removed_nodes: int


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
    return coverage.has_executable_in_range(start_line, end_line) and not coverage.has_covered_point_in_range(start_line, end_line)


def _node_has_point(node: Node, coverage: CoverageMap) -> bool:
    start_line, end_line = _node_line_range(node)
    return coverage.has_executable_in_range(start_line, end_line)


def _node_covered(node: Node, coverage: CoverageMap) -> bool:
    start_line, end_line = _node_line_range(node)
    return coverage.has_covered_point_in_range(start_line, end_line)


def _node_text(source: str, node: Node) -> str:
    source_bytes = source.encode("utf-8")
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8")


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


def _statement_delete_edit(
    source: str,
    node: Node,
    *,
    priority: int = 70,
    kind: str = "statement",
    names: tuple[str, ...] = (),
) -> SliceEdit:
    source_bytes = source.encode("utf-8")
    end = node.end_byte
    while end < len(source_bytes) and source_bytes[end] in b" \t":
        end += 1
    if end < len(source_bytes) and source_bytes[end] == ord("\r"):
        end += 1
    if end < len(source_bytes) and source_bytes[end] == ord("\n"):
        end += 1
    return SliceEdit(node.start_byte, end, "", priority, kind, names)


_DECLARATOR_NODE_TYPES = {
    "identifier",
    "pointer_declarator",
    "array_declarator",
    "reference_declarator",
    "function_declarator",
    "parenthesized_declarator",
}


def _extract_identifier_from_declarator(node: Node, source: str) -> str | None:
    if node.type == "identifier":
        return _node_text(source, node).strip()

    child_decl = node.child_by_field_name("declarator")
    if child_decl is not None:
        return _extract_identifier_from_declarator(child_decl, source)

    for child in node.named_children:
        if child.type in _DECLARATOR_NODE_TYPES:
            name = _extract_identifier_from_declarator(child, source)
            if name:
                return name
    return None


def _extract_declared_identifiers(node: Node, source: str) -> tuple[str, ...]:
    names: list[str] = []
    for child in node.named_children:
        target = None
        if child.type == "init_declarator":
            target = child.child_by_field_name("declarator")
        elif child.type in _DECLARATOR_NODE_TYPES:
            target = child
        if target is None:
            continue
        name = _extract_identifier_from_declarator(target, source)
        if name:
            names.append(name)
    return tuple(dict.fromkeys(names))


def _control_header_uncovered(node: Node, body: Node | None, coverage: CoverageMap) -> bool:
    if body is None:
        return _node_uncovered(node, coverage)
    start_line = node.start_point[0] + 1
    end_line = body.start_point[0] + 1
    return coverage.has_executable_in_range(start_line, end_line) and not coverage.has_covered_point_in_range(start_line, end_line)


def _make_empty_body_edit(node: Node) -> SliceEdit:
    return SliceEdit(node.start_byte, node.end_byte, "{}", 80, "body-empty")


def _collect_tail_prune_edits(source: str, tree: Node, coverage: CoverageMap) -> list[SliceEdit]:
    edits: list[SliceEdit] = []
    statement_like_types = {
        "declaration",
        "expression_statement",
        "if_statement",
        "while_statement",
        "for_statement",
        "do_statement",
        "switch_statement",
        "break_statement",
        "continue_statement",
        "compound_statement",
    }

    for node in _iter_nodes(tree):
        if node.type != "compound_statement":
            continue
        children = [child for child in node.named_children if child.type in statement_like_types]
        if not children:
            continue
        last_covered_idx = -1
        for idx, child in enumerate(children):
            if _node_covered(child, coverage):
                last_covered_idx = idx
        if last_covered_idx < 0:
            continue
        for child in children[last_covered_idx + 1 :]:
            if _node_covered(child, coverage):
                continue
            names: tuple[str, ...] = ()
            kind = "tail"
            if child.type == "declaration":
                names = _extract_declared_identifiers(child, source)
                kind = "declaration"
            edits.append(
                _statement_delete_edit(
                    source,
                    child,
                    priority=95,
                    kind=kind,
                    names=names,
                )
            )
    return edits


def _collect_slice_edits(source: str, coverage: CoverageMap) -> list[SliceEdit]:
    source_bytes = source.encode("utf-8")
    tree = PARSER.parse(source_bytes).root_node
    edits: list[SliceEdit] = []
    removable_statement_types = {
        "expression_statement",
        "declaration",
        "compound_statement",
    }

    edits.extend(_collect_tail_prune_edits(source, tree, coverage))

    for node in _iter_nodes(tree):
        if node.type == "function_definition":
            fn_name = _extract_function_name(node, source)
            if fn_name == "LLVMFuzzerTestOneInput":
                continue
            if _node_has_point(node, coverage) and _node_uncovered(node, coverage):
                edits.append(
                    _statement_delete_edit(source, node, priority=85, kind="function")
                )
            continue

        if node.type == "if_statement":
            if _node_uncovered(node, coverage):
                edits.append(_statement_delete_edit(source, node, priority=100, kind="if"))
                continue
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            if _control_header_uncovered(node, consequence, coverage):
                edits.append(_statement_delete_edit(source, node, priority=100, kind="if"))
                continue

            if alternative is not None and _node_has_point(alternative, coverage) and _node_uncovered(alternative, coverage):
                edits.append(SliceEdit(alternative.start_byte, alternative.end_byte, "", 90, "else"))

            if consequence is not None and _node_has_point(consequence, coverage) and _node_uncovered(consequence, coverage):
                edits.append(_make_empty_body_edit(consequence))
            continue

        if node.type in {"while_statement", "for_statement", "do_statement"}:
            body = node.child_by_field_name("body")
            if _node_uncovered(node, coverage) or _control_header_uncovered(node, body, coverage):
                edits.append(_statement_delete_edit(source, node, priority=100, kind="loop"))
                continue
            if body is not None and _node_has_point(body, coverage) and _node_uncovered(body, coverage):
                edits.append(_make_empty_body_edit(body))
            continue

        if node.type == "switch_statement":
            body = node.child_by_field_name("body")
            if _node_uncovered(node, coverage) or _control_header_uncovered(node, body, coverage):
                edits.append(_statement_delete_edit(source, node, priority=100, kind="switch"))
                continue
            if body is not None and _node_has_point(body, coverage) and _node_uncovered(body, coverage):
                edits.append(_make_empty_body_edit(body))
            continue

        if node.type not in removable_statement_types:
            continue
        if node.parent is None or node.parent.type != "compound_statement":
            continue
        if node.type == "compound_statement" and node.parent.parent is not None and node.parent.parent.type == "if_statement":
            continue
        start_line, _ = _node_line_range(node)
        if coverage.has_executable_on_line(start_line) and _node_uncovered(node, coverage):
            names: tuple[str, ...] = ()
            kind = "statement"
            if node.type == "declaration":
                names = _extract_declared_identifiers(node, source)
                kind = "declaration"
            edits.append(_statement_delete_edit(source, node, kind=kind, names=names))

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


def _overlaps_any(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    return any(not (end <= lo or start >= hi) for lo, hi in ranges)


def _filter_declaration_edits(source: str, edits: list[SliceEdit]) -> list[SliceEdit]:
    source_bytes = source.encode("utf-8")
    tree = PARSER.parse(source_bytes).root_node
    non_decl_ranges = [(edit.start, edit.end) for edit in edits if edit.kind != "declaration"]
    filtered: list[SliceEdit] = []

    for edit in edits:
        if edit.kind != "declaration" or not edit.names:
            filtered.append(edit)
            continue

        has_surviving_use = False
        for node in _iter_nodes(tree):
            if node.type != "identifier":
                continue
            if node.start_byte <= edit.end:
                continue
            if _overlaps_any(node.start_byte, node.end_byte, non_decl_ranges):
                continue
            ident = _node_text(source, node).strip()
            if ident in edit.names:
                has_surviving_use = True
                break

        if not has_surviving_use:
            filtered.append(edit)

    return filtered


def slice_source_by_coverage(source: str, coverage: CoverageMap) -> SliceResult:
    edits = _select_non_overlapping_edits(_collect_slice_edits(source, coverage))
    edits = _filter_declaration_edits(source, edits)
    if not edits:
        return SliceResult(source=source, removed_nodes=0)

    transformed = source.encode("utf-8")
    for edit in sorted(edits, key=lambda item: item.start, reverse=True):
        transformed = (
            transformed[: edit.start]
            + edit.replacement.encode("utf-8")
            + transformed[edit.end :]
        )
    return SliceResult(source=transformed.decode("utf-8"), removed_nodes=len(edits))

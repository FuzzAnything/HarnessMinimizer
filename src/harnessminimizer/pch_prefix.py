"""Extract a fixed header prefix without moving harness declarations into it."""

from pathlib import Path

from tree_sitter import Node
from harnessminimizer.source_language import CPP, SourceLanguage


_CONDITIONALS = frozenset({
    "preproc_if", "preproc_ifdef", "preproc_elif", "preproc_elifdef", "preproc_else",
})
_DIRECTIVES = frozenset({"preproc_def", "preproc_function_def", "preproc_call", "comment"})
_STANDARD_HEADERS = b"#include <stdint.h>\n#include <stddef.h>\n"
_STANDARD_INCLUDES = {b"#include <stdint.h>", b"#include <stddef.h>"}


def _header_includes(node: Node) -> list[Node] | None:
    """Return includes for a complete directive-only node, or None for code.

    Inspect every conditional branch without evaluating it. A declaration,
    function, or parser error anywhere in the block keeps the entire block in
    the body; an open conditional must never straddle the PCH boundary.
    """
    if node.has_error or node.is_missing:
        return None
    if node.type == "preproc_include":
        return [node]
    if node.type in _DIRECTIVES:
        return []
    if node.type not in _CONDITIONALS:
        return None

    includes = []
    for index, child in enumerate(node.children):
        if not child.is_named or node.field_name_for_child(index) in {"condition", "name"}:
            continue
        nested = _header_includes(child)
        if nested is None:
            return None
        includes.extend(nested)
    return includes


def _prefix_region(source: bytes, language: SourceLanguage = CPP) -> tuple[int, int, list[Node]]:
    # The grammar expects a newline after a directive, but C++ also accepts EOF.
    tree = language.parser().parse(source if source.endswith(b"\n") else source + b"\n")
    nodes = tree.root_node.named_children
    includes: list[Node] = []
    insertion = end = 0
    last_index = -1
    for index, node in enumerate(nodes):
        nested = _header_includes(node)
        if nested is None:
            break
        if nested:
            if not includes:
                # Insert the driver headers outside any include conditional,
                # after preceding feature macros, so size_t/uint8_t are available
                # even when the first include's branch is disabled.
                insertion = node.start_byte
            includes.extend(nested)
            end = min(node.end_byte, len(source))
            last_index = index

    if last_index >= 0 and not source[:end].endswith(b"\n"):
        # #endif excludes its trailing comment/newline from its syntax node.
        # Keep attached comments whole, including multiline block comments.
        for node in nodes[last_index + 1:]:
            if node.type != "comment" or source[end:node.start_byte].strip(b" \t\r"):
                break
            end = node.end_byte
        while end < len(source) and source[end:end + 1] in (b" ", b"\t", b"\r"):
            end += 1
        if source[end:end + 1] == b"\n":
            end += 1
    return end, insertion, includes


def _apply_edits(source: bytes, edits: list[tuple[int, int, bytes]]) -> str:
    parts = []
    cursor = 0
    for start, end, replacement in sorted(edits):
        parts.extend((source[cursor:start], replacement))
        cursor = end
    parts.append(source[cursor:])
    result = b"".join(parts)
    if result and not result.endswith(b"\n"):
        result += b"\n"
    return result.decode("utf-8")


def split_source_for_pch(
    source: str, source_dir: Path, *, language: SourceLanguage = CPP,
) -> tuple[str, str, str]:
    """Return (PCH header, restorable prefix, body) using original byte ranges.

    Only the leading directive region through its last include is fixed.
    Trailing body macros and includes after code remain available to reduction.
    Local quoted paths are rewritten only in the temporary PCH header; exported
    source keeps their original spelling.
    """
    data = source.encode("utf-8")
    end, insertion, includes = _prefix_region(data, language)
    prefix = data[:end]
    separator = b"\n" if insertion and data[insertion - 1:insertion] != b"\n" else b""
    shared_edits = [(insertion, insertion, separator + _STANDARD_HEADERS)]
    path_edits = []
    for include in includes:
        include_end = min(include.end_byte, end)
        # Preserve the old deduplication for plain, unconditional driver headers.
        # Includes inside conditionals retain their complete original structure.
        if (include.parent.type == "translation_unit"
                and data[include.start_byte:include_end].strip() in _STANDARD_INCLUDES):
            shared_edits.append((include.start_byte, include_end, b""))
            continue
        path = include.child_by_field_name("path")
        if path is None or path.type != "string_literal":
            continue
        spelling = data[path.start_byte + 1:path.end_byte - 1]
        name = spelling.replace(b"\\\r\n", b"").replace(b"\\\n", b"").decode("utf-8")
        if Path(name).is_absolute():
            continue
        local_header = (source_dir / name).resolve()
        if local_header.exists():
            escaped = str(local_header).replace("\\", "\\\\").replace('"', '\\"')
            path_edits.append((path.start_byte, path.end_byte, f'"{escaped}"'.encode("utf-8")))

    return (
        "// Generated by HarnessMinimizer for Phase 3 PCH compilation.\n"
        + _apply_edits(prefix, shared_edits + path_edits),
        _apply_edits(prefix, shared_edits),
        data[end:].decode("utf-8"),
    )

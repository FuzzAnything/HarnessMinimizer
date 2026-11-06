"""Remove standalone comments and excess blank lines from a reduced C++ source."""

from collections import deque
from pathlib import Path

import tree_sitter_cpp
from tree_sitter import Language, Parser


_CPP_LANGUAGE = Language(tree_sitter_cpp.language())
_MULTILINE_LITERAL_TYPES = {"raw_string_literal", "string_literal", "char_literal"}
_WHITESPACE = frozenset(b" \t\r\f\v")


def clean_reduced_source(path: str) -> None:
    """Delete whole comment lines and keep at most one blank line between code.

    Tree-sitter distinguishes comments from comment-shaped text in raw strings.
    A block comment touching code on either end is kept intact, including its
    interior lines, so deleting a line cannot leave a stray ``/*`` or ``*/``.
    """
    source_path = Path(path)
    source = source_path.read_bytes()
    lines = source.split(b"\n")
    final_newline = source.endswith(b"\n")
    if final_newline:
        lines.pop()
    if not lines:
        return

    tree = Parser(_CPP_LANGUAGE).parse(source)
    comment_bytes = bytearray(len(source))
    line_comments: list[list[int]] = [[] for _ in lines]
    comments: list[tuple[int, int]] = []
    protected_blanks = set()
    nodes = [tree.root_node]
    while nodes:
        node = nodes.pop()
        first = node.start_point.row
        last = node.end_point.row
        if last > first and node.end_point.column == 0:
            last -= 1
        if node.type == "comment":
            comment_id = len(comments)
            comments.append((first, last))
            comment_bytes[node.start_byte:node.end_byte] = b"\x01" * (node.end_byte - node.start_byte)
            for row in range(first, last + 1):
                line_comments[row].append(comment_id)
        elif node.type in _MULTILINE_LITERAL_TYPES and last > first:
            protected_blanks.update(range(first, last + 1))
        nodes.extend(node.children)

    line_starts = []
    position = 0
    for line in lines:
        line_starts.append(position)
        position += len(line) + 1

    continued_rows = {
        row for row in range(1, len(lines))
        if lines[row - 1].rstrip(b" \t\r").endswith(b"\\")
    }
    removable = []
    for row, line in enumerate(lines):
        start = line_starts[row]
        removable.append(row not in continued_rows and bool(line_comments[row]) and all(
            byte in _WHITESPACE or comment_bytes[start + column]
            for column, byte in enumerate(line)
        ))

    # If one line of a comment must stay, keep the whole comment. This also
    # handles several adjacent comment tokens on one otherwise empty line.
    queue = deque(row for row, can_remove in enumerate(removable) if not can_remove)
    seen_comments = set()
    while queue:
        for comment_id in line_comments[queue.popleft()]:
            if comment_id in seen_comments:
                continue
            seen_comments.add(comment_id)
            first, last = comments[comment_id]
            for row in range(first, last + 1):
                if removable[row]:
                    removable[row] = False
                    queue.append(row)

    for first, last in comments:
        if any(not removable[row] for row in range(first, last + 1)):
            protected_blanks.update(range(first, last + 1))
    # A blank physical line can end a backslash-continued macro. Keep it.
    protected_blanks.update(continued_rows)

    retained = [(row, line) for row, line in enumerate(lines) if not removable[row]]
    cleaned = []
    row = 0
    while row < len(retained):
        original_row, line = retained[row]
        if line.strip() or original_row in protected_blanks:
            cleaned.append(line)
            row += 1
            continue
        end = row + 1
        while (end < len(retained) and not retained[end][1].strip()
               and retained[end][0] not in protected_blanks):
            end += 1
        # The requested blank-line limit applies between nonblank code lines.
        between_code = bool(cleaned and cleaned[-1].strip() and end < len(retained)
                            and retained[end][1].strip())
        cleaned.extend([line] if between_code else [item[1] for item in retained[row:end]])
        row = end

    result = b"\n".join(cleaned) + (b"\n" if final_newline else b"")
    if result != source:
        source_path.write_bytes(result)

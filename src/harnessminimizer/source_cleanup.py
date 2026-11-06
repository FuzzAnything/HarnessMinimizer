"""Remove standalone comments from a reduced C or C++ source."""

from collections import deque
from pathlib import Path

from harnessminimizer.source_language import language_for_path


_WHITESPACE = frozenset(b" \t\r\f\v")


def clean_reduced_source(path: str) -> None:
    """Delete whole comment lines, leaving all existing blank lines untouched.

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

    tree = language_for_path(source_path).parser().parse(source)
    comment_bytes = bytearray(len(source))
    line_comments: list[list[int]] = [[] for _ in lines]
    comments: list[tuple[int, int]] = []
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

    retained = [line for row, line in enumerate(lines) if not removable[row]]
    result = b"\n".join(retained) + (b"\n" if final_newline and retained else b"")
    if result != source:
        source_path.write_bytes(result)

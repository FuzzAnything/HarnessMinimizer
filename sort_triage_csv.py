#!/usr/bin/env python3
"""Sort a CSV in place by dir, then none/treereduce/perses/wdd/cdd."""

from __future__ import annotations

import argparse
import csv
import fcntl
import io
import os
from pathlib import Path
from typing import Sequence


TOOL_ORDER = {tool: index for index, tool in enumerate(
    ("none", "treereduce", "perses", "wdd", "cdd")
)}


def sort_csv_in_place(path: Path) -> int:
    # Keep the same file open and locked throughout, so triage CSV writers
    # cannot append between reading and rewriting the rows.
    with path.open("r+", newline="", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        reader = csv.reader(handle, strict=True)
        header = next(reader, None)
        if header is None or any(header.count(column) != 1 for column in ("dir", "tool")):
            raise ValueError("CSV header must contain exactly one 'dir' and one 'tool' column.")
        dir_index = header.index("dir")
        tool_index = header.index("tool")
        rows = []
        for row in reader:
            if not row:
                continue
            if len(row) != len(header):
                raise ValueError(
                    f"CSV row ending at line {reader.line_num} has {len(row)} columns; "
                    f"expected {len(header)}."
                )
            rows.append(row)

        # Unknown tools follow the specified tools, alphabetically. Python's
        # stable sort preserves the order of duplicate (dir, tool) pairs.
        rows.sort(key=lambda row: (
            row[dir_index],
            TOOL_ORDER.get(row[tool_index], len(TOOL_ORDER)),
            row[tool_index],
        ))
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(header)
        writer.writerows(rows)

        # Validate and serialize everything before changing the original file.
        handle.seek(0)
        handle.write(output.getvalue())
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())
    return len(rows)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", type=Path, help="CSV file to sort in place.")
    args = parser.parse_args(argv)
    path = args.csv_file.expanduser()
    try:
        count = sort_csv_in_place(path)
    except (OSError, ValueError, csv.Error) as exc:
        parser.exit(1, f"Error: {exc}\n")
    print(f"Sorted {count} rows in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

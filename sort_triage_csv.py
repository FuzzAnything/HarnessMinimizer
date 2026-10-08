#!/usr/bin/env python3
"""Sort triage results by dataset, case, and reduction tool."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import csv
import fcntl
import os
from pathlib import Path
import tempfile
from typing import Sequence


TOOL_ORDER = {tool: index for index, tool in enumerate(
    ("none", "treereduce", "perses", "wdd", "cdd", "sfc", "vulcan")
)}


@contextmanager
def csv_lock(path: Path):
    # A separate, stable inode protects readers/writers across atomic replacement.
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_name(path.name + ".lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield


def read_csv_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, strict=True)
        header = reader.fieldnames
        if not header or len(header) != len(set(header)):
            raise ValueError(f"Missing or duplicate CSV columns in {path}.")
        rows = list(reader)
        if any(None in row or any(value is None for value in row.values()) for row in rows):
            raise ValueError(f"CSV rows do not match the header in {path}.")
        return header, rows


def write_csv_rows_atomic(path: Path, header: Sequence[str], rows: Sequence[dict]) -> None:
    """Caller holds csv_lock; readers see either complete version of the CSV."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", newline="", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            writer = csv.DictWriter(handle, fieldnames=header)
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def sort_key(row: dict) -> tuple:
    return (row["dataset"], row["dir"], TOOL_ORDER.get(row["tool"], len(TOOL_ORDER)), row["tool"])


def sort_csv_in_place(path: Path) -> int:
    with csv_lock(path):
        header, rows = read_csv_rows(path)
        if not {"dataset", "dir", "tool"}.issubset(header):
            raise ValueError("CSV requires dataset, dir, and tool columns.")
        rows.sort(key=sort_key)
        write_csv_rows_atomic(path, header, rows)
    return len(rows)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", type=Path, help="CSV file to sort in place.")
    args = parser.parse_args(argv)
    try:
        count = sort_csv_in_place(args.csv_file.expanduser())
    except (OSError, ValueError, csv.Error) as exc:
        parser.exit(1, f"Error: {exc}\n")
    print(f"Sorted {count} rows in {args.csv_file}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Deduplicate a triage CSV in place, saving a backup before any changes.

Keep one result per (dir, tool). Conflicting verdicts prefer library-bug for
tool none and harness-bug for every other tool, regardless of vote counts.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
import fcntl
import io
import os
from pathlib import Path
from typing import Sequence


def deduplicate_csv_in_place(path: Path) -> tuple[int, int, int, Path | None]:
    """Return original row count, retained row count, conflicts, and backup path."""
    # Use the triage writers' lock and retain the same inode so writers that
    # have already opened the CSV append to the deduplicated file afterward.
    with path.open("r+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        original = handle.read()
        reader = csv.reader(io.StringIO(original.decode("utf-8"), newline=""), strict=True)
        header = next(reader, None)
        columns = ("dir", "tool", "triage result")
        if header is None or any(header.count(column) != 1 for column in columns):
            raise ValueError(
                "CSV header must contain exactly one 'dir', 'tool', and 'triage result' column."
            )
        dir_index, tool_index, result_index = (header.index(column) for column in columns)
        rows: list[list[str]] = []
        groups: dict[tuple[str, str], list[int]] = {}
        for row in reader:
            if not row:
                continue
            if len(row) != len(header):
                raise ValueError(
                    f"CSV row ending at line {reader.line_num} has {len(row)} columns; "
                    f"expected {len(header)}."
                )
            if not row[dir_index].strip() or not row[tool_index].strip():
                raise ValueError(f"Empty dir or tool at CSV line {reader.line_num}.")
            if row[result_index] not in {"library-bug", "harness-bug"}:
                raise ValueError(
                    f"Invalid triage result at CSV line {reader.line_num}: {row[result_index]!r}."
                )
            groups.setdefault((row[dir_index], row[tool_index]), []).append(len(rows))
            rows.append(row)

        retained_indices = set()
        conflicts = 0
        for (_, tool), indices in groups.items():
            verdicts = {rows[index][result_index] for index in indices}
            if len(verdicts) == 1:
                retained_indices.add(indices[0])
            else:
                conflicts += 1
                preferred = "library-bug" if tool == "none" else "harness-bug"
                retained_indices.add(next(
                    index for index in indices if rows[index][result_index] == preferred
                ))
        # Keep the first occurrence of the selected verdict, preserving all
        # its columns and the relative order of surviving rows.
        retained = [row for index, row in enumerate(rows) if index in retained_indices]
        if len(retained) == len(rows):
            return len(rows), len(retained), 0, None

        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n" if b"\r\n" in original else "\n")
        writer.writerow(header)
        writer.writerows(retained)
        updated = output.getvalue().encode("utf-8")

        # Finish validation and serialization before touching the input file.
        backup = path.with_name(
            path.name + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        )
        with backup.open("xb") as backup_handle:
            os.fchmod(backup_handle.fileno(), os.fstat(handle.fileno()).st_mode & 0o777)
            backup_handle.write(original)
            backup_handle.flush()
            os.fsync(backup_handle.fileno())
        try:
            handle.seek(0)
            handle.write(updated)
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())
        except OSError as exc:
            raise OSError(f"Could not rewrite {path}; original saved in {backup}: {exc}") from exc
    return len(rows), len(retained), conflicts, backup


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", type=Path, help="CSV file to deduplicate in place.")
    args = parser.parse_args(argv)
    path = args.csv_file.expanduser()
    try:
        before, after, conflicts, backup = deduplicate_csv_in_place(path)
    except (OSError, ValueError, csv.Error) as exc:
        parser.exit(1, f"Error: {exc}\n")
    print(f"Rows: {before} -> {after}; removed {before - after}; conflicting pairs resolved: {conflicts}.")
    if backup is not None:
        print(f"Backup: {backup}")
    else:
        print("No duplicate pairs; file unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path("/mnt/raid/home/lihaiying/HarnessMinimizer/benchmark/library-bug")

# Matches lines like:
# real    4m16.949s
# user    151m49.541s
# sys     25m45.470s
# real    12.345s
#
# Also detects already-calculated lines like:
# real    4m16.949s 256.949
TIME_LINE_RE = re.compile(
    r"^(?P<prefix>\s*(?:real|user|sys)\s+)"
    r"(?P<time>(?:(?P<minutes>\d+(?:\.\d+)?)m)?(?P<seconds>\d+(?:\.\d+)?)s)"
    r"(?P<rest>.*)$"
)

# A numeric value appended at the end of the line.
APPENDED_SECONDS_RE = re.compile(r"^\s+\d+(?:\.\d+)?\s*$")


def time_to_seconds(minutes: str | None, seconds: str) -> float:
    total = float(seconds)
    if minutes is not None:
        total += float(minutes) * 60
    return total


def format_seconds(value: float) -> str:
    return f"{value:.3f}".rstrip("0").rstrip(".")


def is_already_calculated_line(line: str) -> bool:
    """
    Returns True if a timing line already has a calculated seconds value appended.
    """
    content = line.rstrip("\n")
    match = TIME_LINE_RE.match(content)

    if not match:
        return False

    rest = match.group("rest")

    return bool(APPENDED_SECONDS_RE.match(rest))


def file_already_calculated(path: Path) -> bool:
    """
    Returns True if the file has timing lines and all timing lines already have
    calculated seconds appended.
    """
    with path.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    timing_line_count = 0
    calculated_line_count = 0

    for line in lines:
        content = line.rstrip("\n")
        match = TIME_LINE_RE.match(content)

        if not match:
            continue

        timing_line_count += 1

        if is_already_calculated_line(line):
            calculated_line_count += 1

    return timing_line_count > 0 and timing_line_count == calculated_line_count


def process_file(path: Path) -> bool:
    if file_already_calculated(path):
        print(f"Skipped already calculated: {path}")
        return False

    changed = False
    new_lines = []

    with path.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    for line in lines:
        newline = "\n" if line.endswith("\n") else ""
        content = line[:-1] if newline else line

        match = TIME_LINE_RE.match(content)
        if not match:
            new_lines.append(line)
            continue

        rest = match.group("rest")

        # If this individual line is already calculated, leave it unchanged.
        if APPENDED_SECONDS_RE.match(rest):
            new_lines.append(line)
            continue

        total_seconds = time_to_seconds(
            match.group("minutes"),
            match.group("seconds"),
        )

        converted = format_seconds(total_seconds)
        new_lines.append(f"{content} {converted}{newline}")
        changed = True

    if changed:
        with path.open("w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return changed


def main() -> None:
    updated_count = 0
    skipped_count = 0

    for subdir in ROOT.iterdir():
        if not subdir.is_dir():
            continue

        path = subdir / "e2e-time.txt"

        if not path.is_file():
            continue

        if file_already_calculated(path):
            print(f"Skipped already calculated: {path}")
            skipped_count += 1
            continue

        if process_file(path):
            print(f"Updated: {path}")
            updated_count += 1

    print(f"Done. Updated {updated_count} file(s). Skipped {skipped_count} already calculated file(s).")


if __name__ == "__main__":
    main()
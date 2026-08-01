#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path("/mnt/raid/home/lihaiying/HarnessMinimizer/benchmark/library-bug")

# Matches timing lines like:
# real    4m16.949s
# user    151m49.541s
# sys     25m45.470s
# real    12.345s
#
# It also matches already-calculated lines like:
# real    4m16.949s 256.949
TIME_LINE_RE = re.compile(
    r"^(?P<prefix>\s*(?:real|user|sys)\s+)"
    r"(?P<time>(?:(?P<minutes>\d+(?:\.\d+)?)m)?(?P<seconds>\d+(?:\.\d+)?)s)"
    r"(?:\s+.*)?$"
)


def time_to_seconds(minutes: str | None, seconds: str) -> float:
    total = float(seconds)
    if minutes is not None:
        total += float(minutes) * 60
    return total


def format_seconds(value: float) -> str:
    return f"{value:.3f}".rstrip("0").rstrip(".")


def process_file(path: Path) -> bool:
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

        total_seconds = time_to_seconds(
            match.group("minutes"),
            match.group("seconds"),
        )

        converted = format_seconds(total_seconds)

        # Rebuild the timing line from the original prefix and original time,
        # discarding any previously appended calculated value.
        new_line = f"{match.group('prefix')}{match.group('time')} {converted}{newline}"

        if new_line != line:
            changed = True

        new_lines.append(new_line)

    if changed:
        with path.open("w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return changed


def main() -> None:
    updated_count = 0
    processed_count = 0

    for subdir in ROOT.iterdir():
        if not subdir.is_dir():
            continue

        path = subdir / "e2e-time.txt"

        if not path.is_file():
            continue

        processed_count += 1

        if process_file(path):
            print(f"Updated: {path}")
            updated_count += 1
        else:
            print(f"No change needed: {path}")

    print(f"Done. Processed {processed_count} file(s). Updated {updated_count} file(s).")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""Copy every CSV under benchmark/library-bug into root temp/ without overwrites."""

from __future__ import annotations

import argparse
import filecmp
import json
import os
from pathlib import Path
import shutil
import tempfile


PROJECT_ROOT = Path(__file__).resolve().parent


def copy_without_overwrite(source: Path, destination: Path) -> tuple[Path, bool]:
    """Reuse identical copies; give different files numbered collision suffixes."""
    number = 1
    while True:
        name = source.name if number == 1 else f"{source.stem}__{number}{source.suffix}"
        target = destination / name
        try:
            with source.open("rb") as incoming:
                # Exclusive creation also protects against concurrent collectors.
                outgoing = target.open("xb")
                try:
                    with outgoing:
                        shutil.copyfileobj(incoming, outgoing)
                    shutil.copystat(source, target)
                except BaseException:
                    # Only remove the incomplete copy created by this call.
                    target.unlink()
                    raise
            return target, True
        except FileExistsError:
            if not target.is_symlink() and target.is_file() and filecmp.cmp(source, target, shallow=False):
                return target, False
            number += 1


def collect_csvs(source_root: Path, destination: Path) -> dict[str, object]:
    source_root = source_root.resolve()
    destination = destination.resolve()
    if not source_root.is_dir():
        raise ValueError(f"CSV source directory not found: {source_root}")
    if destination.is_relative_to(source_root):
        raise ValueError("CSV destination must be outside the source tree")
    destination.mkdir(parents=True, exist_ok=True)
    filecmp.clear_cache()
    records = []
    skipped_symlinks = 0

    def fail_walk(error: OSError) -> None:
        raise error

    for directory, dirs, files in os.walk(source_root, followlinks=False, onerror=fail_walk):
        # Stay inside the requested tree; do not follow links to other datasets.
        dirs[:] = sorted(name for name in dirs if not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            source = Path(directory) / name
            if source.suffix.lower() != ".csv":
                continue
            if source.is_symlink():
                skipped_symlinks += 1
                continue
            if not source.is_file():
                continue
            target, copied = copy_without_overwrite(source, destination)
            records.append({
                "source": str(source.relative_to(source_root)),
                "destination": target.name,
                "action": "copied" if copied else "already_present",
            })

    summary = {
        "source_root": str(source_root),
        "destination": str(destination),
        "csv_files_found": len(records),
        "copied": sum(row["action"] == "copied" for row in records),
        "already_present": sum(row["action"] == "already_present" for row in records),
        "skipped_csv_symlinks": skipped_symlinks,
        "files": records,
    }
    # Keep provenance, including renamed collisions, without replacing old manifests.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="csv_collection_", suffix=".json",
        dir=destination, delete=False,
    ) as manifest:
        json.dump(summary, manifest, indent=2)
        manifest.write("\n")
        manifest_path = manifest.name
    return {**summary, "manifest": manifest_path}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path, default=PROJECT_ROOT / "temp",
        help="Destination directory (default: temp/ at the repository root).",
    )
    args = parser.parse_args()
    try:
        summary = collect_csvs(PROJECT_ROOT / "benchmark/library-bug", args.output_dir)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"CSV collection failed: {exc}\n")
    print(f"CSV files found: {summary['csv_files_found']}")
    print(f"Copied: {summary['copied']}; already present: {summary['already_present']}")
    print(f"CSV symlinks skipped: {summary['skipped_csv_symlinks']}")
    print(f"Destination: {summary['destination']}")
    print(f"Copy manifest: {summary['manifest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

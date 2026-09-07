#!/usr/bin/env python3
"""Install the pinned treereduce with the HarnessReducer cleanup patch."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

COMMIT = "47655579ae4a19e95d7c4f7911d7ded7719b6d22"
SHA256 = "5a1aa914d6c2d8870fc0b5bd2d37d5421764e78ee3b0f96533d937619640c5b0"
HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=HERE.parents[1] / ".tools")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--archive", type=Path, help="Use an already downloaded pinned archive")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="harnessreducer-treereduce-build-") as work:
        work = Path(work)
        archive = args.archive
        if archive is None:
            archive = work / "source.tar.gz"
            with urllib.request.urlopen(
                f"https://codeload.github.com/langston-barrett/treereduce/tar.gz/{COMMIT}", timeout=60,
            ) as response:
                archive.write_bytes(response.read())
        if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
            raise SystemExit("treereduce source checksum mismatch")
        with tarfile.open(archive) as source:
            source.extractall(work, filter="data")
        tree = work / f"treereduce-{COMMIT}"
        subprocess.run(["patch", "--batch", "-p1", "-i", str(HERE / "process-cleanup.patch")], cwd=tree, check=True)
        subprocess.run([
            "cargo", "install", "--locked", "--path", str(tree / "crates/treereduce-c"),
            "--root", str(args.root.resolve()), "--jobs", str(args.jobs), "--force",
        ], cwd=tree, check=True)
        subprocess.run([str(args.root.resolve() / "bin/treereduce-c"), "--harnessreducer-supervisor-version"], check=True)


if __name__ == "__main__":
    main()

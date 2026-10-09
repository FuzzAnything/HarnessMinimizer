#!/usr/bin/env python3
"""Build and install a separately obtained, pinned Perses checkout."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


COMMIT = "6c6ae0db20fa83b0f85a71ca447f0c4d5e056bd2"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
TARGET = "//src/org/perses:perses_deploy.jar"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=PROJECT_ROOT.parent / "perses")
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT / ".tools" / "perses")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    source = args.source.resolve()
    if not source.is_dir():
        parser.error(f"Perses checkout not found: {source}")
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=source, text=True,
    ).strip()
    if revision != COMMIT:
        parser.error(f"Expected Perses commit {COMMIT}; checkout is at {revision}")
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=source, text=True,
    ).strip()
    if dirty:
        parser.error("Perses has tracked changes; build from a clean pinned checkout")
    bazel = shutil.which("bazelisk") or shutil.which("bazel")
    if not bazel:
        parser.error("Install Bazelisk or Bazel (the checkout requires Bazel 9.1.0)")
    command = [bazel, "build", f"--jobs={args.jobs}", "--lockfile_mode=off", "--noshow_progress", TARGET]
    subprocess.run(command, cwd=source, check=True)
    jar = source / "bazel-bin/src/org/perses/perses_deploy.jar"
    if not jar.is_file():
        parser.error(f"Build did not produce {jar}")
    destination = args.root.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    # Stage before replacing, so an interrupted copy does not corrupt the installed JAR.
    with tempfile.TemporaryDirectory(prefix=".install-", dir=destination) as temporary:
        staged = Path(temporary) / "perses_deploy.jar"
        shutil.copy2(jar, staged)
        with staged.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        metadata = {
            "source_commit": revision,
            "source_directory": str(source),
            "jar_sha256": digest,
            "build_command": command,
            "built_at": datetime.now(timezone.utc).isoformat(),
        }
        metadata_path = Path(temporary) / "build_info.json"
        metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        staged.replace(destination / staged.name)
        metadata_path.replace(destination / metadata_path.name)
    print(f"Installed Perses {revision} at {destination / 'perses_deploy.jar'}")


if __name__ == "__main__":
    main()

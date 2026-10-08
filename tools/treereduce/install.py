#!/usr/bin/env python3
"""Install patched treereduce with its notices and rebuildable source archive."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.request

COMMIT = "47655579ae4a19e95d7c4f7911d7ded7719b6d22"
SHA256 = "5a1aa914d6c2d8870fc0b5bd2d37d5421764e78ee3b0f96533d937619640c5b0"
HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
NOTICE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT", "UNLICENSE", "AUTHORS")
LICENSE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "UNLICENSE")
VENDOR_CONFIG = '''[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
'''


def dependency_notices(tree: Path, destination: Path) -> list[dict]:
    """Preserve crate notices, including nested third-party and omitted licenses."""
    supplements = json.loads((HERE / "licenses" / "sources.json").read_text())
    lock = tomllib.loads((tree / "Cargo.lock").read_text())
    records = []
    for package in sorted(lock["package"], key=lambda item: (item["name"], item["version"])):
        if "source" not in package:
            continue  # The local treereduce workspace is covered by its own license.
        name = f'{package["name"]}-{package["version"]}'
        crate = tree / "vendor" / name
        metadata = tomllib.loads((crate / "Cargo.toml").read_text())["package"]
        files = {path.relative_to(crate) for path in crate.rglob("*")
                 if path.is_file() and path.name.upper().startswith(NOTICE_PREFIXES)}
        declared_file = metadata.get("license-file")
        if declared_file:
            files.add(Path(declared_file))
        has_license = any(len(path.parts) == 1 and path.name.upper().startswith(LICENSE_PREFIXES)
                          for path in files) or bool(declared_file)
        target = destination / "dependencies" / name
        for relative in sorted(files):
            source = crate / relative
            if not source.resolve().is_relative_to(crate.resolve()):
                raise RuntimeError(f"License path escapes crate: {name}/{relative}")
            copied = target / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, copied)
        record = {"name": package["name"], "version": package["version"],
                  "license": metadata.get("license"), "repository": metadata.get("repository"),
                  "crate_checksum": package.get("checksum"),
                  "files": [path.as_posix() for path in sorted(files)]}
        if not has_license:
            supplement = supplements.get(name)
            if supplement is None:
                raise RuntimeError(f"Missing upstream license text for {name}")
            text = (HERE / "licenses" / supplement["file"]).read_bytes()
            if hashlib.sha256(text).hexdigest() != supplement["sha256"]:
                raise RuntimeError(f"Supplemental license checksum mismatch: {name}")
            target.mkdir(parents=True, exist_ok=True)
            (target / "LICENSE.upstream").write_bytes(text)
            record["files"].append("LICENSE.upstream")
            record["supplement"] = supplement
        records.append(record)
    return records


def archive_metadata(member: tarfile.TarInfo) -> tarfile.TarInfo:
    """Do not embed the installing user's name or timestamps in source metadata."""
    member.uid = member.gid = member.mtime = 0
    member.uname = member.gname = ""
    return member


def rust_notices(destination: Path, tree: Path) -> None:
    """Retain the compiler distribution's notices for the linked Rust runtime."""
    root = Path(subprocess.check_output(["rustc", "--print", "sysroot"], cwd=tree, text=True).strip())
    docs = root / "share" / "doc" / "rust"
    # Recent Rust releases provide a smaller standard-library-specific bundle.
    source = docs / "COPYRIGHT-library.html"
    if not source.is_file():
        source = docs / "COPYRIGHT.html"
    if not source.is_file():
        raise RuntimeError("Rust copyright notices are missing; use an official Rust toolchain "
                           "that includes share/doc/rust/COPYRIGHT[-library].html")
    target = destination / "rust"
    target.mkdir()
    shutil.copyfile(source, target / source.name)
    (target / "toolchain.txt").write_text(
        subprocess.check_output(["rustc", "--version", "--verbose"], cwd=tree, text=True)
    )


def prepare_distribution(tree: Path, work: Path) -> tuple[Path, Path]:
    """Prepare all redistribution material before replacing an installed binary."""
    notices = work / "notices"
    notices.mkdir()
    shutil.copyfile(tree / "LICENSE", notices / "LICENSE")
    shutil.copyfile(PROJECT / "LICENSE", notices / "LICENSE.HarnessMinimizer")
    shutil.copyfile(PROJECT / "THIRD_PARTY_NOTICES", notices / "THIRD_PARTY_NOTICES")
    shutil.copytree(PROJECT / "LICENSES", notices / "LICENSES")
    records = dependency_notices(tree, notices)
    (notices / "dependencies.json").write_text(json.dumps(records, indent=2) + "\n")
    rust_notices(notices, tree)
    (notices / "README.txt").write_text(
        "This is the HarnessMinimizer-patched treereduce-c executable.\n"
        "Upstream treereduce remains MIT-licensed (LICENSE). HarnessMinimizer's\n"
        "patch additions are covered by LICENSE.HarnessMinimizer: AGPL-3.0-only\n"
        "or a separately negotiated commercial license. The patched executable\n"
        "is not offered as MIT-only. Third-party terms remain in effect.\n\n"
        "dependencies.json identifies the locked crates and their notices in\n"
        "dependencies/. This includes additional workspace/target dependencies\n"
        "shipped as source, not all of which are linked into treereduce-c.\n\n"
        "rust/ retains the Rust toolchain's runtime notices and version.\n\n"
        "The corresponding patched source, locked dependencies and build scripts\n"
        "are in <installation-root>/share/treereduce/treereduce-source.tar.gz.\n"
        "When redistributing the executable or a container containing it under\n"
        "the AGPL option, provide this source archive and these notices alongside\n"
        "it, with equivalent access. See the included licenses for their terms.\n"
    )
    building = work / "BUILDING.txt"
    building.write_text(
        f"Upstream treereduce revision: {COMMIT}\n"
        f"Upstream archive SHA-256: {SHA256}\n\n"
        "Modified in 2026 by HarnessMinimizer Authors: process-group cleanup\n"
        "and supervisor version probe. The patch is already applied here.\n"
        "See harnessminimizer/THIRD_PARTY_NOTICES and notices/README.txt for\n"
        "licensing; the upstream Cargo manifests describe upstream code only.\n\n"
        "From this extracted directory, with Rust/Cargo and a C/C++ toolchain:\n"
        "cargo install --frozen --path crates/treereduce-c --root /chosen/prefix --jobs 2 --force\n"
        "/chosen/prefix/bin/treereduce-c --harnessreducer-supervisor-version\n\n"
        "Cargo uses the included vendor/ directory and needs no registry access.\n"
        "Keep notices/ and this source archive with any redistributed executable.\n"
        "harnessminimizer/tools/treereduce contains the original installer and patch.\n"
    )
    archive = work / "treereduce-source.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(tree, arcname="treereduce-source", filter=archive_metadata)
        bundle.add(building, arcname="treereduce-source/BUILDING.txt", filter=archive_metadata)
        bundle.add(notices, arcname="treereduce-source/notices", filter=archive_metadata)
        for relative in ("LICENSE", "THIRD_PARTY_NOTICES", "LICENSES", "tools/treereduce/install.py",
                         "tools/treereduce/process-cleanup.patch", "tools/treereduce/licenses"):
            bundle.add(PROJECT / relative, arcname=f"treereduce-source/harnessminimizer/{relative}",
                       filter=archive_metadata)
    return notices, archive


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=PROJECT / ".tools")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--archive", type=Path, help="Use an already downloaded pinned archive")
    args = parser.parse_args(argv)
    install_root = args.root.resolve()
    # These accompany the installer in the repository, sdist, and Docker context.
    for relative in ("LICENSE", "THIRD_PARTY_NOTICES", "LICENSES", "tools/treereduce/licenses/sources.json"):
        if not (PROJECT / relative).exists():
            raise SystemExit(f"Missing licensing input: {relative}")
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
            "cargo", "vendor", "--locked", "--versioned-dirs", "--respect-source-config", "vendor",
        ], cwd=tree, check=True, stdout=subprocess.DEVNULL)
        # A relative path makes the archived source rebuildable in another directory.
        config = tree / ".cargo" / "config.toml"
        config.parent.mkdir(exist_ok=True)
        config.write_text(VENDOR_CONFIG)
        notices, source_archive = prepare_distribution(tree, work)
        subprocess.run([
            "cargo", "install", "--frozen", "--path", str(tree / "crates/treereduce-c"),
            "--root", str(install_root), "--jobs", str(args.jobs), "--force",
        ], cwd=tree, check=True)
        license_dir = install_root / "share" / "licenses" / "treereduce"
        shutil.copytree(notices, license_dir, dirs_exist_ok=True)
        source_dir = install_root / "share" / "treereduce"
        source_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_archive, source_dir / source_archive.name)
        subprocess.run([str(install_root / "bin/treereduce-c"), "--harnessreducer-supervisor-version"], check=True)


if __name__ == "__main__":
    main()

"""Exercise installer packaging with the same partial checkout used by Docker."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest


PROJECT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("repository_files", [(), ("LICENSE",),
    ("LICENSE", "THIRD_PARTY_NOTICES", "THIRD_PARTY_LICENSES")])
def test_install_from_tools_directory_with_optional_repository_notices(
    tmp_path, monkeypatch, repository_files,
):
    checkout = tmp_path / "image-layout"
    tools = checkout / "tools" / "treereduce"
    shutil.copytree(PROJECT / "tools" / "treereduce", tools)
    for name in repository_files:
        source = PROJECT / name
        if source.is_dir():
            shutil.copytree(source, checkout / name)
        else:
            shutil.copyfile(source, checkout / name)
    spec = importlib.util.spec_from_file_location("standalone_treereduce_installer", tools / "install.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)

    # Only external build commands are stubbed. Extraction, notice collection,
    # source archiving and installing the distribution all run normally.
    upstream = tmp_path / f"treereduce-{installer.COMMIT}"
    upstream.mkdir()
    (upstream / "LICENSE").write_text("Upstream MIT notice\n")
    (upstream / "Cargo.lock").write_text(
        'version = 3\n[[package]]\nname = "fixture-crate"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    crate = upstream / "vendor" / "fixture-crate-1.0.0"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "fixture-crate"\nversion = "1.0.0"\nlicense = "MIT"\n'
    )
    (crate / "LICENSE").write_text("Dependency MIT notice\n")
    archive = tmp_path / "upstream.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(upstream, arcname=upstream.name)
    monkeypatch.setattr(installer, "SHA256", hashlib.sha256(archive.read_bytes()).hexdigest())

    rust_root = tmp_path / "rust"
    rust_notice = rust_root / "share/doc/rust/COPYRIGHT-library.html"
    rust_notice.parent.mkdir(parents=True)
    rust_notice.write_text("Rust runtime notices\n")

    def toolchain_output(command, **_kwargs):
        if command == ["rustc", "--print", "sysroot"]:
            return str(rust_root) + "\n"
        assert command == ["rustc", "--version", "--verbose"]
        return "rustc fixture\n"

    calls = []
    prefix = tmp_path / "installed"

    def build_command(command, **kwargs):
        calls.append(command)
        assert kwargs["check"] is True
        if command[:2] == ["cargo", "install"]:
            assert Path(command[command.index("--root") + 1]) == prefix
            binary = prefix / "bin/treereduce-c"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"compiled reducer fixture")
        else:
            assert command[0] == "patch" or command[:2] == ["cargo", "vendor"] or command == [
                str(prefix / "bin/treereduce-c"), "--harnessminimizer-supervisor-version",
            ]
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(installer.subprocess, "check_output", toolchain_output)
    monkeypatch.setattr(installer.subprocess, "run", build_command)
    installer.main(["--archive", str(archive), "--root", str(prefix)])

    notices = prefix / "share/licenses/treereduce"
    assert (prefix / "bin/treereduce-c").is_file()
    assert (notices / "LICENSE").read_text() == "Upstream MIT notice\n"
    assert (notices / "dependencies/fixture-crate-1.0.0/LICENSE").read_text() == "Dependency MIT notice\n"
    assert (notices / "rust/COPYRIGHT-library.html").is_file()
    assert json.loads((notices / "dependencies.json").read_text())[0]["name"] == "fixture-crate"
    assert calls[-1] == [str(prefix / "bin/treereduce-c"), "--harnessminimizer-supervisor-version"]
    with tarfile.open(prefix / "share/treereduce/treereduce-source.tar.gz") as bundle:
        members = set(bundle.getnames())
    for name in ("LICENSE", "THIRD_PARTY_NOTICES", "THIRD_PARTY_LICENSES"):
        installed_name = "LICENSE.HarnessMinimizer" if name == "LICENSE" else name
        assert (notices / installed_name).exists() == (name in repository_files)
        assert (f"treereduce-source/harnessminimizer/{name}" in members) == (name in repository_files)
    for relative in ("install.py", "process-cleanup.patch", "licenses/sources.json"):
        assert f"treereduce-source/harnessminimizer/tools/treereduce/{relative}" in members
    assert "treereduce-source/vendor/fixture-crate-1.0.0/LICENSE" in members

"""Native Rust harness compilation, backtrace parsing, comment cleanup, and inlining.

This module relies strictly on the Python standard library (Python 3.12+
``tomllib``) so ``HarnessMinimizer`` gains first-class Rust (``.rs``) support
with zero additional runtime dependencies.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import glob
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
import uuid

from harnessminimizer.safe_files import replace_regular_file


RUST_DIRECT_PLAN_FILE = "rust_direct_compile.json"

RUST_FDP_SOURCE = r'''//! Built-in zero-dependency structured fuzzer input consumer for Rust harnesses.

#[derive(Debug, Clone)]
pub struct FuzzedDataProvider<'a> {
    data: &'a [u8],
}

impl<'a> FuzzedDataProvider<'a> {
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    #[inline]
    pub fn remaining_bytes(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn consume_tail(&mut self, count: usize) -> &'a [u8] {
        let n = count.min(self.data.len());
        let split = self.data.len() - n;
        let (head, tail) = self.data.split_at(split);
        self.data = head;
        tail
    }

    #[inline]
    pub fn consume_bool(&mut self) -> bool {
        (self.consume_u8() & 1) != 0
    }

    #[inline]
    pub fn consume_u8(&mut self) -> u8 {
        self.consume_tail(1).first().copied().unwrap_or(0)
    }

    #[inline]
    pub fn consume_i8(&mut self) -> i8 {
        self.consume_u8() as i8
    }

    #[inline]
    pub fn consume_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        let tail = self.consume_tail(2);
        buf[..tail.len()].copy_from_slice(tail);
        u16::from_le_bytes(buf)
    }

    #[inline]
    pub fn consume_i16(&mut self) -> i16 {
        self.consume_u16() as i16
    }

    #[inline]
    pub fn consume_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        let tail = self.consume_tail(4);
        buf[..tail.len()].copy_from_slice(tail);
        u32::from_le_bytes(buf)
    }

    #[inline]
    pub fn consume_i32(&mut self) -> i32 {
        self.consume_u32() as i32
    }

    #[inline]
    pub fn consume_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        let tail = self.consume_tail(8);
        buf[..tail.len()].copy_from_slice(tail);
        u64::from_le_bytes(buf)
    }

    #[inline]
    pub fn consume_i64(&mut self) -> i64 {
        self.consume_u64() as i64
    }

    #[inline]
    pub fn consume_u128(&mut self) -> u128 {
        let mut buf = [0u8; 16];
        let tail = self.consume_tail(16);
        buf[..tail.len()].copy_from_slice(tail);
        u128::from_le_bytes(buf)
    }

    #[inline]
    pub fn consume_i128(&mut self) -> i128 {
        self.consume_u128() as i128
    }

    #[inline]
    pub fn consume_usize(&mut self) -> usize {
        self.consume_u64() as usize
    }

    #[inline]
    pub fn consume_isize(&mut self) -> isize {
        self.consume_i64() as isize
    }

    #[inline]
    pub fn consume_f32(&mut self) -> f32 {
        f32::from_bits(self.consume_u32())
    }

    #[inline]
    pub fn consume_f64(&mut self) -> f64 {
        f64::from_bits(self.consume_u64())
    }

    #[inline]
    pub fn consume_probability(&mut self) -> f64 {
        (self.consume_u64() as f64) / (u64::MAX as f64)
    }

    pub fn consume_usize_in_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        let span = max - min;
        if span == usize::MAX {
            return self.consume_usize();
        }
        min + (self.consume_usize() % (span + 1))
    }

    pub fn consume_i64_in_range(&mut self, min: i64, max: i64) -> i64 {
        if min >= max {
            return min;
        }
        let span = (max as i128 - min as i128) as u128;
        let offset = if span == u128::MAX {
            self.consume_u128()
        } else {
            self.consume_u128() % (span + 1)
        };
        (min as i128 + offset as i128) as i64
    }

    pub fn consume_u64_in_range(&mut self, min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }
        let span = max - min;
        if span == u64::MAX {
            return self.consume_u64();
        }
        min + (self.consume_u64() % (span + 1))
    }

    #[inline]
    pub fn consume_u32_in_range(&mut self, min: u32, max: u32) -> u32 {
        self.consume_u64_in_range(min as u64, max as u64) as u32
    }

    #[inline]
    pub fn consume_i32_in_range(&mut self, min: i32, max: i32) -> i32 {
        self.consume_i64_in_range(min as i64, max as i64) as i32
    }

    pub fn consume_bytes(&mut self, num_bytes: usize) -> &'a [u8] {
        let n = num_bytes.min(self.data.len());
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        head
    }

    pub fn consume_bytes_vec(&mut self, num_bytes: usize) -> Vec<u8> {
        self.consume_bytes(num_bytes).to_vec()
    }

    pub fn consume_remaining_bytes(&mut self) -> &'a [u8] {
        let rest = self.data;
        self.data = &[];
        rest
    }

    pub fn consume_bytes_as_string(&mut self, num_bytes: usize) -> String {
        String::from_utf8_lossy(self.consume_bytes(num_bytes)).into_owned()
    }

    pub fn consume_random_length_string(&mut self, max_length: usize) -> String {
        let mut out = Vec::with_capacity(max_length.min(self.data.len()));
        let mut idx = 0;
        while idx < self.data.len() && out.len() < max_length {
            let b = self.data[idx];
            idx += 1;
            if b == b'\\' && idx < self.data.len() {
                let next = self.data[idx];
                idx += 1;
                if next == b'\\' {
                    out.push(b'\\');
                } else {
                    break;
                }
            } else {
                out.push(b);
            }
        }
        self.data = &self.data[idx..];
        String::from_utf8_lossy(&out).into_owned()
    }

    pub fn consume_remaining_as_string(&mut self) -> String {
        String::from_utf8_lossy(self.consume_remaining_bytes()).into_owned()
    }

    #[inline]
    pub fn consume_remaining_bytes_as_string(&mut self) -> String {
        self.consume_remaining_as_string()
    }

    pub fn pick_value<'b, T>(&mut self, values: &'b [T]) -> Option<&'b T> {
        if values.is_empty() {
            return None;
        }
        let idx = self.consume_usize_in_range(0, values.len() - 1);
        Some(&values[idx])
    }

    #[inline]
    pub fn pick_value_in_slice<'b, T>(&mut self, values: &'b [T]) -> Option<&'b T> {
        self.pick_value(values)
    }
}
'''


@dataclass(frozen=True)
class RustCrateInfo:
    name: str
    lib_name: str
    manifest_path: str
    package_dir: str
    src_lib_path: str
    edition: str = "2021"
    features: tuple[str, ...] = ()


@dataclass(frozen=True)
class RustBuildConfig:
    project_dir: str
    target_dir: str
    target_triple: str
    features: tuple[str, ...] = ()
    all_features: bool = False
    no_default_features: bool = False
    use_asan: bool = False
    sanitizer: str | None = None
    rustc_flags: tuple[str, ...] = ()
    linker_args: tuple[str, ...] = ()
    plan_file: str | None = None


def get_rustc_host_triple() -> str:
    explicit = os.getenv("CARGO_BUILD_TARGET") or os.getenv("RUST_TARGET_TRIPLE")
    if explicit:
        return explicit.strip()
    rustc = shutil.which("rustc")
    if rustc:
        try:
            res = subprocess.run(
                [rustc, "-vV"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
                check=True,
            )
            for line in res.stdout.splitlines():
                if line.startswith("host:"):
                    triple = line.split(":", 1)[1].strip()
                    if triple:
                        return triple
        except (OSError, subprocess.SubprocessError):
            pass
    return "x86_64-unknown-linux-gnu"


def cargo_target_env_prefix(triple: str) -> str:
    return "CARGO_TARGET_" + re.sub(r"[^A-Za-z0-9]", "_", triple).upper()


def parse_rust_minimizer_flags(
    compile_flags: str | None,
    link_flags: str | None,
    *,
    default_project_dir: str | None = None,
    default_target_dir: str | None = None,
) -> RustBuildConfig:
    """Parse Rust build parameters encoded in ``compile_flags`` / ``link_flags``."""
    tokens: list[str] = []
    for raw in (compile_flags, link_flags):
        if raw and raw.strip():
            try:
                tokens.extend(shlex.split(raw))
            except ValueError:
                tokens.extend(raw.split())

    project_dir = default_project_dir or os.environ.get("SRC") or os.getcwd()
    target_dir = default_target_dir or os.environ.get("CARGO_TARGET_DIR") or ""
    target_triple = ""
    features: list[str] = []
    all_features = False
    no_default_features = False
    use_asan = False
    sanitizer: str | None = None
    rustc_flags: list[str] = []
    linker_args: list[str] = []
    plan_file: str | None = None

    def add_features(spec: str) -> None:
        for item in re.split(r"[,\s]+", spec.strip()):
            if item and item not in features:
                features.append(item)

    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        nxt = tokens[idx + 1] if idx + 1 < len(tokens) else ""
        if tok == "--rust-project-dir" and nxt:
            project_dir = nxt
            idx += 2
            continue
        if tok.startswith("--rust-project-dir="):
            project_dir = tok.split("=", 1)[1]
            idx += 1
            continue
        if tok == "--rust-target-dir" and nxt:
            target_dir = nxt
            idx += 2
            continue
        if tok.startswith("--rust-target-dir="):
            target_dir = tok.split("=", 1)[1]
            idx += 1
            continue
        if tok == "--rust-target" and nxt:
            target_triple = nxt
            idx += 2
            continue
        if tok.startswith("--rust-target="):
            target_triple = tok.split("=", 1)[1]
            idx += 1
            continue
        if tok == "--rust-plan-file" and nxt:
            plan_file = nxt
            idx += 2
            continue
        if tok.startswith("--rust-plan-file="):
            plan_file = tok.split("=", 1)[1]
            idx += 1
            continue
        if tok in {"--rust-features", "--features", "-F"} and nxt:
            add_features(nxt)
            idx += 2
            continue
        if tok.startswith(("--rust-features=", "--features=")):
            add_features(tok.split("=", 1)[1])
            idx += 1
            continue
        if tok in {"--rust-all-features", "--all-features"}:
            all_features = True
            idx += 1
            continue
        if tok in {"--rust-no-default-features", "--no-default-features"}:
            no_default_features = True
            idx += 1
            continue
        if tok == "--rust-asan":
            use_asan = True
            sanitizer = sanitizer or "address"
            idx += 1
            continue
        if tok == "--rust-sanitizer" and nxt:
            use_asan = True
            sanitizer = nxt
            idx += 2
            continue
        if tok.startswith("--rust-sanitizer="):
            use_asan = True
            sanitizer = tok.split("=", 1)[1]
            idx += 1
            continue
        if tok == "--rust-extra-rustc" and nxt:
            rustc_flags.append(nxt)
            idx += 2
            continue
        if tok.startswith("--rust-extra-rustc="):
            rustc_flags.append(tok.split("=", 1)[1])
            idx += 1
            continue
        if tok in {"-C", "-Z", "--cfg"} and nxt:
            rustc_flags.extend([tok, nxt])
            idx += 2
            continue
        if tok.startswith(("-C", "-Z", "--cfg=")):
            rustc_flags.append(tok)
            idx += 1
            continue
        if tok in {"-L", "-l"} and nxt:
            linker_args.extend([tok, nxt])
            idx += 2
            continue
        if tok.startswith(("-L", "-l", "-Wl,")) or tok.endswith((".a", ".so", ".o")):
            linker_args.append(tok)
            idx += 1
            continue
        idx += 1

    resolved_project = str(Path(project_dir).expanduser().resolve())
    resolved_target_dir = (
        str(Path(target_dir).expanduser().resolve())
        if target_dir
        else str((Path(resolved_project) / "target").resolve())
    )
    triple = target_triple or get_rustc_host_triple()
    return RustBuildConfig(
        project_dir=resolved_project,
        target_dir=resolved_target_dir,
        target_triple=triple,
        features=tuple(features),
        all_features=all_features,
        no_default_features=no_default_features,
        use_asan=use_asan,
        sanitizer=sanitizer if use_asan else None,
        rustc_flags=tuple(rustc_flags),
        linker_args=tuple(linker_args),
        plan_file=plan_file,
    )


def _load_toml(path: Path) -> dict | None:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, tomllib.TOMLDecodeError):
        return None


def _inspect_crate_manifest(
    manifest_path: Path, workspace_edition: str | None = None
) -> RustCrateInfo | None:
    data = _load_toml(manifest_path)
    if not data:
        return None
    package = data.get("package")
    if not isinstance(package, dict) or not isinstance(package.get("name"), str):
        return None
    package_dir = manifest_path.parent
    lib_section = data.get("lib")
    lib_rel_path: str | None = None
    lib_name: str | None = None
    if isinstance(lib_section, dict):
        if isinstance(lib_section.get("path"), str):
            lib_rel_path = lib_section["path"]
        if isinstance(lib_section.get("name"), str):
            lib_name = lib_section["name"]
    default_lib = package_dir / "src" / "lib.rs"
    if lib_rel_path:
        src_lib = (package_dir / lib_rel_path).resolve()
    elif default_lib.is_file():
        src_lib = default_lib.resolve()
    else:
        return None
    if not src_lib.is_file():
        return None
    pkg_name = package["name"]
    effective_lib_name = (lib_name or pkg_name).replace("-", "_")
    features_tbl = data.get("features")
    features = (
        tuple(sorted(str(k) for k in features_tbl.keys() if k != "default"))
        if isinstance(features_tbl, dict)
        else ()
    )
    edition_raw = package.get("edition")
    if isinstance(edition_raw, str) and edition_raw:
        edition = edition_raw
    elif isinstance(edition_raw, dict) and edition_raw.get("workspace") and workspace_edition:
        edition = workspace_edition
    else:
        edition = "2021"
    return RustCrateInfo(
        name=pkg_name,
        lib_name=effective_lib_name,
        manifest_path=str(manifest_path.resolve()),
        package_dir=str(package_dir.resolve()),
        src_lib_path=str(src_lib),
        edition=edition,
        features=features,
    )


def discover_rust_crates(project_dir: str) -> list[RustCrateInfo]:
    """Discover all library crates in a Cargo package or workspace."""
    root = Path(project_dir).resolve()
    root_manifest = root / "Cargo.toml"
    data = _load_toml(root_manifest)
    if not data:
        return []
    workspace = data.get("workspace")
    workspace_edition = None
    if isinstance(workspace, dict):
        ws_pkg = workspace.get("package")
        if isinstance(ws_pkg, dict) and isinstance(ws_pkg.get("edition"), str):
            workspace_edition = ws_pkg["edition"]

    seen: set[Path] = set()
    crates: list[RustCrateInfo] = []

    def add_manifest(path: Path) -> None:
        resolved = path.resolve()
        if resolved in seen or not resolved.is_file():
            return
        seen.add(resolved)
        info = _inspect_crate_manifest(resolved, workspace_edition)
        if info is not None:
            crates.append(info)

    add_manifest(root_manifest)
    if isinstance(workspace, dict):
        excludes: set[Path] = set()
        for pat in workspace.get("exclude", []) or []:
            if isinstance(pat, str):
                for match in glob.glob(str(root / pat)):
                    excludes.add(Path(match).resolve())
        for pat in workspace.get("members", []) or []:
            if isinstance(pat, str):
                for match in sorted(glob.glob(str(root / pat))):
                    member = Path(match).resolve()
                    if member in excludes or not member.is_dir():
                        continue
                    if any(part in {"target", ".git"} for part in member.parts):
                        continue
                    add_manifest(member / "Cargo.toml")

    crates.sort(key=lambda c: (0 if Path(c.package_dir) == root else 1, c.name))
    return crates


def _strip_rust_comments_and_strings(source: str) -> str:
    """Replace Rust comments and string literals with spaces, preserving newlines."""
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        # Line comment
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            end = source.find("\n", i + 2)
            if end == -1:
                out.append(" " * (n - i))
                break
            out.append(" " * (end - i))
            i = end
            continue
        # Nested block comment
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if source[j] == "/" and j + 1 < n and source[j + 1] == "*":
                    depth += 1
                    j += 2
                elif source[j] == "*" and j + 1 < n and source[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append("".join("\n" if c == "\n" else " " for c in source[i:j]))
            i = j
            continue
        # Raw string r#"..."# or br#"..."#
        if (ch == "r" or (ch == "b" and i + 1 < n and source[i + 1] == "r")):
            j = i + (2 if ch == "b" else 1)
            hashes = 0
            while j < n and source[j] == "#":
                hashes += 1
                j += 1
            if j < n and source[j] == '"':
                closing = '"' + ("#" * hashes)
                end = source.find(closing, j + 1)
                stop = n if end == -1 else end + len(closing)
                out.append("".join("\n" if c == "\n" else " " for c in source[i:stop]))
                i = stop
                continue
        # Normal or byte string literal
        if ch == '"' or (ch == "b" and i + 1 < n and source[i + 1] == '"'):
            j = i + (2 if ch == "b" else 1)
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == '"':
                    j += 1
                    break
                j += 1
            out.append("".join("\n" if c == "\n" else " " for c in source[i:j]))
            i = j
            continue
        # Char literal (distinguish from Rust lifetime `'a`)
        if ch == "'" or (ch == "b" and i + 1 < n and source[i + 1] == "'"):
            q = i + (1 if ch == "b" else 0)
            if q + 2 < n and source[q + 1] == "\\":
                end = source.find("'", q + 3)
                if end != -1 and end - q <= 12 and "\n" not in source[q:end]:
                    out.append(" " * (end + 1 - i))
                    i = end + 1
                    continue
            elif q + 2 < n and source[q + 2] == "'" and source[q + 1] != "\n":
                out.append(" " * (q + 3 - i))
                i = q + 3
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _is_cfg_test_attribute(attr_body: str) -> bool:
    stripped = attr_body.strip()
    if stripped == "test":
        return True
    match = re.fullmatch(r"cfg\s*\((.*)\)", stripped, flags=re.DOTALL)
    if not match:
        return False
    inner = match.group(1).strip()
    if inner == "test":
        return True
    if re.search(r"\bnot\s*\(\s*test\s*\)", inner):
        return False
    return bool(re.fullmatch(r"(?:all|any)\s*\(.*\btest\b.*\)", inner, flags=re.DOTALL))


def _remove_cfg_test_blocks(source: str) -> str:
    out: list[str] = []
    i = 0
    n = len(source)
    attr_re = re.compile(r"#\[([^\]]+)\]")
    while i < n:
        match = attr_re.match(source, i)
        if not match or not _is_cfg_test_attribute(match.group(1)):
            out.append(source[i])
            i += 1
            continue
        j = match.end()
        while j < n and source[j] not in "{;":
            j += 1
        if j >= n:
            break
        if source[j] == ";":
            i = j + 1
            continue
        depth = 0
        while j < n:
            if source[j] == "{":
                depth += 1
            elif source[j] == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        i = j
    return "".join(out)


def _top_level_rust_items(source: str) -> str:
    out: list[str] = []
    depth = 0
    for ch in source:
        if ch == "{":
            if depth == 0:
                out.append("{")
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0:
                    out.append("}")
        elif depth == 0:
            out.append(ch)
        elif ch == "\n":
            out.append("\n")
    return "".join(out)


def detect_rust_entry_style(source: str) -> str:
    """Detect how a Rust harness exposes its entry point."""
    cleaned = _remove_cfg_test_blocks(_strip_rust_comments_and_strings(source))
    top_level = _top_level_rust_items(cleaned)
    if re.search(r"\bfn\s+LLVMFuzzerTestOneInput\s*\(", top_level):
        return "llvm_fuzzer_entry"
    if re.search(r"\bfuzz_target\s*!", top_level):
        return "fuzz_target_macro"
    if re.search(r"\bpub\s+(?:unsafe\s+)?fn\s+fuzz_target\s*\(", top_level):
        return "fuzz_target_fn"
    if re.search(r"\bfn\s+main\s*\(", top_level):
        return "fn_main"
    return "unknown"


def _toml_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_key(key: str) -> str:
    return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else _toml_quote(key)


def _serialize_toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return _toml_quote(value)
    if isinstance(value, list):
        return "[" + ", ".join(_serialize_toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        items = [f"{_toml_key(str(k))} = {_serialize_toml_value(v)}" for k, v in value.items()]
        return "{ " + ", ".join(items) + " }"
    return _toml_quote(str(value))


def _resolve_patch_paths(obj: object, base_dir: Path) -> object:
    if isinstance(obj, dict):
        out: dict[str, object] = {}
        for k, v in obj.items():
            if k == "path" and isinstance(v, str) and not os.path.isabs(v):
                out[k] = str((base_dir / v).resolve())
            else:
                out[k] = _resolve_patch_paths(v, base_dir)
        return out
    if isinstance(obj, list):
        return [_resolve_patch_paths(v, base_dir) for v in obj]
    return obj


def _extract_patch_replace_toml(project_dir: str) -> str:
    root = Path(project_dir).resolve()
    data = _load_toml(root / "Cargo.toml")
    if not data:
        return ""
    blocks: list[str] = []
    patch_tbl = data.get("patch")
    if isinstance(patch_tbl, dict):
        for registry, entries in patch_tbl.items():
            if not isinstance(entries, dict):
                continue
            resolved = _resolve_patch_paths(entries, root)
            lines = [f"[patch.{_toml_key(str(registry))}]"]
            for dep, spec in resolved.items():
                lines.append(f"{_toml_key(str(dep))} = {_serialize_toml_value(spec)}")
            blocks.append("\n".join(lines))
    replace_tbl = data.get("replace")
    if isinstance(replace_tbl, dict) and replace_tbl:
        resolved = _resolve_patch_paths(replace_tbl, root)
        lines = ["[replace]"]
        for dep, spec in resolved.items():
            lines.append(f"{_toml_key(str(dep))} = {_serialize_toml_value(spec)}")
        blocks.append("\n".join(lines))
    return ("\n\n" + "\n\n".join(blocks) + "\n") if blocks else ""


def _vendor_has_crate(vendor_dir: Path, crate_name: str) -> bool:
    if not vendor_dir.is_dir():
        return False
    if (vendor_dir / crate_name / "Cargo.toml").is_file():
        return True
    ver_pat = re.compile(rf"^{re.escape(crate_name)}-\d")
    try:
        for entry in vendor_dir.iterdir():
            if entry.is_dir() and ver_pat.match(entry.name) and (entry / "Cargo.toml").is_file():
                return True
    except OSError:
        return False
    return False


def _strip_crates_io_replace_with(cfg_text: str) -> str:
    lines = cfg_text.splitlines(keepends=True)
    out: list[str] = []
    in_crates_io = False
    in_source = False
    section_buf: list[str] = []

    def _flush() -> None:
        nonlocal section_buf
        if not section_buf:
            return
        if any(ln.strip() and not ln.lstrip().startswith("#") for ln in section_buf[1:]):
            out.extend(section_buf)
        section_buf = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and not stripped.startswith("[["):
            if in_crates_io:
                _flush()
            header = stripped.split("#", 1)[0].strip()
            in_crates_io = bool(re.fullmatch(r'\[\s*source\s*\.\s*(?:"crates-io"|crates-io)\s*\]', header))
            in_source = bool(re.fullmatch(r"\[\s*source\s*\]", header))
            if in_crates_io:
                section_buf = [line]
                continue
        if in_crates_io:
            if re.match(r"^\s*replace-with\s*=", line):
                continue
            section_buf.append(line)
            continue
        if in_source and re.match(r'^\s*(?:"crates-io"|crates-io)\s*=', line):
            continue
        out.append(line)

    if in_crates_io:
        _flush()
    return "".join(out)


def _sync_cargo_config_and_lock(
    project_dir: str,
    ws: Path,
    *,
    extra_crates: tuple[str, ...] | list[str] = (),
) -> None:
    root = Path(project_dir).resolve()
    lock = root / "Cargo.lock"
    if lock.is_file():
        try:
            replace_regular_file(ws / "Cargo.lock", lock.read_bytes())
        except OSError:
            pass
    for rel in (".cargo/config.toml", ".cargo/config"):
        cfg = root / rel
        if not cfg.is_file():
            continue
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        def _rewrite(match: re.Match[str]) -> str:
            raw_dir = match.group(2)
            if os.path.isabs(raw_dir):
                return match.group(0)
            return f"{match.group(1)}{_toml_quote(str((root / raw_dir).resolve()))}"

        rewritten = re.sub(r'(\bdirectory\s*=\s*)"([^"]+)"', _rewrite, text)
        if extra_crates:
            try:
                parsed_cfg = tomllib.loads(rewritten)
            except (tomllib.TOMLDecodeError, ValueError):
                parsed_cfg = None
            if isinstance(parsed_cfg, dict):
                source_tbl = parsed_cfg.get("source")
                crates_io = source_tbl.get("crates-io") if isinstance(source_tbl, dict) else None
                rep_name = crates_io.get("replace-with") if isinstance(crates_io, dict) else None
                rep_tbl = source_tbl.get(rep_name) if isinstance(rep_name, str) and isinstance(source_tbl, dict) else None
                rep_dir = rep_tbl.get("directory") if isinstance(rep_tbl, dict) else None
                if isinstance(rep_dir, str):
                    vendor_dir = Path(rep_dir) if os.path.isabs(rep_dir) else (root / rep_dir).resolve()
                    if any(not _vendor_has_crate(vendor_dir, pkg) for pkg in extra_crates):
                        rewritten = _strip_crates_io_replace_with(rewritten)
        cfg_dst = ws / ".cargo" / "config.toml"
        cfg_dst.parent.mkdir(parents=True, exist_ok=True)
        replace_regular_file(cfg_dst, rewritten.encode("utf-8"))
        break


def _format_crate_dep(crate: RustCrateInfo, config: RustBuildConfig) -> str:
    parts = [f"path = {_toml_quote(crate.package_dir)}"]
    if config.no_default_features:
        parts.append("default-features = false")
    selected: list[str] = []
    if config.all_features:
        selected = list(crate.features)
    elif config.features:
        for raw_feat in config.features:
            if "/" in raw_feat:
                pkg, feat = raw_feat.split("/", 1)
                if pkg in {crate.name, crate.lib_name} and feat:
                    if (not crate.features or feat in crate.features) and feat not in selected:
                        selected.append(feat)
            elif raw_feat in crate.features and raw_feat not in selected:
                selected.append(raw_feat)
    if selected:
        parts.append("features = [" + ", ".join(_toml_quote(f) for f in selected) + "]")
    return f'{_toml_quote(crate.name)} = {{ {", ".join(parts)} }}'


def _rust_driver_main_source(
    entry_style: str,
    *,
    include_path: str | None = None,
    panic_exit_code: int | None = 77,
) -> str:
    """Build a standalone Rust driver.

    During HarnessMinimizer reference/reduction runs (``panic_exit_code=77``),
    the driver catches panics, prints the panic message plus a forced backtrace,
    and exits with code 77 as expected by ``crash_tester.py``.

    When exporting the final PoC binary for Core (``panic_exit_code=None``),
    the driver invokes ``hm_rust_harness::__hm_run`` directly without
    ``catch_unwind`` so panics abort with ``SIGABRT`` for ``casr-gdb`` and
    ``crash_debugger`` (GDB).
    """
    if panic_exit_code is None:
        return (
            "fn main() {\n"
            "    let args: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();\n"
            "    let data: Vec<u8> = if let Some(path) = args.first() {\n"
            "        std::fs::read(path).unwrap_or_default()\n"
            "    } else {\n"
            "        Vec::new()\n"
            "    };\n"
            "    hm_rust_harness::__hm_run(&data);\n"
            "}\n"
        )

    hook_block = (
        "    std::panic::set_hook(Box::new(|info| {\n"
        "        let thread = std::thread::current();\n"
        "        let name = thread.name().unwrap_or(\"<unnamed>\");\n"
        "        let payload = info.payload().downcast_ref::<&str>().copied()\n"
        "            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))\n"
        "            .unwrap_or(\"Box<dyn Any>\");\n"
        "        if let Some(loc) = info.location() {\n"
        "            eprintln!(\"thread '{}' panicked at {}:{}:{}:\\n{}\", name, loc.file(), loc.line(), loc.column(), payload);\n"
        "        } else {\n"
        "            eprintln!(\"thread '{}' panicked at <unknown>:\\n{}\", name, payload);\n"
        "        }\n"
        "        eprintln!(\"stack backtrace:\\n{}\", std::backtrace::Backtrace::force_capture());\n"
        "    }));\n"
    )
    if include_path is not None:
        # Single-file direct rustc compilation mode: keeps exact candidate path
        # in debug symbols and backtraces via #[path = "..."] or include!(...).
        path_lit = _toml_quote(include_path)
        if entry_style == "fuzz_target_fn":
            harness_decl = (
                f"#[path = {path_lit}]\n"
                "pub mod harness;\n"
                "fn __hm_run(data: &[u8]) { harness::fuzz_target(data); }\n"
            )
        elif entry_style == "fuzz_target_macro":
            harness_decl = (
                "#[macro_export]\n"
                "macro_rules! fuzz_target {\n"
                "    (|$data:ident : &[u8]| $body:expr) => { pub fn __hm_macro_entry($data: &[u8]) { let _ = $body; } };\n"
                "    (|$data:ident| $body:expr) => { pub fn __hm_macro_entry($data: &[u8]) { let _ = $body; } };\n"
                "    (|$data:ident : $ty:ty| $body:expr) => {\n"
                "        pub fn __hm_macro_entry(__raw: &[u8]) {\n"
                "            let mut __u = arbitrary::Unstructured::new(__raw);\n"
                "            if let Ok($data) = <$ty as arbitrary::Arbitrary>::arbitrary(&mut __u) { let _ = $body; }\n"
                "        }\n"
                "    };\n"
                "}\n"
                "pub mod harness {\n"
                f"    include!({path_lit});\n"
                "}\n"
                "fn __hm_run(data: &[u8]) { harness::__hm_macro_entry(data); }\n"
            )
        elif entry_style == "llvm_fuzzer_entry":
            harness_decl = (
                f"#[path = {path_lit}]\n"
                "pub mod harness;\n"
                "fn __hm_run(data: &[u8]) {\n"
                "    unsafe { let _ = harness::LLVMFuzzerTestOneInput(data.as_ptr(), data.len()); }\n"
                "}\n"
            )
        else:  # fn_main
            harness_decl = (
                f"#[path = {path_lit}]\n"
                "pub mod harness;\n"
                "fn __hm_run(_data: &[u8]) { harness::main(); }\n"
            )
        return (
            "#![allow(unused_imports, dead_code, unused_variables)]\n"
            "pub mod fdp;\n"
            "pub use fdp::FuzzedDataProvider;\n\n"
            f"{harness_decl}\n"
            "fn main() {\n"
            f"{hook_block}"
            "    let args: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();\n"
            "    let data: Vec<u8> = if let Some(path) = args.first() {\n"
            "        std::fs::read(path).unwrap_or_default()\n"
            "    } else {\n"
            "        Vec::new()\n"
            "    };\n"
            "    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {\n"
            "        __hm_run(&data);\n"
            "    }));\n"
            "    if res.is_err() {\n"
            f"        std::process::exit({panic_exit_code});\n"
            "    }\n"
            "}\n"
        )

    # Cargo binary driver calling `hm_rust_harness::__hm_run`
    return (
        "fn main() {\n"
        f"{hook_block}"
        "    let args: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();\n"
        "    let data: Vec<u8> = if let Some(path) = args.first() {\n"
        "        std::fs::read(path).unwrap_or_default()\n"
        "    } else {\n"
        "        Vec::new()\n"
        "    };\n"
        "    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {\n"
        "        hm_rust_harness::__hm_run(&data);\n"
        "    }));\n"
        "    if res.is_err() {\n"
        f"        std::process::exit({panic_exit_code});\n"
        "    }\n"
        "}\n"
    )


def _resolve_arbitrary_version(project_dir: str) -> str:
    """Read the locked `arbitrary` crate version from Cargo.lock when present."""
    if not project_dir:
        return "1"
    lock_file = Path(project_dir) / "Cargo.lock"
    if lock_file.is_file():
        try:
            data = tomllib.loads(lock_file.read_text(encoding="utf-8"))
        except Exception:
            data = None
        if isinstance(data, dict):
            for pkg in data.get("package", []) or []:
                if (
                    isinstance(pkg, dict)
                    and pkg.get("name") == "arbitrary"
                    and isinstance(pkg.get("version"), str)
                ):
                    return pkg["version"]
    return "1"


def scaffold_rust_candidate_crate(
    harness_path: str,
    workspace_dir: str | Path,
    config: RustBuildConfig,
    *,
    crates: list[RustCrateInfo] | None = None,
    panic_exit_code: int | None = 77,
    package_name: str = "hm_rust_harness",
    bin_name: str = "poc_driver",
) -> Path:
    """Create a Cargo wrapper crate for compiling a Rust harness."""
    ws = Path(workspace_dir)
    src_out = ws / "src"
    bin_out = src_out / "bin"
    bin_out.mkdir(parents=True, exist_ok=True)

    harness_abs = str(Path(harness_path).resolve())
    harness_source = Path(harness_abs).read_text(encoding="utf-8", errors="replace")
    entry_style = detect_rust_entry_style(harness_source)
    if entry_style == "unknown":
        raise ValueError(
            f"Rust harness {harness_path} must define `pub fn fuzz_target(data: &[u8])`, "
            "`fuzz_target!(|data: &[u8]| { ... })`, `LLVMFuzzerTestOneInput`, or `fn main()`."
        )

    # Strip #![no_main] if present into a copy preserving the original harness
    # basename (under harnesses/) so rustc diagnostics, DWARF stack frames,
    # and harness-crash detection still match the exact harness filename.
    has_no_main = bool(re.search(r"^\s*#!\[no_main\]\s*$", harness_source, flags=re.MULTILINE))
    if has_no_main:
        cleaned = re.sub(r"^\s*#!\[no_main\]\s*$", "", harness_source, flags=re.MULTILINE)
        harnesses_out = ws / "harnesses"
        harnesses_out.mkdir(parents=True, exist_ok=True)
        local_harness = harnesses_out / Path(harness_abs).name
        replace_regular_file(local_harness, cleaned.encode("utf-8"))
        ref_path = str(local_harness.resolve())
    else:
        ref_path = harness_abs

    replace_regular_file(src_out / "fdp.rs", RUST_FDP_SOURCE.encode("utf-8"))
    ref_lit = _toml_quote(ref_path)
    if entry_style == "fuzz_target_fn":
        lib_rs = (
            "#![allow(unused_imports, dead_code, unused_variables)]\n"
            "pub mod fdp;\n"
            "pub use fdp::FuzzedDataProvider;\n"
            f"#[path = {ref_lit}]\n"
            "pub mod harness;\n"
            "#[inline]\n"
            "pub fn __hm_run(data: &[u8]) { harness::fuzz_target(data); }\n"
        )
    elif entry_style == "fuzz_target_macro":
        lib_rs = (
            "#![allow(unused_imports, dead_code, unused_variables)]\n"
            "pub mod fdp;\n"
            "pub use fdp::FuzzedDataProvider;\n"
            "#[macro_export]\n"
            "macro_rules! fuzz_target {\n"
            "    (|$data:ident : &[u8]| $body:expr) => { pub fn __hm_macro_entry($data: &[u8]) { let _ = $body; } };\n"
            "    (|$data:ident| $body:expr) => { pub fn __hm_macro_entry($data: &[u8]) { let _ = $body; } };\n"
            "    (|$data:ident : $ty:ty| $body:expr) => {\n"
            "        pub fn __hm_macro_entry(__raw: &[u8]) {\n"
            "            let mut __u = arbitrary::Unstructured::new(__raw);\n"
            "            if let Ok($data) = <$ty as arbitrary::Arbitrary>::arbitrary(&mut __u) { let _ = $body; }\n"
            "        }\n"
            "    };\n"
            "}\n"
            "pub mod harness {\n"
            f"    include!({ref_lit});\n"
            "}\n"
            "#[inline]\n"
            "pub fn __hm_run(data: &[u8]) { harness::__hm_macro_entry(data); }\n"
        )
    elif entry_style == "llvm_fuzzer_entry":
        lib_rs = (
            "#![allow(unused_imports, dead_code, unused_variables)]\n"
            "pub mod fdp;\n"
            "pub use fdp::FuzzedDataProvider;\n"
            f"#[path = {ref_lit}]\n"
            "pub mod harness;\n"
            "#[inline]\n"
            "pub fn __hm_run(data: &[u8]) {\n"
            "    unsafe { let _ = harness::LLVMFuzzerTestOneInput(data.as_ptr(), data.len()); }\n"
            "}\n"
        )
    else:
        lib_rs = (
            "#![allow(unused_imports, dead_code, unused_variables)]\n"
            "pub mod fdp;\n"
            "pub use fdp::FuzzedDataProvider;\n"
            f"#[path = {ref_lit}]\n"
            "pub mod harness;\n"
            "#[inline]\n"
            "pub fn __hm_run(_data: &[u8]) { harness::main(); }\n"
        )
    replace_regular_file(src_out / "lib.rs", lib_rs.encode("utf-8"))
    replace_regular_file(
        bin_out / f"{bin_name}.rs",
        _rust_driver_main_source(entry_style, panic_exit_code=panic_exit_code).encode("utf-8"),
    )

    discovered = crates if crates is not None else discover_rust_crates(config.project_dir)
    dep_lines: list[str] = []
    seen_names: set[str] = set()
    for crate in discovered:
        if crate.name in seen_names or crate.name in {"hm_rust_harness", package_name}:
            continue
        seen_names.add(crate.name)
        dep_lines.append(_format_crate_dep(crate, config))

    injected_crates: list[str] = []
    if re.search(r"\b(?:use\s+arbitrary\b|arbitrary::)", _strip_rust_comments_and_strings(harness_source)):
        if "arbitrary" not in seen_names:
            arb_ver = _resolve_arbitrary_version(config.project_dir)
            dep_lines.append(
                f'arbitrary = {{ version = {_toml_quote(arb_ver)}, features = ["derive"] }}'
            )
            injected_crates.append("arbitrary")

    edition = discovered[0].edition if discovered else "2021"
    if edition not in {"2018", "2021", "2024"}:
        edition = "2021"
    panic_mode = "abort" if (config.use_asan or panic_exit_code is None) else "unwind"
    patch_toml = _extract_patch_replace_toml(config.project_dir)

    cargo_toml = (
        "[package]\n"
        f"name = {_toml_quote(package_name)}\n"
        'version = "0.1.0"\n'
        f'edition = "{edition}"\n\n'
        "[workspace]\n\n"
        "[lib]\n"
        'name = "hm_rust_harness"\n'
        'path = "src/lib.rs"\n\n'
        "[[bin]]\n"
        f"name = {_toml_quote(bin_name)}\n"
        f"path = {_toml_quote(f'src/bin/{bin_name}.rs')}\n\n"
        "[dependencies]\n"
        + "\n".join(dep_lines)
        + "\n\n"
        "[profile.dev]\n"
        "debug = true\n"
        "debug-assertions = true\n"
        "overflow-checks = true\n"
        f'panic = "{panic_mode}"\n'
        f"{patch_toml}"
    )
    replace_regular_file(ws / "Cargo.toml", cargo_toml.encode("utf-8"))
    _sync_cargo_config_and_lock(config.project_dir, ws, extra_crates=injected_crates)
    return ws


def _rust_build_env(
    config: RustBuildConfig,
    *,
    force_panic_abort: bool = False,
) -> tuple[dict[str, str], list[str]]:
    env = os.environ.copy()
    if "CARGO_ENCODED_RUSTFLAGS" in env:
        raise RuntimeError(
            "CARGO_ENCODED_RUSTFLAGS overrides HarnessMinimizer's target-specific Rust instrumentation flags."
        )
    toolchain = env.get("RUSTUP_TOOLCHAIN")
    if (config.use_asan and toolchain
            and toolchain not in {"nightly", f"nightly-{config.target_triple}"}
            and shutil.which("rustup")):
        raise RuntimeError("RUSTUP_TOOLCHAIN conflicts with HarnessMinimizer's +nightly selection.")
    env["CARGO_TARGET_DIR"] = config.target_dir
    env["CARGO_BUILD_TARGET"] = config.target_triple
    env["RUST_BACKTRACE"] = "full"
    panic_mode = "abort" if (config.use_asan or force_panic_abort) else "unwind"
    rustflags: list[str] = [
        "-C", "debuginfo=2",
        "-C", "opt-level=1",
        "-C", "debug-assertions=on",
        "-C", "overflow-checks=on",
        "-C", f"panic={panic_mode}",
    ]
    if config.use_asan and config.sanitizer:
        rustflags.extend(["-Z", f"sanitizer={config.sanitizer}"])
    rustflags.extend(config.rustc_flags)
    for arg in config.linker_args:
        rustflags.extend(["-C", f"link-arg={arg}"])
    prefix = cargo_target_env_prefix(config.target_triple)
    env.pop("RUSTFLAGS", None)
    env[f"{prefix}_RUSTFLAGS"] = " ".join(rustflags)
    return env, rustflags


def _extract_direct_plan_from_cargo_json(
    stdout_text: str,
    crates: list[RustCrateInfo],
    config: RustBuildConfig,
    *,
    harness_uses_arbitrary: bool = False,
) -> dict[str, object]:
    """Capture prebuilt ``--extern`` rlibs and ``-L`` dirs for lock-free rustc."""
    externs: dict[str, str] = {}
    native_dirs: list[str] = []
    direct_lib_names = {c.lib_name for c in crates} | {"arbitrary"}
    for line in stdout_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        reason = msg.get("reason")
        if reason == "compiler-artifact":
            target = msg.get("target") or {}
            kinds = target.get("kind") or []
            if not any(k in {"lib", "rlib", "proc-macro"} for k in kinds):
                continue
            name = str(target.get("name", "")).replace("-", "_")
            if name not in direct_lib_names:
                continue
            for fname in msg.get("filenames") or []:
                if isinstance(fname, str) and (fname.endswith(".rlib") or fname.endswith(".so")):
                    if os.path.isfile(fname):
                        externs[name] = fname
                        break
        elif reason == "build-script-executed":
            for path in msg.get("linked_paths") or []:
                if isinstance(path, str) and path not in native_dirs:
                    native_dirs.append(path)

    target_deps_dir = Path(config.target_dir) / config.target_triple / "debug" / "deps"
    host_deps_dir = Path(config.target_dir) / "debug" / "deps"
    deps_dir = target_deps_dir if target_deps_dir.is_dir() else host_deps_dir
    # Fallback scan for any target/arbitrary crate rlib not emitted in JSON (already fresh).
    if deps_dir.is_dir():
        fallback_names = [crate.lib_name for crate in crates]
        if harness_uses_arbitrary and "arbitrary" not in fallback_names:
            fallback_names.append("arbitrary")
        for lib_name in fallback_names:
            if lib_name in externs:
                continue
            matches = sorted(
                deps_dir.glob(f"lib{lib_name}-*.rlib"),
                key=lambda p: p.stat().st_mtime_ns,
                reverse=True,
            )
            if matches:
                externs[lib_name] = str(matches[0])
            else:
                plain = deps_dir.parent / f"lib{lib_name}.rlib"
                if plain.is_file():
                    externs[lib_name] = str(plain)

    edition = crates[0].edition if crates else "2021"
    if edition not in {"2018", "2021", "2024"}:
        edition = "2021"
    return {
        "schema_version": 1,
        "edition": edition,
        "target_triple": config.target_triple,
        "use_asan": config.use_asan,
        "sanitizer": config.sanitizer,
        "deps_dir": str(deps_dir) if deps_dir.is_dir() else "",
        "host_deps_dir": str(host_deps_dir) if host_deps_dir.is_dir() and host_deps_dir != deps_dir else "",
        "manifest_dir": str(Path(config.project_dir).resolve()),
        "native_dirs": native_dirs,
        "externs": externs,
        "rustc_flags": list(config.rustc_flags),
        "linker_args": list(config.linker_args),
    }


def compile_rust_reference(
    harness_path: str,
    compile_flags: str | None,
    link_flags: str | None,
    output_bin: str,
    work_dir: str | Path,
    *,
    panic_exit_code: int | None = 77,
) -> Path:
    """Build target crates once via Cargo, write the binary, and save direct rustc plan."""
    work = Path(work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    config = parse_rust_minimizer_flags(compile_flags, link_flags)
    crates = discover_rust_crates(config.project_dir)
    harness_text = Path(harness_path).read_text(encoding="utf-8", errors="replace")
    harness_uses_arbitrary = bool(
        re.search(r"\b(?:use\s+arbitrary\b|arbitrary::)", _strip_rust_comments_and_strings(harness_text))
    )
    bin_name = "poc" if panic_exit_code is None else "poc_driver"
    ws = scaffold_rust_candidate_crate(
        harness_path,
        work / "rust_ref_crate",
        config,
        crates=crates,
        panic_exit_code=panic_exit_code,
        bin_name=bin_name,
    )
    env, _ = _rust_build_env(config, force_panic_abort=(panic_exit_code is None))

    base_cmd = ["cargo"]
    if config.use_asan and shutil.which("rustup"):
        base_cmd.append("+nightly")
    base_cmd.append("build")
    tail_args = [
        "--manifest-path", str(ws / "Cargo.toml"),
        "--target", config.target_triple,
        "--bin", bin_name,
        "--message-format=json-render-diagnostics",
    ]
    offline_cmd = [*base_cmd, "--offline", *tail_args]
    proc = subprocess.run(
        offline_cmd, env=env, cwd=str(ws), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
    )
    if proc.returncode != 0 and env.get("CARGO_NET_OFFLINE", "").lower() not in {"1", "true", "yes"}:
        combined = f"{proc.stderr}\n{proc.stdout}".lower()
        if any(
            hint in combined
            for hint in (
                "offline",
                "no matching package",
                "not cached",
                "failed to select a version",
                "attempting to make an http request",
                "lock file needs to be updated",
                "source replacement",
            )
        ):
            online_cmd = [*base_cmd, *tail_args]
            proc = subprocess.run(
                online_cmd, env=env, cwd=str(ws), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
            )
    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or "cargo build failed"
        raise RuntimeError(f"Failed to compile Rust harness via cargo: {err}")

    built_bin = Path(config.target_dir) / config.target_triple / "debug" / bin_name
    if not built_bin.is_file():
        raise RuntimeError(f"Expected compiled Rust driver at {built_bin}")
    Path(output_bin).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built_bin, output_bin)
    os.chmod(output_bin, 0o755)

    plan = _extract_direct_plan_from_cargo_json(
        proc.stdout, crates, config, harness_uses_arbitrary=harness_uses_arbitrary
    )
    plan_path = Path(config.plan_file) if config.plan_file else (work / RUST_DIRECT_PLAN_FILE)
    replace_regular_file(plan_path, (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return plan_path


def _find_direct_plan_path(
    config: RustBuildConfig,
    work_dir: str | Path | None,
    candidate_path: Path | None = None,
) -> Path | None:
    candidates: list[Path] = []
    if config.plan_file:
        candidates.append(Path(config.plan_file))
    if work_dir:
        candidates.append(Path(work_dir) / RUST_DIRECT_PLAN_FILE)
    if candidate_path is not None:
        candidates.append(candidate_path.parent / RUST_DIRECT_PLAN_FILE)
    if config.target_dir:
        candidates.append(Path(config.target_dir).parent / RUST_DIRECT_PLAN_FILE)
    for path in candidates:
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("deps_dir") and data.get("externs"):
                    return path
            except (OSError, ValueError):
                continue
    return None


def _load_direct_plan(
    config: RustBuildConfig,
    work_dir: str | Path | None,
    candidate_path: Path | None = None,
) -> dict | None:
    path = _find_direct_plan_path(config, work_dir, candidate_path=candidate_path)
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("deps_dir") and data.get("externs"):
            return data
    except (OSError, ValueError):
        return None
    return None


def _is_direct_rustc_limitation(error_output: str) -> bool:
    low = error_output.lower()
    if "error[e0463]" in low or "can't find crate" in low:
        return True
    if "proc-macro" in low or "proc macro" in low:
        return True
    if "environment variable" in low and "not defined at compile time" in low:
        return True
    if "multiple applicable" in low and "extern" in low:
        return True
    return False


def compile_rust_candidate(
    candidate_rs: str,
    output_bin: str,
    compile_flags: str | None,
    link_flags: str | None,
    work_dir: str | Path | None = None,
) -> tuple[int, list[str], str]:
    """Compile a candidate ``.rs`` file using lock-free direct ``rustc`` (Cargo fallback).

    Returns ``(returncode, command, error_output)``.
    """
    config = parse_rust_minimizer_flags(compile_flags, link_flags)
    candidate_path = Path(candidate_rs).resolve()
    try:
        source = candidate_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return -1, ["rustc"], str(exc)

    entry_style = detect_rust_entry_style(source)
    if entry_style == "unknown":
        return -1, ["rustc"], "Candidate is missing a supported Rust fuzz entry point."

    plan_path = _find_direct_plan_path(config, work_dir, candidate_path=candidate_path)
    plan = _load_direct_plan(config, work_dir, candidate_path=candidate_path)
    direct_fallback_triggered = False
    if plan is not None and not plan.get("direct_disabled"):
        with tempfile.TemporaryDirectory(
            prefix="hm_rustc_", dir=os.environ.get("HARNESSMINIMIZER_TMPDIR", "/tmp")
        ) as tmp_dir:
            tmp = Path(tmp_dir)
            replace_regular_file(tmp / "fdp.rs", RUST_FDP_SOURCE.encode("utf-8"))
            has_no_main = bool(re.search(r"^\s*#!\[no_main\]\s*$", source, flags=re.MULTILINE))
            if has_no_main:
                cleaned = re.sub(r"^\s*#!\[no_main\]\s*$", "", source, flags=re.MULTILINE)
                ref = tmp / candidate_path.name
                replace_regular_file(ref, cleaned.encode("utf-8"))
                include_path = str(ref)
            else:
                include_path = str(candidate_path)
            entry_rs = tmp / "main.rs"
            replace_regular_file(
                entry_rs,
                _rust_driver_main_source(entry_style, include_path=include_path).encode("utf-8"),
            )
            rustc_bin = "rustc"
            cmd: list[str] = [rustc_bin]
            if plan.get("use_asan"):
                rustup = shutil.which("rustup")
                if rustup:
                    cmd = [rustup, "run", "nightly", "rustc"]
            cmd.extend([
                "--edition", str(plan.get("edition", "2021")),
                "--crate-type", "bin",
                "--crate-name", "poc_driver",
                "--target", str(plan.get("target_triple", config.target_triple)),
                "-C", "debuginfo=2",
                "-C", "opt-level=1",
                "-C", "debug-assertions=on",
                "-C", "overflow-checks=on",
                "-C", f"panic={'abort' if plan.get('use_asan') else 'unwind'}",
                "-L", f"dependency={plan['deps_dir']}",
            ])
            # Cargo places host proc-macro .so crates (e.g. derive_arbitrary) in
            # <target_dir>/debug/deps even when --target <triple> is passed.
            host_deps = str(plan.get("host_deps_dir") or "")
            if not host_deps and config.target_dir:
                inferred_host = Path(config.target_dir) / "debug" / "deps"
                if inferred_host.is_dir():
                    host_deps = str(inferred_host)
            if host_deps and host_deps != str(plan["deps_dir"]) and os.path.isdir(host_deps):
                cmd.extend(["-L", f"dependency={host_deps}"])
            for native in plan.get("native_dirs") or []:
                cmd.extend(["-L", str(native)])
            for crate_lib, rlib_path in sorted((plan.get("externs") or {}).items()):
                cmd.extend(["--extern", f"{crate_lib}={rlib_path}"])
            if plan.get("use_asan") and plan.get("sanitizer"):
                cmd.extend(["-Z", f"sanitizer={plan['sanitizer']}"])
            cmd.extend(plan.get("rustc_flags") or [])
            for arg in plan.get("linker_args") or []:
                cmd.extend(["-C", f"link-arg={arg}"])
            cmd.extend(["-o", output_bin, str(entry_rs)])

            rustc_env = os.environ.copy()
            manifest_dir = str(plan.get("manifest_dir") or config.project_dir or "")
            if manifest_dir:
                rustc_env["CARGO_MANIFEST_DIR"] = manifest_dir
            proc = subprocess.run(
                cmd, env=rustc_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
            )
            if proc.returncode == 0 and os.path.isfile(output_bin):
                return 0, cmd, ""
            err_text = proc.stderr.strip() or proc.stdout.strip()
            if not _is_direct_rustc_limitation(err_text):
                return proc.returncode or -1, cmd, err_text
            direct_fallback_triggered = True

    # Fallback: compile with an isolated Cargo workspace and per-candidate
    # package/binary name so parallel workers reuse prebuilt target crate
    # artifacts in CARGO_TARGET_DIR without clobbering each other's outputs.
    uid = uuid.uuid4().hex[:10]
    fallback_pkg = f"hm_rust_harness_{uid}"
    fallback_bin = f"poc_driver_{uid}"
    with tempfile.TemporaryDirectory(
        prefix="hm_cargo_", dir=os.environ.get("HARNESSMINIMIZER_TMPDIR", "/tmp")
    ) as tmp_dir:
        ws = scaffold_rust_candidate_crate(
            str(candidate_path),
            Path(tmp_dir) / "crate",
            config,
            package_name=fallback_pkg,
            bin_name=fallback_bin,
        )
        env, _ = _rust_build_env(config)
        cmd = ["cargo"]
        if config.use_asan and shutil.which("rustup"):
            cmd.append("+nightly")
        cmd.extend([
            "build",
            "--offline",
            "--manifest-path", str(ws / "Cargo.toml"),
            "--target", config.target_triple,
            "--bin", fallback_bin,
        ])
        proc = subprocess.run(
            cmd, env=env, cwd=str(ws), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
        )
        if proc.returncode != 0:
            return proc.returncode or -1, cmd, proc.stderr.strip() or proc.stdout.strip()
        built = Path(config.target_dir) / config.target_triple / "debug" / fallback_bin
        if not built.is_file():
            return -1, cmd, f"Missing compiled Rust binary at {built}"
        shutil.copy2(built, output_bin)
        os.chmod(output_bin, 0o755)
        try:
            built.unlink()
        except OSError:
            pass
        if direct_fallback_triggered and plan is not None and plan_path is not None:
            try:
                updated_plan = {**plan, "direct_disabled": True}
                replace_regular_file(
                    plan_path, (json.dumps(updated_plan, indent=2, sort_keys=True) + "\n").encode("utf-8")
                )
            except OSError:
                pass
        return 0, cmd, ""


# ---------------------------------------------------------------------------
# Pure-Python Rust comment cleanup (for source_cleanup.py)
# ---------------------------------------------------------------------------

def strip_rust_comment_lines(source: bytes) -> bytes:
    """Remove standalone comment-only lines from Rust source, keeping code-touching comments intact."""
    text = source.decode("utf-8", errors="surrogateescape")
    lines = text.split("\n")
    final_newline = text.endswith("\n")
    if final_newline:
        lines.pop()
    if not lines:
        return source

    # Track character-level comment ownership and multi-line block comment spans.
    line_starts: list[int] = []
    pos = 0
    for line in lines:
        line_starts.append(pos)
        pos += len(line) + 1

    n = len(text)
    is_comment = bytearray(n)
    comment_spans: list[tuple[int, int]] = []  # (start_row, end_row)
    line_comments: list[list[int]] = [[] for _ in lines]

    def offset_to_row(offset: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo

    i = 0
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i + 2)
            stop = n if end == -1 else end
            row = offset_to_row(i)
            cid = len(comment_spans)
            comment_spans.append((row, row))
            line_comments[row].append(cid)
            is_comment[i:stop] = b"\x01" * (stop - i)
            i = stop
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                    depth += 1
                    j += 2
                elif text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            first_row = offset_to_row(i)
            last_row = offset_to_row(max(i, j - 1))
            cid = len(comment_spans)
            comment_spans.append((first_row, last_row))
            for r in range(first_row, last_row + 1):
                line_comments[r].append(cid)
            is_comment[i:j] = b"\x01" * (j - i)
            i = j
            continue
        # Skip raw strings, normal strings, and char literals so comment-like text inside them is untouched.
        if ch == "r" or (ch == "b" and i + 1 < n and text[i + 1] == "r"):
            j = i + (2 if ch == "b" else 1)
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                closing = '"' + ("#" * hashes)
                end = text.find(closing, j + 1)
                i = n if end == -1 else end + len(closing)
                continue
        if ch == '"' or (ch == "b" and i + 1 < n and text[i + 1] == '"'):
            j = i + (2 if ch == "b" else 1)
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        i += 1

    removable: list[bool] = []
    for row, line in enumerate(lines):
        start = line_starts[row]
        removable.append(
            bool(line_comments[row])
            and all(ch in " \t\r\f\v" or is_comment[start + col] for col, ch in enumerate(line))
        )

    # Keep an entire multi-line block comment if any line it touches has non-comment code.
    from collections import deque

    queue = deque(row for row, can_remove in enumerate(removable) if not can_remove)
    seen_cids: set[int] = set()
    while queue:
        for cid in line_comments[queue.popleft()]:
            if cid in seen_cids:
                continue
            seen_cids.add(cid)
            first_row, last_row = comment_spans[cid]
            for r in range(first_row, last_row + 1):
                if removable[r]:
                    removable[r] = False
                    queue.append(r)

    retained = [line for row, line in enumerate(lines) if not removable[row]]
    result = "\n".join(retained) + ("\n" if final_newline and retained else "")
    return result.encode("utf-8", errors="surrogateescape")


# ---------------------------------------------------------------------------
# Direct-input inlining for Rust harnesses (self-contained, zero .h files)
# ---------------------------------------------------------------------------

def _format_rust_byte_slice(data: bytes) -> str:
    if not data:
        return "const HM_INPUT_BYTES: &[u8] = &[];\n"
    rows = []
    for start in range(0, len(data), 16):
        chunk = data[start : start + 16]
        rows.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    return "const HM_INPUT_BYTES: &[u8] = &[\n" + "\n".join(rows) + "\n];\n"


def inline_rust_direct_input(source: str, crash_bytes: bytes) -> str:
    """Inline *crash_bytes* directly into a Rust fuzz harness without external headers."""
    cleaned = _strip_rust_comments_and_strings(source)
    const_decl = _format_rust_byte_slice(crash_bytes)

    # Style 1: pub fn fuzz_target(data: &[u8]) { ... }
    fn_match = re.search(
        r"\bpub\s+(?:unsafe\s+)?fn\s+fuzz_target\s*\(\s*(mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&(?:'[A-Za-z_][A-Za-z0-9_]*\s+)?\[u8\]\s*,?\s*\)\s*\{",
        cleaned,
    )
    if fn_match:
        mut_kw = fn_match.group(1) or ""
        param = fn_match.group(2)
        if param == "_" or param.startswith("_"):
            return source
        insert_pos = fn_match.end()
        shadow = f"\n    let {mut_kw}{param}: &[u8] = HM_INPUT_BYTES;\n"
        return const_decl + source[:insert_pos] + shadow + source[insert_pos:]

    # Style 2a: fuzz_target!(|data: &[u8]| { ... }); or fuzz_target!(|data| { ... });
    macro_match = re.search(
        r"\bfuzz_target\s*!\s*\(\s*\|\s*(mut\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s*:\s*&(?:'[A-Za-z_][A-Za-z0-9_]*\s+)?\[u8\])?\s*\|\s*\{",
        cleaned,
    )
    if macro_match:
        mut_kw = macro_match.group(1) or ""
        param = macro_match.group(2)
        if param == "_" or param.startswith("_"):
            return source
        insert_pos = macro_match.end()
        shadow = f"\n    let {mut_kw}{param}: &[u8] = HM_INPUT_BYTES;\n"
        return const_decl + source[:insert_pos] + shadow + source[insert_pos:]

    # Style 2b: fuzz_target!(|data: ArbitraryType| { ... });
    typed_macro_match = re.search(
        r"\bfuzz_target\s*!\s*\(\s*\|\s*(mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^|]+?)\s*\|\s*\{",
        cleaned,
    )
    if typed_macro_match:
        mut_kw = typed_macro_match.group(1) or ""
        param = typed_macro_match.group(2)
        ty = source[typed_macro_match.start(3) : typed_macro_match.end(3)].strip()
        if param == "_" or param.startswith("_"):
            return source
        insert_pos = typed_macro_match.end()
        shadow = (
            "\n    let mut __hm_u = arbitrary::Unstructured::new(HM_INPUT_BYTES);\n"
            f"    let Ok({mut_kw}{param}) = <{ty} as arbitrary::Arbitrary>::arbitrary(&mut __hm_u) else {{ return; }};\n"
        )
        return const_decl + source[:insert_pos] + shadow + source[insert_pos:]

    # Style 3: LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 { ... }
    llvm_match = re.search(
        r"\bfn\s+LLVMFuzzerTestOneInput\s*\(\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:[^,]+,\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:[^)]+\)\s*(?:->\s*[^{]+)?\{",
        cleaned,
    )
    if llvm_match:
        data_param, size_param = llvm_match.group(1), llvm_match.group(2)
        stmts = []
        if data_param != "_":
            stmts.append(f"    let {data_param} = HM_INPUT_BYTES.as_ptr();")
        if size_param != "_":
            stmts.append(f"    let {size_param} = HM_INPUT_BYTES.len();")
        if not stmts:
            return source
        insert_pos = llvm_match.end()
        shadow = "\n" + "\n".join(stmts) + "\n"
        return const_decl + source[:insert_pos] + shadow + source[insert_pos:]

    # Style 4: fn main() { ... } — standalone entry with no slice parameter to shadow.
    if re.search(r"\bfn\s+main\s*\(\s*\)", cleaned):
        return source

    raise ValueError("Could not safely locate a supported Rust fuzz entry parameter to inline.")


# ---------------------------------------------------------------------------
# Rust panic & Backtrace extraction (for symbolized_trace.py / reducer_runner.py)
# ---------------------------------------------------------------------------

RUST_PANIC_NEW_PATTERN = re.compile(
    r"thread '[^']*' panicked at (?P<location>[^\n:]+:\d+(?::\d+)?):\s*\n(?P<message>[^\n]+)"
)
RUST_PANIC_OLD_PATTERN = re.compile(
    r"thread '[^']*' panicked at '(?P<message>[^']+)',\s*(?P<location>[^\n:]+:\d+(?::\d+)?)"
)
RUST_BACKTRACE_FRAME_PATTERN = re.compile(
    r"^\s*(?P<num>\d+):\s+(?:(?P<addr>0x[0-9a-fA-F]+)\s+-\s+)?(?P<func>\S.*)$"
)
RUST_BACKTRACE_AT_PATTERN = re.compile(
    r"^\s+at\s+(?P<path>[^:\s]+):(?P<line>\d+)(?::(?P<col>\d+))?\s*$"
)

_RUST_RUNTIME_FRAME_PREFIXES = (
    "std::backtrace",
    "backtrace::",
    "core::panicking::",
    "std::panicking::",
    "std::sys::",
    "std::rt::",
    "rust_begin_unwind",
    "rust_panic",
    "__rust_start_panic",
    "poc_driver::main",
    "core::ops::function::FnOnce::call_once",
    "std::panic::catch_unwind",
)
_RUST_RUNTIME_EXACT_FUNCS = frozenset({
    "raise",
    "__GI_raise",
    "gsignal",
    "__GI_gsignal",
    "abort",
    "__GI_abort",
    "__libc_abort",
    "__libc_fatal",
    "pthread_kill",
    "__pthread_kill_internal",
    "__pthread_kill_implementation",
    "__assert_fail",
})
_RUST_RUNTIME_PATH_MARKERS = (
    "/rustc/",
    "/library/std/",
    "/library/core/",
    "/library/alloc/",
    "library/std/",
    "library/core/",
    "library/alloc/",
    "poc_driver.rs",
    "/rust_ref_crate/src/lib.rs",
    "libc.so",
)
_RUST_RUNTIME_PATH_BASENAMES = frozenset({
    "raise.c",
    "gsignal.c",
    "abort.c",
    "pthread_kill.c",
    "assert.c",
    "libc_fatal.c",
})
_RUST_HARNESS_STOP_FUNCS = (
    "__hm_run",
    "__hm_macro_entry",
    "__fuzzagent_run",
    "__fuzzagent_macro_entry",
    "LLVMFuzzerTestOneInput",
)


def is_rust_runtime_frame(func: str, location: str) -> bool:
    clean_func = func.strip()
    if "::harness::" in clean_func:
        return False
    if clean_func in _RUST_RUNTIME_EXACT_FUNCS:
        return True
    if any(clean_func.startswith(prefix) or f"::{prefix}" in clean_func for prefix in _RUST_RUNTIME_FRAME_PREFIXES):
        return True
    if any(marker in location for marker in _RUST_RUNTIME_PATH_MARKERS):
        return True
    loc_path = location.split(":", 1)[0].replace("\\", "/")
    if loc_path and loc_path.rsplit("/", 1)[-1] in _RUST_RUNTIME_PATH_BASENAMES:
        return True
    return False


def extract_rust_panic_location(output: str) -> str | None:
    for pattern in (RUST_PANIC_NEW_PATTERN, RUST_PANIC_OLD_PATTERN):
        match = pattern.search(output)
        if match:
            return match.group("location").strip()
    return None


def extract_rust_panic_signature(output: str) -> str | None:
    """Extract a stable regex matching a Rust panic location + message."""
    for is_new, pattern in ((True, RUST_PANIC_NEW_PATTERN), (False, RUST_PANIC_OLD_PATTERN)):
        match = pattern.search(output)
        if match:
            location = match.group("location").strip()
            message = match.group("message").strip()
            # Generalize variable numbers/addresses inside panic messages while
            # anchoring the panic location and core message wording.
            loc_re = re.escape(location)
            msg_tokens = re.sub(r"\b0x[0-9a-fA-F]+\b", "__HEX__", message)
            msg_tokens = re.sub(r"\b\d+\b", "__NUM__", msg_tokens)
            msg_re = re.escape(msg_tokens).replace("__HEX__", r"0x[0-9a-fA-F]+").replace("__NUM__", r"\d+")
            if is_new:
                return rf"panicked at {loc_re}:\s*{msg_re}"
            return rf"panicked at '{msg_re}',\s*{loc_re}"
    return None


def extract_rust_backtrace_frames(
    output: str,
    *,
    harness_path: str | None = None,
    stop_at_harness: bool = True,
) -> list[str]:
    """Parse Rust ``stack backtrace:`` into canonical ``#N 0x... in func loc`` lines."""
    lines = output.splitlines()
    start_idx = None
    for idx, line in enumerate(lines):
        if line.strip().lower() == "stack backtrace:":
            start_idx = idx + 1
            break
    if start_idx is None:
        return []

    harness_name = Path(harness_path).name if harness_path else None
    harness_resolved = str(Path(harness_path).resolve()) if harness_path else None

    frames: list[str] = []
    i = start_idx
    seen_non_runtime = False
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            if frames or seen_non_runtime:
                break
            i += 1
            continue
        match = RUST_BACKTRACE_FRAME_PATTERN.match(line)
        if not match:
            if frames or seen_non_runtime:
                break
            i += 1
            continue
        addr = match.group("addr") or "0x0"
        func = match.group("func").strip()
        loc = ""
        if i + 1 < len(lines):
            at_match = RUST_BACKTRACE_AT_PATTERN.match(lines[i + 1])
            if at_match:
                loc = f"{at_match.group('path')}:{at_match.group('line')}"
                if at_match.group("col"):
                    loc += f":{at_match.group('col')}"
                i += 1
        i += 1

        if not seen_non_runtime and is_rust_runtime_frame(func, loc):
            continue
        seen_non_runtime = True

        if stop_at_harness:
            if any(tok in func for tok in _RUST_HARNESS_STOP_FUNCS):
                break
            if harness_resolved and loc and harness_resolved in loc:
                break
            if harness_name and loc and Path(loc.split(":", 1)[0]).name == harness_name:
                break
            if is_rust_runtime_frame(func, loc):
                break

        frame_idx = len(frames)
        if loc:
            frames.append(f"    #{frame_idx} {addr} in {func} {loc}")
        else:
            frames.append(f"    #{frame_idx} {addr} in {func}")
    return frames


def _cli() -> int:
    parser = argparse.ArgumentParser(description="HarnessMinimizer Rust build helper")
    sub = parser.add_subparsers(dest="command", required=True)
    c_parser = sub.add_parser("compile", help="Compile a Rust harness binary")
    c_parser.add_argument("--source", required=True)
    c_parser.add_argument("--output", required=True)
    c_parser.add_argument("--work-dir", default=None)
    c_parser.add_argument("--compile-flags", default="")
    c_parser.add_argument("--link-flags", default="")
    c_parser.add_argument("--reference", action="store_true")
    args = parser.parse_args()

    if args.reference:
        compile_rust_reference(
            args.source, args.compile_flags, args.link_flags, args.output, args.work_dir or Path(args.output).parent
        )
        return 0
    rc, _cmd, err = compile_rust_candidate(
        args.source, args.output, args.compile_flags, args.link_flags, args.work_dir
    )
    if rc != 0:
        print(err, file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(_cli())

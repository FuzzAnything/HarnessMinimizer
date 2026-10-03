"""Durable artifacts and collection transactions for the two evaluation runners."""
from __future__ import annotations

from contextlib import contextmanager
import csv
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile

EXPERIMENT_FORMAT = "harnessreducer-experiments-v1"
DATASETS = (("harness-bug", "harness_bug_cases.tsv"),
            ("library-bug", "library_bug_cases.tsv"))


def case_key(dataset: str, case: str) -> str:
    if dataset not in dict(DATASETS) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", case):
        raise ValueError(f"Invalid dataset/case: {dataset}/{case}")
    return f"{dataset}/{case}"


def select_case_keys(available, requested):
    available = set(available)
    selected = set()
    for value in requested:
        matches = {key for key in available if key == value or ("/" not in value and key.rsplit("/", 1)[-1] == value)}
        if len(matches) != 1:
            reason = "Ambiguous" if matches else "Unknown"
            raise ValueError(f"{reason} case: {value}. Use a dataset/case name.")
        selected.update(matches)
    return selected


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".publish-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path: Path, value) -> None:
    atomic_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_json(path: Path, default=None):
    if not path.exists():
        return default
    return json.loads(path.read_text())


def write_csv(path: Path, rows: list[dict], fields=None) -> None:
    fields = fields or list(dict.fromkeys(key for row in rows for key in row))
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    atomic_text(path, stream.getvalue())


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


@contextmanager
def collection_lock(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".collection.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def append_jsonl(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.write(json.dumps(value, sort_keys=True) + "\n")
        handle.flush()


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text().splitlines(keepends=True)
    # A killed writer may leave an unfinished final record.
    return [json.loads(line) for line in lines if line.endswith("\n")]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path, root: Path) -> str:
    return os.path.relpath(path, root)


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() != destination.resolve():
        shutil.copy2(source, destination)


def snapshot_dependencies(source: Path, destination: Path, compile_flags: str = "") -> list[dict]:
    """Keep recursively included local files without copying target SDKs."""
    records = []
    response_seen = set()
    def expand(tokens):
        expanded = []
        for token in tokens:
            response = Path(token[1:]).resolve() if token.startswith("@") else None
            if response and response.is_file() and response not in response_seen:
                response_seen.add(response)
                saved = destination / "files" / str(response).lstrip("/")
                copy_file(response, saved)
                records.append({"original": str(response), "saved": relative(saved, destination), "sha256": sha256(response), "kind": "response_file"})
                expanded.extend(expand(shlex.split(response.read_text())))
            else:
                expanded.append(token)
        return expanded
    tokens = expand(shlex.split(compile_flags or ""))
    include_dirs = [Path.cwd()]
    for index, token in enumerate(tokens):
        if token in ("-I", "-iquote") and index + 1 < len(tokens):
            include_dirs.append(Path(tokens[index + 1]))
        elif token.startswith("-I") and len(token) > 2:
            include_dirs.append(Path(token[2:]))
    pending = [source.resolve()]
    seen = {source.resolve()}
    for index, token in enumerate(tokens[:-1]):
        if token == "-include":
            path = Path(tokens[index + 1]).resolve()
            if path.is_file():
                saved = destination / "files" / str(path).lstrip("/")
                copy_file(path, saved)
                records.append({"original": str(path), "saved": relative(saved, destination), "sha256": sha256(path), "kind": "forced_include"})
                seen.add(path)
                pending.append(path)
    while pending:
        parent = pending.pop()
        for name in re.findall(r'^\s*#\s*include\s*"([^"\n]+)"', parent.read_text(errors="replace"), re.M):
            matches = [parent.parent / name, *(p / name for p in include_dirs)]
            found = next((p.resolve() for p in matches if p.is_file()), None)
            if found is None:
                records.append({"include": name, "from": str(parent), "status": "unresolved"})
            elif found not in seen:
                seen.add(found)
                saved = destination / "files" / str(found).lstrip("/")
                copy_file(found, saved)
                records.append({"include": name, "original": str(found), "saved": relative(saved, destination), "sha256": sha256(found)})
                pending.append(found)
    write_json(destination / "manifest.json", records)
    return records


def library_identities(link_flags: str) -> list[dict]:
    from harnessreducer.reducer_runner import resolve_amortized_link_inputs
    # The normal resolver is authoritative for -L/-l and archive selection.
    resolved = resolve_amortized_link_inputs(link_flags)
    paths = set()
    def visit(value):
        if isinstance(value, (tuple, list)):
            for entry in value:
                visit(entry)
        elif hasattr(value, "__dict__"):
            visit(list(vars(value).values()))
        elif isinstance(value, (str, Path)) and Path(value).is_file():
            paths.add(Path(value).resolve())
    visit(resolved)
    return [{"path": str(p), "size": p.stat().st_size, "sha256": sha256(p)} for p in sorted(paths)]


def percent(numerator: int, denominator: int):
    return 100.0 * numerator / denominator if denominator else None


def mean(values):
    values = [v for v in values if v is not None and v != ""]
    return sum(map(float, values)) / len(values) if values else None


def selected_runs(root: Path, case: str | None = None):
    selections = sorted((root / "cases").glob("*/*/selected_run.json"))
    keys = {case_key(p.parent.parent.name, p.parent.name) for p in selections}
    requested = select_case_keys(keys, [case]) if case is not None else keys
    for selection in selections:
        key = case_key(selection.parent.parent.name, selection.parent.name)
        if key not in requested:
            continue
        selected = read_json(selection)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", selected["run_id"]):
            raise ValueError(f"Invalid run ID in {selection}")
        run = selection.parent / "runs" / selected["run_id"]
        manifest = read_json(run / "run_manifest.json")
        if not manifest or manifest.get("format") != EXPERIMENT_FORMAT:
            raise ValueError(f"Missing or unsupported experiment manifest: {run}")
        if case_key(manifest["dataset"], manifest["case"]) != key or manifest["run_id"] != selected["run_id"]:
            raise ValueError(f"Selection and manifest disagree: {run}")
        yield run, manifest


def publish_selection(root: Path, case: str, run_id: str) -> None:
    # Select at START, so a failed new run cannot be hidden by an older success.
    with collection_lock(root):
        path = root / "cases" / case / "selected_run.json"
        previous = read_json(path, {})
        if previous.get("run_id", "") < run_id:
            write_json(path, {"case": case, "run_id": run_id})

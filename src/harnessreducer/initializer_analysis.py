"""Bounded, post-failure diagnosis only. Not part of the candidate checker."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import plistlib
import re
import subprocess
import time

from harnessreducer.initializer_protection import phase_flags
from harnessreducer.process_supervisor import run_supervised


@dataclass(frozen=True)
class InitializationDiagnosis:
    status: str
    relevant: tuple[dict, ...]
    wall_ns: int
    log: str


def analyze_uninitialized(
    source: str, directory: Path, compile_flags: str | None, *, replay: bool = False,
) -> InitializationDiagnosis:
    directory.mkdir(parents=True, exist_ok=True)
    source_path = Path(source).resolve()
    report = directory / "diagnostics.plist"
    log = directory / "analyzer.log"
    # New diagnosis directories are used in production; do not consume a stale
    # report if this helper is explicitly called twice on the same directory.
    if report.exists():
        raise ValueError(f"Analyzer report already exists: {report}")
    command = [
        "clang++", *phase_flags(compile_flags, replay=replay), "--analyze",
        "-Xclang", "-analyzer-output=plist", "-x", "c++", str(source_path),
        "-o", str(report),
    ]
    started = time.perf_counter_ns()
    relevant = []
    status = "analysis-failed"
    try:
        proc = run_supervised(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=60, check=False,
        )
        log.write_text(proc.stdout + "\n" + proc.stderr, encoding="utf-8")
        if proc.returncode == 0 and report.is_file():
            with report.open("rb") as stream:
                document = plistlib.load(stream)
            files = document.get("files", [])
            for diagnostic in document.get("diagnostics", []):
                checker = diagnostic.get("check_name", "")
                description = diagnostic.get("description", "")
                location = diagnostic.get("location", {})
                file_index = location.get("file", -1)
                if not isinstance(file_index, int) or not 0 <= file_index < len(files):
                    continue
                if Path(files[file_index]).resolve() != source_path:
                    continue
                if not (
                    checker.startswith("core.uninitialized.")
                    or (checker == "core.CallAndMessage"
                        and re.search(r"uninitiali[sz]ed|uninitiali[sz]ation", description, re.I))
                ):
                    continue
                relevant.append({"checker": checker, "description": description, "location": location})
            status = "uninitialized-use" if relevant else "no-relevant-diagnostic"
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException, subprocess.SubprocessError) as exc:
        log.write_text(f"Analyzer could not complete: {exc}\n", encoding="utf-8")
    result = InitializationDiagnosis(status, tuple(relevant), time.perf_counter_ns() - started, str(log))
    (directory / "analysis.json").write_text(
        json.dumps({**asdict(result), "command": command, "source": str(source_path)}, indent=2) + "\n",
        encoding="utf-8",
    )
    return result

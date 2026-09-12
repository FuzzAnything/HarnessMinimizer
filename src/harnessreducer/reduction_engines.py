"""Reducer commands and the Perses test-script protocol.

The candidate checker keeps its existing 77/1/-1 contract. Only the generated
Perses script translates the result to the zero/nonzero contract of Perses.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from harnessreducer.process_supervisor import run_supervised, treereduce_binary


TOOL_CHOICES = ("treereduce", "wdd", "cdd", "sfc", "vulcan")
PERSES_COMMIT = "6c6ae0db20fa83b0f85a71ca447f0c4d5e056bd2"
CANDIDATE_PLACEHOLDER = "@@.cpp"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
LIST_MINIMIZERS = {"wdd": "WDD", "cdd": "CDD", "sfc": "DFS", "vulcan": "DFS"}


def validate_tool(tool: str) -> None:
    if tool not in TOOL_CHOICES:
        raise ValueError(f"Unknown reduction tool {tool!r}; choose from {', '.join(TOOL_CHOICES)}")


def perses_flags(tool: str, *, stable: bool, jobs: int) -> list[str]:
    validate_tool(tool)
    if tool == "treereduce":
        raise ValueError("treereduce does not use Perses settings")
    flag_values = {
        "--alg": "node_priority",
        "--cleanup-alg": "node_priority",
        "--default-list-minimizer-for-kleene": LIST_MINIMIZERS[tool],
        "--lang": "cpp",
        "--code-format": "ORIG_FORMAT",
        "--threads": str(jobs),
        "--fixpoint": str(stable).lower(),
        "--global-fixpoint": str(stable).lower(),
        "--sfc-fixpoint": str(stable and tool == "sfc").lower(),
        "--vulcan-fixpoint": str(stable and tool == "vulcan").lower(),
        "--enable-sfc": str(tool == "sfc").lower(),
        "--enable-vulcan": str(tool == "vulcan").lower(),
        "--enable-latra": "false",
        "--enable-trec": "false",
        "--enable-lpr": "false",
        "--enable-token-slicer": "false",
        "--enable-tree-slicer": "false",
        "--line-slicer": "OFF",
        "--dyck-node-reducer": "OFF",
        "--call-creduce": "false",
        "--call-formatter": "false",
        "--query-caching": "true",
        "--edit-caching": "true",
        "--pass-level-caching": "true",
        "--global-caching": "false",
        "--reparse-each-iteration": "true",
        "--sfc-subtree-token-count-limit": "64",
        "--sfc-candidate-limit": "64",
        "--window-size": "4",
        "--non-deletion-iteration-limit": "10",
        # Perses's timeout controls waiting on a future, not a process deadline.
        # The shell adapter enforces the actual 300-second candidate deadline.
        "--script-execution-timeout-in-seconds": "300",
        "--script-execution-keep-waiting-after-timeout": "true",
    }
    return [part for pair in flag_values.items() for part in pair]


@dataclass(frozen=True)
class PersesRuntime:
    command: tuple[str, ...]
    jar_sha256: str
    version: str
    java_version: str
    source_commit: str | None

    def metadata(self) -> dict[str, object]:
        return {
            "launch_command": list(self.command),
            "jar_sha256": self.jar_sha256,
            "version": self.version,
            "java_version": self.java_version,
            "source_commit": self.source_commit,
            "expected_source_commit": PERSES_COMMIT,
            "java_environment": {
                key: os.environ[key]
                for key in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS")
                if key in os.environ
            },
        }


def _probe(command: list[str]) -> str:
    try:
        result = run_supervised(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Cannot run Perses dependency: {shlex.join(command)}\n{exc}") from exc
    if result.returncode != 0:
        raise RuntimeError(f"Perses dependency check failed: {shlex.join(command)}\n{result.stdout}")
    return result.stdout.strip()


@lru_cache(maxsize=4)
def _inspect_perses(
    jar_name: str, jar_mtime_ns: int, jar_size: int, java: str, heap: str,
    java_environment: tuple[tuple[str, str], ...],
) -> PersesRuntime:
    # mtime/size/environment are cache keys: a new installation is checked again.
    jar = Path(jar_name)
    command = (java, f"-Xmx{heap}", "-jar", str(jar))
    help_text = _probe([*command, "--help"])
    required = set(perses_flags("wdd", stable=False, jobs=1)[::2]) | {
        "--input-file", "--test-script", "--output-dir", "--verbosity",
    }
    missing = sorted(flag for flag in required if flag not in help_text)
    missing.extend(value for value in ("WDD", "CDD", "DFS", "ORIG_FORMAT") if value not in help_text)
    algorithms = _probe([*command, "--list-algs"])
    if "node_priority" not in algorithms:
        missing.append("node_priority algorithm")
    if missing:
        raise RuntimeError(
            "This Perses JAR does not support the evaluation configurations. Missing: "
            + ", ".join(missing) + ". Build the pinned checkout with tools/perses/install.py."
        )
    with jar.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    source_commit = None
    try:
        build_info = json.loads((jar.parent / "build_info.json").read_text(encoding="utf-8"))
        if build_info.get("jar_sha256") == digest:
            source_commit = build_info.get("source_commit")
    except (OSError, ValueError, AttributeError):
        pass
    return PersesRuntime(
        command=command, jar_sha256=digest,
        version=_probe([*command, "--verbosity", "SEVERE", "--version"]),
        java_version=_probe([java, "-version"]), source_commit=source_commit,
    )


def check_perses() -> PersesRuntime:
    jar = Path(os.environ.get(
        "HARNESSREDUCER_PERSES_JAR",
        str(PROJECT_ROOT / ".tools/perses/perses_deploy.jar"),
    )).expanduser().resolve()
    if not jar.is_file():
        raise RuntimeError(
            f"Perses JAR not found: {jar}\n"
            "Run python tools/perses/install.py --source ../perses, or set "
            "HARNESSREDUCER_PERSES_JAR to a compatible JAR."
        )
    java = shutil.which("java")
    if not java:
        raise RuntimeError("Perses needs Java 17 or newer; java was not found on PATH")
    if not shutil.which("timeout"):
        raise RuntimeError("The Perses checker adapter needs GNU coreutils 'timeout' on PATH")
    heap = os.environ.get("HARNESSREDUCER_PERSES_HEAP", "4g")
    if re.fullmatch(r"[1-9][0-9]*[kKmMgG]", heap) is None:
        raise ValueError("HARNESSREDUCER_PERSES_HEAP must be a positive size such as 4g or 2048m")
    stat = jar.stat()
    environment = tuple(
        (key, os.environ.get(key, ""))
        for key in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS")
    )
    return _inspect_perses(str(jar), stat.st_mtime_ns, stat.st_size, java, heap, environment)


def write_perses_test_script(
    path: Path, checker_command: list[str], *, timeout_seconds: float = 300,
) -> None:
    if checker_command.count(CANDIDATE_PLACEHOLDER) != 1:
        raise ValueError("The checker command must contain exactly one candidate placeholder")
    if timeout_seconds <= 0:
        raise ValueError("The candidate timeout must be positive")
    timeout = shutil.which("timeout")
    if not timeout:
        raise RuntimeError("GNU coreutils 'timeout' is required for the Perses adapter")
    candidate_command = [
        "./candidate.cpp" if part == CANDIDATE_PLACEHOLDER else part
        for part in checker_command
    ]
    # Use this process's Python interpreter for the Python tester, including when
    # the caller imported the API without activating its virtual environment.
    if Path(candidate_command[0]).suffix == ".py":
        candidate_command.insert(0, sys.executable)
    command = [
        timeout, "--signal=TERM", "--kill-after=1s", f"{timeout_seconds:g}s",
        *candidate_command,
    ]
    path.write_text(
        "#!/bin/sh\n"
        "# Perses copies this script beside each candidate; never test the original file.\n"
        "test -f ./candidate.cpp || exit 1\n"
        # No set -e: 77 is deliberately a successful interestingness verdict.
        + shlex.join(command) + "\n"
        "checker_status=$?\n"
        "if [ \"$checker_status\" -eq 77 ]; then exit 0; fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    path.chmod(0o700)


def absolute_checker_paths(command: list[str]) -> list[str]:
    """Freeze setup paths before Perses changes the checker's working directory."""
    path_options = {
        "--crash-input", "--fdp-trace", "--pch-path", "--last-interesting-file",
        "--statistics-file", "--profile-file", "--stack-trace-file", "--debug-log",
        "--amortized-runner-socket", "--amortized-runner-socket-symbolize-0",
        "--dynamic-crash-site-library", "--crash-location-file",
        "--check-reference-file", "--check-statistics-file", "--check-stack-log-file",
    }
    result = list(command)
    candidate_index = result.index(CANDIDATE_PLACEHOLDER)
    for i in range(candidate_index):
        if result[i].endswith(".py") or (i == 0 and "/" in result[i]):
            result[i] = str(Path(result[i]).resolve())
    for i, argument in enumerate(result):
        if i > 0 and result[i - 1] in path_options and argument:
            result[i] = str(Path(argument).resolve())
        elif "=" in argument:
            option, value = argument.split("=", 1)
            if option in path_options and value:
                result[i] = f"{option}={Path(value).resolve()}"
    return result


@dataclass
class ReducerInvocation:
    command: list[str]
    result: Path
    destination: Path
    metadata: dict[str, object]
    cwd: Path | None = None
    log_path: Path | None = None

    def run(self, supervisor=run_supervised) -> subprocess.CompletedProcess:
        kwargs = dict(stderr=subprocess.STDOUT, text=True, check=False, timeout=None, private_tmpdir=True)
        if self.log_path is None:
            return supervisor(self.command, **kwargs)
        with self.log_path.open("w", encoding="utf-8") as log:
            result = supervisor(self.command, stdout=log, cwd=self.cwd, **kwargs)
        if result.returncode:
            # Preserve useful failure evidence without loading a potentially large log.
            with self.log_path.open("rb") as log:
                log.seek(max(0, self.log_path.stat().st_size - 16384))
                tail = log.read().decode("utf-8", errors="replace")
            hint = ""
            if (
                self.metadata.get("tool") == "vulcan"
                and "kotlin.NotImplementedError" in tail
                and "MinimalSparTreeGenerator.preBuildSparTreeNodeRec" in tail
            ):
                hint = (
                    "Vulcan encountered an unsupported grammar operation in Perses. "
                    "The pinned checkout does not implement C++ grammar-label handling "
                    "in MinimalSparTreeGenerator. No successful result will be published; "
                    "no other reducer has been substituted.\n"
                )
            result = subprocess.CompletedProcess(
                result.args, result.returncode, f"{hint}Perses log: {self.log_path}\n{tail}", "",
            )
        return result

    def publish_result(self) -> None:
        if not self.result.is_file():
            raise RuntimeError(f"Reducer did not produce its expected result: {self.result}")
        if self.result.resolve() != self.destination.resolve():
            shutil.copy2(self.result, self.destination)


def prepare_reducer_invocation(
    *, tool: str, source: str, output: str, checker_command: list[str],
    stable: bool, jobs: int,
) -> ReducerInvocation:
    validate_tool(tool)
    if not 1 <= jobs <= 63:
        raise ValueError("Reducer jobs must be between 1 and 63")
    destination = Path(output)
    if tool == "treereduce":
        command = [treereduce_binary(), "-j", str(jobs), "-s", source, "-o", output]
        command.extend(["--stable", "--min-reduction", "1"] if stable else ["--fast"])
        command.extend(["--timeout", "300", "--interesting-exit-code", "77", "--", *checker_command])
        return ReducerInvocation(
            command=command, result=destination, destination=destination,
            metadata={"tool": tool, "command": command},
        )
    runtime = check_perses()
    checker_command = absolute_checker_paths(checker_command)
    # A fresh subdirectory prevents a stale result being published after a failed
    # run, and allows reusing a user-supplied --work-dir without deleting artifacts.
    root = Path(tempfile.mkdtemp(prefix=f"perses-{tool}-", dir=destination.resolve().parent))
    inputs = root / "input"
    inputs.mkdir()
    candidate = inputs / "candidate.cpp"
    shutil.copy2(source, candidate)
    script = inputs / "interesting.sh"
    write_perses_test_script(script, checker_command)
    output_dir = root / "output"
    flags = perses_flags(tool, stable=stable, jobs=jobs)
    command = [
        *runtime.command, *flags,
        "--input-file", str(candidate), "--test-script", str(script),
        "--output-dir", str(output_dir),
    ]
    metadata = {
        "tool": tool, "command": command, "perses": runtime.metadata(),
        "checker_command": checker_command, "candidate_timeout_seconds": 300,
        "input_source": str(Path(source).resolve()), "engine_directory": str(root),
        "log": str(root / "reducer.log"),
        "check_count_definition": "completed checker profile records; excludes unexecuted cached candidates",
    }
    (destination.resolve().parent / "reduction_engine.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8",
    )
    return ReducerInvocation(
        command=command, result=output_dir / candidate.name,
        destination=destination, metadata=metadata, cwd=inputs, log_path=root / "reducer.log",
    )

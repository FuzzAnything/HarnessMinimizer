"""Treereduce invocation and temporary macro-header restoration."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess

from harnessminimizer.process_supervisor import run_supervised, treereduce_binary
from harnessminimizer.macro_headers import MacroPreparation, prepare_macro_headers


@dataclass
class ReducerInvocation:
    command: list[str]
    result: Path
    destination: Path
    metadata: dict[str, object]
    macros: MacroPreparation | None = None
    snapshot_paths: tuple[Path, ...] = ()

    def run(self, supervisor=run_supervised) -> subprocess.CompletedProcess:
        return supervisor(
            self.command, stderr=subprocess.STDOUT, text=True,
            check=False, timeout=None, private_tmpdir=True,
        )

    def publish_result(self) -> None:
        if not self.result.is_file():
            raise RuntimeError(f"Reducer did not produce its expected result: {self.result}")
        if self.result.resolve() != self.destination.resolve():
            shutil.copy2(self.result, self.destination)
        if self.macros is not None:
            self.macros.restore_file(self.destination)
            for path in self.snapshot_paths:
                self.macros.restore_file(path)


def prepare_reducer_invocation(
    *, source: str, output: str, checker_command: list[str],
    stable: bool, jobs: int, candidate_timeout_seconds: int = 300,
) -> ReducerInvocation:
    if not 1 <= jobs <= 63:
        raise ValueError("Reducer jobs must be between 1 and 63")
    if candidate_timeout_seconds <= 0:
        raise ValueError("The candidate timeout must be positive")
    destination = Path(output)
    # Prepare macros after any PCH split; the checker compiles the ordinary headers.
    macros = prepare_macro_headers(Path(source), destination.resolve().parent)
    if macros.headers:
        print(f"[+] Prepared {len(macros.headers)} macro definitions as temporary headers for reduction.")
    snapshot_paths = tuple(
        Path(argument.split("=", 1)[1]).resolve()
        if argument.startswith("--last-interesting-file=")
        else Path(checker_command[index + 1]).resolve()
        for index, argument in enumerate(checker_command)
        if argument.startswith("--last-interesting-file=")
        or (argument == "--last-interesting-file" and index + 1 < len(checker_command))
    )
    command = [treereduce_binary(), "-j", str(jobs), "-s", str(macros.source), "-o", output]
    command.extend(["--stable", "--min-reduction", "1"] if stable else ["--fast"])
    command.extend([
        "--timeout", str(candidate_timeout_seconds), "--interesting-exit-code", "77",
        "--", *checker_command,
    ])
    return ReducerInvocation(
        command=command, result=destination, destination=destination,
        metadata={"tool": "treereduce", "command": command, "macro_preparation": macros.metadata()},
        macros=macros, snapshot_paths=snapshot_paths,
    )

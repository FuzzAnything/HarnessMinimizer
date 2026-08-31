#!/usr/bin/env python3
"""Measure treereduce-c interestingness-check throughput on a C++ baseline."""

from __future__ import annotations

import argparse
from collections import Counter, deque
from datetime import datetime
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Sequence


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_SOURCE = (
    PROJECT_ROOT / "benchmark" / "treereduce-throughput" / "compile_success.cpp"
)
MAX_JOBS = 63
DURATION_PATTERN = re.compile(
    r"^\s*(?P<value>[0-9]+(?:\.[0-9]+)?)\s*(?P<unit>ns|µs|us|ms|s)\s*$"
)
DURATION_MULTIPLIERS = {
    "ns": 1,
    "µs": 1_000,
    "us": 1_000,
    "ms": 1_000_000,
    "s": 1_000_000_000,
}


@dataclass(frozen=True)
class CheckerSpec:
    name: str
    command: list[str]
    interesting_exit_code: int = 0
    interesting_stderr: str | None = None
    source_must_compile: bool = False
    source_must_crash: bool = False


def parse_jobs(value: str) -> list[int]:
    jobs: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            count = int(item)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid job count: {item!r}") from exc
        if not 1 <= count <= MAX_JOBS:
            raise argparse.ArgumentTypeError(
                f"job counts must be between 1 and {MAX_JOBS}"
            )
        if count not in jobs:
            jobs.append(count)
    if not jobs:
        raise argparse.ArgumentTypeError("at least one job count is required")
    return jobs


def duration_ns(value: str) -> int:
    match = DURATION_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError(f"unrecognized duration: {value!r}")
    return int(
        float(match.group("value")) * DURATION_MULTIPLIERS[match.group("unit")]
    )


def percentile(values: Sequence[int], fraction: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def sample_stats(values: Sequence[int]) -> dict[str, int | float]:
    if not values:
        return {
            "count": 0,
            "mean_ns": 0.0,
            "median_ns": 0.0,
            "p95_ns": 0,
            "min_ns": 0,
            "max_ns": 0,
        }
    return {
        "count": len(values),
        "mean_ns": statistics.fmean(values),
        "median_ns": statistics.median(values),
        "p95_ns": percentile(values, 0.95),
        "min_ns": min(values),
        "max_ns": max(values),
    }


class TreereduceLogAccumulator:
    def __init__(self) -> None:
        self.check_durations: list[int] = []
        self.outcomes: Counter[str] = Counter()
        self.json_lines = 0
        self.malformed_lines = 0

    def consume(self, line: str) -> None:
        if not line.startswith("{"):
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            self.malformed_lines += 1
            return
        self.json_lines += 1
        fields = event.get("fields", {})
        if not isinstance(fields, dict):
            return
        message = fields.get("message")
        if isinstance(message, str) and message.startswith("Interesting? "):
            is_interesting = fields.get("is_interesting")
            self.outcomes[
                "interesting" if is_interesting else "uninteresting"
            ] += 1

        span = event.get("span", {})
        if not isinstance(span, dict) or span.get("name") != "Waiting for command":
            return
        if message != "close":
            return
        try:
            busy_ns = duration_ns(str(fields.get("time.busy", "0ns")))
            idle_ns = duration_ns(str(fields.get("time.idle", "0ns")))
        except ValueError:
            self.malformed_lines += 1
            return
        self.check_durations.append(busy_ns + idle_ns)

    def result(self) -> dict[str, object]:
        return {
            "total_checks": sum(self.outcomes.values()),
            "candidate_checks": len(self.check_durations),
            "outcomes": dict(self.outcomes),
            "candidate_check_timing": sample_stats(self.check_durations),
            "json_lines": self.json_lines,
            "malformed_lines": self.malformed_lines,
        }


def parse_treereduce_log(text: str) -> dict[str, object]:
    accumulator = TreereduceLogAccumulator()
    for line in text.splitlines():
        accumulator.consume(line)
    return accumulator.result()


def command_version(command: str) -> str:
    proc = subprocess.run(
        [command, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return proc.stdout.splitlines()[0] if proc.stdout else "unknown"


def terminate_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def run_command_with_timeout(
    command: Sequence[str],
    *,
    timeout_seconds: int,
    env: dict[str, str],
    compressed_log_path: Path | None = None,
) -> tuple[int, dict[str, object], str, int, bool]:
    started_ns = time.perf_counter_ns()
    process = subprocess.Popen(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        start_new_session=True,
    )
    if process.stdout is None:
        raise RuntimeError("failed to capture treereduce output")

    accumulator = TreereduceLogAccumulator()
    tail: deque[str] = deque(maxlen=100)

    def drain_output() -> None:
        log_handle = (
            gzip.open(compressed_log_path, "wt", encoding="utf-8")
            if compressed_log_path is not None
            else None
        )
        try:
            for line in process.stdout:
                tail.append(line)
                accumulator.consume(line)
                if log_handle is not None:
                    log_handle.write(line)
        finally:
            if log_handle is not None:
                log_handle.close()

    reader = threading.Thread(target=drain_output, name="treereduce-log-reader")
    reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_process_group(process)
    wall_ns = time.perf_counter_ns() - started_ns
    reader.join(timeout=30)
    if reader.is_alive():
        raise RuntimeError("timed out while draining treereduce diagnostic output")
    return (
        process.returncode,
        accumulator.result(),
        "".join(tail),
        wall_ns,
        timed_out,
    )


def checker_spec(kind: str, compiler: str) -> CheckerSpec:
    if kind == "compile":
        return CheckerSpec(
            name=kind,
            command=[
                compiler,
                "-O0",
                "-fno-color-diagnostics",
                "@@.cpp",
                "-o",
                "/dev/null",
            ],
            source_must_compile=True,
        )
    if kind == "grep":
        grep = shutil.which("grep")
        if grep is None:
            raise RuntimeError("grep is required for the cheap-check baseline")
        # No @@ marker: treereduce sends each candidate on stdin. This is the
        # low-overhead path recommended by the upstream usage guide.
        return CheckerSpec(name=kind, command=[grep, "-Fq", "int main"])
    if kind == "clang-crash":
        return CheckerSpec(
            name=kind,
            command=[
                compiler,
                "-O0",
                "-fno-color-diagnostics",
                "-fno-crash-diagnostics",
                "-c",
                "@@.cpp",
                "-o",
                "/dev/null",
            ],
            interesting_exit_code=132,
            interesting_stderr="PLEASE submit a bug report",
            source_must_crash=True,
        )
    raise ValueError(f"unknown checker: {kind}")


def build_treereduce_command(
    *,
    treereduce: str,
    source: Path,
    output: Path,
    temp_dir: Path,
    jobs: int,
    stable: bool,
    check_timeout: int,
    check: CheckerSpec,
) -> list[str]:
    command = [
        treereduce,
        "--json",
        "-v",
        "-j",
        str(jobs),
        "-s",
        str(source),
        "-o",
        str(output),
        "--temp-dir",
        str(temp_dir),
        "--timeout",
        str(check_timeout),
        "--interesting-exit-code",
        str(check.interesting_exit_code),
    ]
    if check.interesting_stderr is not None:
        command.extend(["--interesting-stderr", check.interesting_stderr])
    if stable:
        command.extend(["--stable", "--min-reduction", "1"])
    else:
        command.append("--fast")
    command.extend(["--", *check.command])
    return command


def validate_source_for_checker(source: Path, spec: CheckerSpec, compiler: str) -> None:
    if spec.source_must_compile:
        smoke = subprocess.run(
            [
                compiler,
                "-O0",
                "-fno-color-diagnostics",
                str(source),
                "-o",
                "/dev/null",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if smoke.returncode != 0:
            raise SystemExit(f"baseline source does not compile:\n{smoke.stderr}")
    if spec.source_must_crash:
        smoke = subprocess.run(
            [
                compiler,
                "-O0",
                "-fno-color-diagnostics",
                "-fno-crash-diagnostics",
                "-c",
                str(source),
                "-o",
                "/dev/null",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if smoke.returncode != spec.interesting_exit_code:
            raise SystemExit(
                "baseline source did not trigger the expected compiler crash:\n"
                f"returncode={smoke.returncode}\n{smoke.stderr}"
            )
        if spec.interesting_stderr and spec.interesting_stderr not in smoke.stderr:
            raise SystemExit(
                "baseline source crashed, but not with the expected stderr pattern:\n"
                f"{smoke.stderr}"
            )


def render_report(summary: dict[str, object]) -> str:
    rows = summary["aggregate"]
    assert isinstance(rows, list)
    lines = [
        "TREEREDUCE-C THROUGHPUT BASELINE",
        "================================",
        "",
        f"source: {summary['source']}",
        f"source_bytes: {summary['source_bytes']}",
        f"mode: {summary['reduction_mode']}",
        f"treereduce: {summary['treereduce_version']}",
        f"compiler: {summary['compiler_version']}",
        "",
        "Checker  Jobs  Runs  Checks/run  Wall/run s  Checks/s  Mean check ms  Run P95 ms  Interesting",
        "-------  ----  ----  ----------  ----------  --------  -------------  ----------  -----------",
    ]
    for row in rows:
        assert isinstance(row, dict)
        lines.append(
            f"{str(row['checker']):7}  "
            f"{int(row['jobs']):4d}  "
            f"{int(row['runs']):4d}  "
            f"{float(row['mean_checks_per_run']):10.1f}  "
            f"{float(row['mean_wall_seconds']):10.3f}  "
            f"{float(row['checks_per_second']):8.2f}  "
            f"{float(row['mean_check_ms']):13.3f}  "
            f"{float(row['mean_run_p95_check_ms']):10.3f}  "
            f"{float(row['interesting_fraction']):11.3f}"
        )
    lines.extend(
        [
            "",
            "Notes",
            "-----",
            "- compile directly invokes clang++ and requires successful linking.",
            "- clang-crash invokes clang++ with -fno-crash-diagnostics and treats",
            "  Clang's crash banner as the interesting result.",
            "- grep is a cheap stdin-based oracle that approximates reducer/process overhead.",
            "- Debug JSON is enabled so real checks can be counted and timed; it adds overhead,",
            "  especially to the cheap grep case, so that row is a conservative upper-bound probe.",
            "- Checks includes treereduce's initial verification; per-check latency excludes it.",
            "- Raw JSON logs are discarded unless --keep-logs is supplied; retained logs are gzip-compressed.",
        ]
    )
    return "\n".join(lines) + "\n"


def aggregate_runs(runs: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple[str, int], list[dict[str, object]]] = {}
    for run in runs:
        key = (str(run["checker"]), int(run["jobs"]))
        groups.setdefault(key, []).append(run)

    rows: list[dict[str, object]] = []
    for (checker, jobs), current in sorted(groups.items()):
        wall_ns = sum(int(run["wall_ns"]) for run in current)
        checks = sum(int(run["total_checks"]) for run in current)
        interesting = sum(
            int(run.get("outcomes", {}).get("interesting", 0))  # type: ignore[union-attr]
            for run in current
        )
        candidate_checks = sum(int(run["candidate_checks"]) for run in current)
        weighted_mean_numerator = sum(
            float(run["candidate_check_timing"]["mean_ns"])  # type: ignore[index]
            * int(run["candidate_checks"])
            for run in current
            if int(run["candidate_checks"]) > 0
        )
        p95_values = [
            float(run["candidate_check_timing"]["p95_ns"])  # type: ignore[index]
            for run in current
            if int(run["candidate_checks"]) > 0
        ]
        mean_check_ns = (
            weighted_mean_numerator / candidate_checks
            if candidate_checks > 0
            else 0.0
        )
        p95_check_ns = statistics.fmean(p95_values) if p95_values else 0.0
        run_count = len(current)
        rows.append(
            {
                "checker": checker,
                "jobs": jobs,
                "runs": run_count,
                "checks": checks,
                "mean_checks_per_run": checks / run_count,
                "candidate_checks": candidate_checks,
                "wall_seconds": wall_ns / 1_000_000_000.0,
                "mean_wall_seconds": wall_ns / run_count / 1_000_000_000.0,
                "checks_per_second": (
                    0.0 if wall_ns <= 0 else checks / (wall_ns / 1_000_000_000.0)
                ),
                "mean_check_ms": mean_check_ns / 1_000_000.0,
                "mean_run_p95_check_ms": p95_check_ns / 1_000_000.0,
                "interesting_fraction": 0.0 if checks == 0 else interesting / checks,
            }
        )
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run treereduce-c with a direct C++ compiler check and/or a cheap "
            "grep oracle, then report checks per second and per-check latency."
        )
    )
    parser.add_argument("--source", default=str(DEFAULT_SOURCE), help="C++ baseline source")
    parser.add_argument(
        "--checker",
        choices=("both", "compile", "grep", "clang-crash"),
        default="both",
        help="Interestingness check to benchmark (default: both)",
    )
    parser.add_argument(
        "--jobs",
        type=parse_jobs,
        default=parse_jobs("1,2,4,8,16"),
        help="Comma-separated treereduce worker counts (default: 1,2,4,8,16)",
    )
    parser.add_argument("--repetitions", type=int, default=1, help="Runs per configuration")
    parser.add_argument("--stable", action="store_true", help="Use stable fixpoint reduction")
    parser.add_argument("--compiler", default="clang++", help="C++ compiler executable")
    parser.add_argument("--treereduce", default="treereduce-c", help="treereduce executable")
    parser.add_argument(
        "--check-timeout",
        type=int,
        default=60,
        help="Timeout for one interestingness check in seconds",
    )
    parser.add_argument(
        "--run-timeout",
        type=int,
        default=600,
        help="Timeout for one complete reduction run in seconds",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Artifact directory (default: timestamped directory beside the fixture)",
    )
    parser.add_argument(
        "--keep-logs",
        action="store_true",
        help="Keep gzip-compressed treereduce debug JSON for each run",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.repetitions <= 0:
        raise SystemExit("--repetitions must be positive")
    if args.check_timeout <= 0 or args.run_timeout <= 0:
        raise SystemExit("timeouts must be positive")

    source = Path(args.source).expanduser().resolve()
    if not source.is_file():
        raise SystemExit(f"source does not exist: {source}")
    if shutil.which(args.treereduce) is None:
        raise SystemExit(f"treereduce executable not found: {args.treereduce}")
    if shutil.which(args.compiler) is None:
        raise SystemExit(f"compiler executable not found: {args.compiler}")

    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else source.parent / f"results-{stamp}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    checkers = ("compile", "grep") if args.checker == "both" else (args.checker,)
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    runs: list[dict[str, object]] = []

    for checker in checkers:
        check = checker_spec(checker, args.compiler)
        validate_source_for_checker(source, check, args.compiler)
        for jobs in args.jobs:
            for repetition in range(1, args.repetitions + 1):
                run_dir = output_dir / f"{checker}-jobs-{jobs}-run-{repetition}"
                temp_dir = run_dir / "tmp"
                run_dir.mkdir(parents=True, exist_ok=True)
                temp_dir.mkdir(parents=True, exist_ok=True)
                reduced = run_dir / "reduced.cpp"
                command = build_treereduce_command(
                    treereduce=args.treereduce,
                    source=source,
                    output=reduced,
                    temp_dir=temp_dir,
                    jobs=jobs,
                    stable=args.stable,
                    check_timeout=args.check_timeout,
                    check=check,
                )
                print(
                    f"[+] {checker}, jobs={jobs}, run={repetition}: "
                    f"{shlex.join(command)}",
                    flush=True,
                )
                compressed_log_path = (
                    run_dir / "treereduce.jsonl.gz" if args.keep_logs else None
                )
                (
                    returncode,
                    parsed,
                    failure_tail,
                    wall_ns,
                    timed_out,
                ) = run_command_with_timeout(
                    command,
                    timeout_seconds=args.run_timeout,
                    env=env,
                    compressed_log_path=compressed_log_path,
                )
                if returncode != 0 or timed_out:
                    (run_dir / "failure_tail.log").write_text(
                        failure_tail,
                        encoding="utf-8",
                    )
                run = {
                    "checker": checker,
                    "jobs": jobs,
                    "repetition": repetition,
                    "command": command,
                    "returncode": returncode,
                    "timed_out": timed_out,
                    "wall_ns": wall_ns,
                    "wall_seconds": wall_ns / 1_000_000_000.0,
                    "reduced_bytes": reduced.stat().st_size if reduced.exists() else None,
                    **parsed,
                }
                runs.append(run)
                print(
                    f"    {run['total_checks']} checks in {run['wall_seconds']:.3f}s "
                    f"= {float(run['total_checks']) / float(run['wall_seconds']):.2f} checks/s",
                    flush=True,
                )
                if returncode != 0 or timed_out:
                    print(
                        f"[-] Run failed (returncode={returncode}, timed_out={timed_out}); "
                        f"see {run_dir / 'failure_tail.log'}",
                        file=sys.stderr,
                    )

    source_bytes = source.read_bytes()
    summary: dict[str, object] = {
        "schema_version": 1,
        "generated": datetime.now().astimezone().isoformat(),
        "source": str(source),
        "source_bytes": len(source_bytes),
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "reduction_mode": "stable" if args.stable else "fast",
        "platform": platform.platform(),
        "available_cpus": len(os.sched_getaffinity(0)),
        "treereduce_version": command_version(args.treereduce),
        "compiler_version": command_version(args.compiler),
        "runs": runs,
        "aggregate": aggregate_runs(runs),
    }
    json_path = output_dir / "summary.json"
    text_path = output_dir / "summary.txt"
    json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    text_path.write_text(render_report(summary), encoding="utf-8")
    print(f"[+] Summary: {text_path}")
    return 0 if all(int(run["returncode"]) == 0 for run in runs) else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Run the replay and oracle experiments from the two benchmark TSVs."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import traceback
import uuid

from harnessreducer.evaluation_common import (
    DATASETS, EXPERIMENT_FORMAT, case_key, collection_lock, copy_file,
    library_identities, publish_selection, read_json, select_case_keys, selected_runs,
    sha256, snapshot_dependencies, write_csv, write_json,
)
from harnessreducer.evaluation_metrics import MEASUREMENT_STAGE, SOURCE_TOKEN_COUNT_METHOD, count_source_tokens
from harnessreducer.evaluation_reports import (
    collect_oracle, collect_replay, oracle_artifact_errors, replay_measurements,
)
from harnessreducer.evaluation_source import count_calls
from harnessreducer.process_supervisor import run_supervised, termination_guard

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVALUATION_WORKERS = 10
PLACEHOLDERS = re.compile(r"\$\(pwd\)|\$\{PWD\}|\$PWD\b|\{bench_dir\}")
CONFIGURATIONS = {"replay": ("with_replay", "without_replay"), "oracle": ("oracle",)}


def new_run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + uuid.uuid4().hex[:8]


@dataclass(frozen=True)
class EvaluationCase:
    dataset: str
    name: str
    directory: Path
    compile_flags: str
    link_flags: str

    @property
    def key(self):
        return case_key(self.dataset, self.name)


def repository_path(value):
    path = Path(value).expanduser()
    return (path if path.is_absolute() else PROJECT_ROOT / path).resolve()


def benchmark_dir(value):
    direct = repository_path(value)
    if direct.is_dir():
        return direct
    supplied = Path(value)
    if not supplied.is_absolute():
        matches = [PROJECT_ROOT / "benchmark" / supplied] if len(supplied.parts) == 2 else [
            PROJECT_ROOT / "benchmark" / dataset / supplied for dataset, _ in DATASETS
        ] if len(supplied.parts) == 1 else []
        matches = [p.resolve() for p in matches if p.is_dir()]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(f"Ambiguous benchmark: {value}. Use dataset/case.")
    raise ValueError(f"Benchmark directory not found: {value}")


def expand_flags(value: str, benchmark: Path):
    # Parse first: substitutions containing spaces must remain one argument.
    return shlex.join([PLACEHOLDERS.sub(lambda _: str(benchmark), token)
                       for token in shlex.split(value)])


def default_python():
    if os.environ.get("HARNESSREDUCER_PYTHON"):
        return os.environ["HARNESSREDUCER_PYTHON"]
    for name in (".venv", ".venv-host"):
        path = PROJECT_ROOT / name / "bin" / "python"
        if os.access(path, os.X_OK):
            return str(path)
    return sys.executable


def resolve_python(value):
    # A path-valued override must survive the child changing to the harness cwd.
    # Do not resolve the executable's symlink: that would bypass its virtualenv.
    if "/" not in value and not value.startswith("~"):
        return value
    path = Path(value).expanduser()
    return os.path.abspath(path if path.is_absolute() else PROJECT_ROOT / path)


def _shared_arguments(parser, experiment):
    parser.add_argument("--results-root", "--output-dir", type=Path,
                        default=PROJECT_ROOT / "output" / f"{experiment}-evaluation")
    parser.add_argument("--python", default=default_python())
    parser.add_argument("--jobs", type=int, choices=range(1, 64), default=EVALUATION_WORKERS,
                        help="Treereduce workers per reduction (default: 10)")
    if experiment == "oracle":
        parser.add_argument("--oracle-comparison", choices=("paired-execution", "offline"), default="paired-execution")
    parser.add_argument("--auto-var-init-pattern", action="store_true")


def runner_parser(experiment):
    parser = argparse.ArgumentParser(description=f"Run the {experiment} evaluation on one benchmark case")
    parser.add_argument("--dir", required=True, help="Dataset/case, repository-relative path, or absolute path")
    parser.add_argument("--dataset", choices=[name for name, _ in DATASETS], help="Required for inputs outside the benchmark datasets")
    parser.add_argument("--compile-flags", required=True)
    parser.add_argument("--link-flags", required=True)
    parser.add_argument("--harness", default="harness.cpp")
    parser.add_argument("--crash-input", default="crash-input")
    parser.add_argument("--case-id", help="Case label (default: directory name)")
    parser.add_argument("--collect-case-only", action="store_true", help=argparse.SUPPRESS)
    _shared_arguments(parser, experiment)
    return parser


def _stage_final(work: Path, final: Path):
    for path in work.rglob("*.validation.log"):
        copy_file(path, final / "validation_logs" / path.relative_to(work))
    for name in ("initializer_recovery.json", "stack_depth_stability.json", "dynamic_crash_site.json", "crash_pattern.symbolize0", "crash_pattern.symbolize1"):
        if (work / name).is_file():
            copy_file(work / name, final / name)


def reduction_command(experiment, config, args, run, compile_flags, link_flags):
    directory = run / config if experiment == "replay" else run
    command = [args.python, "-m", "harnessreducer.cli", str(run / "reference" / "original.cpp"),
        f"--compile-flags={compile_flags}", f"--link-flags={link_flags}",
        "--crash-input", str(run / "reference" / "crash-input"), "--tool", "treereduce", "--jobs", str(args.jobs),
        "--pch", "--amortize-link", "--no-symbolize", "--stable", "--protect-initializers",
        "--work-dir", str(directory / "work"), "--output", str(directory / "final" / "reduced.cpp")]
    if args.auto_var_init_pattern:
        command.append("--auto-var-init-pattern")
    if experiment == "replay":
        command.append("--capture-raw-output")
        if config == "without_replay":
            command.append("--no-fdp-replay")
    else:
        command.extend(["--oracle-evaluation", str(run)])
    return command


@termination_guard()
def run_evaluation(experiment: str, argv=None):
    parser = runner_parser(experiment)
    args = parser.parse_args(argv)
    try:
        args.python = resolve_python(args.python)
        # Batch cases already have an explicit identity. Missing input directories
        # must still produce a selected failed attempt, not expose an older success.
        benchmark = repository_path(args.dir) if args.dataset and Path(args.dir).is_absolute() else benchmark_dir(args.dir)
        source = (benchmark / args.harness).resolve()
        crash_input = (benchmark / args.crash_input).resolve()
        dataset = args.dataset or benchmark.parent.name
        case = args.case_id or benchmark.name
        key = case_key(dataset, case)
        root = repository_path(args.results_root)
        compile_flags = expand_flags(args.compile_flags, benchmark)
        link_flags = expand_flags(args.link_flags, benchmark)
        if any("FDP_MIN_MODE_" in flag for flag in shlex.split(compile_flags)):
            raise ValueError("FDP mode is controlled by the experiment; remove FDP_MIN_MODE definitions")
        compile_flags = shlex.join([*shlex.split(compile_flags), "-I" + str(source.parent)])
    except ValueError as exc:
        parser.error(str(exc))
    case_dir = root / "cases" / key
    identity = {"dataset": dataset, "case": case, "benchmark": str(benchmark), "source": str(source), "crash_input": str(crash_input)}
    with collection_lock(root):
        previous = read_json(case_dir / "identity.json")
        if previous is not None and previous != identity:
            parser.error("This dataset/case belongs to another input. Choose a different --case-id or --results-root")
        write_json(case_dir / "identity.json", identity)
    run_id = new_run_id()
    run = case_dir / "runs" / run_id
    run.mkdir(parents=True)
    manifest = {"format": EXPERIMENT_FORMAT, "experiment": experiment, "dataset": dataset,
        "case": case, "run_id": run_id, "benchmark": str(benchmark), "status": "running", "configurations": {},
        "settings": {"engine": "treereduce", "jobs": args.jobs, "pch": True, "amortize_link": True,
            "symbolize": False, "stable": True, "protect_initializers": True, "snapshot": False,
            "auto_var_init_pattern": args.auto_var_init_pattern, "compile_flags": compile_flags, "link_flags": link_flags,
            "python": args.python, "token_count_method": SOURCE_TOKEN_COUNT_METHOD,
            "measurement_stage": MEASUREMENT_STAGE},
        "original": {"source": str(source), "crash_input": str(crash_input)}}
    if experiment == "oracle":
        manifest["settings"].update(symbolized_comparison=args.oracle_comparison,
                                    disagreement_policy="accepts_symbolized_rejects_excluding_reverse")
    write_json(run / "run_manifest.json", manifest)
    publish_selection(root, key, run_id)
    collector = collect_replay if experiment == "replay" else collect_oracle
    collector_case = key if args.collect_case_only else None
    try:
        if not source.is_file() or not crash_input.is_file():
            raise ValueError(f"Expected harness and crash input at {source} and {crash_input}")
        manifest["original"].update(sha256=sha256(source), crash_input_sha256=sha256(crash_input), tokens=count_source_tokens(source))
        reference = run / "reference"
        if experiment == "oracle":
            write_csv(reference / "runs.csv", [{"symbolize": mode, "sample_index": i, "status": "not_run", "returncode": None,
                "pattern_matched": None, "usable": False, "depth": None, "trace_id": None, "reason": None, "report": None}
                for mode in (0, 1) for i in range(1, 21)])
        copy_file(source, reference / "original.cpp")
        copy_file(crash_input, reference / "crash-input")
        snapshot_dependencies(source, reference / "dependencies", compile_flags)
        try:
            manifest["original"]["fdp_calls"] = count_calls(source.read_text(encoding="utf-8", errors="replace"))
        except ValueError as exc:
            manifest["original"].update(fdp_calls=None, analysis_error=str(exc))
        build = {**manifest["settings"], "original": manifest["original"], "libraries": library_identities(link_flags),
                 "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True).strip()}
        write_json(reference / "build.json", build)
        write_json(run / "run_manifest.json", manifest)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONUNBUFFERED"] = "1"
        interpreter = shutil.which(args.python) or str(repository_path(args.python))
        env["PATH"] = str(Path(interpreter).absolute().parent) + os.pathsep + env.get("PATH", "")
        env.pop("FDP_TRACE_PATH", None)
        env.pop("FDP_WIDE_TRACE_PATH", None)
        for config in CONFIGURATIONS[experiment]:
            directory = run / config if experiment == "replay" else run
            work, final = directory / "work", directory / "final"
            command = reduction_command(experiment, config, args, run, compile_flags, link_flags)
            prefix = config + "/" if experiment == "replay" else ""
            outcome = {"status": "running", "output": prefix + "final/reduced.cpp", "command": prefix + "commands.json"}
            if experiment == "replay":
                outcome["raw_reduced_harness"] = prefix + "final/reduced.raw.cpp"
            manifest["configurations"][config] = outcome
            write_json(run / "run_manifest.json", manifest)
            print(f"{key} {config}: {directory / 'reduction.log'}", flush=True)
            try:
                final.mkdir(parents=True, exist_ok=True)
                write_json(directory / "commands.json", {"command": command, "cwd": str(benchmark),
                    "environment": {k: env[k] for k in ("PATH", "PYTHONPATH")}})
                with (directory / "reduction.log").open("w") as log:
                    proc = run_supervised(command, cwd=benchmark, env=env, stdout=log, stderr=subprocess.STDOUT,
                                          text=True, check=False, timeout=None)
                passed = proc.returncode == 0 and (final / "reduced.cpp").is_file()
                outcome.update(status="completed" if passed else "unsuccessful", returncode=proc.returncode,
                               final_validation_passed=passed)
                _stage_final(work, final)
                trace = work / "fdp_trace.log"
                if trace.is_file():
                    copy_file(trace, directory / "reference" / "fdp_trace.txt")
                    if Path(str(trace) + ".wide").is_file():
                        copy_file(Path(str(trace) + ".wide"), directory / "reference" / "fdp_trace.txt.wide")
                outcome["generated_headers"] = [str(p.relative_to(run)) for p in sorted(final.glob("*.h"))]
                if experiment == "replay":
                    metrics = replay_measurements(run, manifest, config)
                    write_json(directory / "metrics.json", metrics)
                    if passed and metrics["errors"]:
                        outcome.update(status="incomplete", reason="; ".join(metrics["errors"]))
                else:
                    manifest["reduction_completed"] = (run / "reduction_completed.json").is_file()
                    manifest["final_validation_passed"] = passed
                    write_json(final / "validation.json", {"passed": passed, "policy": "existing final pipeline validation"})
            except Exception as exc:
                outcome.update(status="unsuccessful", reason=str(exc))
                traceback.print_exc()
            write_json(run / "run_manifest.json", manifest)
            try:
                collector(root, collector_case)
                if experiment == "oracle" and outcome["status"] == "completed":
                    errors = oracle_artifact_errors(run, manifest)
                    if errors:
                        outcome.update(status="incomplete", reason="; ".join(errors))
            except Exception as exc:
                outcome.update(status="incomplete", reason=f"Reporting failed: {exc}")
                traceback.print_exc()
        manifest["status"] = "completed" if all(c["status"] == "completed" for c in manifest["configurations"].values()) else "unsuccessful"
    except (KeyboardInterrupt, SystemExit):
        manifest["status"] = "interrupted"
        raise
    except Exception as exc:
        manifest.update(status="unsuccessful", error=str(exc))
        traceback.print_exc()
    finally:
        for config in manifest["configurations"].values():
            if config["status"] == "running":
                config["status"] = "interrupted" if manifest["status"] == "interrupted" else "incomplete"
        write_json(run / "run_manifest.json", manifest)
        try:
            collector(root, collector_case)
        except Exception as exc:
            manifest.update(status="unsuccessful", reporting_error=str(exc))
            write_json(run / "run_manifest.json", manifest)
            traceback.print_exc()
    print(f"Saved {run}", flush=True)
    return 0 if manifest["status"] == "completed" else 1


def load_evaluation_cases():
    cases, seen = [], set()
    for dataset, filename in DATASETS:
        with (PROJECT_ROOT / filename).open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            if reader.fieldnames != ["benchmark", "compile_flags", "link_flags"]:
                raise ValueError(f"Expected benchmark, compile_flags, link_flags columns in {filename}")
            for line, row in enumerate(reader, start=2):
                if None in row or any(row.get(key) is None for key in reader.fieldnames):
                    raise ValueError(f"Invalid TSV row at {filename}:{line}")
                name = row["benchmark"].strip()
                key = case_key(dataset, name)
                if key in seen:
                    raise ValueError(f"Duplicate benchmark: {key}")
                seen.add(key)
                directory = PROJECT_ROOT / "benchmark" / dataset / name
                # Validate quoting before launching any reductions.
                expand_flags(row["compile_flags"], directory)
                expand_flags(row["link_flags"], directory)
                cases.append(EvaluationCase(dataset, name, directory, row["compile_flags"], row["link_flags"]))
    return cases


def batch_parser(experiment):
    parser = argparse.ArgumentParser(description=f"Run the {experiment} evaluation over both TSV datasets")
    parser.add_argument("--case", action="append", dest="cases", help="Dataset/case or unambiguous case name; repeat to select multiple cases")
    parser.add_argument("--parallel", type=int, default=1, help="Concurrent benchmark cases (default: 1)")
    parser.add_argument("--resume", action="store_true", help="Skip complete selected cases; retry incomplete cases in new run directories")
    _shared_arguments(parser, experiment)
    return parser


def _case_completed(root: Path, key: str, experiment: str):
    try:
        runs = list(selected_runs(root, key))
        if len(runs) != 1:
            return False
        run, manifest = runs[0]
        if manifest["experiment"] != experiment or manifest["status"] != "completed":
            return False
        configs = manifest["configurations"]
        if set(configs) != set(CONFIGURATIONS[experiment]):
            return False
        if any(c.get("status") != "completed" for c in configs.values()):
            return False
        if experiment == "replay":
            return all(not replay_measurements(run, manifest, c)["errors"] for c in CONFIGURATIONS[experiment])
        return not oracle_artifact_errors(run, manifest)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def _batch_case_arguments(experiment, args, case):
    arguments = ["--dir", str(case.directory), "--dataset", case.dataset, "--case-id", case.name,
        f"--compile-flags={case.compile_flags}", f"--link-flags={case.link_flags}",
        "--results-root", str(args.results_root), "--python", args.python, "--jobs", str(args.jobs), "--collect-case-only"]
    if args.auto_var_init_pattern:
        arguments.append("--auto-var-init-pattern")
    if experiment == "oracle":
        arguments.extend(["--oracle-comparison", args.oracle_comparison])
    return arguments


def _run_batch_case(task):
    experiment, python, root, invocation, index, total, key, arguments = task
    log = root / "batch-logs" / invocation / (key + ".log")
    print(f"[{index}/{total}] {key}: started. Log: {log}", flush=True)
    selection = root / "cases" / key / "selected_run.json"
    previous = None
    code, error = 1, None
    try:
        previous = selection.read_bytes() if selection.is_file() else None
        log.parent.mkdir(parents=True, exist_ok=True)
        command = [python, str(PROJECT_ROOT / f"run_harnessreducer_{experiment}_eval.py"), *arguments]
        with log.open("w") as handle:
            handle.write("Command: " + shlex.join(command) + "\n\n")
            handle.flush()
            proc = run_supervised(command, cwd=PROJECT_ROOT, stdout=handle, stderr=subprocess.STDOUT,
                                  text=True, check=False, timeout=None)
        code = proc.returncode
        if code:
            error = f"Case worker exited {code}; see {log}"
    except Exception as exc:
        error = str(exc)
        print(f"{key}: could not run: {exc}", file=sys.stderr, flush=True)
    if code:
        try:
            _record_unstarted_failure(experiment, root, key, arguments, previous, error)
        except Exception as exc:
            print(f"{key}: could not record failed attempt: {exc}", file=sys.stderr, flush=True)
    return key, code, str(log)


def _record_unstarted_failure(experiment, root, key, arguments, previous, error):
    """Record failures before the child could publish its own selected attempt."""
    case_dir = root / "cases" / key
    selection = case_dir / "selected_run.json"
    with collection_lock(root):
        current = selection.read_bytes() if selection.is_file() else None
        if current != previous:
            return
        args = runner_parser(experiment).parse_args(arguments)
        dataset, case = key.split("/", 1)
        run_id = new_run_id()
        run = case_dir / "runs" / run_id
        settings = {"engine": "treereduce", "jobs": args.jobs, "measurement_stage": MEASUREMENT_STAGE,
                    "token_count_method": SOURCE_TOKEN_COUNT_METHOD}
        if experiment == "oracle":
            settings["symbolized_comparison"] = args.oracle_comparison
        manifest = {"format": EXPERIMENT_FORMAT, "experiment": experiment, "dataset": dataset, "case": case,
                    "run_id": run_id, "status": "unsuccessful", "error": error, "settings": settings,
                    "original": {}, "configurations": {}, "worker_arguments": arguments}
        write_json(run / "run_manifest.json", manifest)
        write_json(selection, {"case": key, "run_id": run_id})


@termination_guard()
def run_evaluation_batch(experiment: str, *, argv=None):
    parser = batch_parser(experiment)
    args = parser.parse_args(argv)
    if args.parallel < 1:
        parser.error("--parallel must be at least 1")
    try:
        args.results_root = repository_path(args.results_root)
        args.python = resolve_python(args.python)
        cases = load_evaluation_cases()
        if args.cases:
            requested = select_case_keys([case.key for case in cases], args.cases)
            cases = [case for case in cases if case.key in requested]
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    skipped = [case.key for case in cases if args.resume and _case_completed(args.results_root, case.key, experiment)]
    cases = [case for case in cases if case.key not in skipped]
    print(f"{experiment.capitalize()} evaluation: {len(cases)} cases to run, {args.parallel} parallel cases, {args.jobs} workers per reduction", flush=True)
    print(f"Results: {args.results_root}\nResume skipped {len(skipped)} completed cases.", flush=True)
    invocation = new_run_id()
    tasks = [(experiment, args.python, args.results_root, invocation, i, len(cases), case.key,
              _batch_case_arguments(experiment, args, case)) for i, case in enumerate(cases, start=1)]
    unsuccessful = []
    def record(result):
        key, code, log = result
        if code:
            unsuccessful.append(key)
        print(f"{key}: {'incomplete' if code else 'completed'}. Log: {log}", flush=True)
    if args.parallel == 1:
        for task in tasks:
            record(_run_batch_case(task))
    else:
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futures = {pool.submit(_run_batch_case, task): task[6] for task in tasks}
            for future in as_completed(futures):
                try:
                    record(future.result())
                except Exception as exc:
                    unsuccessful.append(futures[future])
                    print(f"{futures[future]}: {exc}", file=sys.stderr)
    reporting_failed = False
    try:
        reporting_failed = not (collect_replay if experiment == "replay" else collect_oracle)(args.results_root)
    except Exception:
        reporting_failed = True
        traceback.print_exc()
    print(f"Completed: {len(cases) - len(unsuccessful)}/{len(cases)}. Results: {args.results_root}", flush=True)
    return 1 if unsuccessful or reporting_failed else 0


def collect_evaluation(experiment: str, argv=None):
    parser = argparse.ArgumentParser(description=f"Collect saved {experiment} evaluation results")
    parser.add_argument("--results-root", "--input-dir", required=True, type=Path)
    parser.add_argument("--case", help="Dataset/case or unambiguous name for a case-specific report")
    args = parser.parse_args(argv)
    try:
        complete = (collect_replay if experiment == "replay" else collect_oracle)(repository_path(args.results_root), args.case)
        return 0 if complete else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Reporting failed: {exc}", file=sys.stderr)
        return 1

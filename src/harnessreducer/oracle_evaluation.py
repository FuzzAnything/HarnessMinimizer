"""Observation of D, the operational oracle F, and symbolized comparison S.

Paired runs execute candidates with symbolization both off and on. Offline
comparison is an explicit option. Observer exceptions never replace the
operational verdict.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from harnessreducer.evaluation_common import (
    append_jsonl, atomic_text, collection_lock, copy_file, read_json, read_jsonl,
    relative, sha256, snapshot_dependencies, write_csv, write_json,
)
from harnessreducer.oracle_paired_execution import (
    PAIRED_MODE, comparison_mode, execute_symbolized, normalized_online_trace,
    symbolized_verdict,
)

_REFERENCE_ROOT: Path | None = None
CATEGORIES = ("fast_accepts_symbolized_rejects", "depth_accepts_symbolized_rejects")
MODULE = re.compile(r"\((?P<module>[^()]+)\+(?P<offset>0x[0-9a-fA-F]+)\)")
LOCATION = re.compile(r"\s(?P<file>/?[^\s():]+):(?P<line>\d+)(?::\d+)?(?:\s|$)")
SYSTEM_FUNCTION = re.compile(r"^(?:__asan|__ubsan|__sanitizer|__interceptor|__libc|__pthread|fuzzer::|std::|__gnu_cxx::)")


def configure_reference_capture(root: str | None) -> None:
    global _REFERENCE_ROOT
    _REFERENCE_ROOT = Path(root).resolve() if root else None


def reference_root() -> Path | None:
    return _REFERENCE_ROOT


@contextmanager
def reference_capture(root: str | None):
    previous = reference_root()
    configure_reference_capture(root)
    try:
        yield
    finally:
        configure_reference_capture(previous)


def _record_observer_error(operation: str, exc: Exception) -> None:
    print(f"[EVALUATION] {operation} observation unavailable: {exc}", file=sys.stderr)
    if _REFERENCE_ROOT is not None:
        try:
            append_jsonl(_REFERENCE_ROOT / "observer-errors.jsonl", {"operation": operation, "error": str(exc)})
        except OSError:
            pass


def record_reduction_completed(source: str) -> None:
    if _REFERENCE_ROOT is not None:
        try:
            write_json(_REFERENCE_ROOT / "reduction_completed.json", {"source": source})
        except Exception as exc:
            _record_observer_error("reduction_completed", exc)


def frame_relevant(frame: dict, harness: str | None = None) -> bool:
    file = frame.get("file") or ""
    function = frame["function"]
    if "LLVMFuzzerTestOneInput" in function or function in {"main", "_start", "__libc_start_main"}:
        return False
    if SYSTEM_FUNCTION.search(function):
        return False
    if any(part in file for part in ("/compiler-rt/", "/libsanitizer/", "/glibc/", "/sysdeps/", "/include/c++/")):
        return False
    return not (harness and os.path.normpath(file) == os.path.normpath(harness)) and not file.endswith("/harness_runner.cpp")


def _target_module(module: str, link_flags: str, binary: str | None) -> bool:
    from harnessreducer.reducer_runner import (
        DynamicCrashSite, infer_target_dynamic_library_hints, _dynamic_site_matches_hints,
        _is_runtime_shared_library,
    )
    if ".so" in Path(module).name:
        if _is_runtime_shared_library(Path(module).name):
            return False
        hints = infer_target_dynamic_library_hints(link_flags)
        return _dynamic_site_matches_hints(DynamicCrashSite(module, Path(module).name, "0x0"), hints)
    return bool(binary and Path(module).resolve() == Path(binary).resolve()) or Path(module).name == "harness_runner"


def _symbolize(module: str, offset: str) -> list[dict]:
    command = [os.environ.get("HARNESSREDUCER_EVAL_SYMBOLIZER", "llvm-symbolizer"),
               "--output-style=JSON", "--inlines", "--demangle", f"--obj={module}", offset]
    env = os.environ.copy()
    env.pop("DEBUGINFOD_URLS", None)
    env.pop("LLVM_SYMBOLIZER_OPTS", None)
    proc = subprocess.run(command, capture_output=True, text=True, timeout=30, env=env, check=False)
    if proc.returncode:
        raise ValueError(f"llvm-symbolizer exited {proc.returncode}: {proc.stderr}")
    value = json.loads(proc.stdout)
    if isinstance(value, list):
        value = value[0]
    result = []
    for entry in value.get("Symbol", []):
        file, line, function = entry.get("FileName"), entry.get("Line"), entry.get("FunctionName")
        if not file or file == "??" or not line or not function or function == "??":
            raise ValueError(f"Incomplete debug information for {module}+{offset}")
        result.append({"function": function, "file": os.path.normpath(file), "line": int(line)})
    if not result:
        raise ValueError(f"No debug information for {module}+{offset}")
    return result


def normalized_trace(report: str, link_flags: str, *, binary=None, harness=None, module_map=None, cache=None):
    from harnessreducer.reducer_runner import extract_first_sanitizer_stack_trace
    trace = extract_first_sanitizer_stack_trace(report)
    if not trace:
        return [], "missing_crash_stack", ""
    frames, rendered, errors = [], [], []
    for raw in trace.splitlines():
        module_match = MODULE.search(raw)
        module = module_match["module"] if module_match else None
        location = LOCATION.search(raw)
        if module and not _target_module(module, link_flags, binary):
            continue
        if "LLVMFuzzerTestOneInput" in raw:
            break
        try:
            if location and " in " in raw:
                function = raw.split(" in ", 1)[1][:location.start() - raw.index(" in ") - 4].strip()
                if not function or function == "??" or location["file"] == "??" or int(location["line"]) <= 0:
                    raise ValueError("Incomplete source information in reference frame")
                current = [{"function": function, "file": os.path.normpath(location["file"]), "line": int(location["line"])}]
            elif module_match:
                actual = (module_map or {}).get(module, module)
                key = (actual, module_match["offset"])
                if cache is not None and key in cache:
                    current = cache[key]
                else:
                    current = _symbolize(*key)
                    if cache is not None:
                        cache[key] = current
            else:
                # Unknown system frames can be ignored only with module evidence.
                raise ValueError("frame has no module or source location")
            for frame in current:
                if "LLVMFuzzerTestOneInput" in frame["function"]:
                    return frames, "; ".join(errors) or None, "\n".join(rendered)
                if frame_relevant(frame, harness):
                    frames.append(frame)
                    rendered.append(f"#{len(frames)-1} {frame['function']} {frame['file']}:{frame['line']}")
        except (OSError, ValueError, subprocess.SubprocessError, KeyError) as exc:
            errors.append(str(exc))
    return frames, "; ".join(errors) or (None if frames else "no_usable_library_frames"), "\n".join(rendered)


def match_trace(candidate: list[dict], references: list[dict]):
    references = [r for r in references if r.get("frames")]
    if not candidate or not references:
        return "unavailable", "missing_candidate_or_reference_trace", None
    for reference in references:
        expected = reference["frames"]
        if not expected or expected[0] != candidate[0]:
            continue
        position = 1
        for frame in candidate[1:]:
            if position < len(expected) and frame == expected[position]:
                position += 1
        if position == len(expected):
            return "accept", "anchored_subsequence", reference["trace_id"]
    return "reject", "different_anchor" if all(r["frames"][0] != candidate[0] for r in references) else "missing_ordered_frames", None


def capture_reference(symbolize, index, proc, binary, harness, link_flags, *, stage="execute"):
    try:
        _capture_reference(symbolize, index, proc, binary, harness, link_flags, stage=stage)
    except Exception as exc:
        # Reference sampling still determines F's original depth policy.
        _record_observer_error("reference", exc)


def _capture_reference(symbolize, index, proc, binary, harness, link_flags, *, stage="execute"):
    if _REFERENCE_ROOT is None:
        return
    root = _REFERENCE_ROOT / "reference"
    report = (proc.stdout or "") + "\n" + (proc.stderr or "")
    path = root / "reports" / f"symbolize_{int(symbolize)}" / f"probe-{index:02d}.log"
    atomic_text(path, report)
    normalizer = normalized_online_trace if comparison_mode(_REFERENCE_ROOT) == PAIRED_MODE else normalized_trace
    frames, error, _ = normalizer(report, link_flags or "", binary=binary, harness=harness) if symbolize and stage == "execute" else ([], None, "")
    append_jsonl(root / "probe-events.jsonl", {
        "symbolize": int(symbolize), "sample_index": index, "stage": stage,
        "returncode": proc.returncode, "report": relative(path, _REFERENCE_ROOT),
        "frames": frames, "trace_error": error, "command": proc.args,
    })


def freeze_references(fast_pattern: str, symbolized_pattern: str | None):
    try:
        _freeze_references(fast_pattern, symbolized_pattern)
    except Exception as exc:
        _record_observer_error("freeze_references", exc)


def _freeze_references(fast_pattern: str, symbolized_pattern: str | None):
    if _REFERENCE_ROOT is None:
        return
    from harnessreducer.reducer_runner import count_first_stack_trace_frames, get_normal_reference_stack_depth_strict
    root = _REFERENCE_ROOT / "reference"
    events = {(e["symbolize"], e["sample_index"]): e for e in read_jsonl(root / "probe-events.jsonl")}
    rows, unique = [], {}
    for mode in (0, 1):
        for index in range(1, 21):
            event = events.get((mode, index), {})
            report = (_REFERENCE_ROOT / event["report"]).read_text() if event.get("report") else ""
            pattern = symbolized_pattern if mode else fast_pattern
            matched = bool(pattern and re.search(pattern, report))
            usable = mode == 1 and event.get("returncode") == 77 and matched and bool(event.get("frames")) and not event.get("trace_error")
            trace_id = None
            if usable:
                key = json.dumps(event["frames"], sort_keys=True)
                trace_id = hashlib.sha256(key.encode()).hexdigest()[:16]
                record = unique.setdefault(trace_id, {"trace_id": trace_id, "frames": event["frames"], "sample_indices": [], "frequency": 0, "crash_location": event["frames"][0]})
                record["sample_indices"].append(index)
                record["frequency"] += 1
            rows.append({"symbolize": mode, "sample_index": index, "status": event.get("stage", "not_run"),
                         "returncode": event.get("returncode"), "pattern_matched": matched, "usable": usable,
                         "depth": count_first_stack_trace_frames(report), "trace_id": trace_id,
                         "reason": event.get("trace_error"), "report": event.get("report"),
                         "function_only_frames": sum(f.get("resolution") == "function" for f in event.get("frames", []))})
    write_csv(root / "runs.csv", rows)
    write_json(root / "traces.json", {"frozen": True, "planned_symbolized_samples": 20,
        "usable_symbolized_samples": sum(r["usable"] for r in rows), "traces": list(unique.values()),
        "fast_pattern": fast_pattern, "symbolized_pattern": symbolized_pattern,
        "strict_depth_configured": get_normal_reference_stack_depth_strict(),
        "comparison_mode": comparison_mode(_REFERENCE_ROOT),
        "frame_policy": ("target frames from live symbolized reports, source coordinates when present, named functions otherwise, module and offset for unnamed target frames"
                         if comparison_mode(_REFERENCE_ROOT) == PAIRED_MODE else
                         "target modules, demangled function, full normalized source path and line, columns ignored, inline frames retained")})


def pattern_verdict(status, report, pattern):
    if status is None or status == 125:
        return "unavailable"
    return "accept" if status == 77 and re.search(pattern, report) else "reject"


def aggregate_verdict(verdicts):
    if "accept" in verdicts:
        return "accept"
    return "reject" if verdicts and all(v == "reject" for v in verdicts) else "unavailable"


def depth_verdict(crash_pattern_verdict, strict_depth, observed_depth, expected_depth):
    if crash_pattern_verdict != "accept":
        return crash_pattern_verdict
    if not strict_depth:
        return "accept"
    return "accept" if observed_depth == expected_depth else "reject"


def attempt_d_verdict(attempt):
    return attempt["d_verdict"]


def comparison_outcome(verdict, symbolized):
    """Classify one pair; reverse mismatches never enter the denominator."""
    if verdict not in {"accept", "reject"} or symbolized not in {"accept", "reject"}:
        return "excluded_unavailable"
    if verdict == symbolized:
        return "agreement"
    if verdict == "accept":
        return "disagreement"
    return "excluded_reverse"


def classify_query(query):
    for stem, verdict in (("fs", query.get("f_verdict")), ("ds", query.get("d_verdict"))):
        outcome = comparison_outcome(verdict, query.get("s_verdict"))
        query[f"{stem}_outcome"] = outcome
        query[f"{stem}_compared"] = outcome in {"agreement", "disagreement"}
    query["categories"] = categories(query.get("d_verdict"), query.get("f_verdict"), query.get("s_verdict"))
    query["category"] = category_field(query["categories"])
    return query


def categories(d, f, s):
    result = []
    if f == "accept" and s == "reject":
        result.append("fast_accepts_symbolized_rejects")
    if d == "accept" and s == "reject":
        result.append("depth_accepts_symbolized_rejects")
    return result


def category_field(categories):
    return ";".join(categories)


def query_categories(query):
    return categories(query.get("d_verdict"), query.get("f_verdict"), query.get("s_verdict"))


def fast_evidence(args, status, report):
    from harnessreducer.reducer_runner import extract_first_dynamic_library_crash_site, count_first_stack_trace_frames
    anchor = bool(args.dynamic_crash_site_library and args.dynamic_crash_site_offset)
    strict = args.stack_depth is not None and (args.strict_stack_depth or not anchor)
    site = extract_first_dynamic_library_crash_site(report, args.link_flags, expected_library=args.dynamic_crash_site_library)
    depth = count_first_stack_trace_frames(report)
    crash_pattern = pattern_verdict(status, report, args.crash_pattern)
    d = depth_verdict(crash_pattern, strict, depth, args.stack_depth)
    reason = "accepted"
    if crash_pattern == "unavailable":
        reason = "execution_error"
    elif status != 77:
        reason = "timeout" if status == 124 else "no_reference_crash"
    elif crash_pattern == "reject":
        reason = "pattern_mismatch"
    elif anchor and site is not None and site.offset.lower() != args.dynamic_crash_site_offset.lower():
        reason = "offset_mismatch"
    elif strict and depth != args.stack_depth:
        reason = "depth_mismatch"
    elif anchor and site is None:
        reason = "missing_location"
    depth_reason = "accepted"
    if crash_pattern == "unavailable":
        depth_reason = "execution_error"
    elif crash_pattern == "reject":
        depth_reason = "pattern_mismatch"
    elif strict and depth != args.stack_depth:
        depth_reason = "depth_mismatch"
    return {"crash_pattern_verdict": crash_pattern, "d_verdict": d,
            "depth_reject_reason": depth_reason, "fast_reject_reason": reason,
            "fast_oracle_mode": "library_offset" if anchor else "stack_depth_fallback",
            "fast_offset_available": site is not None, "fast_depth_enforced": strict,
            "observed_depth": depth, "expected_depth": args.stack_depth,
            "observed_offset": site.offset if site else None,
            "expected_offset": args.dynamic_crash_site_offset}


class QueryObserver:
    def __init__(self, args):
        self.root = Path(args.oracle_evaluation)
        self.comparison_mode = comparison_mode(self.root)
        with collection_lock(self.root / "observations"):
            sequence = self.root / "observations" / "sequence.json"
            self.query_id = int(read_json(sequence, 0)) + 1
            write_json(sequence, self.query_id)
        self.directory = self.root / "observations" / f"query-{self.query_id:06d}"
        self.directory.mkdir()
        self.args = args
        self.finished = False
        self.attempts = []
        self.commands = []
        body = Path(args.source).read_text()
        prefix = Path(args.oracle_prefix).read_text() if args.oracle_prefix else ""
        source = prefix + body
        atomic_text(self.directory / "candidate.cpp", source)
        self.hash = hashlib.sha256(source.encode()).hexdigest()
        write_json(self.directory / "started.json", {"query_id": self.query_id, "candidate_hash": self.hash,
            "tester_command": sys.argv, "cwd": os.getcwd(), "arguments": {k: v for k, v in vars(args).items() if not k.startswith("_")}})

    def command(self, command):
        self.commands.append(command)

    def execution(self, status, report, binary, milliseconds=None, command=None):
        attempt_id = len(self.attempts) + 1
        directory = self.directory / "attempts" / f"attempt-{attempt_id:02d}"
        atomic_text(directory / "unsymbolized.log", report)
        evidence = fast_evidence(self.args, status, report)
        module_map = {}
        if self.comparison_mode != PAIRED_MODE and evidence["crash_pattern_verdict"] == "accept":
            # Shared target libraries stay fixed. Preserve transient static hosts
            # and plugins before cleanup, deduplicating repeated runner binaries.
            # A truncated stack may never reach a candidate frame. Keep the
            # plugin itself so that this execution can still be investigated.
            modules = {match["module"] for match in MODULE.finditer(report)} | {str(binary)}
            for module in sorted(modules):
                path = Path(module)
                if ".so" in path.name and str(path) != str(binary):
                    continue
                if path.is_file():
                    binary_root = self.root / "reference" / "binaries"
                    with collection_lock(binary_root):
                        index_path = binary_root / "index.json"
                        index = read_json(index_path, {})
                        stat = path.stat()
                        identity = [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns]
                        previous = index.get(module, {})
                        digest = previous.get("sha256") if previous.get("identity") == identity else sha256(path)
                        destination = binary_root / digest
                        if not destination.exists():
                            copy_file(path, destination)
                        index[module] = {"identity": identity, "sha256": digest}
                        write_json(index_path, index)
                    module_map[module] = str(destination)
        record = {"query_id": self.query_id, "attempt_id": attempt_id, "returncode": status,
                  "execute_milliseconds": milliseconds, "binary": binary, "module_map": module_map,
                  "report": relative(directory / "unsymbolized.log", self.root), **evidence}
        if self.comparison_mode == PAIRED_MODE:
            # The unsymbolized run cannot determine S because independent executions can disagree.
            symbolized_status, symbolized_report, elapsed = execute_symbolized(self.args, binary, command)
            atomic_text(directory / "symbolized.log", symbolized_report)
            record.update(
                symbolized_returncode=symbolized_status,
                symbolized_execute_milliseconds=elapsed,
                symbolized_report=relative(directory / "symbolized.log", self.root),
            )
        self.attempts.append(record)
        write_json(directory / "execution.json", record)

    def finish(self, code):
        if self.finished:
            return
        last = self.attempts[-1] if self.attempts else {}
        anchor = bool(self.args.dynamic_crash_site_library and self.args.dynamic_crash_site_offset)
        record = {"query_id": self.query_id, "candidate_hash": self.hash,
            "build_status": "built" if self.args._debug_compile_success and code != -1 else "rejected",
            "execution_status": "executed" if self.attempts else "not_executed",
            "query_status": "completed" if code is not None else "incomplete",
            "operational_returncode": code, "f_verdict": "accept" if code == 77 else "unavailable" if code is None else "reject",
            "d_verdict": aggregate_verdict([attempt_d_verdict(a) for a in self.attempts]),
            "comparison_mode": self.comparison_mode,
            "fast_oracle_mode": "library_offset" if anchor else "stack_depth_fallback",
            "fast_offset_available": last.get("fast_offset_available", False),
            "fast_depth_enforced": self.args.stack_depth is not None and (self.args.strict_stack_depth or not anchor),
            "fast_reject_reason": "accepted" if code == 77 else last.get("fast_reject_reason", "build_rejected" if code == -1 else "execution_error"),
            "attempts": self.attempts, "commands": self.commands,
            "link_flags": self.args.link_flags, "compile_flags": self.args.compile_flags,
            "fdp_trace": self.args.fdp_trace}
        write_json(self.directory / "query.json", record)
        self.finished = True
        if any(a.get("crash_pattern_verdict") == "accept" for a in self.attempts):
            snapshot_dependencies(self.directory / "candidate.cpp", self.directory / "dependencies", self.args.compile_flags or "")


def observe(args, operation: str, *values):
    """Do not allow observation to change a candidate's operational result."""
    try:
        observer = getattr(args, "_oracle_observer", None)
        if operation == "start":
            if getattr(args, "oracle_evaluation", None):
                args._oracle_observer = QueryObserver(args)
        elif observer is not None:
            getattr(observer, operation)(*values)
    except Exception as exc:
        print(f"[EVALUATION] Could not record {operation}: {exc}", file=sys.stderr)
        root = getattr(args, "oracle_evaluation", None)
        if root:
            try:
                append_jsonl(Path(root) / "observer-errors.jsonl", {"operation": operation, "error": str(exc), "pid": os.getpid()})
            except OSError:
                pass


def process_observations(root: Path):
    """Resume from durable query records, with no candidate re-execution."""
    pending = [p.parent for p in sorted((root / "observations").glob("query-*/query.json")) if not (p.parent / "result.json").exists()]
    if not pending:
        return
    reference_record = read_json(root / "reference" / "traces.json", {})
    references = reference_record.get("traces", [])
    manifest = read_json(root / "run_manifest.json", {})
    cache = {}
    changed_libraries = []
    for identity in read_json(root / "reference" / "build.json", {}).get("libraries", []):
        path = Path(identity["path"])
        if not path.is_file() or sha256(path) != identity["sha256"]:
            changed_libraries.append(str(path))
    for directory in pending:
        completed = directory / "result.json"
        if completed.exists():
            continue
        query = read_json(directory / "query.json")
        if query is None:
            continue
        started = read_json(directory / "started.json", {})
        args = started.get("arguments", {})
        all_attempts = []
        frames_by_attempt = []
        for attempt in query["attempts"]:
            report = (root / attempt["report"]).read_text()
            crash_pattern = attempt.get("crash_pattern_verdict", "unavailable")
            frames, error, rendered = [], None, ""
            if query.get("comparison_mode") == PAIRED_MODE:
                symbolized_report = (root / attempt["symbolized_report"]).read_text() if attempt.get("symbolized_report") else ""
                verdict, reason, trace_id, frames, symbolized_p = symbolized_verdict(
                    attempt.get("symbolized_returncode"), symbolized_report, reference_record,
                    query.get("link_flags") or "", binary=attempt["binary"], harness=args.get("source"),
                )
                attempt["symbolized_pattern_verdict"] = symbolized_p
                attempt["symbolized_function_only_frames"] = sum(f.get("resolution") == "function" for f in frames)
                rendered = symbolized_report
            elif crash_pattern == "reject":
                verdict, reason, trace_id = "reject", "pattern_or_crash_gate", None
            elif crash_pattern == "unavailable":
                verdict, reason, trace_id = "unavailable", "execution_error", None
            else:
                if changed_libraries:
                    frames, error, rendered = [], "target binary changed or unavailable: " + ", ".join(changed_libraries), ""
                else:
                    frames, error, rendered = normalized_trace(report, query.get("link_flags") or "",
                        binary=attempt["binary"], harness=args.get("source"), module_map=attempt.get("module_map"), cache=cache)
                verdict, reason, trace_id = ("unavailable", error, None) if error else match_trace(frames, references)
            attempt.update(s_verdict=verdict, s_reason=reason, matched_reference_trace_id=trace_id)
            attempt_dir = directory / "attempts" / f"attempt-{attempt['attempt_id']:02d}"
            atomic_text(attempt_dir / "symbolized.log", rendered + "\n")
            write_json(attempt_dir / "frames.json", {"frames": frames, "error": error, "matched_reference_trace_id": trace_id})
            frames_by_attempt.append({"attempt_id": attempt["attempt_id"], "frames": frames, "error": error, "s_reason": reason})
            all_attempts.append(attempt)
        s = aggregate_verdict([a["s_verdict"] for a in all_attempts])
        query["s_verdict"] = s
        decisive = next((a for a in all_attempts if a["s_verdict"] == s), all_attempts[-1] if all_attempts else {})
        query.update(s_reason=decisive.get("s_reason", "not_executed"), matched_reference_trace_id=decisive.get("matched_reference_trace_id"))
        classify_query(query)
        query.update(dataset=manifest["dataset"], case=manifest["case"], run_id=manifest["run_id"], artifact_dir="")
        if query["categories"]:
            destination = root / "candidates" / directory.name
            shutil.copytree(directory, destination, dirs_exist_ok=True)
            # Dependencies were captured while reducer-generated includes existed.
            write_json(destination / "frames.json", frames_by_attempt)
            write_json(destination / "commands.json", {"tester": started, "build": query["commands"], "reference": "../../reference"})
            if decisive:
                attempt_dir = destination / "attempts" / f"attempt-{decisive['attempt_id']:02d}"
                for name in ("unsymbolized.log", "symbolized.log"):
                    copy_file(attempt_dir / name, destination / name)
            query["artifact_dir"] = relative(destination, root)
            # Link reports to retained copies rather than transient observations.
            for attempt in all_attempts:
                attempt["report"] = relative(destination / "attempts" / f"attempt-{attempt['attempt_id']:02d}" / "unsymbolized.log", root)
                if attempt.get("symbolized_report"):
                    attempt["symbolized_report"] = relative(destination / "attempts" / f"attempt-{attempt['attempt_id']:02d}" / "symbolized.log", root)
            write_json(destination / "verdicts.json", query)
        elif s == "unavailable" and all_attempts:
            # An unavailable comparison is unfinished evidence. Keep the raw
            # reports and source so a corrected parser can revisit it later.
            query["artifact_dir"] = relative(directory, root)
            write_json(directory / "frames.json", frames_by_attempt)
        else:
            for attempt in all_attempts:
                attempt["report"] = None
                if attempt.get("symbolized_report"):
                    attempt["symbolized_report"] = None
            # Retain compact decisions after symbolization. Examples keep reports.
        query["attempts"] = all_attempts
        write_json(completed, query)
        if s == "unavailable" and all_attempts:
            continue
        for child in directory.iterdir():
            if child.name in {"result.json", "started.json"}:
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

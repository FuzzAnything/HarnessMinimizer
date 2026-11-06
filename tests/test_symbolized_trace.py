"""Reference trace identity, alternatives, and verified path aliases."""

import os
import re
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from harnessminimizer import reducer_runner as runner
from harnessminimizer.crash_evidence import EvidenceResult
from harnessminimizer.source_alias import SourceAliases
from harnessminimizer.symbolized_trace import (
    TRACE_SET_ENV, SymbolizedTraceReference, extract_stack_trace, normalize_crash_signature,
)
from tests.crash_tester import _evaluate_candidate_crash


def report(frames, *, harness="/tmp/harness.cpp", address=0x100):
    lines = [
        f"    #{index} 0x{address + index:x} in {name} {path}:{line}:3"
        for index, (name, path, line) in enumerate(frames)
    ]
    lines.append(f"    #{len(frames)} 0x{address + len(frames):x} in LLVMFuzzerTestOneInput {harness}:5:1")
    return "\n".join(lines) + "\n"


LIBRARY = "/src/library.cc"
A = [("crash", LIBRARY, 7), ("via_a", LIBRARY, 12)]
B = [("crash", LIBRARY, 7), ("via_b", LIBRARY, 15), ("dispatch", LIBRARY, 20)]


def reference(*reports):
    return SymbolizedTraceReference(tuple(dict.fromkeys(
        normalize_crash_signature(extract_stack_trace(value, "/tmp/harness.cpp"), escape=True)
        for value in reports
    )), 20)


def test_address_and_harness_changes_are_ignored_but_library_changes_are_not():
    recorded = reference(report(A))
    assert recorded.evaluate(report(A, harness="/tmp/reduced.cpp", address=0xabc), "/tmp/reduced.cpp") == (EvidenceResult.MATCH, 1)
    for frames in ([("crash", LIBRARY, 8), A[1]], [A[0], ("different", LIBRARY, 12)],
                   [A[0]], [A[1], A[0]], [*A, ("extra", LIBRARY, 21)]):
        assert recorded.evaluate(report(frames), "/tmp/harness.cpp")[0] is EvidenceResult.MISMATCH


def test_recorded_alternatives_match_without_learning_another():
    recorded = reference(report(A), report(B), report(A, address=0x444))
    assert len(recorded.normalized_patterns) == 2
    assert recorded.evaluate(report(B, address=0x999), "/tmp/harness.cpp") == (EvidenceResult.MATCH, 2)
    assert recorded.evaluate(report([A[0], ("third", LIBRARY, 28)]), "/tmp/harness.cpp")[0] is EvidenceResult.MISMATCH
    assert len(recorded.normalized_patterns) == 2


def test_only_first_stack_is_used_and_missing_trace_is_distinct():
    recorded = reference(report(A))
    assert recorded.evaluate(report(A) + "\nallocation stack:\n" + report(B), "/tmp/harness.cpp")[0] is EvidenceResult.MATCH
    assert recorded.evaluate("SUMMARY: AddressSanitizer: error\n", "/tmp/harness.cpp")[0] is EvidenceResult.MISSING_EVIDENCE
    assert recorded.evaluate(report([], harness="/tmp/harness.cpp"), "/tmp/harness.cpp")[0] is EvidenceResult.MISSING_EVIDENCE


def test_candidate_distinguishes_missing_evidence_from_unrecorded_trace():
    args = SimpleNamespace(
        symbolize=True, _source_aliases=SourceAliases(), _reference_traces=reference(report(A)),
        debug_log=None, crash_pattern="division by zero", skip_crash_pattern=False,
        crash_location_pattern=normalize_crash_signature(f"{LIBRARY}:7:3", escape=True),
        crash_location_file=None, source="/tmp/harness.cpp", stack_depth=999,
        strict_stack_depth=True, stack_trace_file=None,
    )
    matching = f"{LIBRARY}:7:3: runtime error: division by zero\n" + report(A)
    missing = f"{LIBRARY}:7:3: runtime error: division by zero\n"
    unknown = f"{LIBRARY}:7:3: runtime error: division by zero\n" + report([A[0], ("third", LIBRARY, 22)])
    assert _evaluate_candidate_crash(args, 77, matching)[0] is EvidenceResult.MATCH
    assert _evaluate_candidate_crash(args, 77, missing)[0] is EvidenceResult.MISSING_EVIDENCE
    assert _evaluate_candidate_crash(args, 77, unknown)[0] is EvidenceResult.MISMATCH


def test_verified_aliases_apply_to_every_frame_without_rereading_files(tmp_path, monkeypatch):
    originals = [tmp_path / "build" / name for name in ("crash.cc", "caller.cc")]
    aliases = [tmp_path / "src" / name for name in ("crash.cc", "caller.cc")]
    originals[0].parent.mkdir()
    aliases[0].parent.mkdir()
    for original, alias in zip(originals, aliases):
        original.write_text("same source")
        alias.write_bytes(original.read_bytes())
    frames = [(name, str(path), line) for (name, _, line), path in zip(A, originals)]
    alternative = [(name, str(path), line) for (name, _, line), path in zip(A, aliases)]
    recorded = reference(report(frames))
    learning = SourceAliases(allow_verification=True)
    assert recorded.evaluate(report([alternative[0], ("wrong", str(aliases[1]), 12)]),
                             "/tmp/harness.cpp", learning)[0] is EvidenceResult.MISMATCH
    assert not learning.pairs
    assert recorded.evaluate(report(alternative), "/tmp/harness.cpp", learning)[0] is EvidenceResult.MATCH
    assert len(learning.pairs) == 2
    frozen = SourceAliases(learning.pairs)
    monkeypatch.setattr("harnessminimizer.source_alias.filecmp.cmp", lambda *a, **k: (_ for _ in ()).throw(AssertionError("reread")))
    assert recorded.evaluate(report(alternative, address=0x777), "/tmp/harness.cpp", frozen)[0] is EvidenceResult.MATCH
    assert recorded.evaluate(report([alternative[0], ("wrong", str(aliases[1]), 12)]),
                             "/tmp/harness.cpp", frozen)[0] is EvidenceResult.MISMATCH


@pytest.fixture
def collection_state(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "TREEDUCER_DIR", None)
    monkeypatch.setattr(runner, "_IS_USER_WORK_DIR", False)
    runner.configure_work_dir(str(tmp_path / "work"))
    runner.reset_stack_trace_state()
    runner.set_reference_crash_patterns(symbolize_0=r"division by zero", symbolize_1=r"division by zero")
    runner.set_symbolized_reference_crash_location_pattern(re.escape(f"{LIBRARY}:7:3"))
    yield
    runner.reset_stack_trace_state()


def test_collector_keeps_twenty_valid_samples_and_initial_report(collection_state):
    initial = f"{LIBRARY}:7:3: runtime error: division by zero\n" + report(A)
    variants = [f"{LIBRARY}:7:3: runtime error: division by zero\n" + report(A if index % 2 else B)
                for index in range(runner.STACK_DEPTH_STABILITY_RUNS)]
    with patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], 0, "", "")) as compile_run, patch.object(
        runner, "_capture_crash_reference_with_evidence",
        side_effect=[subprocess.CompletedProcess([], 77, "", value) for value in variants],
    ) as run:
        result = runner._collect_symbolized_reference_traces(
            "/tmp/harness.cpp", "seed", compile_flags=None, link_flags=None,
            initial_output=initial,
        )
    assert run.call_count == compile_run.call_count == runner.STACK_DEPTH_STABILITY_RUNS == 20
    assert result.samples_completed == 20
    assert len(result.normalized_patterns) == 2
    assert result.evaluate(variants[1], "/tmp/harness.cpp")[0] is EvidenceResult.MATCH


def test_collector_fails_on_changed_crash_and_never_publishes_partial_set(collection_state):
    initial = f"{LIBRARY}:7:3: runtime error: division by zero\n" + report(A)
    changed = initial.replace("division by zero", "signed integer overflow")
    with patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], 0, "", "")), patch.object(
        runner, "_capture_crash_reference_with_evidence",
        return_value=subprocess.CompletedProcess([], 77, "", changed),
    ):
        with pytest.raises(ValueError, match="Crash pattern changed"):
            runner._collect_symbolized_reference_traces(
                "/tmp/harness.cpp", "seed", compile_flags=None, link_flags=None,
                initial_output=initial,
            )
    assert runner.SYMBOLIZED_TRACE_REFERENCE is None


def test_collector_bounds_missing_reference_evidence(collection_state):
    initial = f"{LIBRARY}:7:3: runtime error: division by zero\n" + report(A)
    incomplete = f"{LIBRARY}:7:3: runtime error: division by zero\n"
    with patch.object(runner, "run_command", return_value=subprocess.CompletedProcess([], 0, "", "")), patch.object(
        runner, "_run_harness_for_crash_reference",
        return_value=subprocess.CompletedProcess([], 77, "", incomplete),
    ) as run:
        with pytest.raises(ValueError, match="Missing or changed crash location"):
            runner._collect_symbolized_reference_traces(
                "/tmp/harness.cpp", "seed", compile_flags=None, link_flags=None,
                initial_output=initial,
            )
    assert run.call_count == runner.REFERENCE_EVIDENCE_ATTEMPTS


def test_trace_set_is_reset_between_reductions(collection_state):
    runner.set_symbolized_reference_traces(reference(report(A)), required=True)
    assert runner.reference_trace_tester_args() == ["--require-reference-traces"]
    assert runner.stack_depth_tester_args(symbolized=True) == []
    runner.reset_stack_trace_state()
    assert runner.reference_trace_tester_args() == []
    assert runner.SYMBOLIZED_TRACE_REFERENCE is None


def test_recovery_attempt_restores_reference_set(collection_state, tmp_path):
    original = reference(report(A))
    runner.set_symbolized_reference_traces(original, required=True)
    with runner.isolated_attempt_work_dir(tmp_path / "retry"):
        runner.set_symbolized_reference_traces(reference(report(B)), required=True)
    assert runner.SYMBOLIZED_TRACE_REFERENCE is original
    assert runner.reference_trace_tester_args() == ["--require-reference-traces"]


@pytest.mark.parametrize("payload", ["", "{}", '{"schema_version":1,"normalized_patterns":[]}'])
def test_checker_rejects_missing_or_invalid_required_trace_set(payload):
    command = [sys.executable, runner.get_crash_tester_path(), "/tmp/candidate.cpp", ".*",
               "--symbolize", "--require-reference-traces"]
    process = subprocess.run(command, capture_output=True, text=True, timeout=10,
                             env={**os.environ, TRACE_SET_ENV: payload})
    assert process.returncode == 2
    assert "Missing or invalid symbolized reference traces" in process.stderr

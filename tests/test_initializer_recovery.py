import json
from pathlib import Path
import subprocess

import pytest

from harnessreducer import initializer_recovery as recovery
from harnessreducer.api import PostReductionOutcome
from harnessreducer.initializer_analysis import InitializationDiagnosis, analyze_uninitialized
from harnessreducer import reducer_runner as runner
from harnessreducer.reduction_profile import write_profile_summary


@pytest.fixture
def work(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "TREEDUCER_DIR", str(tmp_path))
    monkeypatch.setattr(runner, "_IS_USER_WORK_DIR", True)
    source = tmp_path / "tagged.cpp"
    source.write_text("void f(){ int value=7; consume(value); }\n")
    return source


def event(start, compile_ns, success=True):
    return {
        "start_wall_ns": start, "end_wall_ns": start + 1_000_000_000,
        "result_code": 77 if success else -1, "compile_success": success,
        "durations_ns": {"total_ns": 1_000_000_000, "compile_ns": compile_ns,
                         "execute_ns": 1_000_000 if success else 0},
    }


def profile(root, events, wall_ns):
    events_path = root / "candidate_profile.jsonl"
    events_path.write_text("".join(json.dumps(e) + "\n" for e in events))
    write_profile_summary(
        events_path, root / "reduction_profile.json", root / "reduction_profile.txt",
        wall_ns=wall_ns, jobs=2, returncode=0,
        configuration={"jobs": 2, "tool": "treereduce", "compilation_mode": "pch"},
    )


def invoke(work, attempt, profile_enabled=True):
    return recovery.reduce_with_initializer_recovery(
        attempt, str(work), "-std=c++17", replay=True, plugin=True,
        profile=profile_enabled, jobs=2,
    )


def test_success_never_parses_analyzes_or_retries(work, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("successful normal runs must not do recovery work")
    monkeypatch.setattr(recovery, "analyze_uninitialized", forbidden)
    monkeypatch.setattr(recovery, "prepare_initializer_protection", forbidden)
    calls = []
    def attempt(source, flags):
        calls.append(source)
        profile(work.parent, [event(0, 200)], 2_000_000_000)
        return PostReductionOutcome(str(work))
    result = invoke(work, attempt)
    assert result.validated
    assert calls == [str(work)]
    metadata = json.loads((work.parent / "initializer_recovery.json").read_text())
    assert metadata["status"] == "not-needed"
    assert not list(work.parent.glob("initializer-recovery-*"))


@pytest.mark.parametrize("stage", ["final-output", "cleaned-fallback", "fdp-replay", "direct-input"])
@pytest.mark.parametrize("retry_succeeds", [True, False])
def test_one_retry_and_pooled_metrics_preserve_first_attempt(work, monkeypatch, stage, retry_succeeds):
    diagnosis_calls = []
    def diagnose(source, *args):
        diagnosis_calls.append(source)
        return InitializationDiagnosis("uninitialized-use", ({"checker": "core.CallAndMessage"},), 123, "log")
    monkeypatch.setattr(recovery, "analyze_uninitialized", diagnose)
    monkeypatch.setattr(recovery, "verify_preparation", lambda *args, **kwargs: None)
    source_before = work.read_text()
    (work.parent / "poc.out").write_bytes(b"reference executable")
    (work.parent / "crash_pattern.symbolize0").write_text("same-reference")
    calls = []
    def attempt(source, flags, protection=None):
        root = Path(runner.get_work_dir())
        calls.append((root, source))
        result = root / "reduced.cpp"
        if protection is None:
            assert source == str(work)
            result.write_text("void f(){int value; consume(value);}\n")
            profile(root, [event(0, 200_000_000), event(0, 9_000_000_000, False)], 2_000_000_000)
            return PostReductionOutcome(str(result), validated=False, stage=stage,
                                        )
        assert source != str(work) and root != work.parent
        assert protection.restore(Path(source).read_text()) == source_before
        assert (root / "poc.out").read_bytes() == b"reference executable"
        assert (root / "crash_pattern.symbolize0").read_text() == "same-reference"
        result.write_text(source_before)
        profile(root, [event(4_000_000_000, 300_000_000) for _ in range(3)], 3_000_000_000)
        return PostReductionOutcome(str(result), validated=retry_succeeds,
                                    )
    result = invoke(work, attempt)
    assert result.validated is retry_succeeds
    assert Path(result[0]).read_text() == source_before
    assert Path(result[0]).parent != work.parent
    assert len(calls) == 2 and len(diagnosis_calls) == 1
    assert runner.get_work_dir() == str(work.parent)
    assert work.read_text() == source_before
    combined = json.loads((work.parent / "reduction_profile.json").read_text())
    assert combined["reducer"]["wall_ns"] == 5_000_000_000
    assert combined["reducer"]["profiled_checks"] == 5
    assert combined["reducer"]["checks_per_second"] == 1
    assert combined["reducer"]["mean_in_flight_checks"] == 1
    assert combined["reducer"]["worker_utilization"] == .5
    assert combined["reducer"]["result_counts"] == {"77": 4, "-1": 1}
    assert combined["candidate_timing"]["compile_ns"]["count"] == 4
    assert combined["candidate_timing"]["compile_ns"]["mean_ns"] == 275_000_000
    assert combined["candidate_timing"]["compile_ns"]["median_ns"] == 300_000_000
    assert combined["candidate_timing"]["total_ns"]["count"] == 5
    metadata = combined["configuration"]["initializer_recovery"]
    assert metadata["diagnosis_ns"] == 123
    assert metadata["attempt_count"] == 2
    assert metadata["final_validated"] is retry_succeeds
    assert len(list(work.parent.glob("initializer-recovery-*/attempt-1-normal/reduction_profile.json"))) == 1


@pytest.mark.parametrize("status", ["no-relevant-diagnostic", "analysis-failed"])
def test_irrelevant_or_failed_diagnosis_does_not_retry(work, monkeypatch, status):
    monkeypatch.setattr(recovery, "analyze_uninitialized", lambda *a: InitializationDiagnosis(status, (), 1, "log"))
    calls = []
    def attempt(source, flags):
        calls.append(source)
        return PostReductionOutcome(source, validated=False)
    assert not invoke(work, attempt, False).validated
    assert len(calls) == 1


def test_missing_input_does_not_invoke_analyzer(work, monkeypatch):
    monkeypatch.setattr(recovery, "analyze_uninitialized", lambda *a: pytest.fail("must not analyze missing input"))
    assert not invoke(work, lambda s, f: PostReductionOutcome(s, validated=False, stage="missing-input"), False).validated


def test_retry_exception_restores_work_dir_and_retains_profile(work, monkeypatch):
    monkeypatch.setattr(recovery, "analyze_uninitialized", lambda *a: InitializationDiagnosis("uninitialized-use", ({},), 1, "log"))
    monkeypatch.setattr(recovery, "verify_preparation", lambda *a, **kw: None)
    def attempt(source, flags, protection=None):
        if protection is not None:
            raise RuntimeError("synthetic reducer failure")
        profile(work.parent, [event(0, 200)], 1_000_000_000)
        return PostReductionOutcome(source, validated=False,
                                    )
    result = invoke(work, attempt)
    assert not result.validated
    assert result[0] == str(work)
    assert runner.get_work_dir() == str(work.parent)
    summary = json.loads((work.parent / "reduction_profile.json").read_text())
    assert summary["reducer"]["profiled_checks"] == 1
    assert summary["configuration"]["initializer_recovery"]["status"] == "recovery-error"


@pytest.mark.parametrize("library_diagnostic,description", [(True, "uninitialized value"), (False, "Value stored is never read")])
def test_analyzer_filters_library_and_unrelated_diagnostics(tmp_path, monkeypatch, library_diagnostic, description):
    import plistlib
    from harnessreducer import initializer_analysis as analysis
    source = tmp_path / "source.cpp"
    source.write_text("void f(){}")
    def run(command, **kwargs):
        doc = {
            "files": [str(tmp_path / "library.h") if library_diagnostic else str(source)],
            "diagnostics": [{"check_name": "core.CallAndMessage", "description": description,
                             "location": {"file": 0, "line": 1, "col": 1}}],
        }
        Path(command[-1]).write_bytes(plistlib.dumps(doc))
        return subprocess.CompletedProcess(command, 0, "", "warning")
    monkeypatch.setattr(analysis, "run_supervised", run)
    result = analyze_uninitialized(str(source), tmp_path / "diagnosis", "")
    assert result.status == "no-relevant-diagnostic"


def test_analyzer_timeout_is_not_an_initialization_diagnostic(tmp_path, monkeypatch):
    from harnessreducer import initializer_analysis as analysis
    def timeout(command, **kwargs):
        assert kwargs["timeout"] == 60
        raise subprocess.TimeoutExpired(command, 60)
    monkeypatch.setattr(analysis, "run_supervised", timeout)
    result = analyze_uninitialized(str(tmp_path / "s.cpp"), tmp_path / "diagnosis", "")
    assert result.status == "analysis-failed" and not result.relevant


@pytest.mark.parametrize("symbolize", [False, True])
@pytest.mark.parametrize("mode,plugin", [("split", False), ("pch", True)])
@pytest.mark.parametrize("retry_succeeds", [True, False])
def test_api_recovery_preserves_options_and_validation_order(tmp_path, monkeypatch, symbolize, mode, plugin, retry_succeeds):
    """Exercise API orchestration with a harmless synthetic source and no execution."""
    from harnessreducer import api
    source = tmp_path / "harness.cpp"
    original = (
        "#include <cstdint>\n#include <cstddef>\n"
        "struct Point {int x,y;}; void consume(Point);\n"
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {'
        "Point p = {2,3}; consume(p); return 0;}\n"
    )
    source.write_text(original)
    seed = tmp_path / "input"
    seed.write_bytes(b"hello")
    for name in ("check_tree_reducer", "check_harness_compilation", "check_reducer_crash_pattern",
                 "check_reducer_symbolized_crash_pattern", "check_reducer_symbolized_reduction_oracle",
                 "resolve_amortized_link_inputs", "format_reduced_harness", "_append_inline_stack_diagnostics"):
        monkeypatch.setattr(api, name, lambda *a, **kw: None)
    monkeypatch.setattr(api, "has_static_target_libraries", lambda *a: False)
    monkeypatch.setattr(api, "extract_crash_pattern_from_output", lambda *a, **kw: "reference")
    monkeypatch.setattr(api, "get_reference_crash_pattern_symbolize_1", lambda: "symbolized-reference")
    validations = []
    def validate(path, *a, **kwargs):
        validations.append((path, kwargs.get("fdp_trace_file")))
        return retry_succeeds and "Point p = {2,3};" in Path(path).read_text()
    for name in ("validate_crash_pattern_and_stack_trace", "validate_symbolized_crash_pattern_depth_location"):
        monkeypatch.setattr(api, name, validate)
    reductions = []
    def reduce(path, trace, pattern, flags, link, crash_input, **kwargs):
        reductions.append((path, kwargs))
        assert trace is None
        assert kwargs["compilation_mode"] == mode and kwargs["amortize_link"] == plugin
        assert kwargs["symbolize"] == symbolize
        assert kwargs["jobs"] == 2 and kwargs["stable"] is True
        text = Path(path).read_text()
        output = Path(runner.get_work_dir()) / "reduced_harness.cpp"
        if len(reductions) == 1:
            text = text.replace("Point p = {2,3};", "Point p;")
        else:
            assert "HR_KEEP_INIT_" in text
        output.write_text(text)
        return str(output)
    monkeypatch.setattr(api, "run_treereducer", reduce)
    # The analyzer's command/diagnostic filtering is tested separately with Clang;
    # this test isolates retry orchestration and both existing validators.
    monkeypatch.setattr(recovery, "analyze_uninitialized", lambda *a: InitializationDiagnosis("uninitialized-use", ({},), 1, "log"))
    monkeypatch.setattr(recovery, "verify_preparation", lambda *a, **kw: None)
    result = api.reduce_with_config(api.ReductionConfig(
        str(source), crash_input=str(seed), work_dir=str(tmp_path / "work"),
        jobs=2, stable=True, symbolize=symbolize, compilation_mode=mode,
        amortize_link=plugin, protect_initializers=True,
    ))
    assert result.success is retry_succeeds
    assert not list((tmp_path / "work").rglob("*.raw.cpp"))
    assert len(reductions) == 2
    assert len(validations) == (3 if retry_succeeds else 4)
    assert all(trace is None for _, trace in validations)
    assert "HR_KEEP_INIT_" not in Path(result.reduced_harness).read_text()
    assert "initializer_definitions.h" not in Path(result.reduced_harness).read_text()
    assert source.read_text() == original
    assert "Point p = {2,3};" in Path(result.tagged_harness).read_text()


@pytest.mark.parametrize("symbolize", [False, True])
def test_restore_result_and_snapshot_before_fdp_inlining(work, monkeypatch, symbolize):
    from harnessreducer import api
    from harnessreducer.initializer_protection import prepare_initializer_protection
    original = "void f(){int n=fdp.ConsumeIntegral<int>(100001); consume(n);}\n"
    work.write_text(original)
    protection = prepare_initializer_protection(work, work.parent / "protected")
    monkeypatch.setattr(api, "format_reduced_harness", lambda *a: None)
    trace = str(work.parent / "original-trace.log")
    calls = []
    def reduce(source, trace_file, pattern, flags, link_flags, crash_input, **kwargs):
        calls.append(kwargs)
        assert trace_file == trace and kwargs["snapshot"]
        assert kwargs["symbolize"] is symbolize
        result = work.parent / "reduced_harness.cpp"
        # Model the runner after its existing include/macro restoration step.
        result.write_text(Path(source).read_text())
        Path(runner.get_last_interesting_file()).write_text(Path(source).read_text())
        return str(result)
    def inline(source, trace_file, *a, **kwargs):
        assert trace_file == trace
        assert Path(source).read_text() == original
        assert Path(runner.get_last_interesting_file()).read_text() == original
        assert kwargs["snapshot"] and kwargs["symbolize"] is symbolize
        # Real inlining/validation, including partial/zero replacements, has
        # separate tests. This verifies that it sees the original FDP call/ID.
        return PostReductionOutcome(source)
    monkeypatch.setattr(api, "run_treereducer", reduce)
    monkeypatch.setattr(api, "inline_literals_in_reduced_harness", inline)
    result = api._reduction_attempt(
        api.ReductionConfig(str(work), snapshot=True, symbolize=symbolize,
                            compilation_mode="pch", amortize_link=True),
        str(protection.source), trace, "fast-reference", "symbolized-reference", "", protection,
    )
    assert result.validated and len(calls) == 1

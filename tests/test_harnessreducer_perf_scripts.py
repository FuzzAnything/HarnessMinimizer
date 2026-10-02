"""Batch evaluation tests use synthetic reductions and never execute a target."""
import csv
import json
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

import make_harnessreducer_perf_tables as tables
import run_harnessreducer_perf_sweep as sweep
from harnessreducer.evaluation_metrics import (
    count_source_tokens, source_metrics, token_reduction_percent, write_json,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repository(tmp_path, monkeypatch):
    root = tmp_path / "repo with spaces and 'quotes'"
    root.mkdir()
    for dataset, filename in sweep.DATASETS:
        bench = root / "benchmark" / dataset / "case-1"
        bench.mkdir(parents=True)
        (bench / "harness.cpp").write_text('#include <cstdint>\nint unused; int main() { return 0; }\n')
        (bench / "crash-input").write_bytes(b"x")
        with (root / filename).open("w", newline="") as stream:
            writer = csv.writer(stream, delimiter="\t")
            writer.writerow(["benchmark", "compile_flags", "link_flags"])
            writer.writerow(["case-1", '-I$(pwd)/include -DNAME="two words"', '-L${PWD}/lib -lexample'])
    monkeypatch.setattr(sweep, "PROJECT_ROOT", root)
    return root


def profile(tool, optimized):
    factor = 1 if optimized else 2
    return {
        "configuration": {"tool": tool, "initializer_recovery": {
            "status": "recovered", "attempt_count": 2, "final_validated": True,
        }},
        "reducer": {
            "wall_seconds": 10.0 * factor, "profiled_checks": 40,
            "checks_per_second": 4.0 / factor,
            "result_counts": {"77": 10, "1": 15, "-1": 15},
            "mean_in_flight_checks": 0.8, "worker_utilization": 0.8,
        },
        "candidate_timing": {
            field: {"mean_ns": 100_000_000 * factor}
            for field in ("python_import_ns", "compile_ns", "link_ns", "execute_ns", "total_ns")
        },
    }


def fake_reducer(monkeypatch, failure=None):
    commands = []
    active = False
    def reduce(command, **kwargs):
        nonlocal active
        assert not active, "reductions must be serial"
        active = True
        commands.append(command)
        tool = command[command.index("--tool") + 1]
        output = Path(command[command.index("-o") + 1])
        work = Path(command[command.index("--work-dir") + 1])
        bench = kwargs["cwd"]
        assert command[command.index("--jobs") + 1] == "1"
        assert all(flag in command for flag in ("--stable", "--profile", "--capture-raw-output", "--protect-initializers"))
        assert work == output.parent / "work"
        assert command[3] == str(bench / "harness.cpp")
        assert shlex.split(next(a.split("=", 1)[1] for a in command if a.startswith("--compile-flags="))) == [f"-I{bench}/include", "-DNAME=two words"]
        assert shlex.split(next(a.split("=", 1)[1] for a in command if a.startswith("--link-flags="))) == [f"-L{bench}/lib", "-lexample"]
        optimized = "--pch" in command
        assert ("--amortize-link" in command) == optimized
        assert ("--split" in command) != optimized
        assert ("--symbolize" in command) != optimized
        work.mkdir()
        write_json(work / "stack_depth_stability.json", {"total_wall_seconds": 2 if optimized else 4})
        output.write_text('#include <cstdint>\n#define VALUE 42\nint final_value = 42;\n')
        # Raw, restored and inlined text deliberately have different sizes.
        (work / "reduced_harness.cpp").write_text("int restored = 42;\n")
        if failure != "missing_raw" or len(commands) != 1:
            output.with_suffix(".raw.cpp").write_text('#include "temporary_macro.h"\nint x;\n')
        write_json(output.parent / "reduction_profile.json", profile(tool, optimized))
        if failure == "bad_profile" and len(commands) == 1:
            (output.parent / "reduction_profile.json").write_text("invalid json")
        active = False
        if failure == "spawn" and len(commands) == 1:
            raise OSError("synthetic launch failure")
        return subprocess.CompletedProcess(command, 9 if failure == "exit" and len(commands) == 1 else 0)
    monkeypatch.setattr(sweep, "run_supervised", reduce)
    # Each pair has raw walls 12 / 24 and adjusted walls 10 / 20.
    ticks = iter([value for i in range(100) for value in (i * 100, i * 100 + (12 if i % 2 == 0 else 24))])
    monkeypatch.setattr(sweep.time, "perf_counter", lambda: next(ticks))
    return commands


def batch(root):
    return next((root / "output/evaluation").iterdir())


def read_csv(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.mark.parametrize("tool", sweep.TOOL_CHOICES)
def test_serial_two_dataset_evaluation_and_reports(repository, monkeypatch, tool):
    commands = fake_reducer(monkeypatch)
    assert sweep.main(["--tool", tool]) == 0
    assert len(commands) == 4
    root = batch(repository)
    manifest = json.loads((root / "run_manifest.json").read_text())
    assert manifest["status"] == "completed" and manifest["report_returncode"] == 0
    assert [run["dataset"] for run in manifest["runs"]] == ["harness-bug"] * 2 + ["library-bug"] * 2
    assert [run["configuration"] for run in manifest["runs"]] == ["optimized", "split_symbolize"] * 2
    assert len({run["work_dir"] for run in manifest["runs"]}) == 4
    summary = read_csv(root / "evaluation_summary.csv")
    assert len(summary) == 4
    for run, row in zip(manifest["runs"], summary):
        assert run["status"] == row["status"] == "success"
        assert row["measurement_stage"] == "raw_reducer_output"
        assert int(row["remaining_tokens"]) == 6
        original = count_source_tokens(root / run["original_source"])
        assert float(row["token_reduction_percent"]) == pytest.approx(100 * (1 - 6 / original))
        assert int(row["final_output_bytes"]) == (root / run["output"]).stat().st_size
        assert row["initializer_recovery"] == "recovered" and row["reduction_attempts"] == "2"
        assert int(row["total_checks"]) == 40
        assert float(row["checks_per_second"]) == (4 if run["configuration"] == "optimized" else 2)
        assert float(row["full_command_wall_seconds"]) == (10 if run["configuration"] == "optimized" else 20)
        assert json.loads((root / run["run_info"]).read_text())["raw_reduced_harness"] == run["raw_reduced_harness"]
        assert shlex.split((root / run["directory"] / "command.txt").read_text()) == run["command"]
    per_case = root / "harness-bug/case-1" / tool
    rows = read_csv(per_case / f"performance_comparison_{tool}_case-1.csv")
    assert len(rows) == 3 and rows[2]["row_type"] == "speedup"
    for field in (*tables.TIME_METRICS, "checks_per_second"):
        assert float(rows[2][field]) == 2
    assert (per_case / f"performance_tables_{tool}_case-1.txt").is_file()
    # Regeneration reads this batch's raw artifacts, never final/work output or
    # cached metrics; changing the original harness later doesn't change its copy.
    for run in manifest["runs"]:
        Path(run["harness"]).write_text("int changed_original;")
        (root / run["output"]).write_text("int changed_final;")
        (root / run["directory"] / "source_reduction_metrics.json").write_text('{"remaining_tokens":9999}')
    assert tables.main(["--results-dir", str(root)]) == 0
    regenerated = read_csv(root / "evaluation_summary.csv")
    assert [r["remaining_tokens"] for r in regenerated] == [r["remaining_tokens"] for r in summary]
    assert [r["original_tokens"] for r in regenerated] == [r["original_tokens"] for r in summary]


@pytest.mark.parametrize("failure", ["exit", "spawn", "missing_raw", "bad_profile"])
def test_failures_continue_and_partial_reports_have_no_speedups(repository, monkeypatch, failure):
    commands = fake_reducer(monkeypatch, failure)
    assert sweep.main(["--tool", "wdd"]) == 1
    assert len(commands) == 4
    root = batch(repository)
    rows = read_csv(root / "evaluation_summary.csv")
    assert rows[0]["status"] != "success" and all(r["status"] == "success" for r in rows[1:])
    if failure == "missing_raw":
        assert rows[0]["remaining_tokens"] == rows[0]["token_reduction_percent"] == ""
        assert "raw_reduced_harness" in rows[0]["errors"]
    assert len(read_csv(root / "harness-bug/case-1/wdd/performance_comparison_wdd_case-1.csv")) == 2
    assert len(read_csv(root / "library-bug/case-1/wdd/performance_comparison_wdd_case-1.csv")) == 3
    assert tables.main(["--results-dir", str(root)]) == 1


def test_report_failure_affects_batch_exit(repository, monkeypatch):
    commands = fake_reducer(monkeypatch)
    monkeypatch.setattr(tables, "generate_reports", lambda root: (_ for _ in ()).throw(OSError("synthetic disk failure")))
    assert sweep.main(["--tool", "cdd"]) == 1
    assert len(commands) == 4
    manifest = json.loads((batch(repository) / "run_manifest.json").read_text())
    assert manifest["status"] == "failed" and manifest["report_returncode"] == 1
    assert "synthetic disk failure" in manifest["report_error"]


def test_all_expansion_dry_run_creates_nothing(repository, monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sweep, "run_supervised", lambda *a, **kw: pytest.fail("dry run launched a reduction"))
    before = set(repository.rglob("*"))
    assert sweep.main(["--tool", "all", "--dry-run", "--output-root", "custom results"]) == 0
    commands = [shlex.split(line) for line in capsys.readouterr().out.splitlines() if " -m harnessreducer.cli " in line]
    assert len(commands) == 16
    assert {c[c.index("--tool") + 1] for c in commands} == {"treereduce", "perses", "wdd", "cdd"}
    assert all(c[c.index("--jobs") + 1] == "1" for c in commands)
    assert all("--capture-raw-output" in c for c in commands)
    assert all(str(repository / "custom results") in c[c.index("-o") + 1] for c in commands)
    assert set(repository.rglob("*")) == before


def test_full_shell_dry_run_from_another_directory(tmp_path):
    destination = tmp_path / "must not be created"
    result = subprocess.run(
        [str(ROOT / "run_harnessreducer_evaluation.sh"), "--tool", "all", "--dry-run", "--output-root", str(destination)],
        cwd=tmp_path, capture_output=True, text=True, check=True,
    )
    assert "1600 reductions; --jobs 1, serial" in result.stdout
    commands = [shlex.split(line) for line in result.stdout.splitlines() if " -m harnessreducer.cli " in line]
    assert len(commands) == 1600
    assert all(c[c.index("--jobs") + 1] == "1" for c in commands)
    assert not destination.exists()


def test_required_tool_and_fixed_worker_count():
    for argv in ([], ["--tool", "other"], ["--tool", "all", "--jobs", "2"]):
        with pytest.raises(SystemExit):
            sweep.build_parser().parse_args(argv)


@pytest.mark.parametrize("damage", ["columns", "duplicate", "missing_input", "quoting"])
def test_dry_run_validates_both_tsvs(repository, damage):
    path = repository / "library_bug_cases.tsv"
    if damage == "columns":
        path.write_text("benchmark,compile_flags,link_flags\n")
    elif damage == "duplicate":
        with path.open("a") as stream:
            stream.write("case-1\t-Iinclude\t-lfoo\n")
    elif damage == "missing_input":
        (repository / "benchmark/library-bug/case-1/crash-input").unlink()
    else:
        path.write_text("benchmark\tcompile_flags\tlink_flags\ncase-1\t-I'broken\t-lfoo\n")
    with pytest.raises(SystemExit):
        sweep.main(["--tool", "all", "--dry-run"])
    assert not (repository / "output").exists()


def test_placeholders_are_literal_and_preserve_argument_boundaries(tmp_path):
    bench = tmp_path / "space ' quote $dollar"
    flags = '-I$(pwd)/one -L"${PWD}/two three" {bench_dir}/four $PWD/five -DMSG="$(touch not-executed);`uname`"'
    actual = shlex.split(sweep.expand_benchmark_placeholders(flags, bench))
    assert actual == [f"-I{bench}/one", f"-L{bench}/two three", f"{bench}/four", f"{bench}/five", '-DMSG=$(touch not-executed);`uname`']
    assert not (tmp_path / "not-executed").exists()


def test_raw_token_counts_do_not_expand_headers_or_use_final(tmp_path):
    original, raw, final = [tmp_path / name for name in ("original.cpp", "raw.cpp", "final.cpp")]
    original.write_text('int a, b, c; // comment\n')
    raw.write_text('#include "huge.h"\n')
    final.write_text('int restored; int inlined;')
    (tmp_path / "huge.h").write_text('int expanded;\n' * 1000)
    metrics = source_metrics(original, raw, final)
    assert metrics["remaining_tokens"] == 3
    assert metrics["token_reduction_percent"] == pytest.approx(100 * (1 - 3 / 7))
    raw.unlink()
    assert source_metrics(original, raw, final)["remaining_tokens"] is None
    assert source_metrics(original, raw, final)["token_reduction_percent"] is None
    raw.write_text("")
    assert source_metrics(original, raw, final)["remaining_tokens"] == 0
    assert token_reduction_percent(0, 0) is None


def test_interrupted_batch_reports_all_planned_rows(repository, monkeypatch):
    fake_reducer(monkeypatch)
    assert sweep.main(["--tool", "perses"]) == 0
    root = batch(repository)
    manifest = json.loads((root / "run_manifest.json").read_text())
    manifest["status"] = "running"
    manifest["runs"][0]["status"] = "running"
    manifest["runs"][0]["returncode"] = None
    (root / manifest["runs"][0]["raw_reduced_harness"]).unlink()
    write_json(root / "run_manifest.json", manifest)
    assert tables.generate_reports(root) == 1
    rows = read_csv(root / "evaluation_summary.csv")
    assert len(rows) == 4 and rows[0]["status"] == "incomplete"
    assert rows[0]["remaining_tokens"] == ""


def test_reporter_rejects_legacy_results(tmp_path):
    write_json(tmp_path / "run_manifest.json", {"tool": "perses", "runs": []})
    assert tables.main(["--results-dir", str(tmp_path)]) == 1

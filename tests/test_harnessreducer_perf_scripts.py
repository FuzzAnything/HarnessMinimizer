"""Performance-script tests with synthetic profiles, never real reductions."""

import csv
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import collect_harnessreducer_perf_csvs as collector
import make_harnessreducer_perf_tables as tables
import run_harnessreducer_perf_sweep as sweep


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def profile(tool, optimized):
    factor = 1 if optimized else 2
    return {
        "configuration": {"tool": tool, "engine": {"tool": tool}},
        "reducer": {
            "wall_seconds": 10.0 * factor,
            "profiled_checks": 40,
            "checks_per_second": 4.0 / factor,
            "result_counts": {"77": 10, "1": 15, "-1": 15},
            "mean_in_flight_checks": 0.8,
            "worker_utilization": 0.8,
        },
        "candidate_timing": {
            field: {"mean_ns": 100_000_000 * factor}
            for field in ("python_import_ns", "compile_ns", "link_ns", "execute_ns", "total_ns")
        },
    }


@pytest.mark.parametrize("tool", sweep.TOOL_CHOICES)
def test_sweep_passes_tool_and_tables_infer_it(tmp_path, monkeypatch, tool):
    jobs = list(sweep.DEFAULT_JOBS)
    bench = tmp_path / "benchmark with spaces"
    bench.mkdir()
    (bench / "harness.cpp").write_text("int unused; int main() { return 0; }\n")
    (bench / "crash-input").write_bytes(b"input")
    commands = []

    def fake_reduction(command, **kwargs):
        # This stub creates output metadata; it never compiles or executes C++.
        commands.append(command)
        assert command[command.index("--tool") + 1] == tool
        assert kwargs["cwd"] == bench
        assert "--profile" in command and "--stable" in command
        assert command.count("--protect-initializers") == 1
        assert f"--compile-flags=-I{bench}/include" in command
        assert f"--link-flags=-L{bench}/lib -lexample" in command
        optimized = "--pch" in command
        assert ("--amortize-link" in command) == optimized
        assert ("--symbolize" in command) != optimized
        assert ("--split" in command) != optimized
        output = Path(command[command.index("-o") + 1])
        work = Path(command[command.index("--work-dir") + 1])
        assert work == output.parent / "work"
        sweep_root = output.parents[2]
        assert json.loads((sweep_root / "run_manifest.json").read_text())["status"] == "running"
        marker = bench / sweep.TOOL_MARKER_TEMPLATE.format(tool=tool)
        assert marker.read_text().strip() == str(sweep_root)
        output.write_text("int main() { return 0; }\n")
        summary = profile(tool, optimized)
        summary["configuration"]["initializer_recovery"] = {
            "status": "not-needed", "attempt_count": 1, "final_validated": True,
        }
        write_json(output.parent / "reduction_profile.json", summary)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(sweep, "run_supervised", fake_reduction)
    monkeypatch.setattr(sys, "argv", [
        "sweep", "--dir", str(bench), "--tool", tool,
        "--compile-flags=-I{bench_dir}/include", "--link-flags=-L$(pwd)/lib -lexample",
    ])
    assert sweep.main() == 0
    assert len(commands) == 2 * len(jobs)
    root = Path((bench / sweep.LATEST_MARKER_NAME).read_text().strip())
    assert root.name.startswith(f"harnessreducer-perf-comparison-{tool}-")
    manifest = json.loads((root / "run_manifest.json").read_text())
    assert manifest["schema_version"] == 2
    assert manifest["tool"] == tool
    assert manifest["protect_initializers"] is True
    assert manifest["status"] == "completed"
    assert {run["tool"] for run in manifest["runs"]} == {tool}
    assert len({run["work_dir"] for run in manifest["runs"]}) == 2 * len(jobs)
    for run in manifest["runs"]:
        assert run["protect_initializers"] is True
        saved_run = json.loads((Path(run["output"]).parent / "run_info.json").read_text())
        assert saved_run["protect_initializers"] is True
        assert run["total_checks"] == 40
        assert run["source_reduction_metrics"]["token_reduction_percent"] > 0

    # Fixed numbers keep speedup assertions independent of this test's runtime.
    for variant, wall in (("optimized", 12.0), ("split-symbolize", 24.0)):
        for job in jobs:
            (root / variant / f"jobs-{job}" / "full_command_wall_seconds.txt").write_text(str(wall))
    monkeypatch.setattr(sys, "argv", ["tables", "--dir", str(bench)])
    assert tables.main() == 0
    text_path = root / f"performance_tables_{tool}_{bench.name}.txt"
    csv_path = root / f"performance_comparison_{tool}_{bench.name}.csv"
    assert f"Tool:      {tool}" in text_path.read_text()
    with csv_path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert [row["jobs"] for row in rows] == [str(job) for job in jobs for _ in range(3)]
    assert [row["result_type"] for row in rows[:3]] == [
        "optimized", "non_optimized_split_symbolize", "optimized_speedup_x",
    ]
    assert rows[0]["total_checks"] == "40"
    assert rows[0]["initializer_recovery"] == "not-needed"
    assert int(rows[0]["original_tokens"]) > int(rows[0]["final_tokens"])
    assert float(rows[0]["token_reduction_percent"]) > 0
    assert float(rows[0]["compile_milliseconds"]) == 100.0
    for column in (
        "reduction_wall_seconds", "full_command_wall_seconds", "checks_per_second",
        "python_setup_milliseconds", "compile_milliseconds", "link_milliseconds",
        "execute_milliseconds", "total_per_check_milliseconds",
    ):
        assert float(rows[2][column]) == 2.0
    assert rows[2]["total_checks"] == ""


def test_sweep_defaults_and_invalid_options():
    base = ["--dir", "libaom-1", "--compile-flags=", "--link-flags="]
    args = sweep.build_parser().parse_args(base)
    assert args.tool == "treereduce"
    assert args.jobs == [1, 2, 4, 8, 16, 32, 60]
    assert args.protect_initializers
    assert sweep.build_parser().parse_args(base + ["--protect-initializers"]).protect_initializers
    for extra in (["--tool", "creduce"], ["--jobs", "64"], ["--jobs", "0"]):
        with pytest.raises(SystemExit):
            sweep.build_parser().parse_args(base + extra)


def test_csv_records_recovery_and_uses_combined_summary(tmp_path):
    optimized = {1: {"summary": profile("perses", True), "full_wall": 12.0}}
    split = {1: {"summary": profile("perses", False), "full_wall": 24.0}}
    for row, status, attempts in ((optimized[1], "recovered", 2), (split[1], "not-needed", 1)):
        row["summary"]["configuration"]["initializer_recovery"] = {
            "status": status, "attempt_count": attempts, "final_validated": True,
        }
    path = tmp_path / "report.csv"
    tables.write_comparison_csv(path, optimized, split)
    with path.open() as stream:
        rows = list(csv.DictReader(stream))
    assert rows[0]["initializer_recovery"] == "recovered"
    assert rows[0]["reduction_attempts"] == "2"
    assert rows[1]["reduction_attempts"] == "1"
    assert rows[2]["initializer_recovery"] == ""
    assert float(rows[2]["reduction_wall_seconds"]) == 2.0


def test_reports_reject_mixed_protection_policies(tmp_path):
    first = {"summary": profile("perses", True), "job_dir": tmp_path}
    second = {"summary": profile("perses", False), "job_dir": tmp_path}
    first["summary"]["configuration"]["initializer_recovery"] = {
        "status": "not-needed", "attempt_count": 1, "final_validated": True,
    }
    with pytest.raises(SystemExit, match="mixed initializer"):
        tables.validate_sweep({}, {1: first}, {1: second})


def test_infer_legacy_and_profile_only_tools():
    assert tables.infer_tool({}) == "treereduce"
    assert tables.infer_tool({"runs": [{"command": ["python3", "-m", "harnessreducer", "--tool", "wdd"]}]}) == "wdd"
    assert tables.infer_tool({}, {1: {"run_info": {"command": ["--tool=sfc"]}}}) == "sfc"
    assert tables.infer_tool({}, {1: {"summary": profile("cdd", True)}}) == "cdd"
    assert tables.infer_tool({"tool": "perses"}) == "perses"


def test_infer_rejects_conflicts_and_unsafe_names():
    with pytest.raises(SystemExit, match="conflicting reduction tools"):
        tables.infer_tool({"tool": "wdd"}, {1: {"summary": profile("cdd", True)}})
    with pytest.raises(SystemExit, match="conflicting reduction tools"):
        tables.infer_tool({}, {1: {"run_info": {"tool": "wdd"}}}, {1: {"run_info": {"tool": "sfc"}}})
    for value in ("../perses", "", 1, "a/b"):
        with pytest.raises(SystemExit, match="invalid recorded tool"):
            tables.infer_tool({"tool": value})


def test_old_sweep_output_gets_treereduce_name_and_explicit_paths_work(tmp_path, monkeypatch):
    bench = tmp_path / "libaom-1"
    root = bench / "harnessreducer-perf-comparison-old"
    root.mkdir(parents=True)
    (bench / "harness.cpp").write_text("int main() { return 0; }")
    for variant in ("optimized", "split-symbolize"):
        job = root / variant / "jobs-1"
        job.mkdir(parents=True)
        summary = profile("treereduce", variant == "optimized")
        del summary["configuration"]
        write_json(job / "reduction_profile.json", summary)
        (job / "reduced.cpp").write_text("int main() {}")
        (job / "full_command_wall_seconds.txt").write_text("12.0")
    argv = ["tables", "--dir", str(bench), "--results-dir", str(root)]
    monkeypatch.setattr(sys, "argv", argv)
    assert tables.main() == 0
    assert (root / "performance_comparison_treereduce_libaom-1.csv").is_file()
    assert (root / "performance_tables_treereduce_libaom-1.txt").is_file()
    monkeypatch.setattr(sys, "argv", argv + [
        "--output", str(tmp_path / "custom.txt"), "--csv-output", str(tmp_path / "custom.csv"),
    ])
    assert tables.main() == 0
    assert (tmp_path / "custom.txt").is_file()
    assert (tmp_path / "custom.csv").is_file()


def test_collection_copies_nested_files_without_overwriting_and_is_repeatable(tmp_path):
    source = tmp_path / "library-bug"
    destination = tmp_path / "temp"
    files = {
        "bug-1/run-a/results.csv": b"value\n1\n",
        "bug-1/run-b/results.csv": b"value\n2\n",
        "bug-2/results.csv": b"value\n1\n",
        "bug-1/run-b/performance_comparison_wdd_bug-1.csv": b"value\n3\n",
        "bug-1/run-c/performance_comparison_perses_bug-1.csv": b"value\n4\n",
        "bug-2/OTHER.CSV": b"value\n5\n",
    }
    for name, content in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (source / "not-csv.txt").write_text("ignore")
    (source / "linked.csv").symlink_to(source / "bug-2/results.csv")
    (source / "linked-directory").symlink_to(source / "bug-2", target_is_directory=True)
    destination.mkdir()
    (destination / "results.csv").write_bytes(b"keep this original\n")
    first = collector.collect_csvs(source, destination)
    assert first["csv_files_found"] == 6
    assert first["copied"] == 5
    assert first["already_present"] == 1
    assert first["skipped_csv_symlinks"] == 1
    assert (destination / "results.csv").read_bytes() == b"keep this original\n"
    for row in first["files"]:
        assert (destination / row["destination"]).read_bytes() == files[row["source"]]
    assert (destination / "results__2.csv").is_file()
    assert (destination / "results__3.csv").is_file()
    second = collector.collect_csvs(source, destination)
    assert second["copied"] == 0
    assert second["already_present"] == 6
    assert first["manifest"] != second["manifest"]
    for name, content in files.items():
        assert (source / name).read_bytes() == content


def test_collection_rejects_recursive_destination_and_handles_empty_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError, match="outside"):
        collector.collect_csvs(source, source / "output")
    with pytest.raises(ValueError, match="not found"):
        collector.collect_csvs(tmp_path / "missing", tmp_path / "output")
    result = collector.collect_csvs(source, tmp_path / "output")
    assert result["csv_files_found"] == 0
    assert Path(result["manifest"]).is_file()


def test_collector_default_paths_do_not_depend_on_working_directory(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    source = root / "benchmark/library-bug"
    source.mkdir(parents=True)
    (source / "values.csv").write_text("value\n1\n")
    monkeypatch.setattr(collector, "PROJECT_ROOT", root)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["collect"])
    assert collector.main() == 0
    assert (root / "temp/values.csv").is_file()


def saved_sweep(bench, name, tool="wdd", created="2026-09-01T00:00:00+00:00", status="completed"):
    bench.mkdir(parents=True, exist_ok=True)
    (bench / "harness.cpp").write_text("int original; int main() { return 0; }")
    root = bench / name
    root.mkdir(parents=True)
    write_json(root / "run_manifest.json", {
        "tool": tool, "created": created, "status": status, "jobs": [1],
    })
    for variant in ("optimized", "split-symbolize"):
        job = root / variant / "jobs-1"
        job.mkdir(parents=True)
        write_json(job / "reduction_profile.json", profile(tool, variant == "optimized"))
        (job / "reduced.cpp").write_text("int main() { return 0; }")
        (job / "full_command_wall_seconds.txt").write_text("12.0")
    return root


def test_latest_per_tool_reports_only_newest_and_ignores_report_mtime(tmp_path, monkeypatch):
    bench = tmp_path / "libaom-1"
    old_runs = {}
    new_runs = {}
    for index, tool in enumerate(("treereduce", "perses", "wdd", "cdd", "sfc")):
        old_runs[tool] = saved_sweep(bench, f"harnessreducer-perf-comparison-{tool}-old", tool)
        new_runs[tool] = saved_sweep(
            bench, f"harnessreducer-perf-comparison-{tool}-new", tool,
            created=f"2026-09-02T0{index}:00:00+00:00",
        )
        # Rewriting an old report must not make that sweep become the latest.
        os.utime(old_runs[tool], (2_000_000_000, 2_000_000_000))
    (bench / sweep.LATEST_MARKER_NAME).write_text(str(old_runs["perses"]))
    (bench / sweep.TOOL_MARKER_TEMPLATE.format(tool="wdd")).write_text(str(old_runs["wdd"]))
    assert tables.latest_results_by_tool(bench) == new_runs
    assert tables.latest_results_dir(bench) == new_runs["sfc"]

    monkeypatch.setattr(sys, "argv", ["tables", "--dir", str(bench), "--tool", "wdd"])
    assert tables.main() == 0
    assert len(list(bench.glob("*/performance_comparison_*.csv"))) == 1
    assert (new_runs["wdd"] / "performance_comparison_wdd_libaom-1.csv").is_file()
    monkeypatch.setattr(sys, "argv", ["tables", "--dir", str(bench), "--all-tools"])
    assert tables.main() == 0
    for tool, root in new_runs.items():
        assert (root / f"performance_comparison_{tool}_libaom-1.csv").is_file()
        assert (root / f"performance_tables_{tool}_libaom-1.txt").is_file()
    for root in old_runs.values():
        assert not list(root.glob("performance_*"))
    assert tables.latest_results_by_tool(bench) == new_runs


def test_latest_markers_find_custom_paths_and_skip_stale_markers(tmp_path):
    bench = tmp_path / "libaom-1"
    bench.mkdir()
    external = tmp_path / "external"
    wdd = saved_sweep(external, "custom wdd path")
    perses = saved_sweep(external, "custom perses path", "perses")
    for tool, root in (("wdd", wdd), ("perses", perses)):
        (bench / sweep.TOOL_MARKER_TEMPLATE.format(tool=tool)).write_text(str(root))
    (bench / sweep.LATEST_MARKER_NAME).write_text(str(wdd))
    (bench / sweep.TOOL_MARKER_TEMPLATE.format(tool="sfc")).write_text(str(tmp_path / "deleted"))
    (bench / sweep.TOOL_MARKER_TEMPLATE.format(tool="cdd")).write_text("\n")
    assert tables.latest_results_by_tool(bench) == {"perses": perses, "wdd": wdd}


def test_latest_legacy_falls_back_to_directory_timestamp_and_profile_tool(tmp_path):
    bench = tmp_path / "libaom-1"
    roots = []
    for date in ("20200101", "20200102"):
        root = saved_sweep(bench, f"harnessreducer-perf-comparison-{date}-010203", "treereduce")
        (root / "run_manifest.json").unlink()
        for variant in ("optimized", "split-symbolize"):
            data = profile("treereduce", variant == "optimized")
            del data["configuration"]
            write_json(root / variant / "jobs-1/reduction_profile.json", data)
        roots.append(root)
    os.utime(roots[0], (2_000_000_000, 2_000_000_000))
    only_profile = saved_sweep(bench, "harnessreducer-perf-comparison-20200103-010203", "cdd")
    (only_profile / "run_manifest.json").unlink()
    assert tables.latest_results_by_tool(bench) == {"treereduce": roots[1], "cdd": only_profile}


@pytest.mark.parametrize("status", ["running", "failed"])
def test_newest_incomplete_run_is_not_replaced_with_older_success(tmp_path, monkeypatch, capsys, status):
    bench = tmp_path / "libaom-1"
    older = saved_sweep(bench, "harnessreducer-perf-comparison-wdd-older")
    latest = bench / "harnessreducer-perf-comparison-wdd-latest"
    latest.mkdir()
    write_json(latest / "run_manifest.json", {
        "tool": "wdd", "created": "2026-09-02T00:00:00+00:00", "status": status,
    })
    other_tool = saved_sweep(bench, "harnessreducer-perf-comparison-sfc-good", "sfc")
    monkeypatch.setattr(sys, "argv", ["tables", "--dir", str(bench), "--all-tools"])
    assert tables.main() == 1
    assert "not marked completed" in capsys.readouterr().err
    assert not list(older.glob("performance_*"))
    assert not list(latest.glob("performance_*"))
    assert (other_tool / "performance_comparison_sfc_libaom-1.csv").is_file()
    assert tables.latest_results_dir(bench, "wdd") == latest


def test_legacy_partial_worker_sweep_does_not_silently_make_partial_comparison(tmp_path, monkeypatch):
    bench = tmp_path / "libaom-1"
    root = saved_sweep(bench, "harnessreducer-perf-comparison-partial")
    write_json(root / "run_manifest.json", {"tool": "wdd", "jobs": [1, 2]})
    monkeypatch.setattr(sys, "argv", ["tables", "--dir", str(bench), "--tool", "wdd"])
    with pytest.raises(SystemExit, match="not all requested worker"):
        tables.main()
    assert not list(root.glob("performance_*"))


def test_explicit_results_tool_must_match_and_all_tools_disallows_single_output(tmp_path, monkeypatch):
    bench = tmp_path / "libaom-1"
    root = saved_sweep(bench, "harnessreducer-perf-comparison-wdd-example")
    monkeypatch.setattr(sys, "argv", ["tables", "--dir", str(bench), "--tool", "perses", "--results-dir", str(root)])
    with pytest.raises(SystemExit, match="requested tool perses, but results record wdd"):
        tables.main()
    base = ["tables", "--dir", str(bench), "--all-tools"]
    for extra in (["--results-dir", str(root)], ["--output", "one.txt"], ["--csv-output", "one.csv"], ["--tool", "wdd"]):
        monkeypatch.setattr(sys, "argv", base + extra)
        with pytest.raises(SystemExit):
            tables.main()
    assert not list(root.glob("performance_*"))


def test_latest_empty_benchmark_skips_all_but_explicit_tool_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["tables", "--dir", str(tmp_path), "--all-tools"])
    assert tables.main() == 0
    monkeypatch.setattr(sys, "argv", ["tables", "--dir", str(tmp_path), "--tool", "wdd"])
    with pytest.raises(SystemExit, match="no performance result"):
        tables.main()


def test_runner_publishes_per_tool_marker_even_when_sweep_fails(tmp_path, monkeypatch):
    bench = tmp_path / "libaom-1"
    bench.mkdir()
    (bench / "harness.cpp").write_text("int main() {}")
    (bench / "crash-input").write_bytes(b"input")
    external = tmp_path / "custom results"

    def fail(command, **kwargs):
        marker = bench / sweep.TOOL_MARKER_TEMPLATE.format(tool="wdd")
        assert marker.read_text().strip() == str(external)
        assert json.loads((external / "run_manifest.json").read_text())["status"] == "running"
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(sweep, "run_supervised", fail)
    monkeypatch.setattr(sys, "argv", [
        "sweep", "--dir", str(bench), "--tool", "wdd", "--jobs", "1",
        "--compile-flags=", "--link-flags=", "--output-root", str(external),
    ])
    assert sweep.main() == 1
    assert json.loads((external / "run_manifest.json").read_text())["status"] == "failed"
    assert tables.latest_results_dir(bench, "wdd") == external

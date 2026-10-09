"""Protocol and routing tests; no library crash investigation is needed."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import chdir, nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from harnessminimizer import api, reducer_runner
from harnessminimizer.cli import build_parser
from harnessminimizer.process_supervisor import run_supervised
from harnessminimizer.reduction_engines import (
    CANDIDATE_PLACEHOLDER, PERSES_COMMIT, TOOL_CHOICES, PersesRuntime, ReducerInvocation,
    absolute_checker_paths, check_perses, perses_flags, prepare_reducer_invocation, write_perses_test_script,
)


def fake_runtime():
    return PersesRuntime(
        ("java", "-Xmx4g", "-jar", "/test/perses.jar"),
        "test-digest", "test-version", "java 17", PERSES_COMMIT,
    )


class TestEngineSelection(unittest.TestCase):
    def test_cli_defaults_and_choices(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["h.cpp", "-o", "r.cpp"]).tool, "treereduce")
        for tool in TOOL_CHOICES:
            args = parser.parse_args(["h.cpp", "-o", "r.cpp", "--tool", tool, "--jobs", "4"])
            self.assertEqual((args.tool, args.jobs), (tool, 4))

    def test_presets_enable_only_selected_methods(self):
        for tool, minimizer in (("perses", "DFS"), ("wdd", "WDD"), ("cdd", "CDD")):
            for stable in (False, True):
                with self.subTest(tool=tool, stable=stable):
                    flags = perses_flags(tool, stable=stable, jobs=8)
                    opts = dict(zip(flags[::2], flags[1::2]))
                    self.assertEqual(opts["--default-list-minimizer-for-kleene"], minimizer)
                    self.assertEqual(opts["--alg"], "node_priority")
                    self.assertEqual(opts["--cleanup-alg"], "node_priority")
                    self.assertEqual(opts["--threads"], "8")
                    for method in ("latra", "trec", "lpr", "sfc", "vulcan"):
                        self.assertEqual(opts[f"--enable-{method}"], str(method == tool).lower())
                    self.assertEqual(opts["--global-caching"], "false")
                    self.assertEqual(opts["--query-caching"], "true")
                    self.assertEqual(opts["--fixpoint"], str(stable).lower())
                    self.assertEqual(opts["--global-fixpoint"], str(stable).lower())
                    for method in ("sfc", "vulcan"):
                        self.assertEqual(opts[f"--{method}-fixpoint"], str(stable and method == tool).lower())


    def test_perses_api_preflight_does_not_require_treereduce(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(api, "check_perses") as probe, \
             patch.object(api, "check_tree_reducer") as tree_probe, \
             patch.object(api, "check_harness_compilation", side_effect=RuntimeError("stop after preflight")):
            for tool in ("perses", "wdd", "cdd"):
                with self.assertRaisesRegex(RuntimeError, "stop after preflight"):
                    api.reduce_with_config(api.ReductionConfig("unused.cpp", work_dir=tmp, tool=tool))
            self.assertEqual(probe.call_count, 3)
            tree_probe.assert_not_called()

    def test_process_api_passes_tool(self):
        with patch.object(api, "reduce_with_config", return_value=api.ReductionResult("r.cpp", "t.cpp", None)) as reduce:
            self.assertEqual(api.process("h.cpp", tool="wdd"), "r.cpp")
        self.assertEqual(reduce.call_args.args[0].tool, "wdd")

    def test_missing_jar_and_invalid_tool_fail_before_execution(self):
        with patch.dict(os.environ, {"HARNESSMINIMIZER_PERSES_JAR": "/nonexistent/perses.jar"}):
            with self.assertRaisesRegex(RuntimeError, "tools/perses/install.py"):
                check_perses()
        with self.assertRaisesRegex(ValueError, "Unknown reduction tool"):
            api.reduce_with_config(api.ReductionConfig("unused.cpp", tool="latra"))

    def test_only_setup_paths_are_made_absolute(self):
        command = absolute_checker_paths([
            "tests/crash_tester.py", "@@.cpp", "pattern/path",
            "--fdp-trace", "trace.log", "--profile-file=results/events.jsonl",
            "--crash-input", "", "--compile-flags=-I/include -O0",
        ])
        self.assertEqual(command[0], str(Path("tests/crash_tester.py").resolve()))
        self.assertEqual(command[1:3], ["@@.cpp", "pattern/path"])
        self.assertEqual(command[4], str(Path("trace.log").resolve()))
        self.assertEqual(command[5], f"--profile-file={Path('results/events.jsonl').resolve()}")
        self.assertEqual(command[7:], ["", "--compile-flags=-I/include -O0"])


@unittest.skipUnless(shutil.which("timeout"), "GNU timeout is required")
class TestPersesAdapter(unittest.TestCase):
    def test_exit_mapping_and_quoted_arguments(self):
        with tempfile.TemporaryDirectory(prefix="adapter space '") as tmp:
            root = Path(tmp)
            checker = root / "checker with spaces.py"
            arguments = root / "received.json"
            checker.write_text(
                "import json, sys\nfrom pathlib import Path\n"
                "Path(sys.argv[2]).write_text(json.dumps(sys.argv[1:]))\n"
                "sys.exit(int(Path(sys.argv[1]).read_text()))\n", encoding="utf-8",
            )
            candidate_dir = root / "separate candidate directory"
            candidate_dir.mkdir()
            candidate = candidate_dir / "candidate.cpp"
            quoted_flags = "--compile-flags=-I/a path -DMSG=\"hi there\";$(touch never-created);@@.cpp"
            script = candidate_dir / "interesting.sh"
            write_perses_test_script(
                script, [str(checker), CANDIDATE_PLACEHOLDER, str(arguments), quoted_flags],
                checker_cwd=root,
            )
            for result_code in (77, 1, -1, 0, 2, 124):
                with self.subTest(result=result_code):
                    candidate.write_text(str(result_code))
                    proc = run_supervised(["/bin/sh", str(script)], cwd=candidate_dir, timeout=5)
                    self.assertEqual(proc.returncode, 0 if result_code == 77 else 1)
                    self.assertEqual(json.loads(arguments.read_text()), [str(candidate), str(arguments), quoted_flags])
            candidate.unlink()
            self.assertNotEqual(run_supervised(["/bin/sh", str(script)], cwd=candidate_dir).returncode, 0)
            self.assertFalse((candidate_dir / "never-created").exists())
            self.assertFalse((root / "never-created").exists())

    def test_relative_data_and_current_candidates_with_parallel_workers(self):
        with tempfile.TemporaryDirectory(prefix="adapter $ ' ") as tmp:
            root = Path(tmp)
            benchmark = root / "original invocation directory"
            (benchmark / "data" / "nested").mkdir(parents=True)
            resource = benchmark / "data" / "nested" / "value.txt"
            resource.write_text("ready")
            (root / "shared.txt").write_text("shared")
            # A stale original must never be substituted for the current file.
            (benchmark / "candidate.cpp").write_text("77")
            checker = root / "checker.py"
            checker.write_text(
                "import json, sys\nfrom pathlib import Path\n"
                "candidate = Path(sys.argv[1])\n"
                "assert candidate.is_absolute()\n"
                "(candidate.parent / 'observed.json').write_text(json.dumps({\n"
                "    'cwd': str(Path.cwd()), 'candidate': str(candidate),\n"
                "    'content': candidate.read_text()}))\n"
                "if not Path('data/nested/value.txt').is_file(): sys.exit(1)\n"
                "assert Path('data/nested/value.txt').read_text() == 'ready'\n"
                "assert Path('../shared.txt').read_text() == 'shared'\n"
                "sys.exit(int(candidate.read_text()))\n"
            )
            template = root / "interesting.sh"
            with chdir(benchmark):
                write_perses_test_script(template, [str(checker), CANDIDATE_PLACEHOLDER])
            parent_cwd = Path.cwd()
            candidates = []
            for index, code in enumerate((77, 1, -1, 77)):
                directory = root / f"worker {index} ' $(touch forbidden)"
                directory.mkdir()
                candidate = directory / "candidate.cpp"
                candidate.write_text(str(code))
                shutil.copy2(template, directory / "interesting.sh")
                candidates.append((directory, code))

            def run_candidate(item):
                directory, code = item
                # A stale inherited PWD must not redirect the candidate lookup.
                result = run_supervised(
                    ["/bin/sh", "interesting.sh"], cwd=directory, timeout=5,
                    env={**os.environ, "PWD": str(benchmark)},
                )
                return directory, code, result.returncode

            with ThreadPoolExecutor(max_workers=2) as pool:
                for directory, code, result_code in pool.map(run_candidate, candidates):
                    self.assertEqual(result_code, 0 if code == 77 else 1)
                    self.assertEqual(json.loads((directory / "observed.json").read_text()), {
                        "cwd": str(benchmark), "candidate": str(directory / "candidate.cpp"),
                        "content": str(code),
                    })
            self.assertEqual(Path.cwd(), parent_cwd)
            self.assertEqual(resource.read_text(), "ready")
            directory, _ = candidates[0]
            (directory / "candidate.cpp").write_text("1")
            self.assertEqual(run_candidate((directory, 1))[2], 1)
            (directory / "candidate.cpp").write_text("77")
            resource.unlink()
            self.assertEqual(run_candidate((directory, 77))[2], 1)
            (directory / "candidate.cpp").unlink()
            self.assertEqual(run_candidate((directory, 77))[2], 1)
            self.assertEqual((benchmark / "candidate.cpp").read_text(), "77")
            self.assertFalse((benchmark / "forbidden").exists())

    def test_missing_original_directory_rejects_before_invoking_checker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original_cwd = root / "original"
            original_cwd.mkdir()
            (root / "candidate.cpp").write_text("unused")
            checker = root / "checker.py"
            checker.write_text("raise AssertionError('checker must not run')\n")
            script = root / "interesting.sh"
            write_perses_test_script(
                script, [str(checker), CANDIDATE_PLACEHOLDER], checker_cwd=original_cwd,
            )
            original_cwd.rmdir()
            result = run_supervised(
                ["/bin/sh", str(script)], cwd=root, timeout=5,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("AssertionError", result.stderr)
            self.assertIn(str(original_cwd), result.stderr)
            with self.assertRaisesRegex(ValueError, "Checker working directory does not exist"):
                write_perses_test_script(
                    script, [str(checker), CANDIDATE_PLACEHOLDER], checker_cwd=original_cwd,
                )

    def test_timeout_cleans_up_supervised_checker_descendants(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker = root / "hanging.py"
            child_pid = root / "child.pid"
            child_code = f"import os,time;from pathlib import Path;Path({str(child_pid)!r}).write_text(str(os.getpid()));time.sleep(60)"
            checker.write_text(
                "import sys\nfrom harnessminimizer.process_supervisor import run_supervised\n"
                f"run_supervised([sys.executable, '-c', {child_code!r}], timeout=None)\n",
            )
            candidate_dir = root / "candidate directory"
            candidate_dir.mkdir()
            (candidate_dir / "candidate.cpp").write_text("unused")
            script = candidate_dir / "interesting.sh"
            write_perses_test_script(
                script, [str(checker), CANDIDATE_PLACEHOLDER],
                timeout_seconds=1, checker_cwd=root,
            )
            start = time.monotonic()
            result = run_supervised(["/bin/sh", str(script)], cwd=candidate_dir, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertLess(time.monotonic() - start, 5)
            self.assertTrue(child_pid.is_file(), "The test must actually launch a descendant")
            proc_stat = Path("/proc") / child_pid.read_text() / "stat"
            self.assertFalse(proc_stat.exists(), "A timed-out check left its child behind")

    @patch("harnessminimizer.reduction_engines.check_perses", side_effect=lambda: fake_runtime())
    def test_input_is_copied_and_stale_output_is_not_used(self, _probe):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.cpp"
            original.write_text("int original;")
            destination = root / "reduced.cpp"
            destination.write_text("stale previous result")
            invocations = [prepare_reducer_invocation(
                tool="wdd", source=str(original), output=str(destination),
                checker_command=["/test/check.py", CANDIDATE_PLACEHOLDER], stable=True, jobs=1,
            ) for _ in range(2)]
            first, second = invocations
            self.assertNotEqual(first.result, second.result)
            self.assertEqual((first.cwd / "candidate.cpp").read_text(), "int original;")
            with self.assertRaisesRegex(RuntimeError, "expected result"):
                first.publish_result()
            self.assertEqual(destination.read_text(), "stale previous result")
            first.result.parent.mkdir()
            first.result.write_text("int reduced;")
            first.publish_result()
            self.assertEqual(destination.read_text(), "int reduced;")
            self.assertEqual(original.read_text(), "int original;")
            metadata = json.loads((root / "reduction_engine.json").read_text())
            self.assertEqual(metadata["perses"]["source_commit"], PERSES_COMMIT)
            self.assertEqual(metadata["checker_working_directory"], str(Path.cwd()))



class TestEngineRunnerRouting(unittest.TestCase):
    def tearDown(self):
        reducer_runner.TREEDUCER_DIR = None
        reducer_runner._IS_USER_WORK_DIR = False
        reducer_runner.reset_stack_trace_state()

    @patch("harnessminimizer.reduction_engines.check_perses", side_effect=lambda: fake_runtime())
    def test_runner_dispatches_to_perses_with_optional_profiling(self, _probe):
        for profiling in (False, True):
            with self.subTest(profile=profiling), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root / "harness.cpp"
                source.write_text("#define VALUE 7\nint value;\n")
                reducer_runner.configure_work_dir(tmp)
                module = reducer_runner
                run = reducer_runner.run_treereducer

                def pretend_perses(command, **kwargs):
                    output = Path(command[command.index("--output-dir") + 1])
                    output.mkdir()
                    prepared = Path(command[command.index("--input-file") + 1]).read_text()
                    self.assertNotIn("#define", prepared)
                    (output / "candidate.cpp").write_text(prepared.replace("int value;", "int result;"))
                    if profiling:
                        metadata = json.loads((root / "reduction_engine.json").read_text())
                        checker = metadata["checker_command"]
                        profile = Path(checker[checker.index("--profile-file") + 1])
                        events = [{
                            "result_code": code, "compile_success": success,
                            "start_wall_ns": i * 200, "end_wall_ns": i * 200 + 100,
                            "durations_ns": {"compile_ns": compile_ns, "total_ns": 100},
                        } for i, (code, success, compile_ns) in enumerate(((77, True, 11), (-1, False, 99)))]
                        profile.write_text("".join(json.dumps(event) + "\n" for event in events))
                    return subprocess.CompletedProcess(command, 0)

                with patch.object(module, "calibrate_exec_timeout_ms", return_value=2000), \
                     patch.object(module, "run_supervised", side_effect=pretend_perses):
                    result = run(
                        str(source), None, "pattern", None, None, None,
                        tool="cdd", jobs=2, stable=True,
                        profile=profiling, symbolize=False,
                    )
                self.assertEqual(Path(result).read_text(), "#define VALUE 7\nint result;\n")
                metadata = json.loads((root / "reduction_engine.json").read_text())
                checker = metadata["checker_command"]
                self.assertEqual("--profile-file" in checker, profiling)
                if not profiling:
                    self.assertFalse(list(root.glob("*profile*")))
                self.assertEqual(metadata["tool"], "cdd")
                self.assertEqual(metadata["checker_working_directory"], str(Path.cwd()))
                if profiling:
                    profile = json.loads((root / "reduction_profile.json").read_text())
                    self.assertEqual(profile["configuration"]["tool"], "cdd")
                    self.assertEqual(profile["configuration"]["compilation_mode"], "split")
                    self.assertEqual(profile["reducer"]["profiled_checks"], 2)
                    self.assertEqual(profile["reducer"]["result_counts"], {"77": 1, "-1": 1})
                    self.assertEqual(profile["candidate_timing"]["compile_ns"]["mean_ns"], 11)

    @patch("harnessminimizer.reduction_engines.check_perses", side_effect=lambda: fake_runtime())
    def test_pch_and_amortized_link_paths_reach_the_shared_checker(self, _probe):
        with tempfile.TemporaryDirectory(prefix="perses pch ") as tmp:
            root = Path(tmp)
            source = root / "harness.cpp"
            source.write_text("#include <stddef.h>\nint value;")
            body = root / "body.cpp"
            body.write_text("int value;")
            pch = root / "headers.pch"
            pch.write_text("mock PCH")
            artifacts = SimpleNamespace(body_source=str(body), pch_file=str(pch), amortize_link=True)
            socket = str(root / "runner.sock")
            reducer_runner.configure_work_dir(tmp)

            def pretend_perses(command, **kwargs):
                prepared = Path(command[command.index("--input-file") + 1])
                self.assertEqual(prepared.read_text(), body.read_text())
                output = Path(command[command.index("--output-dir") + 1])
                output.mkdir()
                (output / "candidate.cpp").write_text("int reduced;")
                return subprocess.CompletedProcess(command, 0)

            with patch.object(reducer_runner, "prepare_phase3_pch_harness", return_value=artifacts), \
                 patch.object(reducer_runner, "calibrate_exec_timeout_ms", return_value=2000), \
                 patch.object(reducer_runner, "start_amortized_runner", side_effect=lambda *a, **k: nullcontext(SimpleNamespace(socket_path=socket))), \
                 patch.object(reducer_runner, "run_amortized_reference_candidate", return_value=""), \
                 patch.object(reducer_runner, "_append_restore_transition_stack_diagnostics"), \
                 patch.object(reducer_runner, "restore_pch_includes") as restore, \
                 patch.object(reducer_runner, "run_supervised", side_effect=pretend_perses):
                result = reducer_runner.run_treereducer(
                    str(source), str(root / "trace.log"), "pattern", None, None,
                    str(root / "input.bin"), tool="perses", compilation_mode="pch", amortize_link=True,
                    symbolize=False,
                )
            metadata = json.loads((root / "reduction_engine.json").read_text())
            self.assertEqual(metadata["checker_working_directory"], str(Path.cwd()))
            checker = metadata["checker_command"]
            self.assertEqual(checker[checker.index("--pch-path") + 1], str(pch))
            self.assertEqual(checker[checker.index("--amortized-runner-socket") + 1], socket)
            self.assertEqual(checker[checker.index("--fdp-trace") + 1], str(root / "trace.log"))
            restore.assert_called_once_with(result, artifacts)
            self.assertEqual(Path(result).read_text(), "int reduced;")


@pytest.mark.parametrize("stable", [False, True])
@pytest.mark.parametrize("jobs", [1, 63])
def test_treereduce_command_preserves_checker_arguments(tmp_path, stable, jobs):
    source = tmp_path / "quoted ' source.cpp"
    source.write_text("int main() { return 7; }\n")
    output = tmp_path / "reduced.cpp"
    checker = ["checker.py", "@@.cpp", "--compile-flags=-I/path with spaces", "$(literal)"]
    with patch("harnessminimizer.reduction_engines.treereduce_binary", return_value="/tools/treereduce-c"):
        invocation = prepare_reducer_invocation(
           source=str(source), output=str(output), checker_command=checker,
            stable=stable, jobs=jobs,
        )
    expected = ["/tools/treereduce-c", "-j", str(jobs), "-s", str(source), "-o", str(output)]
    expected += ["--stable", "--min-reduction", "1"] if stable else ["--fast"]
    expected += ["--timeout", "300", "--interesting-exit-code", "77", "--", *checker]
    assert invocation.command == expected
    assert invocation.metadata["tool"] == "treereduce"


@pytest.mark.parametrize("jobs", [0, 64])
def test_worker_validation_precedes_source_preparation(tmp_path, jobs):
    with pytest.raises(ValueError, match="between 1 and 63"):
        prepare_reducer_invocation(
            source="missing.cpp", output=str(tmp_path / "reduced.cpp"),
            checker_command=["checker.py", "@@.cpp"], stable=False, jobs=jobs,
        )


def test_invocation_preserves_supervision_and_failure_status(tmp_path):
    output = tmp_path / "reduced.cpp"
    invocation = ReducerInvocation(["treereduce-c"], output, output, {})
    failure = subprocess.CompletedProcess(invocation.command, 1, "failure", "")
    supervisor = Mock(return_value=failure)
    assert invocation.run(supervisor) is failure
    supervisor.assert_called_once_with(
        ["treereduce-c"], stderr=subprocess.STDOUT, text=True,
        check=False, timeout=None, private_tmpdir=True,
    )
    with pytest.raises(RuntimeError, match="expected result"):
        invocation.publish_result()


def test_api_checks_treereduce_before_compiling(tmp_path):
    with patch.object(api, "check_tree_reducer", side_effect=RuntimeError("missing treereduce")) as check, \
            patch.object(api, "check_harness_compilation") as compile, \
            patch.object(api, "check_perses") as perses:
        with pytest.raises(RuntimeError, match="missing treereduce"):
            api.reduce_with_config(api.ReductionConfig("h.cpp", work_dir=str(tmp_path)))
    check.assert_called_once_with()
    compile.assert_not_called()
    perses.assert_not_called()


@pytest.mark.parametrize("tool", ["sfc", "vulcan", "all", "invalid"])
def test_invalid_api_engine_is_rejected_without_creating_work(tmp_path, tool):
    work = tmp_path / "not-created"
    with pytest.raises(ValueError, match="Unknown reduction tool"):
        api.reduce_with_config(api.ReductionConfig("unused.cpp", work_dir=str(work), tool=tool))
    assert not work.exists()


@pytest.mark.parametrize("missing,heap,message", [
    ("java", "4g", "Java"), ("timeout", "4g", "timeout"),
    (None, "0g", "positive size"), (None, "4g; echo invalid", "positive size"),
])
def test_perses_preflight_rejects_missing_tools_and_invalid_heap(tmp_path, monkeypatch, missing, heap, message):
    jar = tmp_path / "external.jar"
    jar.write_bytes(b"mock external JAR")
    monkeypatch.setenv("HARNESSMINIMIZER_PERSES_JAR", str(jar))
    monkeypatch.setenv("HARNESSMINIMIZER_PERSES_HEAP", heap)
    with patch("harnessminimizer.reduction_engines.shutil.which", side_effect=lambda name: None if name == missing else f"/tools/{name}"), \
            patch("harnessminimizer.reduction_engines._inspect_perses") as inspect:
        with pytest.raises((RuntimeError, ValueError), match=message):
            check_perses()
    inspect.assert_not_called()


@pytest.mark.parametrize("tool", ["perses", "wdd", "cdd"])
def test_failed_perses_engine_does_not_publish_or_fall_back(tmp_path, monkeypatch, tool):
    monkeypatch.setattr(reducer_runner, "TREEDUCER_DIR", str(tmp_path))
    source = tmp_path / "source.cpp"
    source.write_text("int value;\n")

    def fail(command, **kwargs):
        kwargs["stdout"].write("engine failed\n")
        return subprocess.CompletedProcess(command, 1)

    with patch("harnessminimizer.reduction_engines.check_perses", return_value=fake_runtime()), \
            patch("harnessminimizer.reduction_engines.treereduce_binary") as tree, \
            patch.object(ReducerInvocation, "publish_result") as publish, \
            patch.object(reducer_runner, "calibrate_exec_timeout_ms", return_value=2000), \
            patch.object(reducer_runner, "run_supervised", side_effect=fail):
        with pytest.raises(RuntimeError, match=f"Failed to run {tool} reducer"):
            reducer_runner.run_treereducer(str(source), None, "pattern", None, None, None,
                                         tool=tool, symbolize=False, jobs=1)
    tree.assert_not_called()
    publish.assert_not_called()
    assert not list(tmp_path.glob("*profile*"))

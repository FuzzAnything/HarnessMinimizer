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
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

from harnessreducer import api, check_mode, reducer_runner
from harnessreducer.cli import build_parser
from harnessreducer.process_supervisor import run_supervised
from harnessreducer.reduction_engines import (
    CANDIDATE_PLACEHOLDER, PERSES_COMMIT, TOOL_CHOICES, PersesRuntime,
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
        for tool, minimizer in (("perses", "DFS"), ("wdd", "WDD"), ("cdd", "CDD"), ("sfc", "DFS"), ("vulcan", "DFS")):
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

    def test_treereduce_command_is_preserved(self):
        with patch("harnessreducer.reduction_engines.check_perses") as probe:
            invocation = prepare_reducer_invocation(
                tool="treereduce", source="source.cpp", output="reduced.cpp",
                checker_command=["/test/check.py", CANDIDATE_PLACEHOLDER, "pattern"],
                stable=True, jobs=2,
            )
        probe.assert_not_called()
        self.assertEqual(invocation.command[1:], [
            "-j", "2", "-s", "source.cpp", "-o", "reduced.cpp",
            "--stable", "--min-reduction", "1", "--timeout", "300",
            "--interesting-exit-code", "77", "--", "/test/check.py", "@@.cpp", "pattern",
        ])

    def test_perses_api_preflight_does_not_require_treereduce(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(api, "check_perses") as probe, \
             patch.object(api, "check_tree_reducer") as tree_probe, \
             patch.object(api, "check_harness_compilation", side_effect=RuntimeError("stop after preflight")):
            for tool in ("perses", "wdd", "cdd", "sfc", "vulcan"):
                with self.assertRaisesRegex(RuntimeError, "stop after preflight"):
                    api.reduce_with_config(api.ReductionConfig("unused.cpp", work_dir=tmp, tool=tool))
            self.assertEqual(probe.call_count, 5)
            tree_probe.assert_not_called()

    def test_process_api_passes_tool(self):
        with patch.object(api, "reduce_with_config", return_value=api.ReductionResult("r.cpp", "t.cpp", None)) as reduce:
            self.assertEqual(api.process("h.cpp", tool="sfc"), "r.cpp")
        self.assertEqual(reduce.call_args.args[0].tool, "sfc")

    def test_missing_jar_and_invalid_tool_fail_before_execution(self):
        with patch.dict(os.environ, {"HARNESSREDUCER_PERSES_JAR": "/nonexistent/perses.jar"}):
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
            quoted_flags = "--compile-flags=-I/a path -DMSG=\"hi there\";$(touch never-created)"
            script = candidate_dir / "interesting.sh"
            write_perses_test_script(script, [str(checker), CANDIDATE_PLACEHOLDER, str(arguments), quoted_flags])
            for result_code in (77, 1, -1, 0, 2, 124):
                with self.subTest(result=result_code):
                    candidate.write_text(str(result_code))
                    proc = run_supervised(["/bin/sh", str(script)], cwd=candidate_dir, timeout=5)
                    self.assertEqual(proc.returncode, 0 if result_code == 77 else 1)
                    self.assertEqual(json.loads(arguments.read_text()), ["./candidate.cpp", str(arguments), quoted_flags])
            candidate.unlink()
            self.assertNotEqual(run_supervised(["/bin/sh", str(script)], cwd=candidate_dir).returncode, 0)
            self.assertFalse((candidate_dir / "never-created").exists())

    def test_timeout_cleans_up_supervised_checker_descendants(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker = root / "hanging.py"
            child_pid = root / "child.pid"
            child_code = f"import os,time;from pathlib import Path;Path({str(child_pid)!r}).write_text(str(os.getpid()));time.sleep(60)"
            checker.write_text(
                "import sys\nfrom harnessreducer.process_supervisor import run_supervised\n"
                f"run_supervised([sys.executable, '-c', {child_code!r}], timeout=None)\n",
            )
            (root / "candidate.cpp").write_text("unused")
            script = root / "interesting.sh"
            write_perses_test_script(script, [str(checker), CANDIDATE_PLACEHOLDER], timeout_seconds=1)
            start = time.monotonic()
            result = run_supervised(["/bin/sh", str(script)], cwd=root, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertLess(time.monotonic() - start, 5)
            self.assertTrue(child_pid.is_file(), "The test must actually launch a descendant")
            proc_stat = Path("/proc") / child_pid.read_text() / "stat"
            self.assertFalse(proc_stat.exists(), "A timed-out check left its child behind")

    @patch("harnessreducer.reduction_engines.check_perses", side_effect=lambda: fake_runtime())
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

    @patch("harnessreducer.reduction_engines.check_perses", side_effect=lambda: fake_runtime())
    def test_upstream_vulcan_failure_is_not_treated_as_success(self, _probe):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.cpp"
            source.write_text("int value;")
            destination = root / "reduced.cpp"
            destination.write_text("previous result")
            invocation = prepare_reducer_invocation(
                tool="vulcan", source=str(source), output=str(destination),
                checker_command=["/test/check.py", CANDIDATE_PLACEHOLDER], stable=True, jobs=1,
            )

            def failing_engine(command, **kwargs):
                kwargs["stdout"].write(
                    'Exception in thread "main" kotlin.NotImplementedError: Not supported yet\n'
                    'at org.perses.spartree.MinimalSparTreeGenerator.preBuildSparTreeNodeRec\n'
                )
                return subprocess.CompletedProcess(command, 1)

            result = invocation.run(failing_engine)
            self.assertEqual(result.returncode, 1)
            self.assertIn("unsupported grammar operation", result.stdout)
            self.assertIn("No successful result will be published", result.stdout)
            self.assertEqual(destination.read_text(), "previous result")


class TestEngineRunnerRouting(unittest.TestCase):
    def tearDown(self):
        reducer_runner.TREEDUCER_DIR = None
        reducer_runner._IS_USER_WORK_DIR = False
        reducer_runner.reset_stack_trace_state()

    @patch("harnessreducer.reduction_engines.check_perses", side_effect=lambda: fake_runtime())
    def test_normal_and_diagnostic_runners_dispatch_to_perses(self, _probe):
        for diagnostic in (False, True):
            with self.subTest(diagnostic=diagnostic), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root / "harness.cpp"
                source.write_text("int value;")
                reducer_runner.configure_work_dir(tmp)
                module = check_mode if diagnostic else reducer_runner
                run = check_mode.run_treereducer_with_check if diagnostic else reducer_runner.run_treereducer

                def pretend_perses(command, **kwargs):
                    output = Path(command[command.index("--output-dir") + 1])
                    output.mkdir()
                    (output / "candidate.cpp").write_text("int result;")
                    if not diagnostic:
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
                        **({} if diagnostic else {"profile": True}),
                    )
                self.assertEqual(Path(result).read_text(), "int result;")
                metadata = json.loads((root / "reduction_engine.json").read_text())
                checker = metadata["checker_command"]
                self.assertEqual("--check-reference-file" in checker, diagnostic)
                self.assertEqual(metadata["tool"], "cdd")
                if not diagnostic:
                    profile = json.loads((root / "reduction_profile.json").read_text())
                    self.assertEqual(profile["configuration"]["tool"], "cdd")
                    self.assertEqual(profile["reducer"]["profiled_checks"], 2)
                    self.assertEqual(profile["reducer"]["result_counts"], {"77": 1, "-1": 1})
                    self.assertEqual(profile["candidate_timing"]["compile_ns"]["mean_ns"], 11)

    @patch("harnessreducer.reduction_engines.check_perses", side_effect=lambda: fake_runtime())
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
                    str(root / "input.bin"), tool="perses", phase3_mode="pch", amortize_link=True,
                )
            checker = json.loads((root / "reduction_engine.json").read_text())["checker_command"]
            self.assertEqual(checker[checker.index("--pch-path") + 1], str(pch))
            self.assertEqual(checker[checker.index("--amortized-runner-socket") + 1], socket)
            self.assertEqual(checker[checker.index("--fdp-trace") + 1], str(root / "trace.log"))
            restore.assert_called_once_with(result, artifacts)
            self.assertEqual(Path(result).read_text(), "int reduced;")


if __name__ == "__main__":
    unittest.main()

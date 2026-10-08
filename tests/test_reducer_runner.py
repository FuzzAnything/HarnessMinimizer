import unittest
import tempfile
import os
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harnessreducer import reducer_runner
from harnessreducer.dynamic_slicer import CoverageMap
from harnessreducer.macro_headers import MacroPreparation


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestReducerRunner(unittest.TestCase):
    def setUp(self):
        # These command-routing tests mock the reducer and use nonexistent
        # source/output paths. Real preparation and restoration have separate
        # filesystem/native tests in test_macro_headers and test_reduction_engines.
        for mock in (
            patch("harnessreducer.reduction_engines.prepare_macro_headers",
                  side_effect=lambda source, work: MacroPreparation(source)),
            patch("harnessreducer.reduction_engines.ReducerInvocation.publish_result"),
        ):
            mock.start()
            self.addCleanup(mock.stop)
        reducer_runner.TREEDUCER_DIR = None
        reducer_runner._IS_USER_WORK_DIR = False
        reducer_runner.set_normal_reference_stack_depth(None)
        reducer_runner.set_symbolized_reference_stack_depth(None)
        reducer_runner.set_normal_reference_stack_depth_strict(False)
        reducer_runner.set_symbolized_reference_stack_depth_strict(False)
        reducer_runner.set_dynamic_reference_crash_site(None)
        reducer_runner.set_symbolized_reference_crash_location_pattern(None)
        reducer_runner.configure_debug_logging(False)

    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_run_command_success(self, mock_run):
        mock_run.return_value = _Proc(returncode=0, stdout="ok", stderr="")
        proc = reducer_runner.run_command(["echo", "ok"], "failed")
        self.assertEqual(proc.stdout, "ok")

    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_run_command_failure(self, mock_run):
        mock_run.return_value = _Proc(returncode=2, stdout="", stderr="err")
        with self.assertRaises(RuntimeError):
            reducer_runner.run_command(["false"], "failed")

    def test_sanitizer_asan_options_can_disable_odr_violation(self):
        self.assertEqual(
            reducer_runner.sanitizer_asan_options(symbolize=False),
            "exitcode=77:symbolize=0:handle_abort=1",
        )
        self.assertEqual(
            reducer_runner.sanitizer_asan_options(
                symbolize=True,
                detect_odr_violation=False,
            ),
            "exitcode=77:symbolize=1:handle_abort=1:detect_odr_violation=0",
        )

    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_run_treereducer_sets_env(self, mock_run, mock_exists):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True
        reducer_runner.set_normal_reference_stack_depth(12)
        reducer_runner.set_normal_reference_stack_depth_strict(True)

        out = reducer_runner.run_treereducer(
            symbolize=False,
            harness_path="/tmp/in.cpp",
            fdp_trace_file="/tmp/trace.log",
            crash_pattern="AddressSanitizer",
            compile_flags="-std=c++17",
            link_flags="-lm",
            crash_input="seed.bin",
        )

        self.assertTrue(out.endswith("reduced_harness.cpp"))
        cmd = mock_run.call_args.args[0]
        self.assertIn("--compile-flags=-std=c++17", cmd)
        self.assertIn("--link-flags=-lm", cmd)
        self.assertIn("--fdp-trace", cmd)
        self.assertIn("/tmp/trace.log", cmd)
        self.assertIn("--split", cmd)
        self.assertIn("--stack-depth", cmd)
        self.assertIn("12", cmd)
        self.assertIn("--strict-stack-depth", cmd)
        self.assertNotIn("--last-interesting-file", cmd)
        self.assertNotIn("--symbolize", cmd)

    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_normal_reduction_has_no_measurement_side_effects(self, mock_run):

        mock_run.return_value = _Proc(returncode=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            reducer_runner.configure_work_dir(tmpdir)
            reducer_runner.set_symbolized_reference_stack_depth(3)
            reducer_runner.set_symbolized_reference_crash_location_pattern(r"/src/target\.cpp:7")
            source = root / "in.cpp"
            source.write_text("int main() { return 0; }\n")
            output = root / "reduced_harness.cpp"
            output.write_text(source.read_text())
            with patch("harnessreducer.reducer_runner.initialize_candidate_profile_events_file",
                       side_effect=AssertionError("profiling is disabled")), \
                    patch("harnessreducer.reducer_runner.write_profile_summary",
                          side_effect=AssertionError("profiling is disabled")):
                self.assertEqual(
                    reducer_runner.run_treereducer(
                        str(source), None, "AddressSanitizer", None, None, None,
                        jobs=1,
                    ),
                    str(output),
                )
            command = mock_run.call_args.args[0]
            self.assertIn("--symbolize", command)
            self.assertNotIn("--profile-file", command)
            self.assertFalse(any(arg.startswith("--oracle-") for arg in command))
            self.assertEqual(command[command.index("--timeout") + 1], "300")
            for artifact in (
                "candidate_profile.jsonl", "reduction_profile.json", "reduction_profile.txt",
                "reduced_harness.raw.cpp", "paired_execution.json",
            ):
                self.assertFalse((root / artifact).exists(), artifact)

    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_run_treereducer_defaults_to_symbolized_oracle(self, mock_run):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as tmpdir:
            reducer_runner.configure_work_dir(tmpdir)
            Path(tmpdir, "reduced_harness.cpp").write_text("", encoding="utf-8")
            reducer_runner.set_symbolized_reference_stack_depth(6)
            reducer_runner.set_symbolized_reference_stack_depth_strict(True)
            reducer_runner.set_symbolized_reference_crash_location_pattern(
                r"/src/lib\.c:10:3"
            )
            reducer_runner.set_dynamic_reference_crash_site(
                reducer_runner.DynamicCrashSite(
                    library_path="/tmp/build/lib/libtarget.so",
                    library_name="libtarget.so",
                    offset="0xbeaf0",
                )
            )

            reducer_runner.run_treereducer(
                harness_path="/tmp/in.cpp",
                fdp_trace_file="/tmp/trace.log",
                crash_pattern="SymbolizedPattern",
                compile_flags=None,
                link_flags="-lm",
                crash_input=None,
            )

        cmd = mock_run.call_args.args[0]
        self.assertIn("--symbolize", cmd)
        self.assertIn("SymbolizedPattern", cmd)
        self.assertIn("--stack-depth", cmd)
        self.assertIn("6", cmd)
        self.assertIn("--strict-stack-depth", cmd)
        self.assertIn("--crash-location-pattern", cmd)
        self.assertIn(r"/src/lib\.c:10:3", cmd)
        self.assertNotIn("--crash-location-file", cmd)
        self.assertNotIn("--dynamic-crash-site-library", cmd)
        self.assertNotIn("--dynamic-crash-site-offset", cmd)

    @patch("harnessreducer.reducer_runner.run_amortized_reference_candidate")
    @patch("harnessreducer.reducer_runner.start_amortized_runner")
    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_run_treereducer_uses_amortized_runner_and_calibrated_depth(
        self,
        mock_run,
        mock_exists,
        mock_start_runner,
        mock_reference,
    ):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True
        mock_start_runner.return_value = nullcontext(
            SimpleNamespace(socket_path="/tmp/harness-runner.sock")
        )
        mock_reference.return_value = (
            "#0 0x111111 in target\n"
            "#1 0x222222 in LLVMFuzzerTestOneInput\n"
        )
        reducer_runner.set_normal_reference_stack_depth_strict(True)

        reducer_runner.run_treereducer(
            symbolize=False,
            harness_path="/tmp/in.cpp",
            fdp_trace_file="/tmp/trace.log",
            crash_pattern="AddressSanitizer",
            compile_flags=None,
            link_flags="/tmp/libtarget.so",
            crash_input=None,
            compilation_mode="split",
            amortize_link=True,
        )

        cmd = mock_run.call_args.args[0]
        self.assertIn("--amortized-runner-socket", cmd)
        self.assertIn("/tmp/harness-runner.sock", cmd)
        self.assertIn("--stack-depth", cmd)
        self.assertIn("2", cmd)
        self.assertIn("--strict-stack-depth", cmd)
        mock_reference.assert_called_once()

    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_run_treereducer_passes_snapshot_flag_when_enabled(self, mock_run, mock_exists):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        reducer_runner.run_treereducer(
            symbolize=False,
            harness_path="/tmp/in.cpp",
            fdp_trace_file="/tmp/trace.log",
            crash_pattern="AddressSanitizer",
            compile_flags=None,
            link_flags=None,
            crash_input=None,
            snapshot=True,
        )

        cmd = mock_run.call_args.args[0]
        self.assertIn("--last-interesting-file", cmd)


    @patch("harnessreducer.reducer_runner.write_profile_summary")
    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_run_treereducer_profiles_candidates_and_uses_requested_jobs(
        self,
        mock_run,
        mock_exists,
        mock_write_profile,
    ):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True
        mock_write_profile.return_value = {
            "reducer": {
                "profiled_checks": 3,
                "wall_seconds": 1.0,
                "checks_per_second": 3.0,
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            reducer_runner.configure_work_dir(tmpdir)
            source = Path(tmpdir) / "in.cpp"
            source.write_text("int main() { return 0; }\n", encoding="utf-8")
            reducer_runner.run_treereducer(
                symbolize=False,
                harness_path=str(source),
                fdp_trace_file=None,
                crash_pattern="AddressSanitizer",
                compile_flags=None,
                link_flags=None,
                crash_input=None,
                jobs=7,
                profile=True,
            )

        cmd = mock_run.call_args.args[0]
        jobs_index = cmd.index("-j")
        self.assertEqual(cmd[jobs_index + 1], "7")
        self.assertIn("--profile-file", cmd)
        mock_write_profile.assert_called_once()
        configuration = mock_write_profile.call_args.kwargs["configuration"]
        self.assertEqual(configuration["compilation_mode"], "split")
        self.assertFalse(configuration["symbolize"])

    def test_run_treereducer_rejects_out_of_range_jobs(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 63"):
            reducer_runner.run_treereducer(
                harness_path="/tmp/in.cpp",
                fdp_trace_file=None,
                crash_pattern="AddressSanitizer",
                compile_flags=None,
                link_flags=None,
                crash_input=None,
                jobs=64,
            )

    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_run_treereducer_adds_normal_path_debug_log(self, mock_run, mock_exists):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        with tempfile.TemporaryDirectory() as tmpdir:
            reducer_runner.configure_work_dir(tmpdir)
            debug_log = reducer_runner.configure_debug_logging(True)
            reducer_runner.run_treereducer(
                symbolize=False,
                harness_path="/tmp/in.cpp",
                fdp_trace_file=None,
                crash_pattern="AddressSanitizer",
                compile_flags=None,
                link_flags=None,
                crash_input=None,
            )

        cmd = mock_run.call_args.args[0]
        self.assertIn("--debug-log", cmd)
        self.assertIn(debug_log, cmd)
        self.assertIn("--debug-stage", cmd)
        self.assertIn("reduction_candidate", cmd)

    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_run_treereducer_uses_split_mode_flag(self, mock_run, mock_exists):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        reducer_runner.run_treereducer(
            symbolize=False,
            harness_path="/tmp/in.cpp",
            fdp_trace_file="/tmp/trace.log",
            crash_pattern="AddressSanitizer",
            compile_flags=None,
            link_flags=None,
            crash_input=None,
            compilation_mode="split",
        )

        cmd = mock_run.call_args.args[0]
        self.assertIn("--split", cmd)

    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.run_supervised")
    def test_run_treereducer_passes_auto_var_init_pattern_to_checker(self, mock_run, mock_exists):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        reducer_runner.run_treereducer(
            symbolize=False,
            harness_path="/tmp/in.cpp",
            fdp_trace_file=None,
            crash_pattern="AddressSanitizer",
            compile_flags=None,
            link_flags=None,
            crash_input=None,
            auto_var_init_pattern=True,
        )

        cmd = mock_run.call_args.args[0]
        self.assertIn("--auto-var-init-pattern", cmd)

    @patch("harnessreducer.reducer_runner.tempfile.mkdtemp")
    def test_configure_work_dir_uses_user_dir_without_tmp_create(self, mock_mkdtemp):
        work_dir = "/tmp/hr_fixed"
        got = reducer_runner.configure_work_dir(work_dir)
        self.assertEqual(got, str(Path(work_dir).resolve()))
        self.assertEqual(reducer_runner.TREEDUCER_DIR, str(Path(work_dir).resolve()))
        self.assertTrue(reducer_runner._IS_USER_WORK_DIR)
        mock_mkdtemp.assert_not_called()

    @patch("harnessreducer.reducer_runner.tempfile.mkdtemp")
    def test_get_work_dir_creates_tmp_when_not_configured(self, mock_mkdtemp):
        mock_mkdtemp.return_value = "/tmp/hr_auto"
        got = reducer_runner.get_work_dir()
        self.assertEqual(got, "/tmp/hr_auto")
        self.assertEqual(reducer_runner.TREEDUCER_DIR, "/tmp/hr_auto")
        self.assertFalse(reducer_runner._IS_USER_WORK_DIR)
        mock_mkdtemp.assert_called_once()

    def test_parse_llvm_cov_show_text_uses_executable_line_semantics(self):
        report = (
            "    1|      2|int main() {\n"
            "    2|      2|  if (x) {\n"
            "    3|      0|    dead();\n"
            "    4|       |  }\n"
            "    5|      2|  live();\n"
        )

        coverage = reducer_runner._parse_llvm_cov_show_text(report)

        self.assertEqual(coverage.executable_lines, frozenset({1, 2, 3, 5}))
        self.assertEqual(coverage.covered_lines, frozenset({1, 2, 5}))

    def test_coverage_count_is_nonzero_handles_scaled_and_zero_counts(self):
        self.assertTrue(reducer_runner._coverage_count_is_nonzero("1"))
        self.assertTrue(reducer_runner._coverage_count_is_nonzero("1.2k"))
        self.assertFalse(reducer_runner._coverage_count_is_nonzero("0"))
        self.assertFalse(reducer_runner._coverage_count_is_nonzero("0.0k"))
        self.assertFalse(reducer_runner._coverage_count_is_nonzero(""))

    def test_validate_compilation_mode_accepts_single_step_alias(self):
        self.assertEqual(
            reducer_runner.validate_compilation_mode("single-step"),
            reducer_runner.PHASE3_DIRECT,
        )

    def test_phase3_compile_flags_use_strict_reduction_warnings(self):
        self.assertEqual(reducer_runner.PHASE3_DIRECT_OPT_FLAGS, ["-gline-tables-only", "-O0"])
        self.assertEqual(reducer_runner.PHASE3_SPLIT_OPT_FLAGS, ["-O0", "-gline-tables-only"])
        self.assertEqual(reducer_runner.PHASE3_PCH_OPT_FLAGS, ["-O0", "-gline-tables-only"])
        self.assertEqual(
            reducer_runner.PHASE3_WARNING_FLAGS,
            [
                "-Werror=uninitialized",
                "-Werror=return-type",
            ],
        )
        self.assertEqual(reducer_runner.POST_REDUCTION_VALIDATION_ATTEMPTS, 5)

    def test_pch_tester_args_preserve_amortized_link_compile_mode(self):
        artifacts = reducer_runner.PchArtifacts(
            body_source="/tmp/body.cpp",
            prefix_header="/tmp/harness_prefix.h",
            pch_file="/tmp/harness_prefix.pch",
            restore_prefix="#include <demo.h>\n",
            amortize_link=True,
        )

        self.assertEqual(
            reducer_runner.pch_tester_args(artifacts, reducer_runner.PHASE3_PCH),
            [
                "--pch",
                "--pch-path",
                "/tmp/harness_prefix.pch",
                "--pch-amortized-link",
            ],
        )


    @patch("harnessreducer.reducer_runner.run_command")
    def test_dump_fdp_trace_clears_stale_trace_before_run(self, mock_run_command):
        with tempfile.TemporaryDirectory() as tmpdir:
            reducer_runner.configure_work_dir(tmpdir)
            trace_path = Path(tmpdir) / "fdp_trace.log"
            wide_trace_path = Path(reducer_runner.fdp_wide_trace_path(trace_path))
            trace_path.write_text("stale trace\n", encoding="utf-8")
            wide_trace_path.write_text("stale wide trace\n", encoding="utf-8")

            def write_fresh_trace(*args, **kwargs):
                self.assertFalse(trace_path.exists())
                self.assertFalse(wide_trace_path.exists())
                self.assertEqual(
                    kwargs["env"]["LD_LIBRARY_PATH"].split(os.pathsep)[0],
                    "/tmp/shared",
                )
                self.assertEqual(kwargs["env"]["FDP_WIDE_TRACE_PATH"], str(wide_trace_path))
                trace_path.write_text("S 100000 1\n", encoding="utf-8")
                wide_trace_path.write_text("V 100001 U 16 1 7\n", encoding="utf-8")
                return _Proc(returncode=77)

            mock_run_command.side_effect = write_fresh_trace

            result = reducer_runner.dump_fdp_trace(
                "/tmp/tagged.out",
                "seed.bin",
                "-L/tmp/shared -ltarget",
            )

            self.assertEqual(result, str(trace_path))
            self.assertEqual(trace_path.read_text(encoding="utf-8"), "S 100000 1\n")
            self.assertEqual(
                wide_trace_path.read_text(encoding="utf-8"),
                "V 100001 U 16 1 7\n",
            )

    @patch("harnessreducer.reducer_runner.validate_crash_pattern_and_stack_trace")
    @patch("harnessreducer.reducer_runner.collect_harness_coverage")
    @patch("harnessreducer.reducer_runner.compile_coverage_harness")
    def test_apply_coverage_guided_slice_returns_sliced_path_on_validation_success(
        self,
        mock_compile_cov,
        mock_collect_cov,
        mock_validate_trace,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            reducer_runner.configure_work_dir(tmpdir)
            source_path = Path(tmpdir) / "harness.cpp"
            source_path.write_text(
                "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
                "  if (size) {\n"
                "    live();\n"
                "  } else {\n"
                "    dead();\n"
                "  }\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            mock_compile_cov.return_value = str(Path(tmpdir) / "poc_cov.out")
            mock_collect_cov.return_value = CoverageMap(
                executable_lines=frozenset({1, 2, 4, 7}),
                covered_lines=frozenset({1, 2, 7}),
            )
            mock_validate_trace.return_value = True

            out = reducer_runner.apply_coverage_guided_slice(
                str(source_path),
                "AddressSanitizer",
                "seed.bin",
                "-std=c++17",
                "-lm",
            )

            self.assertTrue(out.endswith(".sliced.cpp"))
            self.assertTrue(Path(out).exists())
            self.assertNotIn("else", Path(out).read_text(encoding="utf-8"))
            mock_validate_trace.assert_called_once()

    @patch("harnessreducer.reducer_runner.validate_crash_pattern_and_stack_trace")
    @patch("harnessreducer.reducer_runner.collect_harness_coverage")
    @patch("harnessreducer.reducer_runner.compile_coverage_harness")
    def test_apply_coverage_guided_slice_falls_back_on_stack_trace_mismatch(
        self,
        mock_compile_cov,
        mock_collect_cov,
        mock_validate_trace,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            reducer_runner.configure_work_dir(tmpdir)
            source_path = Path(tmpdir) / "harness.cpp"
            source_path.write_text(
                "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
                "  if (size) {\n"
                "    live();\n"
                "  } else {\n"
                "    dead();\n"
                "  }\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            mock_compile_cov.return_value = str(Path(tmpdir) / "poc_cov.out")
            mock_collect_cov.return_value = CoverageMap(
                executable_lines=frozenset({1, 2, 4, 7}),
                covered_lines=frozenset({1, 2, 7}),
            )
            mock_validate_trace.return_value = False

            out = reducer_runner.apply_coverage_guided_slice(
                str(source_path),
                "AddressSanitizer",
                "seed.bin",
                None,
                None,
            )

            self.assertEqual(out, str(source_path))
            mock_validate_trace.assert_called_once()


if __name__ == "__main__":
    unittest.main()

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from harnessreducer import reducer_runner
from harnessreducer.dynamic_slicer import CoverageMap


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestReducerRunner(unittest.TestCase):
    def setUp(self):
        reducer_runner.TREEDUCER_DIR = None
        reducer_runner._IS_USER_WORK_DIR = False
        reducer_runner.set_normal_reference_stack_depth(None)
        reducer_runner.set_symbolized_reference_stack_depth(None)

    @patch("harnessreducer.reducer_runner.subprocess.run")
    def test_run_command_success(self, mock_run):
        mock_run.return_value = _Proc(returncode=0, stdout="ok", stderr="")
        proc = reducer_runner.run_command(["echo", "ok"], "failed")
        self.assertEqual(proc.stdout, "ok")

    @patch("harnessreducer.reducer_runner.subprocess.run")
    def test_run_command_failure(self, mock_run):
        mock_run.return_value = _Proc(returncode=2, stdout="", stderr="err")
        with self.assertRaises(RuntimeError):
            reducer_runner.run_command(["false"], "failed")

    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.subprocess.run")
    def test_run_treereducer_sets_env(self, mock_run, mock_exists):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True
        reducer_runner.set_normal_reference_stack_depth(12)

        out = reducer_runner.run_treereducer(
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
        self.assertIn("--stack-depth", cmd)
        self.assertIn("12", cmd)
        self.assertNotIn("--last-interesting-file", cmd)

    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.subprocess.run")
    def test_run_treereducer_passes_snapshot_flag_when_enabled(self, mock_run, mock_exists):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        reducer_runner.run_treereducer(
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

    @patch("harnessreducer.reducer_runner.initialize_statistics_file")
    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.subprocess.run")
    def test_run_treereducer_adds_statistics_file_when_enabled(
        self,
        mock_run,
        mock_exists,
        mock_initialize_statistics,
    ):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True
        mock_initialize_statistics.return_value = "/tmp/work/statistics.txt"

        reducer_runner.run_treereducer(
            harness_path="/tmp/in.cpp",
            fdp_trace_file="/tmp/trace.log",
            crash_pattern="AddressSanitizer",
            compile_flags=None,
            link_flags=None,
            crash_input=None,
            statistics=True,
        )

        cmd = mock_run.call_args.args[0]
        self.assertIn("--statistics-file", cmd)
        self.assertIn("/tmp/work/statistics.txt", cmd)

    @patch("harnessreducer.reducer_runner.os.path.exists")
    @patch("harnessreducer.reducer_runner.subprocess.run")
    def test_run_treereducer_uses_split_mode_flag(self, mock_run, mock_exists):
        mock_run.return_value = _Proc(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        reducer_runner.run_treereducer(
            harness_path="/tmp/in.cpp",
            fdp_trace_file="/tmp/trace.log",
            crash_pattern="AddressSanitizer",
            compile_flags=None,
            link_flags=None,
            crash_input=None,
            phase3_mode="split",
        )

        cmd = mock_run.call_args.args[0]
        self.assertIn("--split", cmd)

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

    def test_validate_phase3_mode_accepts_single_step_alias(self):
        self.assertEqual(
            reducer_runner.validate_phase3_mode("single-step"),
            reducer_runner.PHASE3_DIRECT,
        )

    def test_phase3_compile_flags_use_o1_and_uninitialized_error(self):
        self.assertEqual(reducer_runner.PHASE3_DIRECT_OPT_FLAGS, ["-g", "-O1"])
        self.assertEqual(reducer_runner.PHASE3_SPLIT_OPT_FLAGS, ["-O1", "-gline-tables-only"])
        self.assertEqual(reducer_runner.PHASE3_PCH_OPT_FLAGS, ["-O1", "-gline-tables-only"])
        self.assertEqual(reducer_runner.PHASE3_WARNING_FLAGS, ["-Werror=uninitialized"])

    def test_initialize_statistics_file_writes_zeroed_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reducer_runner.configure_work_dir(tmpdir)
            path = reducer_runner.initialize_statistics_file()
            text = Path(path).read_text(encoding="utf-8")
            self.assertIn("total: 0", text)
            self.assertIn("count_77: 0", text)
            self.assertIn("count_1: 0", text)
            self.assertIn("count_-1: 0", text)

    @patch("harnessreducer.reducer_runner.run_command")
    def test_dump_fdp_trace_clears_stale_trace_before_run(self, mock_run_command):
        with tempfile.TemporaryDirectory() as tmpdir:
            reducer_runner.configure_work_dir(tmpdir)
            trace_path = Path(tmpdir) / "fdp_trace.log"
            trace_path.write_text("stale trace\n", encoding="utf-8")

            def write_fresh_trace(*args, **kwargs):
                self.assertFalse(trace_path.exists())
                trace_path.write_text("S 100000 1\n", encoding="utf-8")
                return _Proc(returncode=77)

            mock_run_command.side_effect = write_fresh_trace

            result = reducer_runner.dump_fdp_trace("/tmp/tagged.out", "seed.bin")

            self.assertEqual(result, str(trace_path))
            self.assertEqual(trace_path.read_text(encoding="utf-8"), "S 100000 1\n")

    @patch("harnessreducer.reducer_runner.validate_stack_trace")
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

    @patch("harnessreducer.reducer_runner.validate_stack_trace")
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

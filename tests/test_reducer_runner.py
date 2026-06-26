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

    @patch("harnessreducer.reducer_runner.validate_stack_trace")
    @patch("harnessreducer.reducer_runner.check_reducer_crash_pattern")
    @patch("harnessreducer.reducer_runner.collect_harness_coverage")
    @patch("harnessreducer.reducer_runner.compile_coverage_harness")
    def test_apply_coverage_guided_slice_returns_sliced_path_on_validation_success(
        self,
        mock_compile_cov,
        mock_collect_cov,
        mock_check_pattern,
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
                all_point_lines=frozenset({1, 2, 4, 7}),
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
            mock_check_pattern.assert_called_once()
            mock_validate_trace.assert_called_once()

    @patch("harnessreducer.reducer_runner.validate_stack_trace")
    @patch("harnessreducer.reducer_runner.check_reducer_crash_pattern")
    @patch("harnessreducer.reducer_runner.collect_harness_coverage")
    @patch("harnessreducer.reducer_runner.compile_coverage_harness")
    def test_apply_coverage_guided_slice_falls_back_on_stack_trace_mismatch(
        self,
        mock_compile_cov,
        mock_collect_cov,
        mock_check_pattern,
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
                all_point_lines=frozenset({1, 2, 4, 7}),
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
            mock_check_pattern.assert_called_once()
            mock_validate_trace.assert_called_once()


if __name__ == "__main__":
    unittest.main()

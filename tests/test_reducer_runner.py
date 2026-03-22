import unittest
from pathlib import Path
from unittest.mock import patch

from harnessreducer import reducer_runner


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
            extra_args="-std=c++17",
            crash_input="seed.bin",
        )

        self.assertTrue(out.endswith("reduced_harness.cpp"))
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["env"]["FDP_TRACE_PATH"], "/tmp/trace.log")
        self.assertEqual(kwargs["env"]["EXTRA_FLAGS"], "-std=c++17")
        self.assertEqual(kwargs["env"]["CRASH_INPUT"], "seed.bin")

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


if __name__ == "__main__":
    unittest.main()

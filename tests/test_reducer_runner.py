import unittest
from unittest.mock import patch

from harnessreducer import reducer_runner


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestReducerRunner(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

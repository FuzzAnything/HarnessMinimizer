import unittest
from unittest.mock import patch

from harnessreducer.api import ReductionConfig, process, reduce_with_config


class TestApiPipeline(unittest.TestCase):
    @patch("harnessreducer.api.inline_literals_in_reduced_harness")
    @patch("harnessreducer.api.format_reduced_harness")
    @patch("harnessreducer.api.run_treereducer")
    @patch("harnessreducer.api.dump_fdp_trace")
    @patch("harnessreducer.api.compile_dump_mode_harness")
    @patch("harnessreducer.api.apply_coverage_guided_slice")
    @patch("harnessreducer.api.reset_stack_trace_state")
    @patch("harnessreducer.api.configure_work_dir")
    @patch("harnessreducer.api.tag_harness_with_fdp_ids")
    @patch("harnessreducer.api.check_reducer_crash_pattern")
    @patch("harnessreducer.api.extract_crash_pattern_from_output")
    @patch("harnessreducer.api.check_harness_compilation")
    @patch("harnessreducer.api.check_tree_reducer")
    def test_reduce_with_config_returns_result(
        self,
        mock_check,
        mock_check_compile,
        mock_extract,
        mock_check_pattern,
        mock_tag,
        mock_configure,
        mock_reset_stack_state,
        mock_slice,
        mock_compile,
        mock_dump,
        mock_reduce,
        mock_format,
        mock_inline,
    ):
        mock_tag.return_value = "/tmp/tagged.cpp"
        mock_compile.return_value = "/tmp/tagged.out"
        mock_dump.return_value = "/tmp/fdp_trace.log"
        mock_reduce.return_value = "/tmp/reduced.cpp"
        mock_inline.return_value = ("/tmp/reduced.cpp", ())
        mock_extract.return_value = "AddressSanitizer"
        mock_slice.return_value = "/tmp/sliced.cpp"

        config = ReductionConfig(
            harness_path="a.cpp",
            compile_flags="-std=c++17",
            link_flags="-lm",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
            start_id=123,
            marker="M",
        )

        result = reduce_with_config(config)

        self.assertEqual(result.reduced_harness, "/tmp/reduced.cpp")
        self.assertEqual(result.tagged_harness, "/tmp/tagged.cpp")
        self.assertEqual(result.fdp_trace, "/tmp/fdp_trace.log")

        mock_configure.assert_called_once_with("/tmp/workdir")
        mock_reset_stack_state.assert_called_once_with()
        mock_check_compile.assert_called_once_with("a.cpp", "-std=c++17", "-lm")
        mock_extract.assert_called_once_with("seed.bin", harness_path="a.cpp")
        mock_check_pattern.assert_called_once_with(
            "a.cpp",
            "AddressSanitizer",
            "seed.bin",
            "-std=c++17",
            "-lm",
            phase3_mode="direct",
        )
        mock_slice.assert_called_once_with(
            "a.cpp",
            "AddressSanitizer",
            "seed.bin",
            "-std=c++17",
            "-lm",
            phase3_mode="direct",
        )
        mock_tag.assert_called_once_with("/tmp/sliced.cpp", start_id=123, marker="M")
        mock_compile.assert_called_once_with("/tmp/tagged.cpp", "-std=c++17", "-lm")
        mock_dump.assert_called_once_with("/tmp/tagged.out", "seed.bin")
        mock_reduce.assert_called_once_with(
            "/tmp/tagged.cpp",
            "/tmp/fdp_trace.log",
            "AddressSanitizer",
            "-std=c++17",
            "-lm",
            "seed.bin",
            stable=False,
            phase3_mode="direct",
            iteration=None,
            statistics=False,
        )
        mock_format.assert_called_once_with("/tmp/reduced.cpp")
        mock_inline.assert_called_once_with(
            "/tmp/reduced.cpp",
            "/tmp/fdp_trace.log",
            "AddressSanitizer",
            "seed.bin",
            "-std=c++17",
            "-lm",
            123,
            phase3_mode="direct",
            iteration=None,
        )
        mock_check.assert_called_once()

    @patch("harnessreducer.api.reduce_with_config")
    def test_process_compat_wrapper(self, mock_reduce_with_config):
        cfg = ReductionConfig(
            harness_path="a.cpp",
            compile_flags=None,
            link_flags=None,
            crash_input=None,
        )
        expected_reduced = "/tmp/out.cpp"

        class ResultObj:
            reduced_harness = expected_reduced
            tagged_harness = "/tmp/tagged.cpp"
            fdp_trace = "/tmp/trace.log"
            success = True

        mock_reduce_with_config.return_value = ResultObj()

        reduced = process(cfg.harness_path, cfg.compile_flags, cfg.crash_input, link_flags=cfg.link_flags)
        self.assertEqual(reduced, expected_reduced)
        mock_reduce_with_config.assert_called_once()


if __name__ == "__main__":
    unittest.main()

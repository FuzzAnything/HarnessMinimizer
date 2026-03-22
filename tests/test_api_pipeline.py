import unittest
from unittest.mock import patch

from harnessreducer.api import ReductionConfig, process, reduce_with_config


class TestApiPipeline(unittest.TestCase):
    @patch("harnessreducer.api.inline_literals_in_reduced_harness")
    @patch("harnessreducer.api.format_reduced_harness")
    @patch("harnessreducer.api.run_treereducer")
    @patch("harnessreducer.api.dump_fdp_trace")
    @patch("harnessreducer.api.compile_dump_mode_harness")
    @patch("harnessreducer.api.configure_work_dir")
    @patch("harnessreducer.api.tag_harness_with_fdp_ids")
    @patch("harnessreducer.api.check_tree_reducer")
    def test_reduce_with_config_returns_result(
        self,
        mock_check,
        mock_tag,
        mock_configure,
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

        config = ReductionConfig(
            harness_path="a.cpp",
            crash_pattern="AddressSanitizer",
            extra_flags="-std=c++17",
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
        mock_tag.assert_called_once_with("a.cpp", start_id=123, marker="M")
        mock_compile.assert_called_once_with("/tmp/tagged.cpp", "-std=c++17")
        mock_dump.assert_called_once_with("/tmp/tagged.out", "seed.bin")
        mock_reduce.assert_called_once_with(
            "/tmp/tagged.cpp",
            "/tmp/fdp_trace.log",
            "AddressSanitizer",
            "-std=c++17",
            "seed.bin",
        )
        mock_format.assert_called_once_with("/tmp/reduced.cpp")
        mock_inline.assert_called_once_with("/tmp/reduced.cpp", "/tmp/fdp_trace.log")
        mock_check.assert_called_once()

    @patch("harnessreducer.api.reduce_with_config")
    def test_process_compat_wrapper(self, mock_reduce_with_config):
        cfg = ReductionConfig(
            harness_path="a.cpp",
            crash_pattern="boom",
            extra_flags=None,
            crash_input=None,
        )
        expected_reduced = "/tmp/out.cpp"

        class ResultObj:
            reduced_harness = expected_reduced
            tagged_harness = "/tmp/tagged.cpp"
            fdp_trace = "/tmp/trace.log"

        mock_reduce_with_config.return_value = ResultObj()

        reduced = process(cfg.harness_path, cfg.extra_flags, cfg.crash_pattern, cfg.crash_input)
        self.assertEqual(reduced, expected_reduced)
        mock_reduce_with_config.assert_called_once()


if __name__ == "__main__":
    unittest.main()

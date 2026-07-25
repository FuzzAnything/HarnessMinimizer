import unittest
from unittest.mock import patch

from harnessreducer.api import ReductionConfig, TaggedHarness, process, reduce_with_config


class TestApiPipeline(unittest.TestCase):
    def setUp(self):
        self.check_symbolized_patch = patch(
            "harnessreducer.api.check_reducer_symbolized_crash_pattern"
        )
        self.mock_check_symbolized_pattern = self.check_symbolized_patch.start()
        self.addCleanup(self.check_symbolized_patch.stop)

        self.symbolized_pattern_patch = patch(
            "harnessreducer.api.get_reference_crash_pattern_symbolize_1",
            return_value=None,
        )
        self.mock_get_symbolized_pattern = self.symbolized_pattern_patch.start()
        self.addCleanup(self.symbolized_pattern_patch.stop)

    def test_amortize_link_rejects_direct_mode(self):
        with self.assertRaisesRegex(ValueError, "requires split or PCH"):
            reduce_with_config(
                ReductionConfig(
                    harness_path="a.cpp",
                    phase3_mode="direct",
                    amortize_link=True,
                )
            )

    @patch("harnessreducer.api.emit_check_statistics_summary")
    @patch("harnessreducer.api.run_treereducer")
    @patch("harnessreducer.api.run_treereducer_with_check")
    @patch("harnessreducer.api.record_check_reference")
    @patch("harnessreducer.api.inline_literals_in_reduced_harness")
    @patch("harnessreducer.api.format_reduced_harness")
    @patch("harnessreducer.api.dump_fdp_trace")
    @patch("harnessreducer.api.compile_dump_mode_harness")
    @patch("harnessreducer.api.reset_check_state")
    @patch("harnessreducer.api.reset_last_interesting_state")
    @patch("harnessreducer.api.reset_stack_trace_state")
    @patch("harnessreducer.api.configure_work_dir")
    @patch("harnessreducer.api.tag_harness_with_fdp_ids")
    @patch("harnessreducer.api.check_reducer_crash_pattern")
    @patch("harnessreducer.api.extract_crash_pattern_from_output")
    @patch("harnessreducer.api.check_harness_compilation")
    @patch("harnessreducer.api.check_tree_reducer")
    def test_reduce_with_config_uses_check_mode_runner(
        self,
        mock_check_tree,
        mock_check_compile,
        mock_extract,
        mock_check_pattern,
        mock_tag,
        mock_configure,
        mock_reset_stack_state,
        mock_reset_last_interesting_state,
        mock_reset_check_state,
        mock_compile,
        mock_dump,
        mock_format,
        mock_inline,
        mock_record_check_reference,
        mock_run_with_check,
        mock_run_normal,
        mock_emit_check_summary,
    ):
        mock_tag.return_value = "/tmp/tagged.cpp"
        mock_compile.return_value = "/tmp/tagged.out"
        mock_dump.return_value = "/tmp/fdp_trace.log"
        mock_extract.return_value = "AddressSanitizer"
        mock_run_with_check.return_value = "/tmp/reduced.cpp"
        mock_inline.return_value = ("/tmp/reduced.cpp", ())
        mock_record_check_reference.return_value = type(
            "Reference",
            (),
            {"frame_count": 12},
        )()

        config = ReductionConfig(
            harness_path="a.cpp",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
            check=True,
        )

        result = reduce_with_config(config)

        self.assertEqual(result.reduced_harness, "/tmp/reduced.cpp")
        mock_reset_last_interesting_state.assert_called_once_with()
        mock_reset_check_state.assert_called_once_with()
        mock_record_check_reference.assert_called_once_with(
            "seed.bin", ".*", None
        )
        mock_run_with_check.assert_called_once_with(
            "/tmp/tagged.cpp",
            "/tmp/fdp_trace.log",
            None,
            None,
            None,
            "seed.bin",
            stable=False,
            phase3_mode="split",
            snapshot=False,
            amortize_link=False,
            crash_pattern_symbolize_0="AddressSanitizer",
            require_crash_pattern=False,
        )
        mock_run_normal.assert_not_called()
        mock_emit_check_summary.assert_called_once_with()

    @patch("harnessreducer.api.inline_literals_in_reduced_harness")
    @patch("harnessreducer.api.format_reduced_harness")
    @patch("harnessreducer.api.run_treereducer")
    @patch("harnessreducer.api.dump_fdp_trace")
    @patch("harnessreducer.api.compile_dump_mode_harness")
    @patch("harnessreducer.api.apply_coverage_guided_slice")
    @patch("harnessreducer.api.reset_last_interesting_state")
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
        mock_reset_last_interesting_state,
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
        self.mock_get_symbolized_pattern.return_value = "SymbolizedPattern"
        mock_slice.return_value = "/tmp/sliced.cpp"

        config = ReductionConfig(
            harness_path="a.cpp",
            compile_flags="-std=c++17",
            link_flags="-lm",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
            start_id=123,
            marker="M",
            slice_enabled=True,
        )

        result = reduce_with_config(config)

        self.assertEqual(result.reduced_harness, "/tmp/reduced.cpp")
        self.assertEqual(result.tagged_harness, "/tmp/tagged.cpp")
        self.assertEqual(result.fdp_trace, "/tmp/fdp_trace.log")

        mock_configure.assert_called_once_with("/tmp/workdir")
        mock_reset_stack_state.assert_called_once_with()
        mock_reset_last_interesting_state.assert_called_once_with()
        mock_check_compile.assert_called_once_with("a.cpp", "-std=c++17", "-lm")
        mock_extract.assert_called_once_with(
            "seed.bin", harness_path="a.cpp", link_flags="-lm"
        )
        mock_check_pattern.assert_called_once_with(
            "a.cpp",
            "AddressSanitizer",
            "seed.bin",
            "-std=c++17",
            "-lm",
            phase3_mode="direct",
        )
        self.mock_check_symbolized_pattern.assert_called_once_with(
            "a.cpp",
            "SymbolizedPattern",
            "seed.bin",
            "-std=c++17",
            "-lm",
            phase3_mode="direct",
        )
        mock_slice.assert_called_once_with(
            "a.cpp",
            "SymbolizedPattern",
            "seed.bin",
            "-std=c++17",
            "-lm",
            phase3_mode="direct",
            crash_pattern_symbolize_0="AddressSanitizer",
            symbolize=False,
        )
        mock_tag.assert_called_once_with("/tmp/sliced.cpp", start_id=123, marker="M")
        mock_compile.assert_called_once_with("/tmp/tagged.cpp", "-std=c++17", "-lm")
        mock_dump.assert_called_once_with("/tmp/tagged.out", "seed.bin", "-lm")
        mock_reduce.assert_called_once_with(
            "/tmp/tagged.cpp",
            "/tmp/fdp_trace.log",
            "AddressSanitizer",
            "-std=c++17",
            "-lm",
            "seed.bin",
            stable=False,
            phase3_mode="split",
            statistics=False,
            snapshot=False,
            amortize_link=False,
            symbolize=False,
        )
        mock_format.assert_called_once_with("/tmp/reduced.cpp")
        mock_inline.assert_called_once_with(
            "/tmp/reduced.cpp",
            "/tmp/fdp_trace.log",
            "SymbolizedPattern",
            "seed.bin",
            "-std=c++17",
            "-lm",
            123,
            phase3_mode="direct",
            snapshot=False,
            crash_pattern_symbolize_0="AddressSanitizer",
            symbolize=False,
        )
        mock_check.assert_called_once()

    @patch("harnessreducer.api.inline_literals_in_reduced_harness")
    @patch("harnessreducer.api.format_reduced_harness")
    @patch("harnessreducer.api.run_treereducer")
    @patch("harnessreducer.api.dump_fdp_trace")
    @patch("harnessreducer.api.compile_dump_mode_harness")
    @patch("harnessreducer.api.reset_last_interesting_state")
    @patch("harnessreducer.api.reset_stack_trace_state")
    @patch("harnessreducer.api.configure_work_dir")
    @patch("harnessreducer.api.tag_harness_with_fdp_ids")
    @patch("harnessreducer.api.check_reducer_crash_pattern")
    @patch("harnessreducer.api.extract_crash_pattern_from_output")
    @patch("harnessreducer.api.check_harness_compilation")
    @patch("harnessreducer.api.check_tree_reducer")
    def test_reduce_with_config_passes_snapshot_when_enabled(
        self,
        mock_check,
        mock_check_compile,
        mock_extract,
        mock_check_pattern,
        mock_tag,
        mock_configure,
        mock_reset_stack_state,
        mock_reset_last_interesting_state,
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

        config = ReductionConfig(
            harness_path="a.cpp",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
            snapshot=True,
        )

        reduce_with_config(config)

        self.assertTrue(mock_reduce.call_args.kwargs["snapshot"])
        self.assertTrue(mock_inline.call_args.kwargs["snapshot"])

    @patch("harnessreducer.api.inline_literals_in_reduced_harness")
    @patch("harnessreducer.api.format_reduced_harness")
    @patch("harnessreducer.api.run_treereducer")
    @patch("harnessreducer.api.dump_fdp_trace")
    @patch("harnessreducer.api.compile_dump_mode_harness")
    @patch("harnessreducer.api.apply_coverage_guided_slice")
    @patch("harnessreducer.api.reset_last_interesting_state")
    @patch("harnessreducer.api.reset_stack_trace_state")
    @patch("harnessreducer.api.configure_work_dir")
    @patch("harnessreducer.api.tag_harness_with_fdp_ids")
    @patch("harnessreducer.api.check_reducer_crash_pattern")
    @patch("harnessreducer.api.extract_crash_pattern_from_output")
    @patch("harnessreducer.api.check_harness_compilation")
    @patch("harnessreducer.api.check_tree_reducer")
    def test_pch_mode_is_used_only_for_tree_reduction(
        self,
        mock_check,
        mock_check_compile,
        mock_extract,
        mock_check_pattern,
        mock_tag,
        mock_configure,
        mock_reset_stack_state,
        mock_reset_last_interesting_state,
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
            phase3_mode="pch",
            slice_enabled=True,
        )

        reduce_with_config(config)

        self.assertEqual(
            mock_check_pattern.call_args.kwargs["phase3_mode"],
            "direct",
        )
        self.assertEqual(
            mock_slice.call_args.kwargs["phase3_mode"],
            "direct",
        )
        self.assertEqual(
            mock_reduce.call_args.kwargs["phase3_mode"],
            "pch",
        )
        self.assertEqual(
            mock_inline.call_args.kwargs["phase3_mode"],
            "direct",
        )

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
        self.assertEqual(
            mock_reduce_with_config.call_args.args[0].phase3_mode,
            "split",
        )

    @patch("harnessreducer.api.inline_literals_in_reduced_harness")
    @patch("harnessreducer.api.format_reduced_harness")
    @patch("harnessreducer.api.run_treereducer")
    @patch("harnessreducer.api.dump_fdp_trace")
    @patch("harnessreducer.api.compile_dump_mode_harness")
    @patch("harnessreducer.api.apply_coverage_guided_slice")
    @patch("harnessreducer.api.reset_last_interesting_state")
    @patch("harnessreducer.api.reset_stack_trace_state")
    @patch("harnessreducer.api.configure_work_dir")
    @patch("harnessreducer.api.tag_harness_with_fdp_ids")
    @patch("harnessreducer.api.check_reducer_crash_pattern")
    @patch("harnessreducer.api.extract_crash_pattern_from_output")
    @patch("harnessreducer.api.check_harness_compilation")
    @patch("harnessreducer.api.check_tree_reducer")
    def test_reduce_with_config_skips_dynamic_slicing_by_default(
        self,
        mock_check,
        mock_check_compile,
        mock_extract,
        mock_check_pattern,
        mock_tag,
        mock_configure,
        mock_reset_stack_state,
        mock_reset_last_interesting_state,
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

        config = ReductionConfig(
            harness_path="a.cpp",
            compile_flags="-std=c++17",
            link_flags="-lm",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
        )

        reduce_with_config(config)

        mock_slice.assert_not_called()
        mock_tag.assert_called_once_with("a.cpp", start_id=100000, marker="FDP_ID")

    @patch("harnessreducer.api.inline_literals_in_reduced_harness")
    @patch("harnessreducer.api.format_reduced_harness")
    @patch("harnessreducer.api.run_treereducer")
    @patch("harnessreducer.api.dump_fdp_trace")
    @patch("harnessreducer.api.compile_dump_mode_harness")
    @patch("harnessreducer.api.reset_last_interesting_state")
    @patch("harnessreducer.api.reset_stack_trace_state")
    @patch("harnessreducer.api.configure_work_dir")
    @patch("harnessreducer.api.tag_harness_with_fdp_ids")
    @patch("harnessreducer.api.check_reducer_crash_pattern")
    @patch("harnessreducer.api.extract_crash_pattern_from_output")
    @patch("harnessreducer.api.check_harness_compilation")
    @patch("harnessreducer.api.check_tree_reducer")
    def test_reduce_with_config_skips_fdp_dump_for_direct_input_harness(
        self,
        mock_check,
        mock_check_compile,
        mock_extract,
        mock_check_pattern,
        mock_tag,
        mock_configure,
        mock_reset_stack_state,
        mock_reset_last_interesting_state,
        mock_compile,
        mock_dump,
        mock_reduce,
        mock_format,
        mock_inline,
    ):
        mock_tag.return_value = TaggedHarness("/tmp/tagged.cpp", 0)
        mock_reduce.return_value = "/tmp/reduced.cpp"
        mock_inline.return_value = ("/tmp/reduced.cpp", ())
        mock_extract.return_value = "AddressSanitizer"

        config = ReductionConfig(
            harness_path="a.cpp",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
        )

        result = reduce_with_config(config)

        self.assertEqual(result.fdp_trace, None)
        mock_compile.assert_not_called()
        mock_dump.assert_not_called()
        mock_reduce.assert_called_once_with(
            "/tmp/tagged.cpp",
            None,
            "AddressSanitizer",
            None,
            None,
            "seed.bin",
            stable=False,
            phase3_mode="split",
            statistics=False,
            snapshot=False,
            amortize_link=False,
            symbolize=False,
        )
        mock_inline.assert_called_once_with(
            "/tmp/reduced.cpp",
            None,
            None,
            "seed.bin",
            None,
            None,
            100000,
            phase3_mode="direct",
            snapshot=False,
            crash_pattern_symbolize_0="AddressSanitizer",
            symbolize=False,
        )

    @patch("harnessreducer.api.inline_literals_in_reduced_harness")
    @patch("harnessreducer.api.format_reduced_harness")
    @patch("harnessreducer.api.run_treereducer")
    @patch("harnessreducer.api.reset_last_interesting_state")
    @patch("harnessreducer.api.reset_stack_trace_state")
    @patch("harnessreducer.api.configure_work_dir")
    @patch("harnessreducer.api.tag_harness_with_fdp_ids")
    @patch("harnessreducer.api.check_reducer_symbolized_reduction_oracle")
    @patch("harnessreducer.api.check_reducer_crash_pattern")
    @patch("harnessreducer.api.extract_crash_pattern_from_output")
    @patch("harnessreducer.api.check_harness_compilation")
    @patch("harnessreducer.api.check_tree_reducer")
    def test_reduce_with_config_symbolize_uses_symbolized_reduction_oracle(
        self,
        mock_check_tree,
        mock_check_compile,
        mock_extract,
        mock_check_pattern,
        mock_symbolized_oracle,
        mock_tag,
        mock_configure,
        mock_reset_stack_state,
        mock_reset_last_interesting_state,
        mock_reduce,
        mock_format,
        mock_inline,
    ):
        mock_tag.return_value = TaggedHarness("/tmp/tagged.cpp", 0)
        mock_reduce.return_value = "/tmp/reduced.cpp"
        mock_inline.return_value = ("/tmp/reduced.cpp", ())
        mock_extract.return_value = "FastPattern"
        self.mock_get_symbolized_pattern.return_value = "SymbolizedPattern"

        config = ReductionConfig(
            harness_path="a.cpp",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
            symbolize=True,
        )

        result = reduce_with_config(config)

        self.assertEqual(result.reduced_harness, "/tmp/reduced.cpp")
        mock_extract.assert_called_once_with(
            "seed.bin",
            harness_path="a.cpp",
            link_flags=None,
            record_symbolized_crash_location=True,
        )
        mock_symbolized_oracle.assert_called_once_with(
            "a.cpp",
            "SymbolizedPattern",
            "seed.bin",
            None,
            None,
            phase3_mode="direct",
        )
        mock_check_pattern.assert_not_called()
        self.mock_check_symbolized_pattern.assert_not_called()
        mock_reduce.assert_called_once_with(
            "/tmp/tagged.cpp",
            None,
            "SymbolizedPattern",
            None,
            None,
            "seed.bin",
            stable=False,
            phase3_mode="split",
            statistics=False,
            snapshot=False,
            amortize_link=False,
            symbolize=True,
        )
        mock_inline.assert_called_once_with(
            "/tmp/reduced.cpp",
            None,
            "SymbolizedPattern",
            "seed.bin",
            None,
            None,
            100000,
            phase3_mode="direct",
            snapshot=False,
            crash_pattern_symbolize_0="FastPattern",
            symbolize=True,
        )


if __name__ == "__main__":
    unittest.main()

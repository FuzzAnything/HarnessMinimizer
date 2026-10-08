import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch

from harnessminimizer.api import (
    PostReductionOutcome,
    ReductionConfig,
    ReductionResult,
    TaggedHarness,
    _prepare_fuzzer_entry_return,
    process,
    reduce_with_config,
)
from harnessminimizer.reducer_runner import HarnessCrashDetected


class TestApiPipeline(unittest.TestCase):
    def test_defaults_use_unoptimized_configuration(self):
        config = ReductionConfig("h.cpp")
        self.assertEqual(config.compilation_mode, "split")
        self.assertTrue(config.symbolize)
        self.assertFalse(config.amortize_link)
        self.assertEqual(config.jobs, 60)
        self.assertFalse(config.profile)
        self.assertFalse(config.stable)

    def setUp(self):
        self.check_symbolized_patch = patch(
            "harnessminimizer.api.check_reducer_symbolized_crash_pattern"
        )
        self.mock_check_symbolized_pattern = self.check_symbolized_patch.start()
        self.addCleanup(self.check_symbolized_patch.stop)

        self.symbolized_pattern_patch = patch(
            "harnessminimizer.api.get_reference_crash_pattern_symbolize_1",
            return_value=None,
        )
        self.mock_get_symbolized_pattern = self.symbolized_pattern_patch.start()
        self.addCleanup(self.symbolized_pattern_patch.stop)


    def test_amortize_link_rejects_direct_mode(self):
        with self.assertRaisesRegex(ValueError, "requires split or PCH"):
            reduce_with_config(
                ReductionConfig(
                    harness_path="a.cpp",
                    compilation_mode="direct",
                    amortize_link=True,
                )
            )

    def test_prepare_fuzzer_entry_return_adds_return_0_to_int_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "source"
            work_dir = root / "work"
            src_dir.mkdir()
            work_dir.mkdir()
            harness = src_dir / "harness.cpp"
            original = (
                '#include "local_header.h"\n'
                '#include <stddef.h>\n'
                '#include <stdint.h>\n'
                'extern "C" int LLVMFuzzerTestOneInput('
                'const uint8_t *data, size_t size) {\n'
                '  (void)data;\n'
                '  (void)size;\n'
                '}\n'
            )
            harness.write_text(original, encoding="utf-8")

            prepared = _prepare_fuzzer_entry_return(
                str(harness),
                "-std=c++17",
                str(work_dir),
            )

            self.assertNotEqual(prepared.path, str(harness))
            self.assertEqual(harness.read_text(encoding="utf-8"), original)
            prepared_source = Path(prepared.path).read_text(encoding="utf-8")
            self.assertIn("  return 0;\n}", prepared_source)
            self.assertIn(f"-I{src_dir.resolve()}", prepared.compile_flags)

    def test_prepare_fuzzer_entry_return_keeps_existing_return(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            harness = root / "harness.cpp"
            harness.write_text(
                '#include <stddef.h>\n'
                '#include <stdint.h>\n'
                'extern "C" int LLVMFuzzerTestOneInput('
                'const uint8_t *data, size_t size) {\n'
                '  (void)data;\n'
                '  (void)size;\n'
                '  return 0;\n'
                '}\n',
                encoding="utf-8",
            )

            prepared = _prepare_fuzzer_entry_return(
                str(harness),
                "-std=c++17",
                str(root),
            )

            self.assertEqual(prepared.path, str(harness))
            self.assertEqual(prepared.compile_flags, "-std=c++17")

    def test_prepare_fuzzer_entry_return_keeps_void_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            harness = root / "harness.cpp"
            harness.write_text(
                '#include <stddef.h>\n'
                '#include <stdint.h>\n'
                'extern "C" void LLVMFuzzerTestOneInput('
                'const uint8_t *data, size_t size) {\n'
                '  (void)data;\n'
                '  (void)size;\n'
                '}\n',
                encoding="utf-8",
            )

            prepared = _prepare_fuzzer_entry_return(
                str(harness),
                "-std=c++17",
                str(root),
            )

            self.assertEqual(prepared.path, str(harness))
            self.assertEqual(prepared.compile_flags, "-std=c++17")

    @patch("harnessminimizer.api.extract_crash_pattern_from_output")
    @patch("harnessminimizer.api.check_harness_compilation")
    @patch("harnessminimizer.api.check_tree_reducer")
    def test_reduce_with_config_uses_prepared_missing_return_harness(
        self,
        mock_check_tree,
        mock_check_compile,
        mock_extract,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "source"
            work_dir = root / "work"
            src_dir.mkdir()
            harness = src_dir / "harness.cpp"
            harness.write_text(
                '#include "local_header.h"\n'
                '#include <stddef.h>\n'
                '#include <stdint.h>\n'
                'extern "C" int LLVMFuzzerTestOneInput('
                'const uint8_t *data, size_t size) {\n'
                '  (void)data;\n'
                '  (void)size;\n'
                '}\n',
                encoding="utf-8",
            )
            mock_extract.side_effect = HarnessCrashDetected("harness.cpp:4:1")

            result = reduce_with_config(
                ReductionConfig(
                    symbolize=False,
                    harness_path=str(harness),
                    compile_flags="-std=c++17",
                    crash_input="seed.bin",
                    work_dir=str(work_dir),
                )
            )

            self.assertFalse(result.success)
            mock_check_tree.assert_called_once_with()
            prepared_path = mock_check_compile.call_args.args[0]
            prepared_flags = mock_check_compile.call_args.args[1]
            self.assertNotEqual(prepared_path, str(harness))
            self.assertIn(
                "return 0;",
                Path(prepared_path).read_text(encoding="utf-8"),
            )
            self.assertIn(f"-I{src_dir.resolve()}", prepared_flags)
            mock_extract.assert_called_once_with(
                "seed.bin",
                harness_path=prepared_path,
                compile_flags=prepared_flags,
                link_flags=None,
            )

    @patch("harnessminimizer.api.run_treereducer")
    @patch("harnessminimizer.api.tag_harness_with_fdp_ids")
    @patch("harnessminimizer.api.check_reducer_crash_pattern")
    @patch("harnessminimizer.api.extract_crash_pattern_from_output")
    @patch("harnessminimizer.api.check_harness_compilation")
    @patch("harnessminimizer.api.check_tree_reducer")
    @patch("harnessminimizer.api.resolve_amortized_link_inputs")
    def test_pch_amortized_link_stops_before_reduction_for_harness_crash(
        self,
        mock_resolve_amortized,
        mock_check_tree,
        mock_check_compile,
        mock_extract,
        mock_check_pattern,
        mock_tag,
        mock_reduce,
    ):
        mock_extract.side_effect = HarnessCrashDetected("/tmp/harness.cpp:82:36")

        result = reduce_with_config(
            ReductionConfig(
                harness_path="/tmp/harness.cpp",
                compile_flags="-std=c++17",
                link_flags="-lm",
                crash_input="/tmp/crash-input",
                work_dir="/tmp/workdir",
                compilation_mode="pch",
                amortize_link=True,
            )
        )

        self.assertFalse(result.success)
        mock_resolve_amortized.assert_called_once_with("-lm")
        mock_check_tree.assert_called_once()
        mock_check_compile.assert_called_once()
        mock_check_pattern.assert_not_called()
        self.mock_check_symbolized_pattern.assert_not_called()
        mock_tag.assert_not_called()
        mock_reduce.assert_not_called()


    @patch("harnessminimizer.api.inline_literals_in_reduced_harness")
    @patch("harnessminimizer.api.format_reduced_harness")
    @patch("harnessminimizer.api.run_treereducer")
    @patch("harnessminimizer.api.dump_fdp_trace")
    @patch("harnessminimizer.api.compile_dump_mode_harness")
    @patch("harnessminimizer.api.apply_coverage_guided_slice")
    @patch("harnessminimizer.api.reset_last_interesting_state")
    @patch("harnessminimizer.api.reset_stack_trace_state")
    @patch("harnessminimizer.api.configure_work_dir")
    @patch("harnessminimizer.api.tag_harness_with_fdp_ids")
    @patch("harnessminimizer.api.check_reducer_crash_pattern")
    @patch("harnessminimizer.api.extract_crash_pattern_from_output")
    @patch("harnessminimizer.api.check_harness_compilation")
    @patch("harnessminimizer.api.check_tree_reducer")
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
        mock_inline.return_value = PostReductionOutcome("/tmp/reduced.cpp", )
        mock_extract.return_value = "AddressSanitizer"
        self.mock_get_symbolized_pattern.return_value = "SymbolizedPattern"
        mock_slice.return_value = "/tmp/sliced.cpp"

        config = ReductionConfig(
            symbolize=False,
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
            "seed.bin", harness_path="a.cpp", compile_flags="-std=c++17", link_flags="-lm"
        )
        mock_check_pattern.assert_called_once_with(
            "a.cpp",
            "AddressSanitizer",
            "seed.bin",
            "-std=c++17",
            "-lm",
            compilation_mode="direct",
        )
        self.mock_check_symbolized_pattern.assert_called_once_with(
            "a.cpp",
            "SymbolizedPattern",
            "seed.bin",
            "-std=c++17",
            "-lm",
            compilation_mode="direct",
        )
        mock_slice.assert_called_once_with(
            "a.cpp",
            "SymbolizedPattern",
            "seed.bin",
            "-std=c++17",
            "-lm",
            compilation_mode="direct",
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
            compilation_mode="split",
            snapshot=False,
            amortize_link=False,
            symbolize=False,
            jobs=60,
            profile=False,
            auto_var_init_pattern=False,
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
            compilation_mode="direct",
            snapshot=False,
            crash_pattern_symbolize_0="AddressSanitizer",
            symbolize=False,
            auto_var_init_pattern_fallback=False,
        )
        mock_check.assert_called_once()

    @patch("harnessminimizer.api.inline_literals_in_reduced_harness")
    @patch("harnessminimizer.api.format_reduced_harness")
    @patch("harnessminimizer.api.run_treereducer")
    @patch("harnessminimizer.api.dump_fdp_trace")
    @patch("harnessminimizer.api.compile_dump_mode_harness")
    @patch("harnessminimizer.api.reset_last_interesting_state")
    @patch("harnessminimizer.api.reset_stack_trace_state")
    @patch("harnessminimizer.api.configure_work_dir")
    @patch("harnessminimizer.api.tag_harness_with_fdp_ids")
    @patch("harnessminimizer.api.check_reducer_crash_pattern")
    @patch("harnessminimizer.api.extract_crash_pattern_from_output")
    @patch("harnessminimizer.api.check_harness_compilation")
    @patch("harnessminimizer.api.check_tree_reducer")
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
            symbolize=False,
            harness_path="a.cpp",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
            snapshot=True,
        )

        reduce_with_config(config)

        self.assertTrue(mock_reduce.call_args.kwargs["snapshot"])
        self.assertTrue(mock_inline.call_args.kwargs["snapshot"])

    @patch("harnessminimizer.api.inline_literals_in_reduced_harness")
    @patch("harnessminimizer.api.format_reduced_harness")
    @patch("harnessminimizer.api.run_treereducer")
    @patch("harnessminimizer.api.dump_fdp_trace")
    @patch("harnessminimizer.api.compile_dump_mode_harness")
    @patch("harnessminimizer.api.apply_coverage_guided_slice")
    @patch("harnessminimizer.api.reset_last_interesting_state")
    @patch("harnessminimizer.api.reset_stack_trace_state")
    @patch("harnessminimizer.api.configure_work_dir")
    @patch("harnessminimizer.api.tag_harness_with_fdp_ids")
    @patch("harnessminimizer.api.check_reducer_crash_pattern")
    @patch("harnessminimizer.api.extract_crash_pattern_from_output")
    @patch("harnessminimizer.api.check_harness_compilation")
    @patch("harnessminimizer.api.check_tree_reducer")
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
            symbolize=False,
            harness_path="a.cpp",
            compile_flags="-std=c++17",
            link_flags="-lm",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
            compilation_mode="pch",
            slice_enabled=True,
        )

        reduce_with_config(config)

        self.assertEqual(
            mock_check_pattern.call_args.kwargs["compilation_mode"],
            "direct",
        )
        self.assertEqual(
            mock_slice.call_args.kwargs["compilation_mode"],
            "direct",
        )
        self.assertEqual(
            mock_reduce.call_args.kwargs["compilation_mode"],
            "pch",
        )
        self.assertEqual(
            mock_inline.call_args.kwargs["compilation_mode"],
            "direct",
        )

    @patch("harnessminimizer.api.reduce_with_config")
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
            mock_reduce_with_config.call_args.args[0].compilation_mode,
            "split",
        )
        self.assertTrue(mock_reduce_with_config.call_args.args[0].symbolize)

    @patch("harnessminimizer.api.reduce_with_config")
    def test_process_forwards_compilation_mode_and_symbolize_override(self, reduce):
        reduce.return_value = ReductionResult("reduced.cpp", "tagged.cpp", None)
        for mode in ("direct", "split", "pch"):
            for symbolize in (False, True):
                with self.subTest(mode=mode, symbolize=symbolize):
                    self.assertEqual(
                        process("h.cpp", compilation_mode=mode, symbolize=symbolize),
                        "reduced.cpp",
                    )
                    config = reduce.call_args.args[0]
                    self.assertEqual(config.compilation_mode, mode)
                    self.assertEqual(config.symbolize, symbolize)

    @patch("harnessminimizer.api.inline_literals_in_reduced_harness")
    @patch("harnessminimizer.api.format_reduced_harness")
    @patch("harnessminimizer.api.run_treereducer")
    @patch("harnessminimizer.api.dump_fdp_trace")
    @patch("harnessminimizer.api.compile_dump_mode_harness")
    @patch("harnessminimizer.api.apply_coverage_guided_slice")
    @patch("harnessminimizer.api.reset_last_interesting_state")
    @patch("harnessminimizer.api.reset_stack_trace_state")
    @patch("harnessminimizer.api.configure_work_dir")
    @patch("harnessminimizer.api.tag_harness_with_fdp_ids")
    @patch("harnessminimizer.api.check_reducer_crash_pattern")
    @patch("harnessminimizer.api.extract_crash_pattern_from_output")
    @patch("harnessminimizer.api.check_harness_compilation")
    @patch("harnessminimizer.api.check_tree_reducer")
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
            symbolize=False,
            harness_path="a.cpp",
            compile_flags="-std=c++17",
            link_flags="-lm",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
        )

        reduce_with_config(config)

        mock_slice.assert_not_called()
        mock_tag.assert_called_once_with("a.cpp", start_id=100000, marker="FDP_ID")

    @patch("harnessminimizer.api.inline_literals_in_reduced_harness")
    @patch("harnessminimizer.api.format_reduced_harness")
    @patch("harnessminimizer.api.run_treereducer")
    @patch("harnessminimizer.api.dump_fdp_trace")
    @patch("harnessminimizer.api.compile_dump_mode_harness")
    @patch("harnessminimizer.api.reset_last_interesting_state")
    @patch("harnessminimizer.api.reset_stack_trace_state")
    @patch("harnessminimizer.api.configure_work_dir")
    @patch("harnessminimizer.api.tag_harness_with_fdp_ids")
    @patch("harnessminimizer.api.check_reducer_crash_pattern")
    @patch("harnessminimizer.api.extract_crash_pattern_from_output")
    @patch("harnessminimizer.api.check_harness_compilation")
    @patch("harnessminimizer.api.check_tree_reducer")
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
            symbolize=False,
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
            compilation_mode="split",
            snapshot=False,
            amortize_link=False,
            symbolize=False,
            jobs=60,
            profile=False,
            auto_var_init_pattern=False,
        )

    @patch("harnessminimizer.api.validate_stack_trace")
    @patch("harnessminimizer.api.validate_crash_pattern")
    @patch("harnessminimizer.api.inline_literals_in_reduced_harness")
    @patch("harnessminimizer.api.format_reduced_harness")
    @patch("harnessminimizer.api.run_treereducer")
    @patch("harnessminimizer.api.dump_fdp_trace")
    @patch("harnessminimizer.api.compile_dump_mode_harness")
    @patch("harnessminimizer.api.reset_last_interesting_state")
    @patch("harnessminimizer.api.reset_stack_trace_state")
    @patch("harnessminimizer.api.configure_work_dir")
    @patch("harnessminimizer.api.tag_harness_with_fdp_ids")
    @patch("harnessminimizer.api.check_reducer_crash_pattern")
    @patch("harnessminimizer.api.extract_crash_pattern_from_output")
    @patch("harnessminimizer.api.check_harness_compilation")
    @patch("harnessminimizer.api.check_tree_reducer")
    def test_reduce_with_config_debug_tree_validation_enables_oom_retry(
        self,
        mock_check_tree,
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
        mock_validate_crash_pattern,
        mock_validate_stack_trace,
    ):
        mock_tag.return_value = "/tmp/tagged.cpp"
        mock_compile.return_value = "/tmp/tagged.out"
        mock_dump.return_value = "/tmp/fdp_trace.log"
        mock_reduce.return_value = "/tmp/reduced.cpp"
        mock_inline.return_value = ("/tmp/reduced.cpp", ())
        mock_extract.return_value = "AddressSanitizer"

        config = ReductionConfig(
            symbolize=False,
            harness_path="a.cpp",
            compile_flags="-std=c++17",
            link_flags="-lm",
            crash_input="seed.bin",
            work_dir="/tmp/workdir",
            debug=True,
        )

        result = reduce_with_config(config)

        self.assertEqual(result.reduced_harness, "/tmp/reduced.cpp")
        mock_validate_crash_pattern.assert_called_once()
        mock_validate_stack_trace.assert_called_once()
        self.assertTrue(
            mock_validate_crash_pattern.call_args.kwargs[
                "retry_oom_without_rss_limit"
            ]
        )
        self.assertTrue(
            mock_validate_stack_trace.call_args.kwargs[
                "retry_oom_without_rss_limit"
            ]
        )
        mock_inline.assert_called_once()

    @patch("harnessminimizer.api.inline_literals_in_reduced_harness")
    @patch("harnessminimizer.api.format_reduced_harness")
    @patch("harnessminimizer.api.run_treereducer")
    @patch("harnessminimizer.api.reset_last_interesting_state")
    @patch("harnessminimizer.api.reset_stack_trace_state")
    @patch("harnessminimizer.api.configure_work_dir")
    @patch("harnessminimizer.api.tag_harness_with_fdp_ids")
    @patch("harnessminimizer.api.check_reducer_symbolized_reduction_oracle")
    @patch("harnessminimizer.api.check_reducer_crash_pattern")
    @patch("harnessminimizer.api.extract_crash_pattern_from_output")
    @patch("harnessminimizer.api.check_harness_compilation")
    @patch("harnessminimizer.api.check_tree_reducer")
    def test_reduce_with_config_defaults_to_symbolized_reduction_oracle(
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
        )

        result = reduce_with_config(config)

        self.assertEqual(result.reduced_harness, "/tmp/reduced.cpp")
        mock_extract.assert_called_once_with(
            "seed.bin",
            harness_path="a.cpp",
            compile_flags=None,
            link_flags=None,
            record_symbolized_crash_location=True,
        )
        mock_symbolized_oracle.assert_called_once_with(
            "a.cpp",
            "SymbolizedPattern",
            "seed.bin",
            None,
            None,
            compilation_mode="direct",
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
            compilation_mode="split",
            snapshot=False,
            amortize_link=False,
            symbolize=True,
            jobs=60,
            profile=False,
            auto_var_init_pattern=False,
        )
        mock_inline.assert_called_once_with(
            "/tmp/reduced.cpp",
            None,
            "SymbolizedPattern",
            "seed.bin",
            None,
            None,
            100000,
            compilation_mode="direct",
            snapshot=False,
            crash_pattern_symbolize_0="FastPattern",
            symbolize=True,
            auto_var_init_pattern_fallback=False,
        )

        self.mock_get_symbolized_pattern.return_value = None
        with self.assertRaisesRegex(ValueError, "symbolize=1 crash pattern"):
            reduce_with_config(config)


if __name__ == "__main__":
    unittest.main()


def test_removed_api_options_are_rejected():
    import pytest
    for name in ("tool", "check", "statistics", "capture_raw_output", "replay_enabled", "oracle_evaluation"):
        with pytest.raises(TypeError, match=name):
            ReductionConfig("h.cpp", **{name: True})
    for name in ("tool", "check", "statistics"):
        with pytest.raises(TypeError, match=name):
            process("h.cpp", **{name: True})
    with pytest.raises(TypeError, match="raw_reduced_harness"):
        ReductionResult("out.cpp", "tagged.cpp", None, raw_reduced_harness="unused.cpp")

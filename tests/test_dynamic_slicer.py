import tempfile
import textwrap
import unittest

from harnessreducer.dynamic_slicer import CoverageMap, slice_source_by_coverage


class TestDynamicSlicer(unittest.TestCase):
    def test_removes_uncovered_else_statement_and_helper_function(self):
        source = textwrap.dedent(
            """\
            int helper_unused() {
              return 0;
            }

            extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
              if (size) {
                used();
              } else {
                unused();
              }
              skipped();
              target_crash_api();
              return 0;
            }
            """
        )
        coverage = CoverageMap(
            executable_lines=frozenset({1, 6, 8, 11, 12, 13}),
            covered_lines=frozenset({6, 7, 12, 13}),
        )

        result = slice_source_by_coverage(source, coverage)

        self.assertEqual(result.removed_nodes, 3)
        self.assertNotIn("helper_unused", result.source)
        self.assertNotIn("else", result.source)
        self.assertNotIn("skipped();", result.source)
        self.assertIn("used();", result.source)
        self.assertIn("target_crash_api();", result.source)

    def test_replaces_uncovered_if_body_with_empty_block(self):
        source = textwrap.dedent(
            """\
            extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
              if (size) {
                dead();
              }
              target_crash_api();
              return 0;
            }
            """
        )
        coverage = CoverageMap(
            executable_lines=frozenset({1, 2, 3, 5, 6}),
            covered_lines=frozenset({1, 2, 5, 6}),
        )

        result = slice_source_by_coverage(source, coverage)

        self.assertEqual(result.removed_nodes, 1)
        self.assertIn("if (size) {", result.source)
        self.assertIn("  }\n  target_crash_api();", result.source)
        self.assertNotIn("dead();", result.source)

    def test_deletes_uncovered_loop_statement(self):
        source = textwrap.dedent(
            """\
            extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
              while (size) {
                dead();
              }
              target_crash_api();
              return 0;
            }
            """
        )
        coverage = CoverageMap(
            executable_lines=frozenset({2, 3, 5, 6}),
            covered_lines=frozenset({5, 6}),
        )

        result = slice_source_by_coverage(source, coverage)

        self.assertNotIn("while (size)", result.source)
        self.assertIn("target_crash_api();", result.source)

    def test_prunes_uncovered_tail_after_last_covered_statement(self):
        source = textwrap.dedent(
            """\
            extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
              live();
              int iter = 0;
              const int *pkt;
              while (pkt) {
                dead();
              }
              cleanup();
              return 0;
            }
            """
        )
        coverage = CoverageMap(
            executable_lines=frozenset({2, 3, 5, 7, 8}),
            covered_lines=frozenset({2}),
        )

        result = slice_source_by_coverage(source, coverage)

        self.assertIn("live();", result.source)
        self.assertNotIn("iter = 0", result.source)
        self.assertNotIn("pkt;", result.source)
        self.assertNotIn("while (pkt)", result.source)
        self.assertNotIn("cleanup();", result.source)

    def test_keeps_declaration_if_surviving_code_uses_it(self):
        source = textwrap.dedent(
            """\
            extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
              int iter = 0;
              const int *pkt;
              while (pkt) {
                use(iter);
              }
              return 0;
            }
            """
        )
        coverage = CoverageMap(
            executable_lines=frozenset({2, 4, 5, 7}),
            covered_lines=frozenset({4, 5, 7}),
        )

        result = slice_source_by_coverage(source, coverage)

        self.assertIn("int iter = 0;", result.source)


if __name__ == "__main__":
    unittest.main()

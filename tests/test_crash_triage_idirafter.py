"""Regression tests for HarnessMinimizer#6: attached -idirafterDIR include roots.

compile_include_roots must recognize the attached (no-space) form of every gcc
include switch it knows, including -idirafterDIR. Before the fix the attached
form fell through the else branch and the include root was dropped from
contract_search_roots, so contract evidence discovery missed that directory.
"""

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import crash_triage


class CompileIncludeRootsIdirafterTests(unittest.TestCase):
    def test_attached_idirafter_dir_is_recognized(self) -> None:
        with TemporaryDirectory() as directory:
            root = crash_triage.compile_include_roots(f"-idirafter{directory}")
            self.assertEqual(root, [Path(directory).resolve()])

    def test_separate_idirafter_dir_still_works(self) -> None:
        with TemporaryDirectory() as directory:
            root = crash_triage.compile_include_roots(f"-idirafter {directory}")
            self.assertEqual(root, [Path(directory).resolve()])

    def test_attached_idirafter_root_feeds_contract_search_roots(self) -> None:
        # End-to-end: an attached -idirafterDIR must reach contract_search_roots
        # the same way -Idir does (issue's impact chain).
        with TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            include = tmp_path / "third_party_include"
            include.mkdir()
            harness = tmp_path / "harness.cpp"
            harness.write_text(
                'extern "C" int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long);\n'
            )
            ctx = crash_triage.TriageContext(
                harness=harness,
                crash_input=tmp_path / "crash-input",
                binary=tmp_path / "fuzzer",
                compile_command=[],
                compile_flags=f"-idirafter{include}",
                link_flags=None,
                timeout_seconds=1,
                output_path=tmp_path / "report.md",
                work_dir=tmp_path,
            )
            roots = crash_triage.contract_search_roots(ctx, [])
            self.assertIn(include.resolve(), roots)

    def test_non_idirafter_tokens_are_not_swallowed(self) -> None:
        # Guard against prefix overreach: "-idirafter" only, or a token that
        # merely starts with those letters, must not yield a bogus root.
        self.assertEqual(crash_triage.compile_include_roots("-idirafter"), [])
        self.assertEqual(crash_triage.compile_include_roots("-idirafterX"), [])
        # Bare switch with next token (separate form) is the supported path.
        self.assertEqual(crash_triage.compile_include_roots("-idirafterX /tmp"), [])

    def test_other_include_switches_unaffected(self) -> None:
        with TemporaryDirectory() as directory:
            for flag in ("-I", "-isystem", "-iquote"):
                roots = crash_triage.compile_include_roots(f"{flag}{directory}")
                self.assertEqual(roots, [Path(directory).resolve()], flag)


if __name__ == "__main__":
    unittest.main()

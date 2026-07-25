from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import crash_triage


class CrashTriageContractTests(unittest.TestCase):
    def make_ctx(
        self,
        tmp_path: Path,
        compile_flags: str | None = None,
    ) -> crash_triage.TriageContext:
        harness = tmp_path / "harness.cpp"
        crash_input = tmp_path / "crash-input"
        harness.write_text(
            'extern "C" int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long);\n'
        )
        crash_input.write_bytes(b"crash")
        return crash_triage.TriageContext(
            harness=harness,
            crash_input=crash_input,
            binary=tmp_path / "fuzzer",
            compile_command=[],
            compile_flags=compile_flags,
            link_flags=None,
            timeout_seconds=1,
            output_path=tmp_path / "report.md",
            work_dir=tmp_path,
        )

    def test_discover_contract_evidence_searches_docs_and_include_dirs(self) -> None:
        with TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            docs = tmp_path / "docs"
            include = tmp_path / "include"
            docs.mkdir()
            include.mkdir()
            (docs / "README.md").write_text(
                "The png_image_write_to_memory API requires width and height to be non-zero.\n"
            )
            (include / "png.h").write_text(
                "int png_image_write_to_memory(void *image);\n"
            )
            ctx = self.make_ctx(tmp_path, compile_flags=f"-I{include}")

            output = crash_triage.discover_contract_evidence(
                ctx,
                ["png_image_write_to_memory"],
                ["width", "height", "non-zero"],
                [],
            )

            self.assertIn("README.md", output)
            self.assertIn("png_image_write_to_memory API requires width and height", output)
            self.assertIn(str(include / "png.h"), output)

    def test_library_bug_report_requires_contract_validity_analysis(self) -> None:
        with TemporaryDirectory() as directory:
            ctx = self.make_ctx(Path(directory))

            result = crash_triage.run_tool(
                ctx,
                "generate_crash_report",
                {
                    "triage": "library-bug",
                    "content": (
                        "# Crash Report\n\n"
                        "## Triage Verdict\n"
                        "**Classification**: Genuine Library Bug\n"
                    ),
                },
            )

            self.assertTrue(result.startswith("[!] Error:"))
            self.assertFalse(ctx.report_written)
            self.assertFalse(ctx.output_path.exists())

    def test_library_bug_report_accepts_positive_validity_proof(self) -> None:
        with TemporaryDirectory() as directory:
            ctx = self.make_ctx(Path(directory))

            result = crash_triage.run_tool(
                ctx,
                "generate_crash_report",
                {
                    "triage": "library-bug",
                    "content": """# Crash Report

## Triage Verdict
**Classification**: Genuine Library Bug
**Confidence**: High

## Contract and Validity Analysis
**Contract Sources Checked**:
- /tmp/api.md:1 documents the valid input range.

**Applicable Preconditions**:
- `len` must be between 1 and 16.

**Validity Proof**:
- The harness constrains `len` to 1..16 before calling the API.

## Judgement Citations
- **Claim**: The harness input satisfies the documented length range.
  **Source**: /tmp/api.md:1 and harness.cpp:12.
- **Claim**: The crash is therefore attributable to the library.
  **Source**: Sanitizer stack trace and validated harness preconditions.
""",
                },
            )

            self.assertTrue(result.startswith("[*] Crash report generated successfully:"))
            self.assertTrue(ctx.report_written)
            self.assertIn("Validity Proof", ctx.output_path.read_text())

    def test_reports_require_judgement_citations(self) -> None:
        with TemporaryDirectory() as directory:
            ctx = self.make_ctx(Path(directory))

            result = crash_triage.run_tool(
                ctx,
                "generate_crash_report",
                {
                    "triage": "harness-bug",
                    "content": """# Crash Report

## Triage Verdict
**Classification**: Harness Misuse
**Confidence**: High
""",
                },
            )

            self.assertTrue(result.startswith("[!] Error:"))
            self.assertIn("Judgement Citations", result)


if __name__ == "__main__":
    unittest.main()

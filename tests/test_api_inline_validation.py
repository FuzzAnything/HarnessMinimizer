from pathlib import Path
from unittest.mock import MagicMock, patch

from harnessreducer.api import ADDITIONAL_HEADES, inline_literals_in_reduced_harness


def test_inline_literals_returns_inline_file_when_crash_preserved(tmp_path: Path) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text("int x = 0;\n", encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source", return_value=("int y = 1;\n", 1)
    ), patch("harnessreducer.api.get_crash_tester_path", return_value="/tmp/crash_tester.py"), patch(
        "harnessreducer.api.run_command"
    ) as mock_run:
        proc = MagicMock()
        proc.returncode = 77
        mock_run.return_value = proc

        out = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
        )

    assert out.endswith(".inline.cpp")
    content = Path(out).read_text(encoding="utf-8")
    for header in ADDITIONAL_HEADES:
        assert header in content
    assert "int y = 1;" in content


def test_inline_literals_falls_back_when_crash_not_preserved(tmp_path: Path) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text("int x = 0;\n", encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source", return_value=("int broken = 1;\n", 1)
    ), patch("harnessreducer.api.get_crash_tester_path", return_value="/tmp/crash_tester.py"), patch(
        "harnessreducer.api.run_command"
    ) as mock_run:
        proc = MagicMock()
        proc.returncode = 1
        mock_run.return_value = proc

        out = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
        )

    assert out == str(reduced)
    content = reduced.read_text(encoding="utf-8")
    for header in ADDITIONAL_HEADES:
        assert header in content

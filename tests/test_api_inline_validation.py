from pathlib import Path
from unittest.mock import MagicMock, patch

from harnessreducer.api import ADDITIONAL_HEADES, inline_literals_in_reduced_harness
from harnessreducer.fdp_transform import InlineResult, InlineSkip


def test_inline_literals_returns_inline_file_when_crash_preserved(tmp_path: Path) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text("int x = 0;\n", encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=InlineResult(source="int y = 1;\n", replaced=1),
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
    reduced.write_text(
        "auto bytes = fdp->ConsumeBytes<uint8_t>(length, 100001);\n",
        encoding="utf-8",
    )
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=InlineResult(source="int broken = 1;\n", replaced=1),
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
    assert "ConsumeBytes<uint8_t>(length)" in content
    assert "100001" not in content


def test_inline_literals_reports_repeated_ids_preserved_for_replay(
    tmp_path: Path, capsys
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text("int x = 0;\n", encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    inline_result = InlineResult(
        source="int y = 1;\n",
        replaced=1,
        skipped=(
            InlineSkip(
                key=100012,
                method="ConsumeBytes",
                reason="repeated-trace-id",
                record_count=200,
            ),
        ),
    )

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=inline_result,
    ), patch("harnessreducer.api.get_crash_tester_path", return_value="/tmp/crash_tester.py"), patch(
        "harnessreducer.api.run_command"
    ) as mock_run:
        proc = MagicMock()
        proc.returncode = 77
        mock_run.return_value = proc

        inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
        )

    captured = capsys.readouterr()
    assert "Preserved FDP callsites for replay" in captured.out
    assert "100012(ConsumeBytes, 200 records)" in captured.out


def test_inline_literals_skips_validation_when_nothing_was_inlined(
    tmp_path: Path, capsys
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(
        "auto bytes = fdp.ConsumeBytes<uint8_t>(length, /*FDP_ID:100001*/ 100001);\n",
        encoding="utf-8",
    )
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    inline_result = InlineResult(
        source=reduced.read_text(encoding="utf-8"),
        replaced=0,
        skipped=(
            InlineSkip(
                key=100001,
                method="ConsumeBytes",
                reason="repeated-trace-id",
                record_count=12,
            ),
        ),
    )

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=inline_result,
    ), patch("harnessreducer.api.run_command") as mock_run:
        out = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
        )

    assert out == str(reduced)
    mock_run.assert_not_called()
    content = reduced.read_text(encoding="utf-8")
    assert "100001" not in content
    captured = capsys.readouterr()
    assert "Skipping inline validation because no FDP callsites were inlined" in captured.out


def test_inline_literals_persists_validation_failure_log(tmp_path: Path, capsys) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(
        "auto bytes = fdp->ConsumeBytes<uint8_t>(length, 100001);\n",
        encoding="utf-8",
    )
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=InlineResult(source="int broken = 1;\n", replaced=1),
    ), patch("harnessreducer.api.get_crash_tester_path", return_value="/tmp/crash_tester.py"), patch(
        "harnessreducer.api.run_command"
    ) as mock_run:
        proc = MagicMock()
        proc.returncode = 1
        proc.stdout = "compile or run stdout\n"
        proc.stderr = "compile or run stderr\n"
        mock_run.return_value = proc

        out = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
        )

    assert out == str(reduced)
    log_path = tmp_path / "reduced.inline.cpp.validation.log"
    assert log_path.exists()
    log_content = log_path.read_text(encoding="utf-8")
    assert "returncode: 1" in log_content
    assert "compile or run stdout" in log_content
    assert "compile or run stderr" in log_content
    captured = capsys.readouterr()
    assert str(log_path) in captured.out

from pathlib import Path
from unittest.mock import patch

from harnessreducer.api import ADDITIONAL_HEADERS, inline_literals_in_reduced_harness
from harnessreducer.fdp_transform import InlineResult, InlineSkip
from harnessreducer.reducer_runner import POST_REDUCTION_VALIDATION_ATTEMPTS


def test_inline_literals_returns_inline_file_when_crash_preserved(tmp_path: Path) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text("int x = 0;\n", encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=InlineResult(source="int y = 1;\n", replaced=1),
    ), patch("harnessreducer.api.validate_crash_pattern_and_stack_trace", return_value=True):

        out, generated_headers = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
        )

    assert out.endswith(".inline.cpp")
    assert generated_headers == ()
    content = Path(out).read_text(encoding="utf-8")
    for header in ADDITIONAL_HEADERS:
        assert header in content
    assert "int y = 1;" in content


def test_inline_literals_uses_fast_pattern_when_symbolized_pattern_is_missing(
    tmp_path: Path,
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text("auto value = fdp.ConsumeIntegral<int>(100001);\n", encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=InlineResult(source="int y = 1;\n", replaced=1),
    ), patch(
        "harnessreducer.api.validate_crash_pattern_and_stack_trace",
        return_value=True,
    ) as mock_validate:
        out, generated_headers = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            None,
            "seed.bin",
            "-I/tmp/include",
            "",
            crash_pattern_symbolize_0="FastPattern",
        )

    assert out.endswith(".inline.cpp")
    assert generated_headers == ()
    mock_validate.assert_called_once()
    assert mock_validate.call_args.args[1] == "FastPattern"
    assert mock_validate.call_args.args[2] is None
    assert mock_validate.call_args.kwargs["fdp_trace_file"] is None
    assert mock_validate.call_args.kwargs["retry_oom_without_rss_limit"] is True


def test_inline_literals_supports_direct_input_without_fdp_trace(
    tmp_path: Path,
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(
        """
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return data[0] == size ? 1 : 0;
}
""",
        encoding="utf-8",
    )
    seed = tmp_path / "seed.bin"
    seed.write_bytes(bytes([0x41, 0x42, 0x00]))

    with patch("harnessreducer.api.validate_crash_pattern_and_stack_trace", return_value=True) as mock_validate:
        out, generated_headers = inline_literals_in_reduced_harness(
            str(reduced),
            None,
            "AddressSanitizer",
            str(seed),
            "-I/tmp/include",
            "",
        )

    assert out.endswith(".inline.cpp")
    assert len(generated_headers) == 1
    header = Path(generated_headers[0])
    assert header.name == "harness_values.h"
    header_content = header.read_text(encoding="utf-8")
    assert "static uint8_t fuzz_values[]" in header_content
    assert "0x41, 0x42, 0x00" in header_content
    assert "static constexpr size_t fuzz_index = sizeof(fuzz_values);" in header_content

    content = Path(out).read_text(encoding="utf-8")
    assert '#include "harness_values.h"' in content
    assert "data = ::fuzz_values;" in content
    assert "size = ::fuzz_index;" in content
    mock_validate.assert_called_once()
    assert mock_validate.call_args.kwargs["fdp_trace_file"] is None
    assert mock_validate.call_args.kwargs["retry_oom_without_rss_limit"] is True
    assert mock_validate.call_args.kwargs["evidence_attempts"] == POST_REDUCTION_VALIDATION_ATTEMPTS


def test_inline_literals_supports_direct_input_after_parameter_type_reduction(
    tmp_path: Path,
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(
        """
#include <unistd.h>
extern "C" int LLVMFuzzerTestOneInput(int *data, int size) {
  return write(1, data, size) < 0 ? 1 : 0;
}
""",
        encoding="utf-8",
    )
    seed = tmp_path / "seed.bin"
    seed.write_bytes(bytes([0x41, 0x42, 0x00]))

    with patch("harnessreducer.api.validate_crash_pattern_and_stack_trace", return_value=True):
        out, _generated_headers = inline_literals_in_reduced_harness(
            str(reduced),
            None,
            "AddressSanitizer",
            str(seed),
            "",
            "",
        )

    content = Path(out).read_text(encoding="utf-8")
    assert "data = reinterpret_cast<decltype(data)>(::fuzz_values);" in content
    assert "size = static_cast<decltype(size)>(::fuzz_index);" in content


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
    ), patch("harnessreducer.api.validate_crash_pattern_and_stack_trace", return_value=False):

        out, generated_headers = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
        )

    assert out == str(reduced)
    assert generated_headers == ()
    content = reduced.read_text(encoding="utf-8")
    for header in ADDITIONAL_HEADERS:
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
        source="auto bytes = fdp.ConsumeBytes<uint8_t>(length, /*FDP_ID:100012*/ 100012);\n",
        replaced=1,
        skipped=(
            InlineSkip(
                key=100012,
                method="ConsumeBytes",
                reason="unsupported-repeated-trace-id",
                record_count=200,
            ),
        ),
    )

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=inline_result,
    ), patch("harnessreducer.api.validate_crash_pattern_and_stack_trace", return_value=True):

        inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
        )

    captured = capsys.readouterr()
    assert "FDP callsites left unchanged" in captured.out
    assert "ID 100012: ConsumeBytes (unsupported record format, 200 record(s))" in captured.out


def test_inline_literals_validates_unreplayed_repeated_calls_and_cleans_ids(
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
        detected_calls=1,
        skipped=(
            InlineSkip(
                key=100001,
                method="ConsumeBytes",
                reason="unsupported-repeated-trace-id",
                record_count=12,
            ),
        ),
    )

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=inline_result,
    ), patch("harnessreducer.api.validate_crash_pattern_and_stack_trace", return_value=True) as mock_validate:
        out, generated_headers = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
        )

    assert out == str(reduced.with_suffix(".inline.cpp"))
    assert generated_headers == ()
    assert mock_validate.call_count == 2
    assert mock_validate.call_args_list[0].kwargs["fdp_trace_file"] == str(trace)
    assert mock_validate.call_args_list[1].kwargs["fdp_trace_file"] is None
    assert mock_validate.call_args_list[0].kwargs["evidence_attempts"] == POST_REDUCTION_VALIDATION_ATTEMPTS
    assert mock_validate.call_args_list[1].kwargs["evidence_attempts"] == POST_REDUCTION_VALIDATION_ATTEMPTS
    content = Path(out).read_text(encoding="utf-8")
    assert "100001" not in content
    assert "100001" in reduced.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert "FDP callsite(s) remain after replacement" in captured.out
    assert "ID 100001: ConsumeBytes (unsupported record format, 12 record(s))" in captured.out
    assert "Skipping inline validation" not in captured.out


def test_inline_literals_validates_when_fdp_calls_remain_unreplayed(
    tmp_path: Path, capsys
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(
        """
#include <fuzzer/FuzzedDataProvider.h>
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, int size) {
  FuzzedDataProvider fdp(data, size);
  return fdp.ConsumeIntegralInRange<size_t>(1, 0, 0);
}
""",
        encoding="utf-8",
    )
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("S 100004 4\n", encoding="utf-8")

    with patch("harnessreducer.api.validate_crash_pattern_and_stack_trace", return_value=True) as mock_validate:
        out, generated_headers = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
        )

    assert out.endswith(".inline.cpp")
    assert generated_headers == ()
    assert mock_validate.call_count == 2
    assert mock_validate.call_args_list[0].kwargs["fdp_trace_file"] == str(trace)
    assert mock_validate.call_args_list[1].kwargs["fdp_trace_file"] is None
    assert mock_validate.call_args_list[0].kwargs["retry_oom_without_rss_limit"] is True
    assert mock_validate.call_args_list[0].kwargs["evidence_attempts"] == POST_REDUCTION_VALIDATION_ATTEMPTS
    assert mock_validate.call_args_list[1].kwargs["evidence_attempts"] == POST_REDUCTION_VALIDATION_ATTEMPTS
    captured = capsys.readouterr()
    assert "FDP callsite(s) remain after replacement" in captured.out


def test_inline_literals_reports_missing_record_without_injected_id(
    tmp_path: Path, capsys
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(
        "auto value = fdp.ConsumeIntegral<int>();\n",
        encoding="utf-8",
    )
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    inline_result = InlineResult(
        source=reduced.read_text(encoding="utf-8"),
        replaced=0,
        detected_calls=1,
        skipped=(
            InlineSkip(
                key=None,
                method="ConsumeIntegral",
                reason="missing-trace-record",
                record_count=0,
            ),
        ),
    )

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=inline_result,
    ), patch("harnessreducer.api.validate_crash_pattern_and_stack_trace", return_value=True):
        inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
        )

    captured = capsys.readouterr()
    assert "no injected ID: ConsumeIntegral (missing matching record)" in captured.out


def test_inline_literals_reports_unsupported_record_format(
    tmp_path: Path, capsys
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(
        "auto flag = fdp.ConsumeBool(/*FDP_ID:100004*/ 100004);\n",
        encoding="utf-8",
    )
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    inline_result = InlineResult(
        source=reduced.read_text(encoding="utf-8"),
        replaced=0,
        detected_calls=1,
        skipped=(
            InlineSkip(
                key=100004,
                method="ConsumeBool",
                reason="unsupported-record-format",
                record_count=1,
            ),
        ),
    )

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=inline_result,
    ), patch("harnessreducer.api.validate_crash_pattern_and_stack_trace", return_value=True):
        inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
        )

    captured = capsys.readouterr()
    assert "ID 100004: ConsumeBool (unsupported record format, 1 record(s))" in captured.out


def test_inline_literals_rejects_replay_success_when_final_output_fails(
    tmp_path: Path, capsys
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(
        "auto value = fdp.ConsumeIntegral<int>(/*FDP_ID:100001*/ 100001);\n",
        encoding="utf-8",
    )
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")
    inline_result = InlineResult(
        source=reduced.read_text(encoding="utf-8"),
        replaced=0,
        detected_calls=1,
        skipped=(
            InlineSkip(
                key=100001,
                method="ConsumeIntegral",
                reason="missing-trace-record",
                record_count=0,
            ),
        ),
    )

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=inline_result,
    ), patch(
        "harnessreducer.api.validate_crash_pattern_and_stack_trace",
        side_effect=[True, False, False],
    ) as mock_validate:
        out, generated_headers = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
        )

    assert out == str(reduced)
    assert generated_headers == ()
    assert mock_validate.call_count == 3
    assert mock_validate.call_args_list[0].kwargs["fdp_trace_file"] == str(trace)
    assert mock_validate.call_args_list[1].kwargs["fdp_trace_file"] is None
    assert mock_validate.call_args_list[2].kwargs["fdp_trace_file"] is None
    captured = capsys.readouterr()
    assert "Replay validation preserved crash behavior" in captured.out
    assert "Final output validation failed" in captured.out


def test_inline_literals_persists_validation_failure_log(tmp_path: Path, capsys) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text(
        "auto bytes = fdp->ConsumeBytes<uint8_t>(length, 100001);\n",
        encoding="utf-8",
    )
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    def _write_failure_log(*args, **kwargs) -> bool:
        Path(kwargs["validation_log_path"]).write_text(
            "returncode: 1\n===== stdout =====\ncompile or run stdout\n===== stderr =====\ncompile or run stderr\n",
            encoding="utf-8",
        )
        return False

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=InlineResult(source="int broken = 1;\n", replaced=1),
    ), patch(
        "harnessreducer.api.validate_crash_pattern_and_stack_trace",
        side_effect=_write_failure_log,
    ):

        out, generated_headers = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
        )

    assert out == str(reduced)
    assert generated_headers == ()
    log_path = tmp_path / "reduced.inline.cpp.validation.log"
    assert log_path.exists()
    log_content = log_path.read_text(encoding="utf-8")
    assert "returncode: 1" in log_content
    assert "compile or run stdout" in log_content
    assert "compile or run stderr" in log_content
    captured = capsys.readouterr()
    assert str(log_path) in captured.out


def test_inline_literals_retries_last_interesting_snapshot_when_primary_inline_fails(
    tmp_path: Path,
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text("int primary = 0;\n", encoding="utf-8")
    snapshot = tmp_path / "last_interesting.cpp"
    snapshot.write_text("int backup = 1;\n", encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    with patch("harnessreducer.api.load_trace", return_value={}) as mock_load_trace, patch(
        "harnessreducer.api.inline_source_with_report",
        side_effect=[
            InlineResult(source="int broken = 1;\n", replaced=1),
            InlineResult(source="int fixed = 1;\n", replaced=1),
        ],
    ), patch(
        "harnessreducer.api.validate_crash_pattern_and_stack_trace",
        side_effect=[False, True],
    ), patch(
        "harnessreducer.api.get_last_interesting_file",
        return_value=str(snapshot),
    ):
        out, _headers = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
            snapshot=True,
        )

    assert out == str(snapshot.with_suffix(".inline.cpp"))
    assert Path(out).exists()
    assert mock_load_trace.call_count == 2


def test_inline_literals_falls_back_to_snapshot_base_when_snapshot_inline_fails(
    tmp_path: Path,
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text("int primary = 0;\n", encoding="utf-8")
    snapshot = tmp_path / "last_interesting.cpp"
    snapshot.write_text(
        "auto bytes = fdp->ConsumeBytes<uint8_t>(length, 100001);\n",
        encoding="utf-8",
    )
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    with patch("harnessreducer.api.load_trace", return_value={}), patch(
        "harnessreducer.api.inline_source_with_report",
        side_effect=[
            InlineResult(source="int broken = 1;\n", replaced=1),
            InlineResult(source="int also_broken = 1;\n", replaced=1),
        ],
    ), patch(
        "harnessreducer.api.validate_crash_pattern_and_stack_trace",
        side_effect=[False, False, False],
    ), patch(
        "harnessreducer.api.get_last_interesting_file",
        return_value=str(snapshot),
    ):
        out, _headers = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
            snapshot=True,
        )

    assert out == str(snapshot)
    content = snapshot.read_text(encoding="utf-8")
    assert "100001" not in content


def test_inline_literals_does_not_use_snapshot_unless_enabled(
    tmp_path: Path,
) -> None:
    reduced = tmp_path / "reduced.cpp"
    reduced.write_text("int primary = 0;\n", encoding="utf-8")
    snapshot = tmp_path / "last_interesting.cpp"
    snapshot.write_text("int backup = 1;\n", encoding="utf-8")
    trace = tmp_path / "fdp_trace.log"
    trace.write_text("", encoding="utf-8")

    with patch("harnessreducer.api.load_trace", return_value={}) as mock_load_trace, patch(
        "harnessreducer.api.inline_source_with_report",
        return_value=InlineResult(source="int broken = 1;\n", replaced=1),
    ), patch(
        "harnessreducer.api.validate_crash_pattern_and_stack_trace",
        return_value=False,
    ), patch(
        "harnessreducer.api.get_last_interesting_file",
        return_value=str(snapshot),
    ):
        out, _headers = inline_literals_in_reduced_harness(
            str(reduced),
            str(trace),
            "AddressSanitizer",
            "seed.bin",
            "-I/tmp/include",
            "",
        )

    assert out == str(reduced)
    assert mock_load_trace.call_count == 1

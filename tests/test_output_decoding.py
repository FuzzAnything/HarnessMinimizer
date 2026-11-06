"""Arbitrary target bytes must not prevent crash evidence from being checked."""

from argparse import Namespace
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

from harnessminimizer import reducer_runner as runner
from harnessminimizer.crash_evidence import EvidenceResult
from harnessminimizer.fdp_transform import load_trace
from harnessminimizer.process_supervisor import run_supervised
from tests import crash_tester


NOISE = b"target bytes: \x8d\xff\n"
REPORT = (
    b"    #0 0xabcd in target /src/library.cpp:42:3\n"
    b"    #1 0xbeef in LLVMFuzzerTestOneInput /tmp/harness.cpp:9:1\n"
    b"SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
)


def emitting_command(stdout=b"", stderr=b"", status=0, tail="pass"):
    return [sys.executable, "-c", (
        f"import os, time; os.write(1, {stdout!r}); os.write(2, {stderr!r}); "
        f"{tail}; raise SystemExit({status})"
    )]


@pytest.mark.parametrize("text", [False, True])
@pytest.mark.parametrize("merged", [False, True])
def test_supervisor_preserves_binary_and_decodes_text_tolerantly(text, merged):
    stdout = "valid UTF-8: λ".encode() + b"\x8d\r\n"
    stderr = NOISE + REPORT
    result = run_supervised(
        emitting_command(stdout, stderr, 77), stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merged else subprocess.PIPE,
        text=text, private_tmpdir=True,
    )
    expected_stdout = stdout + stderr if merged else stdout
    expected_stderr = None if merged else stderr
    if text:
        expected_stdout = expected_stdout.decode("utf-8", "replace").replace("\r\n", "\n")
        if expected_stderr is not None:
            expected_stderr = expected_stderr.decode("utf-8", "replace")
    assert (result.returncode, result.stdout, result.stderr) == (77, expected_stdout, expected_stderr)


def test_supervisor_honors_explicit_decoding_policy():
    command = emitting_command(stderr=b"\x8d")
    result = run_supervised(command, stderr=subprocess.PIPE, text=True, encoding="latin-1")
    assert result.stderr == "\x8d"
    with pytest.raises(UnicodeDecodeError):
        run_supervised(command, stderr=subprocess.PIPE, text=True, errors="strict")


def test_check_and_timeout_keep_the_real_failure():
    with pytest.raises(subprocess.CalledProcessError) as failed:
        run_supervised(emitting_command(stderr=NOISE, status=7),
                       stderr=subprocess.PIPE, text=True, check=True)
    assert failed.value.returncode == 7
    assert failed.value.stderr == NOISE.decode("utf-8", "replace")

    with pytest.raises(subprocess.TimeoutExpired) as timed_out:
        run_supervised(emitting_command(stderr=NOISE, tail="time.sleep(8)"),
                       stderr=subprocess.PIPE, text=True, timeout=0.5)
    # TimeoutExpired continues to carry the exact partial bytes.
    assert timed_out.value.stderr == NOISE


def test_reference_execution_still_extracts_the_sanitizer_signature(tmp_path):
    target = tmp_path / "target.py"
    target.write_text(f"import os\nos.write(2, {NOISE + REPORT!r})\nraise SystemExit(77)\n")
    result = runner._run_harness_for_crash_reference(
        sys.executable, str(target), symbolize=False,
    )
    assert result.returncode == 77
    assert "\ufffd" in result.stderr
    pattern = runner._extract_crash_signature_from_output(result.stderr)
    assert pattern and re.search(pattern, REPORT.decode())
    assert runner.extract_symbolized_crash_location(result.stderr, "/tmp/harness.cpp") == "/src/library.cpp:42:3"


@pytest.mark.parametrize("report,status,expected", [
    (REPORT, 77, EvidenceResult.MATCH),
    (b"", 77, EvidenceResult.MISMATCH),
    (REPORT.replace(b"heap-buffer-overflow", b"stack-overflow"), 77, EvidenceResult.MISMATCH),
    (REPORT.replace(b":42:3", b":43:3"), 77, EvidenceResult.MISMATCH),
    (REPORT, 0, EvidenceResult.MISMATCH),
])
def test_candidate_execution_keeps_all_crash_checks(report, status, expected):
    actual_status, output, _elapsed = crash_tester.run_executable(
        emitting_command(stdout=NOISE, stderr=NOISE + report, status=status),
        env=os.environ.copy(), exec_timeout_ms=2000,
    )
    args = Namespace(
        source="/tmp/harness.cpp", symbolize=True, debug_log=None,
        skip_crash_pattern=False,
        crash_pattern=runner._extract_crash_signature_from_output(REPORT.decode()),
        crash_location_pattern=r"/src/library\.cpp:42:3", crash_location_file=None,
        stack_depth=2, strict_stack_depth=True, stack_trace_file=None,
    )
    assert "\ufffd" in output
    result, _missing = crash_tester._evaluate_candidate_crash(args, actual_status, output)
    assert result is expected


def test_candidate_timeout_preserves_non_utf8_diagnostics():
    status, output, _elapsed = crash_tester.run_executable(
        emitting_command(stderr=NOISE, tail="time.sleep(8)"),
        env=os.environ.copy(), exec_timeout_ms=500,
    )
    assert status == 124
    assert NOISE.decode("utf-8", "replace") in output
    assert "Execution timed out" in output


def test_dump_output_decoding_does_not_change_fdp_trace(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "get_work_dir", lambda: str(tmp_path))
    target = tmp_path / "dump.py"
    target.write_text(
        "import os\nfrom pathlib import Path\n"
        "Path(os.environ['FDP_TRACE_PATH']).write_bytes(b'S 100000 7\\n')\n"
        f"os.write(2, {NOISE + REPORT!r})\nraise SystemExit(77)\n"
    )
    trace = Path(runner.dump_fdp_trace(sys.executable, str(target)))
    assert trace.read_bytes() == b"S 100000 7\n"
    assert list(load_trace(trace)[100000]) == [("S", 7)]


def test_runner_startup_reports_non_utf8_failure(tmp_path, monkeypatch):
    target = tmp_path / "failed-runner"
    target.write_text(f"#!{sys.executable}\nimport os\nos.write(2, {NOISE!r})\nraise SystemExit(1)\n")
    target.chmod(0o755)
    monkeypatch.setattr(runner, "resolve_amortized_link_inputs",
                        lambda _flags: runner.AmortizedLinkInputs((), (), ()))
    monkeypatch.setattr(runner, "_compile_harness_runner", lambda *_args: str(target))
    with pytest.raises(RuntimeError, match="failed during startup") as failure:
        with runner.start_amortized_runner(None, None, None, symbolize=False):
            pytest.fail("A failed runner must not be accepted")
    assert NOISE.decode("utf-8", "replace") in str(failure.value)

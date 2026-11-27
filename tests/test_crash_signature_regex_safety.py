"""Regression: crash-signature extraction must emit regex-safe patterns (R93).

_extract_crash_signature_from_output results are consumed as regexes by
crash_tester (re.search(crash_pattern, run_log)). Branches that embed source
paths or raw condition text must escape, otherwise the signature fails to
match the very output it was extracted from (wrong-reject).
"""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from harnessminimizer.reducer_runner import (  # noqa: E402
    _extract_crash_signature_from_output,
)


def _assert_matches_own_output(output: str) -> str:
    sig = _extract_crash_signature_from_output(output)
    assert sig, f"no signature extracted from {output!r}"
    assert re.search(sig, output), (
        f"signature {sig!r} does not match its own output {output!r}"
    )
    return sig


def test_abort_assert_path_with_plus_is_regex_safe():
    _assert_matches_own_output(
        "poc.out: /root/src/targets/c++/encoder/file.c:358: Assertion `x > 0` failed."
    )


def test_ubsan_summary_path_with_plus_is_regex_safe():
    _assert_matches_own_output(
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /root/src/c++/foo.c:42:5"
    )


def test_absl_check_condition_with_metachars_is_regex_safe():
    _assert_matches_own_output(
        "F0000 00:00:00: Check failed: (size_t)offset + len <= buf_size (5 vs. 4)"
    )


@pytest.mark.parametrize(
    "output",
    [
        "fixture.out: /src/__ADDR__/file.c:358: Assertion `ready` failed.",
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/__ADDR__/file.c:42:5",
        "Check failed: marker == __ADDR__ (1 vs. 2)",
    ],
    ids=["assertion", "ubsan-summary", "absl-check"],
)
def test_literal_address_marker_remains_literal(output: str):
    sig = _assert_matches_own_output(output)
    assert re.search(sig, output.replace("__ADDR__", "0x2a")) is None


def test_safe_branches_still_match():
    _assert_matches_own_output("SUMMARY: AddressSanitizer: heap-buffer-overflow")
    _assert_matches_own_output("SUMMARY: libFuzzer: deadly signal")
    _assert_matches_own_output(
        "ERROR: AddressSanitizer: stack-overflow on address 0x7ffc (pc 0x000000)"
    )


def test_runtime_error_branch_keeps_escape():
    # Pre-existing escape=True branch: path metachars + address normalization.
    out = "/src/c++/x.c:1:2: runtime error: 0x10 null deref"
    sig = _extract_crash_signature_from_output(out)
    assert sig and re.search(sig, out)

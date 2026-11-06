"""Match sanitizer source locations across verified copies of a source file."""

import filecmp
from pathlib import Path
import re


_PATTERN_PATH = re.compile(r"(?P<path>/(?:\\.|[^:\\])+):\d+(?::\d+)?")
_OUTPUT_LOCATION = re.compile(r"(?P<path>/[^\s:]+):\d+(?::\d+)?")


def _reference_path(pattern: str) -> str | None:
    """Recover a literal source path from the patterns recorded by the runner."""
    match = _PATTERN_PATH.search(pattern)
    if match is None:
        return None
    escaped_path = match.group("path")
    path = re.sub(r"\\(.)", r"\1", escaped_path)
    if re.escape(path) == escaped_path:
        return path
    # The UBSan SUMMARY fallback is stored without re.escape. Restrict this
    # form to plain path characters rather than interpreting arbitrary regex.
    if (
        pattern.startswith("SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ")
        and re.fullmatch(r"/[A-Za-z0-9_./+~-]+", escaped_path)
    ):
        return escaped_path
    return None


def _matches_verified_alias(pattern: str, text: str, *, fullmatch: bool) -> bool:
    reference = _reference_path(pattern)
    location = _OUTPUT_LOCATION.search(text)
    if reference is None or location is None:
        return False

    candidate = location.group("path")
    if reference == candidate or Path(reference).name != Path(candidate).name:
        return False
    try:
        if not filecmp.cmp(reference, candidate, shallow=False):
            return False
    except OSError:
        return False

    normalized = text[:location.start("path")] + reference + text[location.end("path"):]
    return (re.fullmatch(pattern, normalized) if fullmatch else re.search(pattern, normalized)) is not None


def matches_crash_pattern(pattern: str, output: str) -> bool:
    if re.search(pattern, output) is not None:
        return True
    # Only a sanitizer report can establish a crash-site alias. The error
    # wording and source coordinates remain subject to the original regex.
    return any(
        _matches_verified_alias(pattern, line, fullmatch=False)
        for line in output.splitlines()
        if "runtime error:" in line or "SUMMARY: UndefinedBehaviorSanitizer:" in line
    )


def matches_crash_location(pattern: str, location: str) -> bool:
    return re.fullmatch(pattern, location) is not None or _matches_verified_alias(
        pattern, location, fullmatch=True,
    )

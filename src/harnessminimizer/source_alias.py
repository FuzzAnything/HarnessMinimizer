"""Match sanitizer source locations across verified copies of a source file."""

import filecmp
import json
import os
from pathlib import Path
import re
import tempfile


_PATTERN_PATH = re.compile(r"(?P<path>/(?:\\.|[^:\\])+):\d+(?::\d+)?")
_OUTPUT_LOCATION = re.compile(r"(?P<path>/[^\s:]+):\d+(?::\d+)?")


class SourceAliases:
    """Approved path pairs; only the original plugin check may learn new ones."""

    def __init__(self, pairs=(), *, allow_verification: bool = False):
        self.pairs = {tuple(sorted(pair)) for pair in pairs}
        self.allow_verification = allow_verification

    @classmethod
    def from_json(cls, text: str, *, allow_verification: bool = False):
        pairs = json.loads(text)
        if not isinstance(pairs, list) or any(
            not isinstance(pair, list) or len(pair) != 2
            or any(not isinstance(path, str) or not path.startswith("/") for path in pair)
            for pair in pairs
        ):
            raise ValueError("Source aliases must be a list of absolute path pairs")
        return cls(pairs, allow_verification=allow_verification)

    def to_json(self) -> str:
        return json.dumps(sorted(self.pairs))

    def save(self, path: str) -> None:
        destination = Path(path)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                         delete=False) as handle:
            temporary = Path(handle.name)
            try:
                handle.write(self.to_json() + "\n")
                handle.close()
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)

    def accepts(self, reference: str, candidate: str) -> bool:
        pair = tuple(sorted((reference, candidate)))
        if pair in self.pairs:
            return True
        if not self.allow_verification or Path(reference).name != Path(candidate).name:
            return False
        try:
            if not filecmp.cmp(reference, candidate, shallow=False):
                return False
        except OSError:
            return False
        self.pairs.add(pair)
        return True


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


def _matches_verified_alias(
    pattern: str, text: str, *, fullmatch: bool, aliases: SourceAliases,
) -> bool:
    reference = _reference_path(pattern)
    location = _OUTPUT_LOCATION.search(text)
    if reference is None or location is None:
        return False

    candidate = location.group("path")
    if reference == candidate:
        return False

    normalized = text[:location.start("path")] + reference + text[location.end("path"):]
    match = re.fullmatch(pattern, normalized) if fullmatch else re.search(pattern, normalized)
    return match is not None and aliases.accepts(reference, candidate)


def matches_crash_pattern(
    pattern: str, output: str, aliases: SourceAliases | None = None,
) -> bool:
    if re.search(pattern, output) is not None:
        return True
    if aliases is None:
        aliases = SourceAliases(allow_verification=True)
    # Only a sanitizer report can establish a crash-site alias. The error
    # wording and source coordinates remain subject to the original regex.
    return any(
        _matches_verified_alias(pattern, line, fullmatch=False, aliases=aliases)
        for line in output.splitlines()
        if "runtime error:" in line or "SUMMARY: UndefinedBehaviorSanitizer:" in line
    )


def matches_crash_location(
    pattern: str, location: str, aliases: SourceAliases | None = None,
) -> bool:
    if aliases is None:
        aliases = SourceAliases(allow_verification=True)
    return re.fullmatch(pattern, location) is not None or _matches_verified_alias(
        pattern, location, fullmatch=True, aliases=aliases,
    )

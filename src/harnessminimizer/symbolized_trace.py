"""In-memory reference traces, shared by preparation and candidate checking."""

from dataclasses import dataclass, field
import json
from pathlib import Path
import re

from harnessminimizer.crash_evidence import EvidenceResult
from harnessminimizer.source_alias import SourceAliases, _matches_verified_alias


TRACE_SET_ENV = "HARNESSMINIMIZER_SYMBOLIZED_TRACE_SET"
STACK_FRAME_COUNT_PATTERN = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\b")
SOURCE_LOCATION_PATTERN = re.compile(r"(/[^:\s\)]+):(\d+)(?::(\d+))?")
LLVMFuzzerTestOneInput_PATTERN = re.compile(r"\bLLVMFuzzerTestOneInput\b")
MEMORY_ADDRESS_PATTERN = re.compile(r"\b0x[0-9a-fA-F]+\b")


def normalize_crash_signature(signature: str, escape: bool = False) -> str:
    signature = signature.strip()
    if escape:
        placeholder = "__ADDR__"
        signature = MEMORY_ADDRESS_PATTERN.sub(placeholder, signature)
        signature = re.escape(signature)
        return signature.replace(re.escape(placeholder), r"0x[0-9a-fA-F]+")
    return MEMORY_ADDRESS_PATTERN.sub(r"0x[0-9a-fA-F]+", signature)


def _frame_matches_harness_source(frame_line: str, harness_path: str | None) -> bool:
    if not harness_path:
        return False
    harness_resolved = str(Path(harness_path).resolve())
    if harness_resolved in frame_line:
        return True
    match = SOURCE_LOCATION_PATTERN.search(frame_line)
    if not match:
        return Path(harness_path).name in frame_line
    frame_source = match.group(1)
    try:
        if Path(frame_source).resolve() == Path(harness_path).resolve():
            return True
    except OSError:
        pass
    return Path(frame_source).name == Path(harness_path).name


def extract_stack_trace(output: str, harness_path: str | None = None) -> str | None:
    """Extract only the first contiguous trace, stopping before harness frames."""
    frames = []
    in_first_trace = False
    for line in output.splitlines():
        if STACK_FRAME_COUNT_PATTERN.match(line):
            in_first_trace = True
            if _frame_matches_harness_source(line, harness_path):
                break
            if LLVMFuzzerTestOneInput_PATTERN.search(line):
                break
            frames.append(line)
        elif in_first_trace:
            break
    return "\n".join(frames) if frames else None


@dataclass(frozen=True)
class SymbolizedTraceReference:
    normalized_patterns: tuple[str, ...]
    samples_completed: int
    serialized: str = field(init=False, repr=False, compare=False)
    _compiled: tuple = field(init=False, repr=False, compare=False)
    _frames: tuple = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if not self.normalized_patterns or any(
            not isinstance(pattern, str) or not pattern.strip() for pattern in self.normalized_patterns
        ):
            raise ValueError("Reference traces must contain nonempty regex patterns")
        if type(self.samples_completed) is not int or self.samples_completed < 0:
            raise ValueError("Reference trace sample count must be a nonnegative integer")
        patterns = tuple(dict.fromkeys(self.normalized_patterns))
        object.__setattr__(self, "normalized_patterns", patterns)
        object.__setattr__(self, "_compiled", tuple(re.compile(pattern) for pattern in patterns))
        # re.escape represents each newline as a backslash followed by a newline.
        object.__setattr__(self, "_frames", tuple(
            tuple(re.compile(frame) for frame in pattern.split("\\\n")) for pattern in patterns
        ))
        object.__setattr__(self, "serialized", json.dumps({
            "schema_version": 1, "normalized_patterns": patterns,
            "samples_completed": self.samples_completed,
        }, separators=(",", ":")))

    @classmethod
    def from_json(cls, payload: str):
        value = json.loads(payload)
        if not isinstance(value, dict) or value.get("schema_version") != 1 or not isinstance(value.get("normalized_patterns"), list):
            raise ValueError("Invalid symbolized reference trace payload")
        return cls(tuple(value["normalized_patterns"]), value.get("samples_completed"))

    def evaluate(
        self, output: str, harness_path: str | None, aliases: SourceAliases | None = None,
    ) -> tuple[EvidenceResult, int | None]:
        trace = extract_stack_trace(output, harness_path)
        if trace is None:
            return EvidenceResult.MISSING_EVIDENCE, None
        trace = trace.strip()
        lines = trace.splitlines()
        for index, (pattern, frames) in enumerate(zip(self._compiled, self._frames), start=1):
            if pattern.fullmatch(trace):
                return EvidenceResult.MATCH, index
            if aliases is None or len(lines) != len(frames):
                continue
            # Learning is transactional: a rejected alternative cannot approve
            # path pairs. Only the original plugin check permits verification.
            trial = SourceAliases(aliases.pairs, allow_verification=aliases.allow_verification)
            if all(
                frame.fullmatch(line) or _matches_verified_alias(
                    frame.pattern, line, fullmatch=True, aliases=trial,
                ) for frame, line in zip(frames, lines)
            ):
                aliases.pairs.update(trial.pairs)
                return EvidenceResult.MATCH, index
        return EvidenceResult.MISMATCH, None

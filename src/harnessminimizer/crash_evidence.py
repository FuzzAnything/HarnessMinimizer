"""Bounded recovery from missing crash evidence; observed mismatches never retry."""

from enum import Enum


REFERENCE_EVIDENCE_ATTEMPTS = 5
CANDIDATE_EVIDENCE_ATTEMPTS = 3


class EvidenceResult(Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    MISSING_EVIDENCE = "missing_evidence"


def retry_missing_evidence(
    reason: str, attempt: int, max_attempts: int, *, context: str,
) -> bool:
    if attempt < max_attempts:
        print(f"[!] Missing {reason} in {context} attempt {attempt}/{max_attempts}; retrying.")
        return True
    print(f"[!] Missing {reason} after {context} attempt {attempt}/{max_attempts}; attempts exhausted.")
    return False

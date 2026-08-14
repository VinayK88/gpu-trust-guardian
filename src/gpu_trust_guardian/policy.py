"""Deterministic policy gate for model keys and sensitive GPU workloads."""

from __future__ import annotations

from .models import AttestationEvidence, Finding


def decide(findings: list[Finding], attestation: AttestationEvidence) -> tuple[int, str]:
    score = min(100, sum(item.score for item in findings))
    critical = any(item.severity == "critical" for item in findings)
    high = any(item.severity == "high" for item in findings)
    if not attestation.trusted or critical or score >= 70:
        return score, "BLOCK"
    if high or score >= 35:
        return score, "QUARANTINE"
    return score, "ALLOW"

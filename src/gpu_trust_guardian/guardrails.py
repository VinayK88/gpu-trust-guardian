"""Runnable reference guard for an AI-assisted GPU security analyst."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any


ALLOWED_TOOLS = {"get_gpu_status", "search_evidence", "summarize_incident", "quarantine_workload"}
APPROVAL_TOOLS = {"quarantine_workload"}
INJECTION_PATTERNS = (
    r"ignore (all|any|the) previous",
    r"reveal (the )?(system|developer) prompt",
    r"disable (the )?(guardrail|policy)",
    r"bypass (approval|authorization)",
)
SECRET_PATTERNS = (
    r"AKIA[0-9A-Z]{16}",
    r"(?i)(api[_ -]?key|password|secret)\s*[:=]\s*\S+",
)


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    reason: str
    requires_approval: bool
    sanitized_message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _redact(message: str) -> str:
    sanitized = message
    for pattern in SECRET_PATTERNS:
        sanitized = re.sub(pattern, "[REDACTED]", sanitized)
    return sanitized


def evaluate_request(
    message: str,
    tool: str | None = None,
    human_approved: bool = False,
) -> GuardDecision:
    sanitized = _redact(message)
    if any(re.search(pattern, message, flags=re.IGNORECASE) for pattern in INJECTION_PATTERNS):
        return GuardDecision(False, "prompt-injection pattern detected", False, sanitized)
    if sanitized != message:
        return GuardDecision(False, "possible credential or secret detected", False, sanitized)
    if tool and tool not in ALLOWED_TOOLS:
        return GuardDecision(False, "tool is outside the analyst allowlist", False, sanitized)
    if tool in APPROVAL_TOOLS and not human_approved:
        return GuardDecision(False, "human approval is required for containment", True, sanitized)
    return GuardDecision(True, "request passed bounded policy checks", False, sanitized)


def evaluate_cases(cases: list[dict[str, Any]], guarded: bool = True) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        if guarded:
            decision = evaluate_request(
                str(case["message"]),
                tool=case.get("tool"),
                human_approved=bool(case.get("human_approved", False)),
            )
            actual_allowed = decision.allowed
            reason = decision.reason
        else:
            actual_allowed = True
            reason = "unguarded baseline permits every request"
        results.append(
            {
                **case,
                "actual_allowed": actual_allowed,
                "correct": actual_allowed == bool(case["expected_allowed"]),
                "reason": reason,
            }
        )
    return results

"""Severity bands and the evidence gate.

The evidence gate is the most important safety property in the scoring layer:
an alert whose evidence is explicitly marked insufficient can never be rated
high. The system is allowed to say "this is suspicious"; it is not allowed to
escalate on a weak inference.
"""

from __future__ import annotations

from netshield.config.settings import ScoringConfig

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def severity_for(score: int, config: ScoringConfig) -> str:
    if score >= config.medium_max:
        return "high"
    if score >= config.low_max:
        return "medium"
    return "low"


def apply_evidence_gate(severity: str, evidence_sufficient: bool) -> str:
    if not evidence_sufficient and SEVERITY_ORDER[severity] > SEVERITY_ORDER["medium"]:
        return "medium"
    return severity

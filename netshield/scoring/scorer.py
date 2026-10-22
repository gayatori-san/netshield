"""Transparent threat scoring.

    score = clamp(rule_base + volume_bonus + frequency_bonus, 0, 100)

Every term is visible in the alert's ``reasons`` and ``facts``. There are no
confidence percentages and no accuracy claims: the number is an analyst
triage aid, not a probability that an attack occurred.
"""

from __future__ import annotations

from netshield.config.settings import DedupConfig, ScoringConfig
from netshield.detectors.dedup import AlertDeduplicator
from netshield.models import Alert, AlertCandidate
from netshield.scoring.severity import apply_evidence_gate, severity_for

RULE_BASE = {
    "PORT_SCAN_PORTS": 40,
    "PORT_SCAN_HOSTS": 40,
    "REPEATED_CONNECTIONS": 30,
    "SENSITIVE_PORT": 25,
    "CONN_RATE_ANOMALY": 30,
    "TRAFFIC_SPIKE": 45,
    "BASELINE_DEVIATION": 40,
}

MAX_VOLUME_BONUS = 30
MAX_FREQUENCY_BONUS = 20
FREQUENCY_STEP = 5
RECURRENCE_WINDOW_SECONDS = 600


class AlertScorer:
    def __init__(self, scoring: ScoringConfig, dedup: DedupConfig):
        self.config = scoring
        self.deduplicator = AlertDeduplicator(dedup.suppression_seconds)

    def score(
        self,
        candidate: AlertCandidate,
        now: float,
        recurrence_count: int = 1,
        data_origin: str = "real",
    ) -> Alert:
        facts = dict(candidate.facts)
        observed = int(facts.get("observed", 0))
        required = int(facts.get("required", 0))
        sufficient = bool(facts.get("evidence_sufficient", True))
        volume_scale = bool(facts.get("volume_scale", True))
        metric = str(facts.get("metric", "observed value"))
        window = facts.get("window_seconds")

        volume_observed = int(facts.get("volume_observed", observed))
        volume_required = int(facts.get("volume_required", required))

        base = RULE_BASE.get(candidate.rule_id, 20)

        volume_bonus = 0
        if volume_scale and volume_required > 0:
            ratio = max(0.0, volume_observed / volume_required)
            volume_bonus = min(MAX_VOLUME_BONUS, int(ratio * MAX_VOLUME_BONUS))

        frequency_bonus = min(MAX_FREQUENCY_BONUS, max(0, recurrence_count - 1) * FREQUENCY_STEP)

        score = max(0, min(100, base + volume_bonus + frequency_bonus))
        severity = severity_for(score, self.config)
        final_severity = apply_evidence_gate(severity, sufficient)

        reasons: list[str] = []
        if window:
            reasons.append(f"{metric}: {observed} observed vs threshold {required} within {window}s")
        else:
            reasons.append(f"{metric}: {observed} observed vs threshold {required}")
        reasons.append(f"Rule base weight +{base}")

        if volume_bonus:
            reasons.append(
                f"Volume {volume_observed}/{volume_required} "
                f"({volume_observed / max(volume_required, 1):.1f}x) contributed +{volume_bonus}"
            )
        if frequency_bonus:
            reasons.append(f"{recurrence_count} recent alerts from this source contributed +{frequency_bonus}")

        if not sufficient:
            detail = facts.get("insufficient_reason") or "evidence is incomplete or ambiguous"
            reasons.append(f"Evidence marked insufficient ({detail}); severity capped at medium")
        elif final_severity != severity:
            reasons.append("Severity capped at medium because evidence is insufficient")

        fingerprint = self.deduplicator.fingerprint(
            candidate.rule_id, candidate.src_ip, candidate.dst_ip, candidate.window_end
        )

        return Alert(
            rule_id=candidate.rule_id,
            title=candidate.title,
            severity=final_severity,
            score=score,
            reasons=reasons,
            evidence=candidate.evidence,
            facts={**facts, "base": base, "volume_bonus": volume_bonus, "frequency_bonus": frequency_bonus},
            evidence_sufficient=sufficient,
            src_ip=candidate.src_ip,
            dst_ip=candidate.dst_ip,
            detected_at=candidate.window_end,
            window_start=candidate.window_start,
            window_end=candidate.window_end,
            data_origin=data_origin,
            fingerprint=fingerprint,
        )

    def should_emit(self, alert: Alert, now: float) -> bool:
        identity = f"{alert.rule_id}|{alert.src_ip or '-'}|{alert.dst_ip or '-'}"
        return self.deduplicator.should_emit(alert.fingerprint, now, identity=identity)

    def reset(self) -> None:
        self.deduplicator.reset()

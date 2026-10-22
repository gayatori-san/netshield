"""Shared data contracts.

Every stage of the pipeline exchanges these dataclasses instead of ad-hoc
dictionaries. That single decision removes most integration bugs, because a
typo in a dict key becomes an attribute error at the point of use rather
than a silently missing field in the dashboard.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high")
STATUSES = ("new", "acknowledged", "resolved")

RULE_TITLES = {
    "PORT_SCAN_PORTS": "Possible port scan (many destination ports)",
    "PORT_SCAN_HOSTS": "Possible host sweep (many destination hosts)",
    "REPEATED_CONNECTIONS": "Repeated connection attempts",
    "SENSITIVE_PORT": "Connection to a sensitive service port",
    "CONN_RATE_ANOMALY": "Unusual connection rate for this source",
    "TRAFFIC_SPIKE": "Traffic rate spike",
    "BASELINE_DEVIATION": "Traffic above rolling baseline",
    "HALF_OPEN_PATTERN": "Many half-open TCP handshakes (inferred)",
}


@dataclass(frozen=True, slots=True)
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    flags: str | None
    tcp_state: str | None
    size: int
    source: str

    @property
    def is_connection_attempt(self) -> bool:
        if self.protocol == "TCP":
            return self.tcp_state == "SYN"
        return self.protocol == "UDP"


@dataclass
class AlertCandidate:
    rule_id: str
    src_ip: str | None
    dst_ip: str | None
    window_start: float
    window_end: float
    evidence: dict = field(default_factory=dict)
    facts: dict = field(default_factory=dict)

    @property
    def title(self) -> str:
        return RULE_TITLES.get(self.rule_id, self.rule_id)


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    score: int
    reasons: list[str]
    evidence: dict
    facts: dict
    evidence_sufficient: bool
    src_ip: str | None
    dst_ip: str | None
    detected_at: float
    window_start: float
    window_end: float
    data_origin: str = "real"
    status: str = "new"
    analyst_notes: str | None = None
    fingerprint: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_db_row(self) -> dict:
        import json

        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "score": self.score,
            "reasons_json": json.dumps(self.reasons),
            "evidence_json": json.dumps(self.evidence, default=str),
            "facts_json": json.dumps(self.facts, default=str),
            "evidence_sufficient": 1 if self.evidence_sufficient else 0,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "detected_at": self.detected_at,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "status": self.status,
            "analyst_notes": self.analyst_notes,
            "data_origin": self.data_origin,
            "created_at": self.detected_at,
            "updated_at": self.detected_at,
        }


@dataclass
class FeatureSnapshot:
    now: float
    total_packets: int
    total_bytes: int
    current_pps: float
    baseline_pps: float
    window_packets: int
    active_flows: int
    protocol_counts: dict[str, int]
    top_sources: list[tuple[str, int]]
    top_destinations: list[tuple[str, int]]


@dataclass
class CaptureStatus:
    state: str = "idle"
    mode: str | None = None
    target: str | None = None
    started_at: float | None = None
    finished_at: float | None = None
    packets_processed: int = 0
    packets_skipped: int = 0
    alerts_raised: int = 0
    error: str | None = None
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "mode": self.mode,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "packets_processed": self.packets_processed,
            "packets_skipped": self.packets_skipped,
            "alerts_raised": self.alerts_raised,
            "error": self.error,
            "message": self.message,
        }

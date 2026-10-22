"""Detector protocol and shared helpers.

Every detector is deterministic and does no I/O: it consumes PacketRecord
objects and returns AlertCandidate objects for a given logical clock value.
No detector reads the wall clock or the database. That is what makes each
rule testable in isolation and makes a replay reproducible.
"""

from __future__ import annotations

from collections import deque
from typing import Protocol

from netshield.models import AlertCandidate, PacketRecord


class Detector(Protocol):
    rule_id: str

    def update(self, pkt: PacketRecord) -> None: ...

    def flush(self, now: float) -> list[AlertCandidate]: ...

    def reset(self) -> None: ...


def prune_timestamps(mapping: dict, cutoff: float) -> None:
    """Drop timestamped entries older than cutoff from a dict of dicts."""
    for key in list(mapping.keys()):
        inner = mapping[key]
        for sub_key in [k for k, ts in inner.items() if ts < cutoff]:
            del inner[sub_key]
        if not inner:
            del mapping[key]


def prune_deques(mapping: dict, cutoff: float) -> None:
    """Drop timestamps older than cutoff from a dict of deques."""
    for key in list(mapping.keys()):
        queue = mapping[key]
        while queue and queue[0] < cutoff:
            queue.popleft()
        if not queue:
            del mapping[key]


def trim_deque(queue: deque, cutoff: float) -> None:
    while queue and queue[0] < cutoff:
        queue.popleft()


def candidate(
    rule_id: str,
    src_ip: str | None,
    dst_ip: str | None,
    window_start: float,
    window_end: float,
    evidence: dict,
    facts: dict,
) -> AlertCandidate:
    return AlertCandidate(
        rule_id=rule_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        window_start=window_start,
        window_end=window_end,
        evidence=evidence,
        facts=facts,
    )

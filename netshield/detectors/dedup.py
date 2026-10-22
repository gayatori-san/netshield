"""Duplicate-alert suppression.

Two layers exist on purpose:

1. This in-memory check stops the scoring/insert path from being re-run for
   the same observation every flush tick.
2. The SQLite UNIQUE(fingerprint) index is the durable backstop, so a restart
   or a concurrent writer cannot create a duplicate either.

The fingerprint includes a coarse time bucket, so a scan that lasts ten
minutes produces one incident per bucket rather than hundreds of rows.
"""

from __future__ import annotations

import hashlib


class AlertDeduplicator:
    def __init__(self, suppression_seconds: int = 300):
        if suppression_seconds <= 0:
            raise ValueError("suppression_seconds must be positive")
        self.suppression_seconds = suppression_seconds
        self._seen: dict[str, float] = {}

    def bucket(self, timestamp: float) -> int:
        return int(timestamp // self.suppression_seconds)

    def fingerprint(self, rule_id: str, src_ip: str | None, dst_ip: str | None, window_end: float) -> str:
        raw = f"{rule_id}|{src_ip or '-'}|{dst_ip or '-'}|{self.bucket(window_end)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def should_emit(
        self, fingerprint: str, now: float, identity: str | None = None
    ) -> bool:
        """Return True when this observation should become an incident.

        ``fingerprint`` changes when a sliding window crosses a coarse time
        bucket. Suppression therefore keys on ``identity`` (rule + addresses)
        when provided, so one ongoing pattern cannot produce a second incident
        merely because the bucket boundary moved. The fingerprint remains the
        durable database key, so a genuinely new bucket can still be stored
        after the suppression window.
        """
        key = identity or fingerprint
        last = self._seen.get(key)
        if last is not None and (now - last) < self.suppression_seconds:
            return False
        self._seen[key] = now
        self._prune(now)
        return True

    def _prune(self, now: float) -> None:
        cutoff = now - (self.suppression_seconds * 2)
        for key in [k for k, ts in self._seen.items() if ts < cutoff]:
            del self._seen[key]

    def reset(self) -> None:
        self._seen.clear()

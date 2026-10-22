"""Windowed traffic statistics used by the dashboard and the detectors.

The aggregator keeps *display* statistics (protocol mix, top talkers, rate
series) plus a rolling EWMA baseline. Detection rules keep their own state so
each rule can be unit-tested in isolation; see detectors/ for that tradeoff.

Bounded structures throughout: a flood of spoofed addresses must not turn the
monitor itself into the victim.
"""

from __future__ import annotations

from collections import Counter

from netshield.features.extract import FlowExtractor
from netshield.models import FeatureSnapshot, PacketRecord


class TrafficAggregator:
    def __init__(
        self,
        baseline_alpha: float = 0.3,
        rate_window_seconds: int = 300,
        max_endpoints: int = 5000,
        max_flows: int = 20000,
    ):
        self.baseline_alpha = baseline_alpha
        self.rate_window_seconds = rate_window_seconds
        self.max_endpoints = max_endpoints

        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts: Counter[str] = Counter()
        self.src_counts: Counter[str] = Counter()
        self.dst_counts: Counter[str] = Counter()

        self._buckets: dict[int, list[int]] = {}
        self._last_second: int | None = None
        self._last_second_packets = 0
        self._baseline: float | None = None
        self._baseline_samples = 0
        self._last_ts = 0.0

        self.flows = FlowExtractor(max_flows=max_flows)

    def observe(self, pkt: PacketRecord) -> None:
        self.total_packets += 1
        self.total_bytes += pkt.size
        self.protocol_counts[pkt.protocol] += 1
        self.src_counts[pkt.src_ip] += 1
        self.dst_counts[pkt.dst_ip] += 1
        self._trim_counter(self.src_counts)
        self._trim_counter(self.dst_counts)

        second = int(pkt.timestamp)
        bucket = self._buckets.setdefault(second, [0, 0])
        bucket[0] += 1
        bucket[1] += pkt.size

        self._update_baseline(second)
        self._last_ts = max(self._last_ts, pkt.timestamp)
        self.flows.observe(pkt)
        self._prune_buckets(second)

    def _update_baseline(self, second: int) -> None:
        if self._last_second is None:
            self._last_second = second
            self._last_second_packets = 1
            return
        if second == self._last_second:
            self._last_second_packets += 1
            return
        completed = self._last_second_packets
        if self._baseline is None:
            self._baseline = float(completed)
        else:
            self._baseline = self.baseline_alpha * completed + (1 - self.baseline_alpha) * self._baseline
        self._baseline_samples += 1
        self._last_second = second
        self._last_second_packets = 1

    def _prune_buckets(self, now_second: int) -> None:
        cutoff = now_second - self.rate_window_seconds
        for sec in [s for s in self._buckets if s < cutoff]:
            del self._buckets[sec]

    def _trim_counter(self, counter: Counter[str]) -> None:
        if len(counter) > self.max_endpoints:
            for key, _ in counter.most_common()[self.max_endpoints :]:
                counter.pop(key, None)

    @property
    def last_timestamp(self) -> float:
        return self._last_ts

    def current_pps(self) -> float:
        if not self._buckets:
            return 0.0
        latest = max(self._buckets)
        return float(self._buckets[latest][0])

    def baseline_pps(self) -> float:
        return float(self._baseline) if self._baseline is not None else 0.0

    def baseline_samples(self) -> int:
        return self._baseline_samples

    def recent_packets_in_window(self, now: float, window_seconds: int) -> int:
        cutoff = int(now) - window_seconds
        return sum(b[0] for sec, b in self._buckets.items() if sec >= cutoff)

    def snapshot(self, now: float) -> FeatureSnapshot:
        return FeatureSnapshot(
            now=now,
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            current_pps=self.current_pps(),
            baseline_pps=self.baseline_pps(),
            window_packets=self.recent_packets_in_window(now, 60),
            active_flows=self.flows.active_count(),
            protocol_counts=dict(self.protocol_counts),
            top_sources=self.src_counts.most_common(10),
            top_destinations=self.dst_counts.most_common(10),
        )

    def drain_buckets(self) -> list[dict]:
        """Return completed per-second buckets for persistence and clear them."""
        if not self._buckets:
            return []
        latest = max(self._buckets)
        rows = [
            {"bucket_ts": sec, "packets": vals[0], "bytes": vals[1]}
            for sec, vals in sorted(self._buckets.items())
            if sec < latest
        ]
        for row in rows:
            self._buckets.pop(row["bucket_ts"], None)
        return rows

    def recent_buckets(self, limit: int = 120) -> list[dict]:
        return [
            {"bucket_ts": sec, "packets": vals[0], "bytes": vals[1]}
            for sec, vals in sorted(self._buckets.items())[-limit:]
        ]

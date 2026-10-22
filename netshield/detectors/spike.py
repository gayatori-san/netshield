"""Traffic-rate spike detection.

Two mutually exclusive observations per one-second bucket:

* TRAFFIC_SPIKE      -- the bucket exceeds an absolute packets-per-second
                        ceiling. This is a factual rate observation.
* BASELINE_DEVIATION -- the bucket exceeds a multiple of the host's rolling
                        EWMA baseline, above a minimum rate floor.

Why the floor matters: a ratio against a 2 pps baseline is meaningless
(3x2 = 6 pps is not a flood). Why the baseline sample minimum matters: a
baseline computed from one second is not a baseline.

A spike is *not* proof of DDoS. A backup job, a video call, a CDN fetch or a
local curl loop all produce the same shape. The alert text says "traffic rate
spike" on purpose.
"""

from __future__ import annotations

from collections import Counter

from netshield.config.settings import SpikeConfig
from netshield.detectors.base import candidate
from netshield.models import AlertCandidate, PacketRecord


class TrafficSpikeDetector:
    rule_id = "TRAFFIC_SPIKE"

    def __init__(self, config: SpikeConfig):
        self.config = config
        self.reset()

    def reset(self) -> None:
        self._seconds: dict[int, dict] = {}
        self._pending: set[int] = set()
        self._baseline: float | None = None
        self._samples = 0
        self._current_second: int | None = None
        self._current_count = 0
        self._baseline_at: dict[int, float | None] = {}
        self._samples_at: dict[int, int] = {}

    def update(self, pkt: PacketRecord) -> None:
        second = int(pkt.timestamp)

        if self._current_second is None:
            self._current_second = second
            self._current_count = 0
            self._baseline_at[second] = self._baseline
            self._samples_at[second] = self._samples
        elif second == self._current_second:
            pass
        elif second > self._current_second:
            if self._baseline is None:
                self._baseline = float(self._current_count)
            else:
                alpha = self.config.baseline_alpha
                self._baseline = alpha * self._current_count + (1 - alpha) * self._baseline
            self._samples += 1
            self._current_second = second
            self._current_count = 0
            self._baseline_at[second] = self._baseline
            self._samples_at[second] = self._samples
        else:
            self._baseline_at.setdefault(second, self._baseline)
            self._samples_at.setdefault(second, self._samples)

        self._current_count += 1

        bucket = self._seconds.get(second)
        if bucket is None:
            bucket = {"packets": 0, "bytes": 0, "src": Counter(), "dst": Counter()}
            self._seconds[second] = bucket
        bucket["packets"] += 1
        bucket["bytes"] += pkt.size
        bucket["src"][pkt.src_ip] += 1
        bucket["dst"][pkt.dst_ip] += 1
        if len(bucket["src"]) > 64:
            bucket["src"] = Counter(dict(bucket["src"].most_common(32)))
        if len(bucket["dst"]) > 64:
            bucket["dst"] = Counter(dict(bucket["dst"].most_common(32)))

        self._pending.add(second)

    def flush(self, now: float) -> list[AlertCandidate]:
        cutoff = int(now) - max(self.config.baseline_window_seconds, self.config.window_seconds)
        results: list[AlertCandidate] = []

        for second in sorted(self._pending):
            data = self._seconds.get(second)
            if data is None:
                continue
            pps = data["packets"]
            baseline = self._baseline_at.get(second)
            samples = self._samples_at.get(second, 0)
            top_src = data["src"].most_common(3)
            top_dst = data["dst"].most_common(3)
            src = top_src[0][0] if top_src else None
            dst = top_dst[0][0] if top_dst else None

            if pps >= self.config.spike_absolute_pps:
                results.append(
                    candidate(
                        rule_id="TRAFFIC_SPIKE",
                        src_ip=src,
                        dst_ip=dst,
                        window_start=float(second),
                        window_end=float(second + 1),
                        evidence={
                            "packets_per_second": pps,
                            "bytes_in_second": data["bytes"],
                            "top_sources": top_src,
                            "top_destinations": top_dst,
                            "absolute_threshold": self.config.spike_absolute_pps,
                            "note": "A high packet rate is a factual observation. It does "
                            "not establish a denial-of-service attack: backups, video "
                            "calls and file transfers produce the same pattern.",
                        },
                        facts={
                            "metric": "packets per second",
                            "observed": pps,
                            "required": self.config.spike_absolute_pps,
                            "volume_observed": pps,
                            "volume_required": self.config.spike_absolute_pps,
                            "evidence_sufficient": True,
                            "volume_scale": True,
                        },
                    )
                )
            elif (
                baseline is not None
                and samples >= self.config.baseline_min_samples
                and pps >= self.config.spike_min_pps
                and pps >= self.config.spike_baseline_ratio * baseline
            ):
                results.append(
                    candidate(
                        rule_id="BASELINE_DEVIATION",
                        src_ip=src,
                        dst_ip=dst,
                        window_start=float(second),
                        window_end=float(second + 1),
                        evidence={
                            "packets_per_second": pps,
                            "baseline_pps": round(baseline, 2),
                            "baseline_samples": samples,
                            "multiple_of_baseline": round(pps / baseline, 2) if baseline else None,
                            "top_sources": top_src,
                            "top_destinations": top_dst,
                            "note": "The rate is unusual for this capture's own history. "
                            "That is a relative observation, not proof of an attack.",
                        },
                        facts={
                            "metric": "packets per second",
                            "observed": pps,
                            "required": max(1, int(round(self.config.spike_baseline_ratio * baseline))),
                            "volume_observed": pps,
                            "volume_required": self.config.spike_min_pps,
                            "baseline_pps": round(baseline, 2),
                            "baseline_samples": samples,
                            "evidence_sufficient": True,
                            "volume_scale": True,
                        },
                    )
                )

        self._pending.clear()

        for second in [s for s in self._seconds if s < cutoff]:
            self._seconds.pop(second, None)
            self._baseline_at.pop(second, None)
            self._samples_at.pop(second, None)

        return results

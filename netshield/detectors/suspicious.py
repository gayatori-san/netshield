"""Suspicious-connection detection.

Three related but distinct observations:

* REPEATED_CONNECTIONS -- many SYNs to the same destination service that never
  receive a SYN-ACK. This is the closest packet-metadata approximation of
  "repeated failed connection attempts". It remains an *inference*: a one-way
  capture, a middlebox drop and a genuinely closed port all look identical.
  The alert is therefore marked as insufficient evidence on its own, and the
  severity is capped at medium.

* SENSITIVE_PORT -- a connection attempt to a remote-administration or
  database service. A single attempt is recorded but marked insufficient;
  two or more attempts are treated as sufficient evidence.

* CONN_RATE_ANOMALY -- the source's TCP connection rate exceeds an absolute
  floor AND a multiple of its own rolling baseline. The baseline comparison
  is what separates "busy" from "abnormal for this host".

Only TCP SYN packets are counted. UDP is connectionless: DNS and QUIC produce
large volumes of normal UDP "attempts", so counting them would guarantee
false positives.
"""

from __future__ import annotations

from collections import deque

from netshield.config.settings import SuspiciousConfig
from netshield.detectors.base import candidate
from netshield.models import AlertCandidate, PacketRecord

SENSITIVE_PORT_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

VOLUME_REFERENCE_FOR_SENSITIVE_PORT = 5


class SuspiciousConnectionDetector:
    rule_id = "SUSPICIOUS"

    def __init__(self, config: SuspiciousConfig):
        self.config = config
        self.reset()

    def reset(self) -> None:
        self._syn: dict[tuple[str, str, int], deque[tuple[float, int | None]]] = {}
        self._synack: dict[tuple[str, str, int], deque[float]] = {}
        self._sensitive: dict[tuple[str, int], dict] = {}
        self._conn_buckets: dict[str, dict[int, int]] = {}
        self._conn_baseline: dict[str, float] = {}
        self._conn_samples: dict[str, int] = {}
        self._conn_last_second: dict[str, int] = {}
        self._conn_pending: dict[str, int] = {}

    def update(self, pkt: PacketRecord) -> None:
        ts = pkt.timestamp

        if pkt.protocol == "TCP" and pkt.tcp_state == "SYN" and pkt.dst_port is not None:
            key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
            self._syn.setdefault(key, deque()).append((ts, pkt.src_port))

            if pkt.dst_port in self.config.sensitive_ports:
                entry = self._sensitive.get((pkt.src_ip, pkt.dst_port))
                if entry is None:
                    entry = {"times": deque(), "sports": set()}
                    self._sensitive[(pkt.src_ip, pkt.dst_port)] = entry
                entry["times"].append(ts)
                entry["sports"].add(pkt.src_port)

            self._advance_conn_rate(pkt.src_ip, int(ts))

        elif pkt.protocol == "TCP" and pkt.tcp_state == "SYN_ACK" and pkt.src_port is not None:
            key = (pkt.dst_ip, pkt.src_ip, pkt.src_port)
            self._synack.setdefault(key, deque()).append(ts)

    def _advance_conn_rate(self, src: str, second: int) -> None:
        bucket = self._conn_buckets.setdefault(src, {})
        bucket[second] = bucket.get(second, 0) + 1

        last = self._conn_last_second.get(src)
        if last is None:
            self._conn_last_second[src] = second
            self._conn_pending[src] = 1
            return
        if second == last:
            self._conn_pending[src] = self._conn_pending.get(src, 0) + 1
            return
        if second < last:
            return
        completed = self._conn_pending.get(src, 0)
        baseline = self._conn_baseline.get(src)
        alpha = self.config.conn_baseline_alpha
        self._conn_baseline[src] = float(completed) if baseline is None else alpha * completed + (1 - alpha) * baseline
        self._conn_samples[src] = self._conn_samples.get(src, 0) + 1
        self._conn_last_second[src] = second
        self._conn_pending[src] = 1

    def flush(self, now: float) -> list[AlertCandidate]:
        cutoff = now - self.config.window_seconds
        cutoff_second = int(cutoff)

        for key in list(self._syn):
            queue = self._syn[key]
            while queue and queue[0][0] < cutoff:
                queue.popleft()
            if not queue:
                del self._syn[key]

        for key in list(self._synack):
            queue = self._synack[key]
            while queue and queue[0] < cutoff:
                queue.popleft()
            if not queue:
                del self._synack[key]

        for key in list(self._sensitive):
            entry = self._sensitive[key]
            while entry["times"] and entry["times"][0] < cutoff:
                entry["times"].popleft()
            if not entry["times"]:
                del self._sensitive[key]

        for src in list(self._conn_buckets):
            bucket = self._conn_buckets[src]
            for second in [s for s in bucket if s < cutoff_second]:
                del bucket[second]

        results: list[AlertCandidate] = []

        for (src, dst, dport), syns in self._syn.items():
            replies = len(self._synack.get((src, dst, dport), ()))
            unanswered = len(syns) - replies
            if unanswered < self.config.repeat_attempt_threshold:
                continue
            distinct_sports = len({sport for _, sport in syns if sport is not None})
            results.append(
                candidate(
                    rule_id="REPEATED_CONNECTIONS",
                    src_ip=src,
                    dst_ip=dst,
                    window_start=cutoff,
                    window_end=now,
                    evidence={
                        "destination_port": dport,
                        "syn_packets": len(syns),
                        "syn_ack_packets": replies,
                        "unanswered_syns": unanswered,
                        "distinct_source_ports": distinct_sports,
                        "first_seen": syns[0][0],
                        "last_seen": syns[-1][0],
                        "inference": "No SYN-ACK was observed. This can mean the service "
                        "refused or dropped the connections, or that replies were not captured.",
                    },
                    facts={
                        "metric": "unanswered TCP SYNs to one destination port",
                        "observed": unanswered,
                        "required": self.config.repeat_attempt_threshold,
                        "window_seconds": self.config.window_seconds,
                        "destination_port": dport,
                        "evidence_sufficient": False,
                        "insufficient_reason": "SYN/SYN-ACK asymmetry may be capture loss rather than failed connections",
                        "volume_scale": True,
                    },
                )
            )

        for (src, dport), entry in self._sensitive.items():
            count = len(entry["times"])
            if count < 1:
                continue
            name = SENSITIVE_PORT_NAMES.get(dport, "sensitive service")
            results.append(
                candidate(
                    rule_id="SENSITIVE_PORT",
                    src_ip=src,
                    dst_ip=None,
                    window_start=cutoff,
                    window_end=now,
                    evidence={
                        "destination_port": dport,
                        "service": name,
                        "attempts": count,
                        "distinct_source_ports": len(entry["sports"]),
                        "first_seen": entry["times"][0],
                        "last_seen": entry["times"][-1],
                        "note": "A single connection to an administrative service is "
                        "routine. This is only noteworthy when repeated or unexpected.",
                    },
                    facts={
                        "metric": "connection attempts to a sensitive port",
                        "observed": count,
                        "required": 1,
                        "volume_observed": count,
                        "volume_required": VOLUME_REFERENCE_FOR_SENSITIVE_PORT,
                        "window_seconds": self.config.window_seconds,
                        "destination_port": dport,
                        "evidence_sufficient": count >= 2,
                        "insufficient_reason": "a single connection to an administrative port is routine",
                        "volume_scale": True,
                    },
                )
            )

        for src, bucket in self._conn_buckets.items():
            rate = sum(bucket.values())
            if rate < self.config.conn_rate_threshold:
                continue
            baseline = self._conn_baseline.get(src)
            samples = self._conn_samples.get(src, 0)
            has_baseline = baseline is not None and samples >= self.config.conn_baseline_min_samples
            multiple = (rate / baseline) if has_baseline and baseline and baseline > 0 else None
            sufficient = bool(has_baseline and multiple is not None and multiple >= self.config.conn_rate_multiplier)
            results.append(
                candidate(
                    rule_id="CONN_RATE_ANOMALY",
                    src_ip=src,
                    dst_ip=None,
                    window_start=cutoff,
                    window_end=now,
                    evidence={
                        "connections_in_window": rate,
                        "baseline_connections_per_second": round(baseline, 2) if baseline is not None else None,
                        "baseline_samples": samples,
                        "multiple_of_baseline": round(multiple, 2) if multiple is not None else None,
                        "note": "A high connection rate is normal for busy clients. "
                        "It only becomes evidence when it is unusual for this source.",
                    },
                    facts={
                        "metric": "TCP connections in window",
                        "observed": rate,
                        "required": self.config.conn_rate_threshold,
                        "window_seconds": self.config.window_seconds,
                        "baseline_samples": samples,
                        "evidence_sufficient": sufficient,
                        "insufficient_reason": "no stable per-source baseline exists yet",
                        "volume_scale": True,
                    },
                )
            )

        return results

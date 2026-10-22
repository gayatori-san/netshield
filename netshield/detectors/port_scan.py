"""Port-scan and host-sweep detection.

Key correctness decision: only *connection attempts* count as scan evidence.
A TCP SYN (without ACK) or a UDP datagram is an attempt; a SYN-ACK, RST or
plain ACK is a response. Without this distinction, the victim of a scan looks
like a scanner, because it sends one reply per probed port -- a very common
false positive in student IDS projects.

Metadata cannot tell a malicious scan from an inventory scanner, an uptime
monitor or a vulnerability assessment, so the alert wording stays
"possible".
"""

from __future__ import annotations

from collections import deque

from netshield.config.settings import PortScanConfig
from netshield.detectors.base import candidate
from netshield.models import AlertCandidate, PacketRecord


class PortScanDetector:
    rule_id = "PORT_SCAN"

    def __init__(self, config: PortScanConfig):
        self.config = config
        self.reset()

    def reset(self) -> None:
        self._ports: dict[tuple[str, str], dict[int, float]] = {}
        self._hosts: dict[str, dict[str, float]] = {}
        self._pair_attempts: dict[tuple[str, str], deque[float]] = {}
        self._src_attempts: dict[str, deque[float]] = {}

    def update(self, pkt: PacketRecord) -> None:
        if not pkt.is_connection_attempt or pkt.dst_port is None:
            return

        pair = (pkt.src_ip, pkt.dst_ip)
        self._ports.setdefault(pair, {})[pkt.dst_port] = pkt.timestamp
        self._hosts.setdefault(pkt.src_ip, {})[pkt.dst_ip] = pkt.timestamp
        self._pair_attempts.setdefault(pair, deque()).append(pkt.timestamp)
        self._src_attempts.setdefault(pkt.src_ip, deque()).append(pkt.timestamp)

    def flush(self, now: float) -> list[AlertCandidate]:
        cutoff = now - self.config.window_seconds
        for pair in list(self._ports):
            self._ports[pair] = {p: ts for p, ts in self._ports[pair].items() if ts >= cutoff}
        for src in list(self._hosts):
            self._hosts[src] = {d: ts for d, ts in self._hosts[src].items() if ts >= cutoff}
        for mapping in (self._pair_attempts, self._src_attempts):
            for key in list(mapping):
                queue = mapping[key]
                while queue and queue[0] < cutoff:
                    queue.popleft()

        results: list[AlertCandidate] = []

        for (src, dst), ports in self._ports.items():
            if len(ports) < self.config.distinct_port_threshold:
                continue
            attempts = len(self._pair_attempts.get((src, dst), ()))
            if attempts < self.config.min_packets_per_target:
                continue
            observed = len(ports)
            required = self.config.distinct_port_threshold
            sample = sorted(ports)[:40]
            results.append(
                candidate(
                    rule_id="PORT_SCAN_PORTS",
                    src_ip=src,
                    dst_ip=dst,
                    window_start=now - self.config.window_seconds,
                    window_end=now,
                    evidence={
                        "distinct_destination_ports": observed,
                        "ports_sample": sample,
                        "connection_attempts": attempts,
                        "note": "Distinct destination ports contacted by one source. "
                        "This pattern is also produced by legitimate scanners.",
                    },
                    facts={
                        "metric": "distinct destination ports",
                        "observed": observed,
                        "required": required,
                        "window_seconds": self.config.window_seconds,
                        "connection_attempts": attempts,
                        "occurrences": 1,
                        "evidence_sufficient": True,
                        "volume_scale": True,
                    },
                )
            )

        for src, hosts in self._hosts.items():
            if len(hosts) < self.config.distinct_host_threshold:
                continue
            attempts = len(self._src_attempts.get(src, ()))
            if attempts < self.config.distinct_host_threshold:
                continue
            observed = len(hosts)
            required = self.config.distinct_host_threshold
            results.append(
                candidate(
                    rule_id="PORT_SCAN_HOSTS",
                    src_ip=src,
                    dst_ip=None,
                    window_start=now - self.config.window_seconds,
                    window_end=now,
                    evidence={
                        "distinct_destination_hosts": observed,
                        "hosts_sample": sorted(hosts)[:40],
                        "connection_attempts": attempts,
                        "note": "One source contacted many hosts within the window. "
                        "A host sweep and a busy load balancer probe look identical "
                        "from packet metadata alone.",
                    },
                    facts={
                        "metric": "distinct destination hosts",
                        "observed": observed,
                        "required": required,
                        "window_seconds": self.config.window_seconds,
                        "connection_attempts": attempts,
                        "occurrences": 1,
                        "evidence_sufficient": True,
                        "volume_scale": True,
                    },
                )
            )

        results.sort(key=lambda c: c.facts.get("observed", 0), reverse=True)
        return results

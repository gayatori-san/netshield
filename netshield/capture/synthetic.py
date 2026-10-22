"""Labelled synthetic traffic for the demonstration mode.

This is *not* an attack generator. It builds packet **records** in memory and
paces them onto the pipeline; nothing is sent to the network and no raw socket
is involved. Every record carries the ``synthetic:demo`` source label and the
pipeline marks the run as ``demonstration`` origin, so the dashboard can never
present this traffic as observed evidence.

The scenario is deliberately small and readable so it can be explained in a
viva: normal traffic, one port scan, one host sweep, repeated SSH attempts and
one traffic spike.
"""

from __future__ import annotations

import random
import time
from typing import Iterator

from netshield.models import CaptureStatus, PacketRecord

DEMO_SECONDS = 60.0
LABEL = "synthetic:demo"

# (client, server, destination port) — all non-sensitive ports.
NORMAL_FLOWS = (
    ("10.0.0.20", "10.0.0.10", 443),
    ("10.0.0.21", "10.0.0.10", 443),
    ("10.0.0.22", "10.0.0.11", 8080),
)

SCAN_SRC = "203.0.113.50"
SCAN_DST = "10.0.0.10"
SWEEP_SRC = "203.0.113.77"
SWEEP_PORT = 443
SSH_SRC = "10.0.0.66"
SSH_DST = "10.0.0.60"
SPIKE_SRC = "10.0.0.99"
SPIKE_DST = "10.0.0.50"

SCAN_START, SCAN_END = 20.0, 28.0
SWEEP_START, SWEEP_END = 28.0, 36.0
SSH_START, SSH_END = 36.0, 42.0
SPIKE_AT = 44.0
SPIKE_PACKETS = 600


class SyntheticSource:
    def __init__(self, duration: float = 45.0, *, pace: bool = True, seed: int = 1337):
        self.duration = duration
        self.pace = pace
        self.seed = seed
        self.label = LABEL
        self._stop = False
        self._status = CaptureStatus(
            state="idle", mode="demo", target="labelled synthetic demonstration"
        )
        self._speed = DEMO_SECONDS / duration if duration > 0 else 1.0

    def start(self) -> None:
        self._status = CaptureStatus(
            state="running",
            mode="demo",
            target="labelled synthetic demonstration",
            started_at=time.time(),
            message="replaying a labelled lab scenario (no packets are sent)",
        )

    def packets(self) -> Iterator[PacketRecord]:
        records = self._build()
        if not records:
            return
        base = records[0].timestamp
        wall_start = time.monotonic()
        try:
            for record in records:
                if self._stop:
                    break
                if self.pace and self._speed > 0:
                    target = wall_start + (record.timestamp - base) / self._speed
                    while not self._stop:
                        remaining = target - time.monotonic()
                        if remaining <= 0:
                            break
                        time.sleep(min(remaining, 0.2))
                    if self._stop:
                        break
                yield record
        finally:
            self._status.state = "completed"
            self._status.finished_at = time.time()

    def stop(self) -> None:
        self._stop = True

    def status(self) -> CaptureStatus:
        return self._status

    # ------------------------------------------------------------------
    def _build(self) -> list[PacketRecord]:
        rng = random.Random(self.seed)
        # Anchor to a whole second so each scripted event falls inside one
        # detector bucket; a fractional anchor would split the flood across
        # two seconds and hide it from the absolute-rate rule.
        start = float(int(time.time()))
        rows: list[tuple] = []

        def add(offset, src, dst, sport, dport, proto, flags, state):
            size = rng.randint(60, 1400) if proto == "TCP" else rng.randint(70, 300)
            rows.append((start + offset, src, dst, sport, dport, proto, flags, state, size))

        def normal_window(begin: float, end: float) -> None:
            for second in range(int(begin), int(end)):
                for index, (client, server, port) in enumerate(NORMAL_FLOWS):
                    sport = 40000 + second * 7 + index * 3
                    add(second + 0.05, client, server, sport, port, "TCP", "S", "SYN")
                    add(second + 0.06, server, client, port, sport, "TCP", "SA", "SYN_ACK")
                    for turn in range(4):
                        add(
                            second + 0.1 + turn * 0.2,
                            client,
                            server,
                            sport,
                            port,
                            "TCP",
                            "A",
                            "ACK",
                        )
                if second % 4 == 0:
                    add(second + 0.5, "10.0.0.20", "10.0.0.1", 51000 + second, 53, "UDP", None, None)

        normal_window(0, SCAN_START)
        normal_window(SPIKE_AT + 2, DEMO_SECONDS)

        # Port scan: 40 distinct ports, one SYN each, no replies.
        for index in range(40):
            offset = SCAN_START + index * (SCAN_END - SCAN_START) / 40
            add(offset, SCAN_SRC, SCAN_DST, 50000 + index, 1000 + index, "TCP", "S", "SYN")

        # Host sweep: one port across 30 hosts.
        for index in range(30):
            offset = SWEEP_START + index * (SWEEP_END - SWEEP_START) / 30
            add(offset, SWEEP_SRC, f"10.0.0.{10 + index}", 49000 + index, SWEEP_PORT, "TCP", "S", "SYN")

        # Repeated failed SSH attempts.
        for index in range(20):
            offset = SSH_START + index * (SSH_END - SSH_START) / 20
            add(offset, SSH_SRC, SSH_DST, 52000 + index, 22, "TCP", "S", "SYN")

        # One-second flood: 600 datagrams from a single source.
        for index in range(SPIKE_PACKETS):
            add(SPIKE_AT + index / SPIKE_PACKETS, SPIKE_SRC, SPIKE_DST, 33000, 9999, "UDP", None, None)

        rows.sort(key=lambda row: row[0])
        return [
            PacketRecord(
                timestamp=ts,
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                protocol=proto,
                flags=flags,
                tcp_state=state,
                size=size,
                source=LABEL,
            )
            for ts, src, dst, sport, dport, proto, flags, state, size in rows
        ]

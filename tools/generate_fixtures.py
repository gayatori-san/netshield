"""Generate deterministic offline PCAP fixtures.

Nothing here transmits a packet. Scapy writes frames to a file only, so this
tool is safe to run on any machine: it is a file generator, not a traffic
generator.

Addresses use RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) for "external" hosts and RFC 1918 ranges for "internal" ones,
so no real organisation is represented.
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

from scapy.all import Ether, ICMP, IP, TCP, UDP, PcapWriter

BASE_TS = 1_700_000_000.0
MAC_SRC = "02:00:00:00:00:01"
MAC_DST = "02:00:00:00:00:02"


def _tcp(src, dst, sport, dport, flags="S", ts=BASE_TS, payload=b""):
    pkt = Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload
    pkt.time = ts
    return pkt


def _udp(src, dst, sport, dport, ts=BASE_TS, payload=b"\x00" * 32):
    pkt = Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload
    pkt.time = ts
    return pkt


def _icmp(src, dst, ts=BASE_TS):
    pkt = Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=src, dst=dst) / ICMP()
    pkt.time = ts
    return pkt


def write_pcap(path: Path, packets: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = PcapWriter(str(path), sync=True)
    try:
        for pkt in packets:
            writer.write(pkt)
    finally:
        writer.close()


def normal_traffic(rng: random.Random, seconds: int = 30, pps: float = 4.0) -> list:
    """Ordinary-looking browsing traffic: no single source touches many ports."""
    hosts = ["10.0.0.21", "10.0.0.22", "10.0.0.23"]
    web = ["192.0.2.10", "198.51.100.20"]
    packets = []
    for sec in range(seconds):
        for i in range(int(pps)):
            src = rng.choice(hosts)
            dst = rng.choice(web)
            ts = BASE_TS + sec + i / max(pps, 1)
            sport = rng.randint(32768, 60999)
            choice = rng.random()
            if choice < 0.55:
                packets.append(_tcp(src, dst, sport, 443, "S", ts))
                packets.append(_tcp(dst, src, 443, sport, "SA", ts + 0.01))
                packets.append(_tcp(src, dst, sport, 443, "A", ts + 0.02))
            elif choice < 0.75:
                packets.append(_tcp(src, dst, sport, 80, "S", ts))
                packets.append(_tcp(dst, src, 80, sport, "SA", ts + 0.01))
                packets.append(_tcp(src, dst, sport, 80, "A", ts + 0.02))
            elif choice < 0.92:
                packets.append(_udp(src, "10.0.0.1", rng.randint(32768, 60999), 53, ts))
            else:
                packets.append(_icmp(src, dst, ts))
    return packets


def port_scan(rng: random.Random) -> list:
    """One external source probes 60 ports on one internal host."""
    packets = normal_traffic(rng, seconds=5, pps=4.0)
    scanner = "203.0.113.50"
    target = "10.0.0.10"
    for index, port in enumerate(range(20, 80)):
        ts = BASE_TS + 10 + index * 0.05
        sport = 40000 + index
        packets.append(_tcp(scanner, target, sport, port, "S", ts))
        packets.append(_tcp(target, scanner, port, sport, "RA", ts + 0.02))
    return packets


def host_sweep(rng: random.Random) -> list:
    """One source touches many hosts, one port each."""
    packets = normal_traffic(rng, seconds=4, pps=4.0)
    scanner = "198.51.100.77"
    for index, last in enumerate(range(1, 41)):
        ts = BASE_TS + 10 + index * 0.05
        packets.append(_tcp(scanner, f"10.0.0.{last}", 41000 + index, 80, "S", ts))
    return packets


def traffic_spike(rng: random.Random) -> list:
    """A calm baseline, then a burst that clearly exceeds the absolute ceiling."""
    packets = normal_traffic(rng, seconds=8, pps=4.0)
    burst_start = BASE_TS + 8
    for second in range(2):
        for index in range(600):
            ts = burst_start + second + index / 600.0
            packets.append(_udp("10.0.0.66", "10.0.0.77", 50000 + (index % 500), 9999, ts, b"\x00" * 60))
    return packets


def suspicious_traffic(rng: random.Random) -> list:
    """Repeated attempts to a sensitive admin port + half-open handshakes."""
    packets = normal_traffic(rng, seconds=4, pps=4.0)
    internal = "10.0.0.40"
    server = "10.0.0.60"
    for index in range(30):
        ts = BASE_TS + 6 + index * 0.2
        packets.append(_tcp(internal, server, 50000 + index, 22, "S", ts))
    return packets


def malformed_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"this is definitely not a pcap file\n" + bytes(range(256)) * 4)


def empty_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")


def empty_valid_pcap(path: Path) -> None:
    write_pcap(path, [])


def generate_all(outdir: Path) -> dict[str, Path]:
    rng = random.Random(1337)
    outdir.mkdir(parents=True, exist_ok=True)
    produced = {
        "normal_day": outdir / "normal_day.pcap",
        "port_scan_lab": outdir / "port_scan_lab.pcap",
        "host_sweep_lab": outdir / "host_sweep_lab.pcap",
        "traffic_spike_lab": outdir / "traffic_spike_lab.pcap",
        "suspicious_lab": outdir / "suspicious_lab.pcap",
        "malformed": outdir / "malformed.pcap",
        "empty": outdir / "empty.pcap",
        "empty_valid": outdir / "empty_valid.pcap",
    }
    write_pcap(produced["normal_day"], normal_traffic(rng))
    write_pcap(produced["port_scan_lab"], port_scan(rng))
    write_pcap(produced["host_sweep_lab"], host_sweep(rng))
    write_pcap(produced["traffic_spike_lab"], traffic_spike(rng))
    write_pcap(produced["suspicious_lab"], suspicious_traffic(rng))
    malformed_file(produced["malformed"])
    empty_file(produced["empty"])
    empty_valid_pcap(produced["empty_valid"])
    return produced


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate offline NetShield PCAP fixtures")
    parser.add_argument("--outdir", default="tests/fixtures", type=Path)
    args = parser.parse_args()
    produced = generate_all(args.outdir)
    for name, path in produced.items():
        size = path.stat().st_size
        print(f"{name:20s} {str(path):45s} {size:>8d} bytes")


if __name__ == "__main__":
    main()

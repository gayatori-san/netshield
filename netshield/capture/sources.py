"""Packet normalisation: convert Scapy packets into PacketRecord objects.

Only network/transport metadata is extracted. Payload bytes are deliberately
never copied, logged or stored: capturing payloads of real traffic is where a
monitoring tool most often becomes a liability.
"""

from __future__ import annotations

from typing import Iterator, Protocol

from netshield.models import CaptureStatus, PacketRecord

try:  # Scapy is imported lazily so config-only code paths stay light.
    from scapy.layers.inet import ICMP, IP, TCP, UDP
except Exception:  # pragma: no cover - only reached if scapy is missing
    IP = TCP = UDP = ICMP = None  # type: ignore[assignment]


class PacketSource(Protocol):
    def start(self) -> None: ...
    def packets(self) -> Iterator[PacketRecord]: ...
    def stop(self) -> None: ...
    def status(self) -> CaptureStatus: ...


def classify_tcp_state(flags: str) -> str:
    """Map a Scapy TCP flags string to a coarse connection state.

    Only the states needed by the detectors are produced. This is metadata
    interpretation, not a TCP state machine: we never claim to know whether a
    connection actually completed.
    """
    if "R" in flags:
        return "RST"
    if "S" in flags and "A" in flags:
        return "SYN_ACK"
    if "S" in flags:
        return "SYN"
    if "F" in flags:
        return "FIN"
    if "A" in flags:
        return "ACK"
    return "OTHER"


def normalize_packet(pkt, source: str, timestamp: float | None = None) -> PacketRecord | None:
    """Convert one Scapy packet into a PacketRecord.

    Returns None for anything that is not an IP packet (ARP, IPv6-only,
    truncated frames). Returning None instead of raising is what makes
    malformed captures survivable.
    """
    if IP is None:
        raise RuntimeError("scapy is not installed; run: pip install -r requirements.txt")

    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
    if not src_ip or not dst_ip:
        return None

    protocol = "OTHER"
    src_port = None
    dst_port = None
    flags = None
    tcp_state = None

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        protocol = "TCP"
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        flags = str(tcp.flags)
        tcp_state = classify_tcp_state(flags)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        protocol = "UDP"
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"

    ts = float(pkt.time) if timestamp is None else float(timestamp)

    return PacketRecord(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flags=flags,
        tcp_state=tcp_state,
        size=len(pkt),
        source=source,
    )

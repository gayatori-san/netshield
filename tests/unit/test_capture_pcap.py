from __future__ import annotations

import pytest

from netshield.capture.pcap import CaptureError, PcapSource
from netshield.capture.sources import classify_tcp_state, normalize_packet

from scapy.all import ARP, Ether, IP, TCP, UDP


def collect(source: PcapSource) -> list:
    source.start()
    return list(source.packets())


class TestPcapParsing:
    def test_reads_a_valid_capture(self, fixtures_dir):
        packets = collect(PcapSource(fixtures_dir / "normal_day.pcap"))
        assert len(packets) > 0
        assert {p.protocol for p in packets} <= {"TCP", "UDP", "ICMP", "OTHER"}
        assert all(p.src_ip and p.dst_ip for p in packets)
        assert all(p.source.startswith("pcap:") for p in packets)

    def test_parses_expected_port_scan_shape(self, fixtures_dir):
        packets = collect(PcapSource(fixtures_dir / "port_scan_lab.pcap"))
        scanner = [p for p in packets if p.src_ip == "203.0.113.50"]
        assert len(scanner) == 60
        assert len({p.dst_port for p in scanner}) == 60
        assert {p.tcp_state for p in scanner} == {"SYN"}

    def test_zero_byte_file_is_graceful(self, fixtures_dir):
        source = PcapSource(fixtures_dir / "empty.pcap")
        packets = collect(source)
        status = source.status()
        assert packets == []
        assert status.state == "completed"
        assert status.error is None
        assert "empty" in status.message

    def test_valid_pcap_with_no_records(self, fixtures_dir):
        source = PcapSource(fixtures_dir / "empty_valid.pcap")
        packets = collect(source)
        assert packets == []
        assert source.status().state == "completed"

    def test_malformed_file_reports_error_without_raising(self, fixtures_dir):
        source = PcapSource(fixtures_dir / "malformed.pcap")
        packets = collect(source)
        status = source.status()
        assert packets == []
        assert status.state == "error"
        assert status.error and "readable capture" in status.error

    def test_missing_file_raises_capture_error(self, tmp_path):
        with pytest.raises(CaptureError):
            PcapSource(tmp_path / "nope.pcap").start()

    def test_status_before_start_is_idle(self, fixtures_dir):
        assert PcapSource(fixtures_dir / "normal_day.pcap").status().state == "idle"


class TestNormalization:
    def test_non_ip_packet_is_skipped(self):
        arp = Ether() / ARP()
        arp.time = 1.0
        assert normalize_packet(arp, "test") is None

    def test_tcp_packet_fields(self):
        pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=1234, dport=443, flags="S")
        pkt.time = 42.0
        rec = normalize_packet(pkt, "test")
        assert rec is not None
        assert (rec.src_ip, rec.dst_ip) == ("10.0.0.5", "10.0.0.9")
        assert (rec.src_port, rec.dst_port) == (1234, 443)
        assert rec.protocol == "TCP"
        assert rec.tcp_state == "SYN"
        assert rec.is_connection_attempt is True
        assert rec.timestamp == 42.0
        assert rec.size > 0

    def test_udp_packet_is_a_connection_attempt(self):
        pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / UDP(sport=5353, dport=53)
        pkt.time = 1.0
        rec = normalize_packet(pkt, "test")
        assert rec is not None
        assert rec.protocol == "UDP"
        assert rec.tcp_state is None
        assert rec.is_connection_attempt is True

    def test_explicit_timestamp_override(self):
        pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=1, dport=2, flags="A")
        rec = normalize_packet(pkt, "synthetic:x", timestamp=99.5)
        assert rec is not None and rec.timestamp == 99.5
        assert rec.source == "synthetic:x"

    @pytest.mark.parametrize(
        "flags,state",
        [
            ("S", "SYN"),
            ("SA", "SYN_ACK"),
            ("A", "ACK"),
            ("RA", "RST"),
            ("R", "RST"),
            ("F", "FIN"),
            ("FA", "FIN"),
            ("PA", "ACK"),
            ("", "OTHER"),
        ],
    )
    def test_tcp_state_classification(self, flags, state):
        assert classify_tcp_state(flags) == state

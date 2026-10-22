from __future__ import annotations

from netshield.config.settings import PortScanConfig
from netshield.detectors.port_scan import PortScanDetector

SRC = "203.0.113.50"
DST = "10.0.0.10"


def feed(detector, packets):
    for pkt in packets:
        detector.update(pkt)


def config(**overrides) -> PortScanConfig:
    base = dict(
        window_seconds=60,
        distinct_port_threshold=15,
        distinct_host_threshold=20,
        min_packets_per_target=10,
    )
    base.update(overrides)
    return PortScanConfig(**base)


def scan_packets(packet_factory, ports, src=SRC, dst=DST, start=100.0, step=0.05):
    return [
        packet_factory(src=src, dst=dst, sport=40000 + i, dport=port, ts=start + i * step)
        for i, port in enumerate(ports)
    ]


class TestPortScanThresholds:
    def test_below_port_threshold_does_not_alert(self, packet_factory):
        detector = PortScanDetector(config())
        feed(detector, scan_packets(packet_factory, range(1000, 1014)))
        assert detector.flush(150.0) == []

    def test_at_port_threshold_alerts(self, packet_factory):
        detector = PortScanDetector(config())
        feed(detector, scan_packets(packet_factory, range(1000, 1015)))
        results = detector.flush(150.0)
        assert len(results) == 1
        alert = results[0]
        assert alert.rule_id == "PORT_SCAN_PORTS"
        assert alert.src_ip == SRC and alert.dst_ip == DST
        assert alert.facts["observed"] == 15
        assert alert.facts["required"] == 15
        assert alert.facts["evidence_sufficient"] is True
        assert alert.evidence["distinct_destination_ports"] == 15

    def test_single_connection_is_never_a_scan(self, packet_factory):
        detector = PortScanDetector(config(distinct_port_threshold=1))
        detector.update(packet_factory(dport=443, ts=100.0))
        results = detector.flush(101.0)
        assert results == [] or all(r.rule_id != "PORT_SCAN_PORTS" for r in results)

    def test_minimum_packets_per_target_blocks_truncated_capture(self, packet_factory):
        detector = PortScanDetector(config(distinct_port_threshold=3, min_packets_per_target=10))
        feed(detector, scan_packets(packet_factory, [80, 81, 82]))
        assert detector.flush(150.0) == []

    def test_minimum_packets_satisfied_allows_alert(self, packet_factory):
        detector = PortScanDetector(config(distinct_port_threshold=3, min_packets_per_target=10))
        packets = scan_packets(packet_factory, [80, 81, 82] * 4)[:10]
        feed(detector, packets)
        results = detector.flush(150.0)
        assert any(r.rule_id == "PORT_SCAN_PORTS" for r in results)

    def test_old_packets_outside_window_are_ignored(self, packet_factory):
        detector = PortScanDetector(config())
        feed(detector, scan_packets(packet_factory, range(1000, 1030), start=0.0))
        assert detector.flush(500.0) == []


class TestPortScanFalsePositives:
    def test_responses_are_not_counted_as_scan_attempts(self, packet_factory):
        """The victim of a scan sends one reply per probed port.

        Counting replies would flag the victim as a scanner -- a classic
        false positive. Only connection attempts may count.
        """
        detector = PortScanDetector(config())
        replies = [
            packet_factory(src=DST, dst=SRC, sport=1000 + i, dport=40000 + i, state="RST", flags="RA", ts=100.0 + i * 0.01)
            for i in range(40)
        ]
        feed(detector, replies)
        assert detector.flush(150.0) == []

    def test_syn_ack_replies_are_not_counted(self, packet_factory):
        detector = PortScanDetector(config())
        replies = [
            packet_factory(src=DST, dst=SRC, sport=1000 + i, dport=40000 + i, state="SYN_ACK", flags="SA", ts=100.0)
            for i in range(40)
        ]
        feed(detector, replies)
        assert detector.flush(150.0) == []

    def test_normal_fixture_produces_no_scan_alert(self, replay):
        detector = PortScanDetector(config())
        candidates = replay("normal_day.pcap", [detector])
        assert candidates == []


class TestHostSweep:
    def test_many_destinations_alert(self, packet_factory):
        detector = PortScanDetector(config())
        packets = [
            packet_factory(src=SRC, dst=f"10.0.0.{i + 1}", sport=40000 + i, dport=80, ts=100.0 + i * 0.05)
            for i in range(25)
        ]
        feed(detector, packets)
        results = detector.flush(150.0)
        host_alerts = [r for r in results if r.rule_id == "PORT_SCAN_HOSTS"]
        assert len(host_alerts) == 1
        assert host_alerts[0].facts["observed"] == 25
        assert host_alerts[0].dst_ip is None

    def test_host_sweep_fixture_alerts(self, replay):
        detector = PortScanDetector(config())
        candidates = replay("host_sweep_lab.pcap", [detector])
        assert any(c.rule_id == "PORT_SCAN_HOSTS" for c in candidates)


class TestPortScanFixture:
    def test_port_scan_fixture_alerts_on_scanner_only(self, replay):
        detector = PortScanDetector(config())
        candidates = replay("port_scan_lab.pcap", [detector])
        scanners = [c for c in candidates if c.rule_id == "PORT_SCAN_PORTS"]
        assert len(scanners) == 1
        assert scanners[0].src_ip == SRC
        assert scanners[0].dst_ip == DST
        assert scanners[0].facts["observed"] == 60
        assert all(c.src_ip != DST for c in candidates), "the scan target must not be flagged"

    def test_reset_clears_state(self, packet_factory):
        detector = PortScanDetector(config())
        feed(detector, scan_packets(packet_factory, range(1000, 1020)))
        detector.reset()
        assert detector.flush(150.0) == []

from __future__ import annotations

from netshield.config.settings import SuspiciousConfig
from netshield.detectors.suspicious import SuspiciousConnectionDetector

INTERNAL = "10.0.0.40"
SERVER = "10.0.0.60"


def config(**overrides) -> SuspiciousConfig:
    base = dict(
        window_seconds=60,
        repeat_attempt_threshold=15,
        conn_rate_threshold=300,
        conn_rate_multiplier=3.0,
        conn_baseline_alpha=0.3,
        conn_baseline_min_samples=3,
        sensitive_ports=(22, 3389),
    )
    base.update(overrides)
    return SuspiciousConfig(**base)


def by_rule(candidates, rule):
    return [c for c in candidates if c.rule_id == rule]


class TestRepeatedConnections:
    def test_unanswered_syns_alert(self, packet_factory):
        detector = SuspiciousConnectionDetector(config())
        for i in range(20):
            detector.update(packet_factory(src=INTERNAL, dst=SERVER, sport=50000 + i, dport=9999, ts=100 + i * 0.1))
        results = detector.flush(160.0)
        repeated = by_rule(results, "REPEATED_CONNECTIONS")
        assert len(repeated) == 1
        assert repeated[0].facts["observed"] == 20
        assert repeated[0].facts["evidence_sufficient"] is False
        assert repeated[0].evidence["unanswered_syns"] == 20

    def test_answered_connections_are_not_repeated_failures(self, packet_factory):
        detector = SuspiciousConnectionDetector(config())
        for i in range(20):
            ts = 100 + i * 0.1
            detector.update(packet_factory(src=INTERNAL, dst=SERVER, sport=50000 + i, dport=9999, ts=ts))
            detector.update(
                packet_factory(src=SERVER, dst=INTERNAL, sport=9999, dport=50000 + i, state="SYN_ACK", flags="SA", ts=ts + 0.01)
            )
        assert by_rule(detector.flush(160.0), "REPEATED_CONNECTIONS") == []

    def test_below_threshold_does_not_alert(self, packet_factory):
        detector = SuspiciousConnectionDetector(config())
        for i in range(14):
            detector.update(packet_factory(src=INTERNAL, dst=SERVER, sport=50000 + i, dport=9999, ts=100 + i * 0.1))
        assert by_rule(detector.flush(160.0), "REPEATED_CONNECTIONS") == []


class TestSensitivePort:
    def test_single_attempt_is_recorded_but_insufficient(self, packet_factory):
        detector = SuspiciousConnectionDetector(config())
        detector.update(packet_factory(src=INTERNAL, dst=SERVER, sport=50001, dport=22, ts=100.0))
        results = by_rule(detector.flush(160.0), "SENSITIVE_PORT")
        assert len(results) == 1
        assert results[0].facts["evidence_sufficient"] is False
        assert results[0].facts["observed"] == 1

    def test_repeated_attempts_are_sufficient(self, packet_factory):
        detector = SuspiciousConnectionDetector(config())
        for i in range(3):
            detector.update(packet_factory(src=INTERNAL, dst=SERVER, sport=50001 + i, dport=22, ts=100 + i))
        results = by_rule(detector.flush(160.0), "SENSITIVE_PORT")
        assert results[0].facts["evidence_sufficient"] is True
        assert results[0].facts["observed"] == 3

    def test_non_sensitive_port_is_ignored(self, packet_factory):
        detector = SuspiciousConnectionDetector(config())
        for i in range(5):
            detector.update(packet_factory(src=INTERNAL, dst=SERVER, sport=50001 + i, dport=8080, ts=100 + i))
        assert by_rule(detector.flush(160.0), "SENSITIVE_PORT") == []


class TestConnectionRate:
    def _feed_rate(self, detector, packet_factory, seconds, per_second, start, port_base=1000):
        port = port_base
        for sec in range(seconds):
            for i in range(per_second):
                detector.update(
                    packet_factory(
                        src=INTERNAL,
                        dst=SERVER,
                        sport=20000 + (port % 40000),
                        dport=2000 + (port % 500),
                        ts=start + sec + i / max(per_second, 1),
                    )
                )
                port += 1

    def test_normal_rate_below_threshold_does_not_alert(self, packet_factory):
        detector = SuspiciousConnectionDetector(config())
        self._feed_rate(detector, packet_factory, seconds=10, per_second=5, start=100)
        assert by_rule(detector.flush(160.0), "CONN_RATE_ANOMALY") == []

    def test_rate_without_baseline_is_insufficient(self, packet_factory):
        detector = SuspiciousConnectionDetector(config())
        self._feed_rate(detector, packet_factory, seconds=1, per_second=400, start=100)
        results = by_rule(detector.flush(160.0), "CONN_RATE_ANOMALY")
        assert len(results) == 1
        assert results[0].facts["evidence_sufficient"] is False
        assert "baseline" in results[0].facts["insufficient_reason"]

    def test_rate_above_baseline_is_sufficient(self, packet_factory):
        detector = SuspiciousConnectionDetector(config())
        self._feed_rate(detector, packet_factory, seconds=4, per_second=10, start=100)
        self._feed_rate(detector, packet_factory, seconds=1, per_second=400, start=104, port_base=30000)
        results = by_rule(detector.flush(160.0), "CONN_RATE_ANOMALY")
        assert len(results) == 1
        assert results[0].facts["observed"] == 440
        assert results[0].facts["evidence_sufficient"] is True
        assert results[0].evidence["multiple_of_baseline"] >= 3.0


class TestUdpNoise:
    def test_dns_volume_does_not_trigger_suspicious_rules(self, packet_factory):
        detector = SuspiciousConnectionDetector(config())
        for i in range(500):
            detector.update(
                packet_factory(
                    src=INTERNAL,
                    dst="10.0.0.1",
                    sport=30000 + (i % 30000),
                    dport=53,
                    proto="UDP",
                    state=None,
                    flags=None,
                    ts=100 + i * 0.01,
                )
            )
        assert detector.flush(160.0) == []


class TestSuspiciousFixture:
    def test_fixture_produces_repeated_and_sensitive_alerts(self, replay):
        detector = SuspiciousConnectionDetector(config())
        candidates = replay("suspicious_lab.pcap", [detector])
        rules = {c.rule_id for c in candidates}
        assert "REPEATED_CONNECTIONS" in rules
        assert "SENSITIVE_PORT" in rules
        assert all(c.src_ip == INTERNAL for c in candidates)

    def test_normal_fixture_produces_no_suspicious_alert(self, replay):
        detector = SuspiciousConnectionDetector(config())
        assert replay("normal_day.pcap", [detector]) == []

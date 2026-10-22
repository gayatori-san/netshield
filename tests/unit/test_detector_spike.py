from __future__ import annotations

from netshield.config.settings import SpikeConfig
from netshield.detectors.spike import TrafficSpikeDetector


def config(**overrides) -> SpikeConfig:
    base = dict(
        window_seconds=10,
        baseline_window_seconds=300,
        spike_absolute_pps=500,
        spike_baseline_ratio=3.0,
        spike_min_pps=100,
        baseline_alpha=0.3,
        baseline_min_samples=3,
    )
    base.update(overrides)
    return SpikeConfig(**base)


def feed_second(detector, packet_factory, second, count, size=60):
    for i in range(count):
        detector.update(packet_factory(ts=second + i / max(count, 1), size=size))


class TestAbsoluteSpike:
    def test_normal_rate_does_not_alert(self, packet_factory):
        detector = TrafficSpikeDetector(config())
        for second in range(5):
            feed_second(detector, packet_factory, second, 20)
        assert detector.flush(10.0) == []

    def test_absolute_spike_alerts(self, packet_factory):
        detector = TrafficSpikeDetector(config())
        for second in range(4):
            feed_second(detector, packet_factory, second, 10)
        feed_second(detector, packet_factory, 4, 600)
        results = detector.flush(6.0)
        assert len(results) == 1
        assert results[0].rule_id == "TRAFFIC_SPIKE"
        assert results[0].facts["observed"] == 600
        assert results[0].facts["evidence_sufficient"] is True
        assert results[0].window_start == 4.0

    def test_spike_includes_top_talkers(self, packet_factory):
        detector = TrafficSpikeDetector(config())
        for i in range(600):
            detector.update(packet_factory(src="10.0.0.66", dst="10.0.0.77", ts=4 + i / 600, proto="UDP"))
        result = detector.flush(6.0)[0]
        assert result.src_ip == "10.0.0.66"
        assert result.dst_ip == "10.0.0.77"
        assert result.evidence["top_sources"][0] == ("10.0.0.66", 600)


class TestBaselineDeviation:
    def test_deviation_above_baseline_but_below_absolute_alerts(self, packet_factory):
        detector = TrafficSpikeDetector(config())
        for second in range(4):
            feed_second(detector, packet_factory, second, 20)
        feed_second(detector, packet_factory, 4, 150)
        results = detector.flush(6.0)
        assert len(results) == 1
        assert results[0].rule_id == "BASELINE_DEVIATION"
        assert results[0].evidence["baseline_pps"] == 20.0
        assert results[0].evidence["multiple_of_baseline"] >= 3.0
        assert results[0].facts["evidence_sufficient"] is True

    def test_ratio_against_tiny_baseline_is_blocked_by_floor(self, packet_factory):
        """2 pps baseline -> 6 pps is 3x, but it is not a flood."""
        detector = TrafficSpikeDetector(config())
        for second in range(4):
            feed_second(detector, packet_factory, second, 2)
        feed_second(detector, packet_factory, 4, 6)
        assert detector.flush(6.0) == []

    def test_baseline_needs_minimum_samples(self, packet_factory):
        detector = TrafficSpikeDetector(config())
        feed_second(detector, packet_factory, 0, 10)
        feed_second(detector, packet_factory, 1, 150)
        assert detector.flush(3.0) == []

    def test_absolute_and_baseline_rules_are_mutually_exclusive(self, packet_factory):
        detector = TrafficSpikeDetector(config())
        for second in range(4):
            feed_second(detector, packet_factory, second, 20)
        feed_second(detector, packet_factory, 4, 600)
        results = detector.flush(6.0)
        rules = [r.rule_id for r in results]
        assert rules.count("TRAFFIC_SPIKE") == 1
        assert "BASELINE_DEVIATION" not in rules


class TestSpikeFixture:
    def test_traffic_spike_fixture_alerts(self, replay):
        detector = TrafficSpikeDetector(config())
        candidates = replay("traffic_spike_lab.pcap", [detector])
        assert any(c.rule_id == "TRAFFIC_SPIKE" for c in candidates)

    def test_normal_fixture_produces_no_spike_alert(self, replay):
        detector = TrafficSpikeDetector(config())
        assert replay("normal_day.pcap", [detector]) == []

    def test_pending_seconds_are_evaluated_only_once(self, packet_factory):
        detector = TrafficSpikeDetector(config())
        feed_second(detector, packet_factory, 0, 600)
        first = detector.flush(2.0)
        second = detector.flush(3.0)
        assert len(first) == 1
        assert second == []

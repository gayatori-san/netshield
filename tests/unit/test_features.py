from __future__ import annotations

from netshield.features.aggregation import TrafficAggregator
from netshield.features.extract import FlowExtractor, flow_key_from


class TestFlowExtractor:
    def test_counts_packets_and_bytes_per_direction(self, packet_factory):
        flows = FlowExtractor()
        flows.observe(packet_factory(sport=1111, dport=80, ts=1.0, size=100))
        flows.observe(packet_factory(sport=1111, dport=80, ts=2.0, size=50))
        flows.observe(packet_factory(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1111, ts=3.0, size=40))
        assert flows.active_count() == 2

    def test_direction_is_part_of_the_flow_key(self, packet_factory):
        a = packet_factory(sport=1111, dport=80)
        b = packet_factory(src=a.dst_ip, dst=a.src_ip, sport=a.dst_port, dport=a.src_port)
        assert flow_key_from(a) != flow_key_from(b)

    def test_counts_tcp_states(self, packet_factory):
        flows = FlowExtractor()
        for state in ["SYN", "SYN_ACK", "RST", "FIN"]:
            flows.observe(packet_factory(state=state))
        state = flows.observe(packet_factory(state="ACK"))
        assert (state.syn, state.syn_ack, state.rst, state.fin) == (1, 1, 1, 1)

    def test_table_is_bounded(self, packet_factory):
        flows = FlowExtractor(max_flows=10)
        for i in range(100):
            flows.observe(packet_factory(sport=10000 + i))
        assert flows.active_count() == 10

    def test_idle_eviction(self, packet_factory):
        flows = FlowExtractor(idle_seconds=10)
        flows.observe(packet_factory(ts=100.0))
        assert flows.evict_idle(now=105.0) == 0
        assert flows.evict_idle(now=200.0) == 1
        assert flows.active_count() == 0


class TestTrafficAggregator:
    def test_totals_and_protocol_mix(self, packet_factory):
        agg = TrafficAggregator()
        agg.observe(packet_factory(proto="TCP", ts=1.0, size=60))
        agg.observe(packet_factory(proto="UDP", ts=1.1, size=40))
        agg.observe(packet_factory(proto="TCP", ts=1.2, size=60))
        snap = agg.snapshot(now=1.2)
        assert snap.total_packets == 3
        assert snap.total_bytes == 160
        assert snap.protocol_counts == {"TCP": 2, "UDP": 1}
        # Two TCP packets share a 5-tuple, so they are one flow; the UDP
        # packet is a separate flow despite the same addresses.
        assert snap.active_flows == 2

    def test_top_talkers_are_ordered(self, packet_factory):
        agg = TrafficAggregator()
        for _ in range(5):
            agg.observe(packet_factory(src="10.0.0.1", dst="10.0.0.9", dport=80, ts=1.0))
        for _ in range(2):
            agg.observe(packet_factory(src="10.0.0.2", dst="10.0.0.8", dport=443, ts=1.0))
        snap = agg.snapshot(now=1.0)
        assert snap.top_sources[0] == ("10.0.0.1", 5)
        assert snap.top_destinations[0] == ("10.0.0.9", 5)

    def test_current_pps_uses_latest_bucket(self, packet_factory):
        agg = TrafficAggregator()
        for i in range(10):
            agg.observe(packet_factory(ts=100.0 + i * 0.01))
        assert agg.current_pps() == 10.0

    def test_baseline_requires_a_completed_second(self, packet_factory):
        agg = TrafficAggregator(baseline_alpha=0.5)
        for i in range(4):
            agg.observe(packet_factory(ts=100.0 + i * 0.01))
        assert agg.baseline_samples() == 0
        for i in range(8):
            agg.observe(packet_factory(ts=101.0 + i * 0.01))
        assert agg.baseline_samples() == 1
        assert agg.baseline_pps() == 4.0

    def test_drain_buckets_excludes_current_second(self, packet_factory):
        agg = TrafficAggregator()
        agg.observe(packet_factory(ts=100.0))
        agg.observe(packet_factory(ts=101.0))
        rows = agg.drain_buckets()
        assert [r["bucket_ts"] for r in rows] == [100]
        assert agg.recent_buckets() == [{"bucket_ts": 101, "packets": 1, "bytes": 60}]

    def test_endpoint_counter_is_bounded(self, packet_factory):
        agg = TrafficAggregator(max_endpoints=5)
        for i in range(50):
            agg.observe(packet_factory(src=f"10.1.0.{i}", dst=f"10.2.0.{i}"))
        snap = agg.snapshot(now=0.0)
        assert len(snap.top_sources) <= 10
        assert len(agg.src_counts) <= 5

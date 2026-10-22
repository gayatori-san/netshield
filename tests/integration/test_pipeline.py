from __future__ import annotations

import time

import pytest

from netshield.pipeline import PipelineBusy, PipelineError, ProcessingPipeline
from netshield.storage.db import Database
from netshield.storage.repositories import (
    IncidentRepository,
    PacketRepository,
    TrafficRepository,
)


def wait_for(pipeline: ProcessingPipeline, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while pipeline.running and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not pipeline.running, "pipeline did not finish in time"


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "pipeline.db")
    yield database
    database.close()


@pytest.fixture
def pipeline(settings, db):
    return ProcessingPipeline(settings, db, demo_pace=False)


class TestPcapRun:
    def test_port_scan_capture_creates_incidents_and_packets(self, pipeline, db, fixtures_dir):
        pipeline.start("pcap", path=str(fixtures_dir / "port_scan_lab.pcap"))
        wait_for(pipeline)

        status = pipeline.status()
        assert status["state"] == "completed"
        assert status["packets_processed"] == 166

        incidents = IncidentRepository(db).list()
        rules = {row["rule_id"] for row in incidents[0]}
        assert "PORT_SCAN_PORTS" in rules

        storage = PacketRepository(db)
        assert storage.count() == 166
        assert TrafficRepository(db).series() != []

    def test_all_alerts_are_marked_as_real_capture(self, pipeline, db, fixtures_dir):
        pipeline.start("pcap", path=str(fixtures_dir / "suspicious_lab.pcap"))
        wait_for(pipeline)
        rows, _ = IncidentRepository(db).list()
        assert rows
        assert all(row["data_origin"] == "real" for row in rows)

    def test_missing_path_is_rejected_before_starting(self, pipeline):
        with pytest.raises(PipelineError):
            pipeline.start("pcap", path="/nonexistent/file.pcap")
        assert pipeline.running is False
        assert pipeline.status()["state"] == "idle"

    def test_invalid_capture_reports_error_state(self, pipeline, fixtures_dir):
        pipeline.start("pcap", path=str(fixtures_dir / "malformed.pcap"))
        wait_for(pipeline)
        status = pipeline.status()
        assert status["state"] == "error"
        assert "readable capture" in status["error"]


class TestDemoRun:
    def test_demo_produces_every_rule_with_demonstration_origin(self, pipeline, db):
        pipeline.start("demo")
        wait_for(pipeline)

        status = pipeline.status()
        assert status["state"] == "completed"
        assert status["mode"] == "demo"

        rows, _ = IncidentRepository(db).list(per_page=100)
        rules = {row["rule_id"] for row in rows}
        assert {
            "PORT_SCAN_PORTS",
            "PORT_SCAN_HOSTS",
            "REPEATED_CONNECTIONS",
            "SENSITIVE_PORT",
            "TRAFFIC_SPIKE",
        } <= rules
        assert all(row["data_origin"] == "demonstration" for row in rows)
        assert all(
            "synthetic:demo" not in (row["analyst_notes"] or "") for row in rows
        )

    def test_demo_does_not_emit_alerts_for_normal_traffic_hosts(self, pipeline, db):
        pipeline.start("demo")
        wait_for(pipeline)
        rows, _ = IncidentRepository(db).list(per_page=200)
        sources = {row["src_ip"] for row in rows}
        assert "10.0.0.20" not in sources
        assert "10.0.0.21" not in sources


class TestLifecycle:
    def test_second_start_while_running_is_rejected(self, settings, db):
        slow = ProcessingPipeline(settings, db, demo_pace=True)
        slow.start("demo")
        try:
            with pytest.raises(PipelineBusy):
                slow.start("demo")
        finally:
            slow.stop()
        assert slow.running is False

    def test_stop_is_idempotent(self, pipeline, fixtures_dir):
        pipeline.start("pcap", path=str(fixtures_dir / "normal_day.pcap"))
        wait_for(pipeline)
        first = pipeline.stop()
        second = pipeline.stop()
        assert first["running"] is False
        assert second["running"] is False

    def test_unknown_mode_rejected(self, pipeline):
        with pytest.raises(PipelineError):
            pipeline.start("telepathy")

    def test_live_mode_requires_interface(self, pipeline):
        with pytest.raises(PipelineError):
            pipeline.start("live")

    def test_live_mode_rejects_unknown_interface(self, pipeline):
        with pytest.raises(PipelineError):
            pipeline.start("live", iface="netshield-not-a-real-interface")
        assert pipeline.status()["state"] == "idle"

    def test_configure_while_idle_applies_immediately(self, pipeline, settings):
        assert pipeline.configure(settings) is True

    def test_configure_while_running_defers_to_next_capture(self, pipeline, settings):
        pipeline.start("demo")
        try:
            assert pipeline.configure(settings) is False
        finally:
            pipeline.stop()


class TestSnapshot:
    def test_snapshot_is_json_safe_before_and_after_a_run(self, pipeline, fixtures_dir):
        empty = pipeline.snapshot()
        assert empty["total_packets"] == 0
        assert empty["top_sources"] == []

        pipeline.start("pcap", path=str(fixtures_dir / "normal_day.pcap"))
        wait_for(pipeline)

        snap = pipeline.snapshot()
        assert snap["total_packets"] == 308
        assert snap["protocol_counts"]
        assert all(isinstance(pair, list) for pair in snap["top_sources"])

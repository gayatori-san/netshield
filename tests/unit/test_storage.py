from __future__ import annotations

import uuid

import pytest

from netshield.models import Alert, PacketRecord
from netshield.storage.db import Database
from netshield.storage.repositories import (
    IncidentRepository,
    PacketRepository,
    ResponseRepository,
    SettingsRepository,
    TrafficRepository,
)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "test.db")
    database.init_schema()
    yield database
    database.close()


@pytest.fixture
def incidents(db):
    return IncidentRepository(db)


def make_alert(**overrides) -> Alert:
    base = dict(
        rule_id="PORT_SCAN_PORTS",
        title="Possible port scan (many destination ports)",
        severity="high",
        score=70,
        reasons=["distinct destination ports: 60 observed vs threshold 15"],
        evidence={"distinct_destination_ports": 60},
        facts={"observed": 60, "required": 15},
        evidence_sufficient=True,
        src_ip="203.0.113.50",
        dst_ip="10.0.0.10",
        detected_at=100.0,
        window_start=40.0,
        window_end=100.0,
        fingerprint=uuid.uuid4().hex,
    )
    base.update(overrides)
    return Alert(**base)


class TestIncidentRepository:
    def test_insert_and_get_round_trip(self, incidents):
        alert = make_alert()
        assert incidents.insert(alert) is True

        stored = incidents.get(alert.id)
        assert stored is not None
        assert stored["rule_id"] == "PORT_SCAN_PORTS"
        assert stored["reasons"] == alert.reasons
        assert stored["evidence"] == {"distinct_destination_ports": 60}
        assert stored["evidence_sufficient"] is True
        assert stored["status"] == "new"

    def test_duplicate_fingerprint_is_rejected(self, incidents):
        alert = make_alert()
        assert incidents.insert(alert) is True
        assert incidents.insert(make_alert(fingerprint=alert.fingerprint)) is False
        assert incidents.list()[1] == 1

    def test_get_missing_returns_none(self, incidents):
        assert incidents.get("nothing") is None

    def test_status_change_is_recorded_in_timeline(self, incidents):
        alert = make_alert()
        incidents.insert(alert)

        updated = incidents.update_status(alert.id, "acknowledged", note="looking", now=200.0)
        assert updated is not None
        assert updated["status"] == "acknowledged"
        assert updated["analyst_notes"] == "looking"

        types = [event["event_type"] for event in incidents.events(alert.id)]
        assert types == ["detected", "acknowledged"]

    def test_invalid_status_rejected(self, incidents):
        alert = make_alert()
        incidents.insert(alert)
        with pytest.raises(ValueError):
            incidents.update_status(alert.id, "closed")

    def test_add_note_without_status_change(self, incidents):
        alert = make_alert()
        incidents.insert(alert)
        incidents.add_note(alert.id, "escalated to lab owner", now=150.0)

        stored = incidents.get(alert.id)
        assert stored["status"] == "new"
        assert stored["analyst_notes"] == "escalated to lab owner"
        assert incidents.events(alert.id)[-1]["event_type"] == "note"

    def test_list_filters(self, incidents):
        incidents.insert(make_alert(severity="high", rule_id="PORT_SCAN_PORTS", detected_at=100.0))
        incidents.insert(make_alert(severity="low", rule_id="SENSITIVE_PORT", detected_at=200.0))
        incidents.insert(
            make_alert(
                severity="medium",
                rule_id="TRAFFIC_SPIKE",
                src_ip="10.0.0.99",
                detected_at=300.0,
                data_origin="demonstration",
            )
        )

        assert incidents.list(severities=["high"])[1] == 1
        assert incidents.list(rule_id="SENSITIVE_PORT")[1] == 1
        assert incidents.list(search="10.0.0.99")[1] == 1
        assert incidents.list(origin="demonstration")[1] == 1
        assert incidents.list(date_from=150.0)[1] == 2
        assert incidents.list(date_from=150.0, date_to=250.0)[1] == 1
        assert incidents.list(status="new")[1] == 3

    def test_pagination_and_order(self, incidents):
        for offset in range(5):
            incidents.insert(make_alert(detected_at=100.0 + offset, fingerprint=uuid.uuid4().hex))

        page, total = incidents.list(page=2, per_page=2)
        assert total == 5
        assert len(page) == 2
        assert page[0]["detected_at"] == 102.0

    def test_stats(self, incidents):
        incidents.insert(make_alert(severity="high"))
        incidents.insert(make_alert(severity="high", fingerprint=uuid.uuid4().hex))
        low = make_alert(severity="low", rule_id="SENSITIVE_PORT", fingerprint=uuid.uuid4().hex)
        incidents.insert(low)
        incidents.update_status(low.id, "resolved")

        stats = incidents.stats()
        assert stats["total"] == 3
        assert stats["open"] == 2
        assert stats["by_severity"] == {"low": 1, "medium": 0, "high": 2}
        assert stats["open_by_severity"] == {"low": 0, "medium": 0, "high": 2}
        assert stats["by_status"]["resolved"] == 1

    def test_export_csv_neutralises_formula_injection(self, incidents):
        alert = make_alert(analyst_notes="=cmd|' /C calc'!A0")
        incidents.insert(alert)

        text = incidents.export_csv()
        lines = text.strip().splitlines()
        assert lines[0].startswith("id,detected_at,rule_id")
        assert "'=cmd" in lines[1]

    def test_export_respects_filters(self, incidents):
        incidents.insert(make_alert(severity="high"))
        incidents.insert(make_alert(severity="low", fingerprint=uuid.uuid4().hex))

        text = incidents.export_csv(severities=["low"])
        assert len(text.strip().splitlines()) == 2


class TestPacketRepository:
    def _record(self, ts, src="10.0.0.1", dst="10.0.0.2", proto="TCP"):
        return PacketRecord(
            timestamp=ts,
            src_ip=src,
            dst_ip=dst,
            src_port=40000,
            dst_port=443,
            protocol=proto,
            flags="S",
            tcp_state="SYN",
            size=60,
            source="test",
        )

    def test_add_and_list(self, db):
        repo = PacketRepository(db)
        assert repo.add_many([self._record(1.0), self._record(2.0)], "real") == 2
        assert repo.count() == 2

        rows, total = repo.list(per_page=1)
        assert total == 2
        assert rows[0]["ts"] == 2.0
        assert rows[0]["origin"] == "real"

    def test_filters(self, db):
        repo = PacketRepository(db)
        repo.add_many(
            [self._record(1.0, proto="TCP"), self._record(2.0, proto="UDP", src="10.0.0.9")],
            "real",
        )
        assert repo.list(protocol="udp")[1] == 1
        assert repo.list(src="10.0.0.9")[1] == 1
        assert repo.list(search="UDP")[1] == 1
        assert repo.protocol_counts() == {"TCP": 1, "UDP": 1}

    def test_prune_uses_ingestion_time_not_packet_time(self, db):
        repo = PacketRepository(db)
        repo.add_many([self._record(0.0)], "real", now=1_000_000.0)
        assert repo.prune(days=7, now=1_000_000.0) == 0
        assert repo.prune(days=7, now=1_000_000.0 + 8 * 86400) == 1

    def test_unknown_origin_rejected(self, db):
        with pytest.raises(ValueError):
            PacketRepository(db).add_many([self._record(1.0)], "made-up")


class TestTrafficRepository:
    def test_upsert_is_idempotent_and_series_is_ordered(self, db):
        repo = TrafficRepository(db)
        repo.upsert([(100, 10, 600), (101, 20, 1200)])
        repo.upsert([(101, 25, 1500)])

        series = repo.series()
        assert [row["bucket_ts"] for row in series] == [100, 101]
        assert series[1]["packets"] == 25

    def test_series_limit_keeps_newest(self, db):
        repo = TrafficRepository(db)
        repo.upsert((second, second, second * 10) for second in range(10))
        series = repo.series(limit=3)
        assert [row["bucket_ts"] for row in series] == [7, 8, 9]


class TestSettingsAndResponseRepositories:
    def test_settings_round_trip(self, db):
        repo = SettingsRepository(db)
        assert repo.get("mode") is None
        assert repo.get("mode", "fallback") == "fallback"
        repo.set("mode", "demo")
        repo.set("mode", "live")
        assert repo.get("mode") == "live"
        assert repo.all() == {"mode": "live"}

    def test_response_actions(self, db):
        repo = ResponseRepository(db)
        repo.add(
            target_ip="10.0.0.66",
            action="simulated_block",
            applied=False,
            mode="simulated",
            reason="operator requested",
            now=10.0,
        )
        rows = repo.list()
        assert len(rows) == 1
        assert rows[0]["applied"] is False
        assert rows[0]["target_ip"] == "10.0.0.66"

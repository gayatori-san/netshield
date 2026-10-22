from __future__ import annotations

import io
import time

import pytest

from netshield.api.app import create_app
from netshield.config.settings import load_settings
from netshield.storage.db import Database


@pytest.fixture
def settings(tmp_path):
    base = load_settings()
    return base.with_overrides(db_path=tmp_path / "api.db")


@pytest.fixture(autouse=True)
def isolate_uploads(tmp_path, fixtures_dir, monkeypatch):
    from netshield.api import routes

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(routes, "UPLOAD_DIR", upload_dir)
    monkeypatch.setattr(
        routes, "CAPTURE_ROOTS", ((upload_dir, "captures"), (fixtures_dir, "fixtures"))
    )


@pytest.fixture
def app(settings):
    application = create_app(settings, demo_pace=False)
    application.config.update(TESTING=True)
    yield application
    application.extensions["netshield"].pipeline.stop()
    application.extensions["netshield"].db.close()


@pytest.fixture
def client(app):
    return app.test_client()


def services(app):
    return app.extensions["netshield"]


def wait_for_capture(app, timeout: float = 20.0) -> None:
    pipeline = services(app).pipeline
    deadline = time.monotonic() + timeout
    while pipeline.running and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not pipeline.running


def run_pcap(client, app, name: str, fixtures_dir) -> None:
    response = client.post(
        "/api/capture/start",
        json={"mode": "pcap", "path": str(fixtures_dir / name)},
    )
    assert response.status_code == 202, response.get_json()
    wait_for_capture(app)


class TestEnvelope:
    def test_health(self, client):
        body = client.get("/api/health").get_json()
        assert body["ok"] is True
        assert body["data"]["status"] == "ok"

    def test_unknown_route_uses_envelope(self, client):
        response = client.get("/api/does-not-exist")
        assert response.status_code == 404
        body = response.get_json()
        assert body["ok"] is False
        assert body["error"]["code"] == "not_found"

    def test_wrong_method_uses_envelope(self, client):
        response = client.delete("/api/health")
        assert response.status_code == 405
        assert response.get_json()["error"]["code"] == "method_not_allowed"

    def test_rules_catalogue(self, client):
        body = client.get("/api/rules").get_json()
        ids = {rule["id"] for rule in body["data"]["rules"]}
        assert {"PORT_SCAN_PORTS", "TRAFFIC_SPIKE", "SENSITIVE_PORT"} <= ids


class TestOverview:
    def test_empty_state_is_explicit(self, client):
        body = client.get("/api/overview").get_json()
        data = body["data"]
        assert body["ok"] is True
        assert data["counters"]["total"] == 0
        assert data["recent_alerts"] == []
        assert data["packet_count"] == 0
        assert data["status"]["state"] == "idle"

    def test_overview_after_demo_contains_findings(self, client, app):
        assert client.post("/api/capture/start", json={"mode": "demo"}).status_code == 202
        wait_for_capture(app)

        data = client.get("/api/overview").get_json()["data"]
        assert data["counters"]["total"] > 0
        assert data["packet_count"] > 0
        assert data["traffic_series"]
        assert data["recent_alerts"]
        assert data["status"]["state"] == "completed"


class TestTrafficEndpoints:
    def test_pagination_validation(self, client):
        response = client.get("/api/traffic?page=0&per_page=9999")
        assert response.status_code == 400
        fields = {field["field"] for field in response.get_json()["error"]["detail"]["fields"]}
        assert fields == {"page", "per_page"}

    def test_traffic_rows_and_filters(self, client, app, fixtures_dir):
        run_pcap(client, app, "normal_day.pcap", fixtures_dir)

        body = client.get("/api/traffic?per_page=5").get_json()
        assert body["meta"]["total"] > 0
        assert len(body["data"]["packets"]) == 5
        assert body["data"]["packets"][0]["blocked"] is False

        tcp = client.get("/api/traffic?proto=TCP").get_json()
        assert all(row["protocol"] == "TCP" for row in tcp["data"]["packets"])

    def test_bad_protocol_is_rejected(self, client):
        response = client.get("/api/traffic?proto=SMTP")
        assert response.status_code == 400
        assert response.get_json()["error"]["detail"]["fields"][0]["field"] == "proto"


class TestIncidentEndpoints:
    def test_alert_list_and_filters(self, client, app, fixtures_dir):
        run_pcap(client, app, "port_scan_lab.pcap", fixtures_dir)

        body = client.get("/api/alerts").get_json()
        assert body["meta"]["total"] >= 1
        assert body["data"]["incidents"]

        scans = client.get("/api/alerts?rule=PORT_SCAN_PORTS").get_json()
        assert scans["meta"]["total"] >= 1
        assert all(row["rule_id"] == "PORT_SCAN_PORTS" for row in scans["data"]["incidents"])

        empty = client.get("/api/alerts?severity=low&rule=PORT_SCAN_PORTS").get_json()
        assert empty["meta"]["total"] == 0

    def test_bad_filters_are_reported_together(self, client):
        response = client.get("/api/alerts?severity=catastrophic&status=closed&from=yesterday")
        assert response.status_code == 400
        fields = {field["field"] for field in response.get_json()["error"]["detail"]["fields"]}
        assert {"severity", "status", "from"} <= fields

    def test_detail_missing_is_404(self, client):
        response = client.get("/api/alerts/nope")
        assert response.status_code == 404
        assert response.get_json()["error"]["code"] == "not_found"

    def test_ack_and_resolve_flow(self, client, app, fixtures_dir):
        run_pcap(client, app, "suspicious_lab.pcap", fixtures_dir)
        incident = client.get("/api/alerts").get_json()["data"]["incidents"][0]

        acked = client.post(f"/api/alerts/{incident['id']}/ack", json={"note": "on it"})
        assert acked.status_code == 200
        assert acked.get_json()["data"]["incident"]["status"] == "acknowledged"
        assert acked.get_json()["data"]["incident"]["analyst_notes"] == "on it"

        resolved = client.post(f"/api/alerts/{incident['id']}/resolve", json={"note": "done"})
        assert resolved.get_json()["data"]["incident"]["status"] == "resolved"
        events = [event["event_type"] for event in resolved.get_json()["data"]["events"]]
        assert events == ["detected", "acknowledged", "resolved"]

    def test_ack_missing_is_404(self, client):
        assert client.post("/api/alerts/nope/ack", json={}).status_code == 404

    def test_incident_alias_returns_same_payload(self, client, app, fixtures_dir):
        run_pcap(client, app, "port_scan_lab.pcap", fixtures_dir)
        incident = client.get("/api/incidents").get_json()["data"]["incidents"][0]
        detail = client.get(f"/api/incidents/{incident['id']}").get_json()
        assert detail["data"]["incident"]["id"] == incident["id"]


class TestExport:
    def test_csv_download(self, client, app, fixtures_dir):
        run_pcap(client, app, "port_scan_lab.pcap", fixtures_dir)
        response = client.get("/api/export/incidents.csv")
        assert response.status_code == 200
        assert response.mimetype == "text/csv"
        assert "attachment" in response.headers["Content-Disposition"]
        lines = response.get_data(as_text=True).strip().splitlines()
        assert lines[0].startswith("id,detected_at,rule_id")
        assert len(lines) > 1

    def test_csv_honours_filters(self, client, app, fixtures_dir):
        run_pcap(client, app, "port_scan_lab.pcap", fixtures_dir)

        scans = client.get("/api/export/incidents.csv?rule=PORT_SCAN_PORTS")
        assert len(scans.get_data(as_text=True).strip().splitlines()) == 2

        none = client.get("/api/export/incidents.csv?rule=TRAFFIC_SPIKE")
        assert len(none.get_data(as_text=True).strip().splitlines()) == 1


class TestSettings:
    def test_get_settings(self, client):
        data = client.get("/api/settings").get_json()["data"]
        assert data["settings"]["port_scan"]["distinct_port_threshold"] == 15
        assert data["settings"]["safe_response"]["enabled"] is False

    def test_update_threshold(self, client):
        response = client.put(
            "/api/settings",
            json={"port_scan": {"distinct_port_threshold": 25}},
        )
        assert response.status_code == 200
        body = response.get_json()["data"]
        assert body["settings"]["port_scan"]["distinct_port_threshold"] == 25
        assert body["applied_immediately"] is True

        again = client.get("/api/settings").get_json()["data"]
        assert again["settings"]["port_scan"]["distinct_port_threshold"] == 25

    def test_out_of_range_value_is_rejected(self, client):
        response = client.put(
            "/api/settings", json={"port_scan": {"distinct_port_threshold": 1}}
        )
        assert response.status_code == 400
        field = response.get_json()["error"]["detail"]["fields"][0]
        assert field["field"] == "port_scan.distinct_port_threshold"

    def test_unknown_setting_is_rejected(self, client):
        response = client.put("/api/settings", json={"port_scan": {"magic": 1}})
        assert response.status_code == 400
        assert response.get_json()["error"]["detail"]["fields"][0]["reason"] == "unknown setting"

    def test_scoring_band_order_is_enforced(self, client):
        response = client.put(
            "/api/settings", json={"scoring": {"low_max": 80, "medium_max": 70}}
        )
        assert response.status_code == 400
        assert "less than" in response.get_json()["error"]["detail"]["fields"][0]["reason"]

    def test_deployment_settings_cannot_be_changed(self, client):
        response = client.put("/api/settings", json={"db_path": "/tmp/evil.db"})
        assert response.status_code == 400


class TestCaptureControl:
    def test_start_rejects_unknown_mode(self, client):
        response = client.post("/api/capture/start", json={"mode": "telepathy"})
        assert response.status_code == 400
        assert response.get_json()["error"]["detail"]["field"] == "mode"

    def test_start_rejects_path_outside_allowed_roots(self, client, tmp_path):
        outside = tmp_path / "outside.pcap"
        outside.write_bytes(b"junk")
        response = client.post("/api/capture/start", json={"mode": "pcap", "path": str(outside)})
        assert response.status_code == 400
        assert response.get_json()["error"]["detail"]["field"] == "path"

    def test_start_pcap_and_status(self, client, app, fixtures_dir):
        response = client.post(
            "/api/capture/start",
            json={"mode": "pcap", "path": str(fixtures_dir / "port_scan_lab.pcap")},
        )
        assert response.status_code == 202
        assert response.get_json()["data"]["capture"]["mode"] == "pcap"

        wait_for_capture(app)
        status = client.get("/api/capture/status").get_json()["data"]["capture"]
        assert status["state"] == "completed"
        assert status["packets_processed"] == 166

    def test_busy_capture_returns_409(self, client):
        client.post("/api/capture/start", json={"mode": "demo"})
        try:
            second = client.post("/api/capture/start", json={"mode": "demo"})
            assert second.status_code == 409
            assert second.get_json()["error"]["code"] == "conflict"
        finally:
            client.post("/api/capture/stop")

    def test_stop_is_idempotent(self, client):
        first = client.post("/api/capture/stop")
        second = client.post("/api/capture/stop")
        assert first.status_code == 200
        assert second.status_code == 200
        assert second.get_json()["data"]["capture"]["running"] is False

    def test_live_requires_explicit_confirmation(self, client):
        response = client.post(
            "/api/capture/start", json={"mode": "live", "iface": "lo"}
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["detail"]["field"] == "confirm_authorization"

    def test_live_rejects_unknown_interface(self, client):
        response = client.post(
            "/api/capture/start",
            json={"mode": "live", "iface": "netshield-nope", "confirm_authorization": True},
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "capture_error"

    def test_capture_files_lists_fixtures(self, client):
        files = client.get("/api/capture/files").get_json()["data"]["files"]
        names = {item["name"] for item in files}
        assert "port_scan_lab.pcap" in names
        assert all(item["size"] > 0 for item in files)


class TestUpload:
    def test_upload_valid_capture(self, client, fixtures_dir):
        payload = (fixtures_dir / "port_scan_lab.pcap").read_bytes()
        response = client.post(
            "/api/capture/upload",
            data={"file": (io.BytesIO(payload), "my-capture.pcap")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 201, response.get_json()
        uploaded = response.get_json()["data"]["file"]
        assert uploaded["size"] == len(payload)

        started = client.post(
            "/api/capture/start", json={"mode": "pcap", "path": uploaded["path"]}
        )
        assert started.status_code == 202
        client.post("/api/capture/stop")

    def test_upload_rejects_wrong_extension(self, client):
        response = client.post(
            "/api/capture/upload",
            data={"file": (io.BytesIO(b"hello"), "notes.txt")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["detail"]["field"] == "file"

    def test_upload_rejects_fake_capture(self, client):
        response = client.post(
            "/api/capture/upload",
            data={"file": (io.BytesIO(b"not a pcap at all"), "fake.pcap")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        assert "signature" in response.get_json()["error"]["detail"]["reason"]


class TestResponseApi:
    def test_disabled_by_default(self, client):
        response = client.post(
            "/api/response",
            json={"action": "simulate_block", "target_ip": "10.0.0.66"},
        )
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "response_disabled"

    def test_rejects_target_outside_lab_range(self, client):
        client.put("/api/settings", json={"safe_response": {"enabled": True}})
        response = client.post(
            "/api/response",
            json={"action": "simulate_block", "target_ip": "8.8.8.8"},
        )
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "target_not_allowed"

    def test_simulated_block_and_unblock(self, client):
        client.put("/api/settings", json={"safe_response": {"enabled": True}})

        blocked = client.post(
            "/api/response",
            json={"action": "simulate_block", "target_ip": "10.0.0.66"},
        )
        assert blocked.status_code == 201
        payload = blocked.get_json()["data"]["action"]
        assert payload["blocked"] is True
        assert payload["mode"] == "simulated"
        assert "simulation only" in payload["message"]

        log = client.get("/api/response").get_json()["data"]
        assert log["blocked_targets"] == ["10.0.0.66"]
        assert log["actions"][0]["action"] == "simulate_block"

        unblocked = client.post(
            "/api/response",
            json={"action": "simulate_unblock", "target_ip": "10.0.0.66"},
        )
        assert unblocked.get_json()["data"]["action"]["blocked"] is False
        assert client.get("/api/response").get_json()["data"]["blocked_targets"] == []

    def test_firewall_path_is_disabled_by_default(self, client):
        client.put("/api/settings", json={"safe_response": {"enabled": True}})
        response = client.post(
            "/api/response",
            json={"action": "firewall_block", "target_ip": "10.0.0.66"},
        )
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "firewall_disabled"

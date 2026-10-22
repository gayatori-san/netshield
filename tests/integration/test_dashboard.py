from __future__ import annotations

import re

import pytest

from netshield.api.app import create_app
from netshield.config.settings import load_settings


@pytest.fixture
def app(tmp_path, stub_auth):
    settings = load_settings().with_overrides(db_path=tmp_path / "ui.db")
    application = create_app(settings, demo_pace=False, auth_backend=stub_auth)
    application.config.update(TESTING=True)
    yield application
    application.extensions["netshield"].pipeline.stop()
    application.extensions["netshield"].db.close()


@pytest.fixture
def client(app, auth_client):
    return auth_client(app, use_session_cookie=True)


PAGES = [
    ("/", "Overview"),
    ("/alerts", "Alerts"),
    ("/traffic", "Traffic"),
    ("/settings", "Settings"),
]


@pytest.mark.parametrize("path,title", PAGES)
def test_pages_render(client, path, title):
    response = client.get(path)
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert response.mimetype == "text/html"
    assert f"<title>{title} · NetShield</title>" in body
    assert 'id="capturePill"' in body
    assert "{{" not in body


@pytest.mark.parametrize("path,label", PAGES)
def test_nav_marks_active_page(client, path, label):
    body = client.get(path).get_data(as_text=True)
    assert body.count('class="active"') == 1
    match = re.search(r'<a href="([^"]+)" class="active">', body)
    assert match is not None
    assert match.group(1) == path
    assert f"\n        {label}\n" in body


def test_static_assets_are_served(client):
    checks = [
        ("/static/css/app.css", "text/css"),
        ("/static/vendor/chart.umd.min.js", "javascript"),
        ("/static/img/shield.svg", "image/svg+xml"),
        ("/static/js/overview.js", "javascript"),
    ]
    for path, mimetype in checks:
        response = client.get(path)
        try:
            assert response.status_code == 200
            assert mimetype in response.mimetype
            assert response.get_data()
        finally:
            response.close()


@pytest.mark.parametrize("path", ["/", "/alerts", "/traffic", "/settings"])
def test_security_headers(client, path):
    headers = client.get(path).headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "'unsafe-inline'" not in csp


def test_pages_survive_populated_database(client, app, fixtures_dir, auth_client):
    api = auth_client(app)
    started = api.post(
        "/api/capture/start",
        json={"mode": "pcap", "path": str(fixtures_dir / "port_scan_lab.pcap")},
    )
    assert started.status_code == 202
    import time

    deadline = time.monotonic() + 20
    pipeline = app.extensions["netshield"].pipeline
    while pipeline.running and time.monotonic() < deadline:
        time.sleep(0.02)

    for path, _ in PAGES:
        assert client.get(path).status_code == 200

from __future__ import annotations

import pytest

from netshield.api.app import create_app
from netshield.auth.rate_limit import SlidingWindowLimiter
from netshield.config.settings import load_settings
from tests.auth_support import ADMIN, EXPIRED, REVOKED, VALID


@pytest.fixture
def settings(tmp_path):
    return load_settings().with_overrides(db_path=tmp_path / "auth.db")


@pytest.fixture
def app(settings, stub_auth, tmp_path):
    from netshield.api import routes

    uploads = tmp_path / "uploads"
    uploads.mkdir()
    routes.UPLOAD_DIR = uploads
    application = create_app(settings, demo_pace=False, auth_backend=stub_auth)
    application.config.update(TESTING=True)
    yield application
    application.extensions["netshield"].pipeline.stop()
    application.extensions["netshield"].db.close()


@pytest.fixture
def anon(app):
    return app.test_client()


@pytest.fixture
def bearer(app):
    def make(token=VALID):
        client = app.test_client()
        client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        return client

    return make


@pytest.fixture
def session_client(app):
    def make(token=VALID):
        client = app.test_client()
        client.set_cookie("netshield_session", f"session:{token}")
        return client

    return make


class TestPublicSurface:
    def test_health_needs_no_auth(self, anon):
        response = anon.get("/api/health")
        assert response.status_code == 200
        assert response.get_json()["data"]["status"] == "ok"

    def test_login_page_is_public(self, anon):
        response = anon.get("/login")
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert 'id="loginForm"' in body
        assert "firebase-auth-compat.js" in body
        assert response.headers["Cache-Control"] == "no-store"

    def test_static_asset_is_public(self, anon):
        response = anon.get("/static/css/auth.css")
        try:
            assert response.status_code == 200
        finally:
            response.close()

    def test_login_page_does_not_expose_inline_scripts(self, anon):
        body = anon.get("/login").get_data(as_text=True)
        assert "<script>" not in body

    def test_web_config_cannot_break_out_of_its_script_tag(self, anon, stub_auth):
        stub_auth.web_config = {"apiKey": "</script><script>alert(1)</script>"}
        body = anon.get("/login").get_data(as_text=True)
        assert "<script>alert(1)</script>" not in body
        assert "\\u003c/script\\u003e" in body


class TestPageProtection:
    @pytest.mark.parametrize("path", ["/", "/alerts", "/traffic", "/settings"])
    def test_pages_redirect_to_login(self, anon, path):
        response = anon.get(path)
        assert response.status_code == 302
        assert response.headers["Location"].startswith("/login?next=")

    def test_redirect_has_safe_next(self, anon):
        from urllib.parse import parse_qs, urlsplit

        location = anon.get("/alerts?severity=high").headers["Location"]
        assert parse_qs(urlsplit(location).query)["next"] == ["/alerts?severity=high"]

    @pytest.mark.parametrize("path", ["/", "/alerts", "/traffic", "/settings"])
    def test_valid_session_cookie_opens_pages(self, session_client, path):
        response = session_client().get(path)
        assert response.status_code == 200
        assert 'id="signOutButton"' in response.get_data(as_text=True)

    def test_invalid_session_cookie_is_cleared(self, anon):
        anon.set_cookie("netshield_session", "session:not-a-token")
        response = anon.get("/")
        assert response.status_code == 302
        assert "netshield_session=;" in response.headers["Set-Cookie"]

    def test_login_page_redirects_an_authenticated_session(self, session_client):
        response = session_client().get("/login?next=/traffic")
        assert response.status_code == 302
        assert response.headers["Location"] == "/traffic"

    def test_login_page_rejects_offsite_next(self, anon):
        response = anon.get("/login?next=//evil.example/path")
        assert response.status_code == 200
        assert 'data-next="/"' in response.get_data(as_text=True)


class TestApiProtection:
    @pytest.mark.parametrize(
        "path", ["/api/overview", "/api/alerts", "/api/traffic", "/api/settings", "/api/response"]
    )
    def test_missing_token_is_401(self, anon, path):
        response = anon.get(path)
        assert response.status_code == 401
        body = response.get_json()
        assert body["error"]["code"] == "unauthenticated"
        assert response.headers["WWW-Authenticate"].startswith("Bearer")

    @pytest.mark.parametrize("token", ["not-a-token", EXPIRED, REVOKED])
    def test_invalid_tokens_are_401(self, bearer, token):
        response = bearer(token).get("/api/overview")
        assert response.status_code == 401
        assert response.get_json()["error"]["code"] == "unauthenticated"

    def test_malformed_authorization_header_is_401(self, anon):
        anon.environ_base["HTTP_AUTHORIZATION"] = "Basic abc"
        response = anon.get("/api/overview")
        assert response.status_code == 401

    def test_valid_bearer_opens_api(self, bearer):
        response = bearer().get("/api/overview")
        assert response.status_code == 200
        assert response.get_json()["ok"] is True

    def test_session_cookie_allows_safe_api_reads(self, session_client):
        response = session_client().get("/api/overview")
        assert response.status_code == 200

    def test_stale_bearer_falls_back_to_cookie_for_reads(self, session_client):
        client = session_client()
        client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {EXPIRED}"
        response = client.get("/api/overview")
        assert response.status_code == 200

    @pytest.mark.parametrize(
        "method,path",
        [
            ("post", "/api/capture/start"),
            ("post", "/api/capture/stop"),
            ("put", "/api/settings"),
            ("post", "/api/alerts/missing/ack"),
            ("post", "/api/response"),
        ],
    )
    def test_cookie_authenticated_writes_are_csrf_blocked(self, session_client, method, path):
        client = session_client()
        response = getattr(client, method)(path, json={})
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "csrf_required"

    def test_bearer_writes_are_allowed(self, bearer):
        response = bearer().put(
            "/api/settings", json={"port_scan": {"distinct_port_threshold": 12}}
        )
        assert response.status_code == 200


class TestSessionEndpoints:
    def test_session_requires_token(self, anon):
        assert anon.post("/api/auth/session", json={}).status_code == 401

    def test_session_rejects_invalid_token(self, bearer):
        response = bearer(EXPIRED).post("/api/auth/session", json={})
        assert response.status_code == 401

    def test_session_sets_hardened_cookie(self, bearer):
        response = bearer().post("/api/auth/session", json={})
        assert response.status_code == 200
        cookie = response.headers["Set-Cookie"]
        assert "netshield_session=" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=Lax" in cookie
        assert "Max-Age=3600" in cookie
        assert "Secure" not in cookie

    def test_session_cookie_is_secure_behind_https(self, bearer):
        response = bearer().post(
            "/api/auth/session", json={}, base_url="https://netshield.example"
        )
        assert response.status_code == 200
        assert "Secure" in response.headers["Set-Cookie"]

    def test_me_returns_public_user(self, bearer):
        body = bearer().get("/api/auth/me").get_json()
        assert body["data"]["user"]["email"] == "operator@example.test"
        assert body["data"]["user"]["is_admin"] is False

    def test_logout_clears_cookie(self, anon):
        anon.set_cookie("netshield_session", f"session:{VALID}")
        response = anon.post("/api/auth/logout")
        assert response.status_code == 200
        assert "netshield_session=;" in response.headers["Set-Cookie"]


class TestPermissions:
    def test_regular_user_cannot_apply_a_response(self, bearer):
        response = bearer(VALID).post(
            "/api/response",
            json={"action": "simulate_block", "target_ip": "10.0.0.9"},
        )
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "forbidden"

    def test_admin_may_apply_a_response(self, bearer):
        client = bearer(ADMIN)
        enabled = client.put("/api/settings", json={"safe_response": {"enabled": True}})
        assert enabled.status_code == 200

        response = client.post(
            "/api/response",
            json={"action": "simulate_block", "target_ip": "10.0.0.9"},
        )
        assert response.status_code == 201
        assert response.get_json()["data"]["action"]["mode"] == "simulated"

    def test_admin_claim_grants_permission(self):
        from netshield.auth.backend import AuthUser

        user = AuthUser(uid="1", claims={"admin": True})
        assert user.has_permission("admin")
        assert user.has_permission("anything")


class TestAuthOutage:
    def test_session_endpoint_fails_closed(self, bearer, stub_auth):
        stub_auth.unavailable = True
        response = bearer().post("/api/auth/session", json={})
        assert response.status_code == 503
        assert response.get_json()["error"]["code"] == "auth_unavailable"

    def test_api_fails_closed(self, bearer, stub_auth):
        stub_auth.unavailable = True
        response = bearer().get("/api/overview")
        assert response.status_code == 503

    def test_login_page_still_renders_during_outage(self, anon, stub_auth):
        stub_auth.unavailable = True
        response = anon.get("/login")
        assert response.status_code == 200


class TestRateLimiting:
    def test_session_endpoint_returns_429_with_retry_after(self, app):
        app.extensions["auth_limiter"] = SlidingWindowLimiter(limit=2)
        client = app.test_client()
        client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {VALID}"
        assert client.post("/api/auth/session", json={}).status_code == 200
        assert client.post("/api/auth/session", json={}).status_code == 200
        response = client.post("/api/auth/session", json={})
        assert response.status_code == 429
        assert response.get_json()["error"]["code"] == "rate_limited"
        assert int(response.headers["Retry-After"]) >= 1

    def test_limiter_window_recovers(self):
        now = [0.0]

        def clock():
            return now[0]

        limiter = SlidingWindowLimiter(limit=1, window_seconds=10, clock=clock)
        assert limiter.hit("1.2.3.4") == (True, 0)
        allowed, retry = limiter.hit("1.2.3.4")
        assert allowed is False and retry == 10
        now[0] = 11.0
        assert limiter.hit("1.2.3.4") == (True, 0)

from __future__ import annotations

from datetime import timedelta

import pytest

from netshield.auth.backend import (
    AuthUnavailable,
    AuthUser,
    FirebaseAuthManager,
    TokenExpired,
    TokenInvalid,
    TokenRevoked,
    _translate_sdk_error,
    build_auth_manager,
    load_web_config,
)
from netshield.auth.urls import safe_next_path

WEB = {
    "FIREBASE_WEB_API_KEY": "api-key",
    "FIREBASE_AUTH_DOMAIN": "demo.firebaseapp.com",
    "FIREBASE_PROJECT_ID": "demo",
    "FIREBASE_STORAGE_BUCKET": "demo.appspot.com",
    "FIREBASE_MESSAGING_SENDER_ID": "123",
    "FIREBASE_APP_ID": "1:123:web:abc",
}


class TestWebConfig:
    def test_complete_config(self):
        config, error = load_web_config(WEB)
        assert error is None
        assert config == {
            "apiKey": "api-key",
            "authDomain": "demo.firebaseapp.com",
            "projectId": "demo",
            "storageBucket": "demo.appspot.com",
            "messagingSenderId": "123",
            "appId": "1:123:web:abc",
        }

    def test_missing_config_is_explicit(self):
        config, error = load_web_config({})
        assert config is None
        assert "FIREBASE_WEB_API_KEY" in error
        assert "README" in error

    def test_partial_config_names_only_missing_keys(self):
        partial = dict(WEB)
        partial.pop("FIREBASE_APP_ID")
        config, error = load_web_config(partial)
        assert config is None
        assert "FIREBASE_APP_ID" in error
        assert "FIREBASE_WEB_API_KEY" not in error


class TestSafeRedirects:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("/alerts", "/alerts"),
            ("/traffic?proto=TCP", "/traffic?proto=TCP"),
            ("//evil.example", "/"),
            ("https://evil.example", "/"),
            ("/\\evil", "/"),
            ("/login", "/"),
            ("/login/", "/"),
            ("/login?next=/", "/"),
            (None, "/"),
            ("x" * 3000, "/"),
        ],
    )
    def test_safe_next_path(self, value, expected):
        assert safe_next_path(value) == expected


class TestManagerWithoutFirebase:
    def manager(self, **kwargs):
        defaults = dict(
            web_config={"apiKey": "x"},
            web_error=None,
            admin_ready=True,
            admin_error=None,
            verifier=lambda token: {"uid": "u1", "email": "a@b.test"},
            session_creator=lambda token, expires: "cookie-value",
            session_verifier=lambda cookie: {"uid": "u1"},
        )
        defaults.update(kwargs)
        return FirebaseAuthManager(**defaults)

    def test_verifier_claims_become_user(self):
        user = self.manager().verify_id_token("token")
        assert user.uid == "u1"
        assert user.email == "a@b.test"

    def test_expired_verifier_error_is_preserved(self):
        def verifier(token):
            raise TokenExpired("expired")

        with pytest.raises(TokenExpired):
            self.manager(verifier=verifier).verify_id_token("token")

    def test_oversized_token_is_rejected_before_verifier(self):
        manager = self.manager(verifier=lambda token: {"uid": "u"})
        with pytest.raises(Exception) as caught:
            manager.verify_id_token("x" * 20_001)
        assert "too large" in str(caught.value)

    def test_unready_manager_fails_closed(self):
        manager = self.manager(admin_ready=False, admin_error="no credentials")
        with pytest.raises(AuthUnavailable) as caught:
            manager.verify_id_token("token")
        assert "no credentials" in str(caught.value)

    def test_session_creator_receives_configured_lifetime(self):
        seen = {}

        def creator(token, expires):
            seen["expires"] = expires
            return "cookie"

        manager = self.manager(session_creator=creator, session_max_age=600)
        assert manager.create_session_cookie("token") == "cookie"
        assert seen["expires"] == timedelta(seconds=600)

    def test_cookie_secure_modes(self):
        assert self.manager(cookie_secure_mode="true").cookie_secure(False) is True
        assert self.manager(cookie_secure_mode="false").cookie_secure(True) is False
        assert self.manager(cookie_secure_mode="auto").cookie_secure(True) is True
        assert self.manager(cookie_secure_mode="auto").cookie_secure(False) is False


class TestBuildManagerConfiguration:
    def test_missing_everything_is_not_ready(self):
        manager = build_auth_manager({})
        assert manager.ready is False
        assert manager.web_error and "FIREBASE_WEB_API_KEY" in manager.web_error
        assert manager.admin_error and "credentials" in manager.admin_error

    def test_malformed_service_account_never_echoes_contents(self):
        env = dict(WEB)
        env["FIREBASE_SERVICE_ACCOUNT_JSON"] = '{"private_key": "SECRET"}'
        manager = build_auth_manager(env)
        assert manager.ready is False
        assert "SECRET" not in (manager.admin_error or "")

    def test_project_mismatch_is_reported(self):
        env = dict(WEB)
        env["FIREBASE_PROJECT_ID"] = "web-project"
        env["FIREBASE_SERVICE_ACCOUNT_JSON"] = (
            '{"type":"service_account","project_id":"other-project",'
            '"private_key":"x","client_email":"a@b.test"}'
        )
        manager = build_auth_manager(env)
        assert manager.ready is False
        assert "does not match" in (manager.admin_error or "")

    def test_invalid_session_lifetime_falls_back(self):
        env = dict(WEB)
        env["NETSHIELD_SESSION_MAX_AGE"] = "60"
        env["FIREBASE_SERVICE_ACCOUNT_JSON"] = "{}"
        manager = build_auth_manager(env)
        assert manager.session_max_age == 432000


class TestUserClaims:
    def test_admin_claim(self):
        user = AuthUser(uid="u", claims={"admin": True})
        assert user.is_admin
        assert user.has_permission("admin")
        assert user.public_dict()["is_admin"] is True

    def test_permissions_list(self):
        user = AuthUser(uid="u", claims={"permissions": ["view", "export"]})
        assert user.permissions == ("export", "view")
        assert user.has_permission("view")
        assert not user.has_permission("admin")

    def test_initials(self):
        assert AuthUser(uid="u", name="Ada Lovelace").initials == "AL"
        assert AuthUser(uid="u", email="ops@example.test").initials == "OP"


class TestSdkErrorTranslation:
    def test_deleted_user_is_not_an_outage(self):
        from firebase_admin import auth as fb_auth

        error = _translate_sdk_error(fb_auth.UserNotFoundError("missing"))
        assert isinstance(error, TokenRevoked)

    def test_disabled_user_is_rejected(self):
        from firebase_admin import auth as fb_auth

        error = _translate_sdk_error(fb_auth.UserDisabledError("disabled"))
        assert isinstance(error, TokenInvalid)

    def test_missing_iam_permission_is_an_outage(self):
        from firebase_admin import auth as fb_auth

        error = _translate_sdk_error(
            fb_auth.InsufficientPermissionError("denied", None, None)
        )
        assert isinstance(error, AuthUnavailable)

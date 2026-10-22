"""Deterministic auth doubles for tests. No Firebase project is required."""

from __future__ import annotations

from netshield.auth.backend import (
    AuthUnavailable,
    AuthUser,
    TokenExpired,
    TokenInvalid,
    TokenRevoked,
)

VALID = "valid-token"
ADMIN = "admin-token"
EXPIRED = "expired-token"
REVOKED = "revoked-token"

TOKEN_USERS = {
    VALID: AuthUser(uid="uid-operator", email="operator@example.test", name="Operator One"),
    ADMIN: AuthUser(
        uid="uid-admin",
        email="admin@example.test",
        name="Admin One",
        claims={"admin": True},
    ),
}

SESSION_PREFIX = "session:"


class StubAuthBackend:
    cookie_name = "netshield_session"
    session_max_age = 3600
    web_config = {"apiKey": "test-api-key", "projectId": "test-project"}
    web_error = None
    admin_error = None
    ready = True

    def __init__(self) -> None:
        self.verified_tokens: list[str] = []
        self.verified_cookies: list[str] = []
        self.unavailable = False

    def cookie_secure(self, request_is_secure: bool) -> bool:
        return bool(request_is_secure)

    def verify_id_token(self, token: str) -> AuthUser:
        self.verified_tokens.append(token)
        if self.unavailable:
            raise AuthUnavailable("The authentication backend is unavailable.")
        if token == EXPIRED:
            raise TokenExpired("The authentication token has expired.")
        if token == REVOKED:
            raise TokenRevoked("The authentication token was revoked.")
        user = TOKEN_USERS.get(token)
        if user is None:
            raise TokenInvalid("The authentication token is invalid.")
        return user

    def verify_session_cookie(self, cookie: str) -> AuthUser:
        self.verified_cookies.append(cookie)
        token = cookie[len(SESSION_PREFIX):] if cookie.startswith(SESSION_PREFIX) else cookie
        return self.verify_id_token(token)

    def create_session_cookie(self, token: str) -> str:
        self.verify_id_token(token)
        return f"{SESSION_PREFIX}{token}"

"""Central authentication guard.

A single ``before_request`` hook protects every dashboard page and API route.
Individual routes never re-implement token parsing. Sensitive operations may
add a permission check (for example real firewall changes require the
``admin`` permission).
"""

from __future__ import annotations

from functools import wraps
from typing import Callable

from flask import current_app, g, redirect, request, url_for

from netshield.api.errors import (
    AuthUnavailableError,
    CsrfError,
    ForbiddenError,
    UnauthenticatedError,
)
from netshield.auth.backend import AuthBackendError, AuthUnavailable, AuthUser
from netshield.auth.urls import safe_next_path

PUBLIC_PATHS = {
    "/login",
    "/login/",
    "/favicon.ico",
    "/api/health",
    "/api/auth/session",
    "/api/auth/logout",
}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _is_public(path: str) -> bool:
    return (
        path == "/static"
        or path.startswith("/static/")
        or path in PUBLIC_PATHS
    )


def _current_backend():
    return current_app.extensions["auth"]


def bearer_token() -> str | None:
    header = request.headers.get("Authorization")
    if not header:
        return None
    scheme, separator, token = header.partition(" ")
    if separator and scheme.lower() == "bearer" and token.strip():
        return token.strip()
    raise UnauthenticatedError(
        "The Authorization header must use the Bearer scheme.",
        detail={"header": "Authorization", "reason": "expected Bearer <ID token>"},
    )


def _raise_backend_error(exc: AuthBackendError) -> None:
    if isinstance(exc, AuthUnavailable):
        raise AuthUnavailableError(str(exc)) from exc
    raise UnauthenticatedError(
        str(exc), detail={"reason": getattr(exc, "code", "invalid_token")}
    ) from exc


def _request_target() -> str:
    target = request.full_path.rstrip("?")
    return safe_next_path(target)


def _login_redirect(clear_cookie: bool = False):
    response = redirect(url_for("auth.login", next=_request_target()))
    if clear_cookie:
        backend = _current_backend()
        response.delete_cookie(
            backend.cookie_name,
            path="/",
            secure=backend.cookie_secure(request.is_secure),
            httponly=True,
            samesite="Lax",
        )
    return response


def _cookie_user(backend) -> AuthUser | None:
    cookie = request.cookies.get(backend.cookie_name)
    if not cookie:
        return None
    try:
        user = backend.verify_session_cookie(cookie)
    except AuthBackendError:
        g.auth_clear_session = True
        raise
    g.auth_user = user
    g.auth_method = "cookie"
    return user


def _api_guard():
    backend = _current_backend()
    token = bearer_token()

    if token is not None:
        try:
            user = backend.verify_id_token(token)
        except AuthBackendError as exc:
            if request.method in SAFE_METHODS and request.cookies.get(
                backend.cookie_name
            ):
                try:
                    if _cookie_user(backend) is not None:
                        return None
                except AuthBackendError:
                    pass
            _raise_backend_error(exc)
        g.auth_user = user
        g.auth_method = "bearer"
        return None

    if _cookie_user(backend) is None:
        raise UnauthenticatedError("Sign in to use the NetShield API.")

    if request.method not in SAFE_METHODS:
        raise CsrfError(
            "State-changing API requests must send a Firebase ID token in the "
            "Authorization header.",
            detail={
                "reason": "cookie_authenticated_write",
                "hint": "Send Authorization: Bearer <ID_TOKEN>.",
            },
        )
    return None


def _page_guard():
    backend = _current_backend()
    cookie = request.cookies.get(backend.cookie_name)
    if not cookie:
        return _login_redirect()

    try:
        user = backend.verify_session_cookie(cookie)
    except AuthBackendError as exc:
        if isinstance(exc, AuthUnavailable):
            current_app.logger.warning("Session verification unavailable: %s", exc)
            return _login_redirect(clear_cookie=False)
        return _login_redirect(clear_cookie=True)

    g.auth_user = user
    g.auth_method = "session"
    return None


def install_auth_guard(app) -> None:
    @app.before_request
    def _authenticate():
        if _is_public(request.path):
            return None
        if request.path.startswith("/api/"):
            return _api_guard()
        return _page_guard()

    @app.after_request
    def _clear_rejected_cookie(response):
        if g.pop("auth_clear_session", False):
            backend = _current_backend()
            response.delete_cookie(
                backend.cookie_name,
                path="/",
                secure=backend.cookie_secure(request.is_secure),
                httponly=True,
                samesite="Lax",
            )
        return response


def current_user() -> AuthUser | None:
    return getattr(g, "auth_user", None)


def ensure_permission(permission: str) -> AuthUser:
    user = current_user()
    if user is None:
        raise UnauthenticatedError("Sign in to use the NetShield API.")
    if not user.has_permission(permission):
        raise ForbiddenError(
            f"This action requires the '{permission}' permission.",
            detail={"permission": permission},
        )
    return user


def require_permission(permission: str) -> Callable:
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapper(*args, **kwargs):
            ensure_permission(permission)
            return view(*args, **kwargs)

        return wrapper

    return decorator

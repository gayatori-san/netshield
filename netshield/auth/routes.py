"""Login page and session endpoints.

The browser signs in with the Firebase JS SDK. It then posts the resulting ID
token (Bearer) to ``/api/auth/session``; Flask verifies it with the Admin SDK
and exchanges it for an HttpOnly Firebase session cookie. The cookie is only
accepted for page navigation and safe GET downloads. State-changing API calls
must use the Bearer ID token, which makes cookie-based CSRF ineffective.
"""

from __future__ import annotations

import json

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, url_for

from netshield.api.errors import (
    AuthUnavailableError,
    RateLimitError,
    UnauthenticatedError,
)
from netshield.auth.backend import AuthBackendError, AuthUnavailable, AuthUser
from netshield.auth.guard import _raise_backend_error, bearer_token, current_user
from netshield.auth.urls import safe_next_path

auth_ui = Blueprint("auth", __name__)
auth_api = Blueprint("auth_api", __name__, url_prefix="/api/auth")


def _backend():
    return current_app.extensions["auth"]


def _web_config_json() -> str:
    backend = _backend()
    if not backend.web_config:
        return ""
    return (
        json.dumps(backend.web_config, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


@auth_ui.get("/login")
def login():
    backend = _backend()
    next_path = safe_next_path(request.args.get("next"))
    cookie = request.cookies.get(backend.cookie_name)

    if cookie:
        try:
            backend.verify_session_cookie(cookie)
        except AuthBackendError as exc:
            response = current_app.make_response(
                render_template(
                    "login.html",
                    web_config_json=_web_config_json(),
                    web_error=backend.web_error,
                    admin_error=backend.admin_error,
                    auth_ready=backend.ready,
                    next_path=next_path,
                )
            )
            if not isinstance(exc, AuthUnavailable):
                response.delete_cookie(
                    backend.cookie_name,
                    path="/",
                    secure=backend.cookie_secure(request.is_secure),
                    httponly=True,
                    samesite="Lax",
                )
        else:
            response = redirect(next_path or url_for("ui.overview"))
        response.headers["Cache-Control"] = "no-store"
        return response

    response = current_app.make_response(
        render_template(
            "login.html",
            web_config_json=_web_config_json(),
            web_error=backend.web_error,
            admin_error=backend.admin_error,
            auth_ready=backend.ready,
            next_path=next_path,
        )
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@auth_api.post("/session")
def create_session():
    backend = _backend()
    limiter = current_app.extensions["auth_limiter"]
    remote = request.remote_addr or "unknown"
    allowed, retry_after = limiter.hit(remote)
    if not allowed:
        raise RateLimitError(
            "Too many sign-in attempts from this address. Try again shortly.",
            retry_after=retry_after,
        )

    token = bearer_token()
    if token is None:
        raise UnauthenticatedError("A Firebase ID token is required.")

    try:
        user = backend.verify_id_token(token)
        cookie_value = backend.create_session_cookie(token)
    except AuthBackendError as exc:
        if isinstance(exc, AuthUnavailable):
            raise AuthUnavailableError(str(exc)) from exc
        _raise_backend_error(exc)

    response = jsonify(
        {
            "ok": True,
            "data": {
                "user": user.public_dict(),
                "expires_in": backend.session_max_age,
            },
        }
    )
    response.set_cookie(
        backend.cookie_name,
        cookie_value,
        max_age=backend.session_max_age,
        secure=backend.cookie_secure(request.is_secure),
        httponly=True,
        samesite="Lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@auth_api.post("/logout")
def logout():
    backend = _backend()
    response = jsonify({"ok": True, "data": {"signed_out": True}})
    response.delete_cookie(
        backend.cookie_name,
        path="/",
        secure=backend.cookie_secure(request.is_secure),
        httponly=True,
        samesite="Lax",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@auth_api.get("/me")
def me():
    user = current_user()
    if not isinstance(user, AuthUser):  # pragma: no cover - guard guarantees it
        raise UnauthenticatedError("Sign in to use the NetShield API.")
    return jsonify({"ok": True, "data": {"user": user.public_dict()}})

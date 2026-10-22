"""Flask application factory."""

from __future__ import annotations

import json
import os
import secrets
from types import SimpleNamespace

from flask import Flask, g, request
from werkzeug.middleware.proxy_fix import ProxyFix

from netshield.api.errors import register_error_handlers
from netshield.api.routes import MAX_UPLOAD_BYTES, api
from netshield.auth import (
    FirebaseAuthManager,
    SlidingWindowLimiter,
    build_auth_manager,
    install_auth_guard,
)
from netshield.auth.rate_limit import build_limiter
from netshield.auth.routes import auth_api, auth_ui
from netshield.config.settings import Settings, load_settings
from netshield.pipeline import ProcessingPipeline
from netshield.responses import ResponseService
from netshield.storage.db import Database
from netshield.storage.repositories import ResponseRepository


def create_app(
    settings: Settings | None = None,
    *,
    db: Database | None = None,
    pipeline: ProcessingPipeline | None = None,
    demo_pace: bool = True,
    auth_backend: FirebaseAuthManager | None = None,
    auth_limiter: SlidingWindowLimiter | None = None,
) -> Flask:
    settings = settings or load_settings()
    database = db or Database(settings.db_path)
    database.init_schema()
    pipeline = pipeline or ProcessingPipeline(settings, database, demo_pace=demo_pace)
    responses = ResponseService(settings, ResponseRepository(database))
    auth = auth_backend if auth_backend is not None else build_auth_manager()
    limiter = auth_limiter if auth_limiter is not None else build_limiter()

    app = Flask(
        __name__,
        template_folder="../dashboard/templates",
        static_folder="../dashboard/static",
        static_url_path="/static",
    )
    app.json.sort_keys = False
    app.config.update(
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        SECRET_KEY=os.environ.get("NETSHIELD_SECRET_KEY") or secrets.token_hex(16),
        JSON_SORT_KEYS=False,
    )
    app.extensions["netshield"] = SimpleNamespace(
        settings=settings,
        db=database,
        pipeline=pipeline,
        responses=responses,
    )
    app.extensions["auth"] = auth
    app.extensions["auth_limiter"] = limiter

    if os.environ.get("NETSHIELD_TRUST_PROXY", "false").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    ):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.register_blueprint(api)
    app.register_blueprint(auth_ui)
    app.register_blueprint(auth_api)
    register_error_handlers(app)
    install_auth_guard(app)

    @app.context_processor
    def _inject_auth_context():
        backend = app.extensions["auth"]
        config_json = (
            json.dumps(backend.web_config, separators=(",", ":"))
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
            if backend.web_config
            else ""
        )
        return {
            "auth_user": g.get("auth_user"),
            "firebase_web_config_json": config_json,
            "firebase_web_error": backend.web_error,
            "firebase_admin_error": backend.admin_error,
            "auth_ready": backend.ready,
        }

    @app.teardown_appcontext
    def _close_request_connection(exc):
        # Each request thread owns a SQLite connection; without this the dev
        # server would leak one file handle per request.
        database.close_thread()

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; font-src 'self'; "
            "connect-src 'self' https://identitytoolkit.googleapis.com "
            "https://securetoken.googleapis.com "
            "https://firebaseinstallations.googleapis.com "
            "https://www.googleapis.com; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "frame-src 'none'; form-action 'self'",
        )
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    from netshield.dashboard.routes import ui

    app.register_blueprint(ui)

    if not auth.ready:
        app.logger.warning(
            "Authentication is not fully configured; protected pages and APIs "
            "remain inaccessible. See README -> Firebase setup."
        )
    return app

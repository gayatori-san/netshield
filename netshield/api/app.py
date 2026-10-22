"""Flask application factory."""

from __future__ import annotations

import os
import secrets
from types import SimpleNamespace

from flask import Flask

from netshield.api.errors import register_error_handlers
from netshield.api.routes import MAX_UPLOAD_BYTES, api
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
) -> Flask:
    settings = settings or load_settings()
    database = db or Database(settings.db_path)
    database.init_schema()
    pipeline = pipeline or ProcessingPipeline(settings, database, demo_pace=demo_pace)
    responses = ResponseService(settings, ResponseRepository(database))

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

    app.register_blueprint(api)
    register_error_handlers(app)

    @app.teardown_appcontext
    def _close_request_connection(exc):
        # Each request thread owns a SQLite connection; without this the dev
        # server would leak one file handle per request.
        database.close_thread()

    from netshield.dashboard.routes import ui

    app.register_blueprint(ui)
    return app

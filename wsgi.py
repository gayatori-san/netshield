"""Production WSGI entry point.

Gunicorn must run exactly one worker: the capture pipeline and its feature
windows live in process memory. Use threads for concurrency.

    gunicorn --workers 1 --threads 4 --bind 0.0.0.0:$PORT wsgi:app
"""

from __future__ import annotations

from netshield.api.app import create_app

app = create_app()

"""Production WSGI entry point for hosted deployments.

Run with:
    gunicorn --bind 0.0.0.0:$PORT wsgi:app

The hosted service is for the web dashboard and offline/demo analysis.
Live packet capture and real firewall actions should remain disabled on a
public multi-tenant host.
"""
import os

# Render provides PORT. Keep SQLite in the ephemeral writable filesystem
# unless NETSHIELD_DB_PATH is explicitly configured to a persistent disk.
os.environ.setdefault("NETSHIELD_HOST", "0.0.0.0")
os.environ.setdefault("NETSHIELD_PORT", os.environ.get("PORT", "10000"))
os.environ.setdefault("NETSHIELD_DB_PATH", "/tmp/netshield.db")

from netshield.api.app import create_app
from netshield.config.settings import load_settings

settings = load_settings()
app = create_app(settings, demo_pace=False)

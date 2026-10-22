"""Dashboard pages.

Each page loads one template; all data arrives from the JSON API, so there is
no second data path to keep in sync.
"""

from __future__ import annotations

from flask import Blueprint, render_template

ui = Blueprint("ui", __name__)


@ui.get("/")
def index():
    return render_template("overview.html")

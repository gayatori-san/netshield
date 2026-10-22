"""Dashboard pages.

Each page renders one template; all data arrives from the JSON API, so there is
no second data path to keep in sync and no sample data baked into the HTML.
"""

from __future__ import annotations

from flask import Blueprint, render_template

ui = Blueprint("ui", __name__)


@ui.get("/")
def overview():
    return render_template("overview.html")


@ui.get("/alerts")
def alerts():
    return render_template("alerts.html")


@ui.get("/traffic")
def traffic():
    return render_template("traffic.html")


@ui.get("/settings")
def settings():
    return render_template("settings.html")

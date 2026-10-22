"""HTTP API.

Every JSON response uses ``{ok, data, meta}`` / ``{ok, error}``. Two routes
intentionally break that rule: the CSV export (a file download) and the static
dashboard assets.

The API does not accept arbitrary filesystem paths. PCAP analysis is limited
to files inside ``data/pcap`` (uploads land there) or ``tests/fixtures``
(sample captures), and the resolved path must stay inside that root.
"""

from __future__ import annotations

import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, Response, current_app, jsonify, request
from werkzeug.utils import secure_filename

from netshield.api.errors import ApiError, ConflictError, NotFoundError, ValidationError
from netshield.api.validation import (
    ParamReader,
    apply_settings_patch,
    as_choice,
    incident_filters,
    json_object,
    optional_note,
)
from netshield.capture.pcap import has_capture_signature
from netshield.config.settings import PROJECT_ROOT
from netshield.models import RULE_TITLES
from netshield.pipeline import PipelineBusy, PipelineError
from netshield.responses import ACTIONS, ResponseError, ResponseRequest
from netshield.scoring.scorer import RULE_BASE
from netshield.storage.repositories import (
    IncidentRepository,
    PacketRepository,
    ResponseRepository,
    TrafficRepository,
)

api = Blueprint("api", __name__, url_prefix="/api")

CAPTURE_ROOTS = (
    (PROJECT_ROOT / "data" / "pcap", "captures"),
    (PROJECT_ROOT / "tests" / "fixtures", "fixtures"),
)
UPLOAD_DIR = PROJECT_ROOT / "data" / "pcap"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_UPLOAD_SUFFIXES = (".pcap", ".pcapng", ".cap")


def services():
    return current_app.extensions["netshield"]


def ok(data, *, meta: dict | None = None, status: int = 200):
    body = {"ok": True, "data": data}
    if meta is not None:
        body["meta"] = meta
    return jsonify(body), status


def page_meta(page: int, per_page: int, total: int) -> dict:
    pages = max(1, (total + per_page - 1) // per_page)
    return {"page": page, "per_page": per_page, "total": total, "pages": pages}


@api.get("/health")
def health():
    return ok({"status": "ok", "service": "netshield", "time": time.time()})


@api.get("/rules")
def rules():
    return ok(
        {
            "rules": [
                {"id": rule_id, "title": title, "base_score": RULE_BASE.get(rule_id, 0)}
                for rule_id, title in RULE_TITLES.items()
            ]
        }
    )


@api.get("/interfaces")
def interfaces():
    names = [name for _, name in socket.if_nameindex()]
    can_capture = False
    if hasattr(socket, "AF_PACKET"):
        try:
            probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        except PermissionError:
            can_capture = False
        except OSError:
            can_capture = False
        else:
            probe.close()
            can_capture = True
    return ok({"interfaces": names, "can_capture": can_capture})


@api.get("/overview")
def overview():
    state = services()
    pipeline = state.pipeline
    incidents = IncidentRepository(state.db)
    packets = PacketRepository(state.db)
    traffic = TrafficRepository(state.db)

    return ok(
        {
            "status": pipeline.status(),
            "features": pipeline.snapshot(),
            "counters": incidents.stats(),
            "recent_alerts": incidents.recent(8),
            "traffic_series": traffic.series(limit=120),
            "protocol_counts": packets.protocol_counts(),
            "packet_count": packets.count(),
            "blocked_targets": state.responses.blocked_targets(),
            "thresholds": state.settings.to_public_dict(),
        }
    )


@api.get("/traffic")
def traffic_list():
    reader = ParamReader(request.args)
    page = reader.int("page", default=1, minimum=1, maximum=100000)
    per_page = reader.int("per_page", default=50, minimum=1, maximum=500)
    src = reader.text("src", max_length=64)
    dst = reader.text("dst", max_length=64)
    protocol = reader.choice("proto", ("TCP", "UDP", "ICMP", "OTHER"))
    search = reader.text("q")
    reader.finish()

    rows, total = PacketRepository(services().db).list(
        page=page,
        per_page=per_page,
        src=src,
        dst=dst,
        protocol=protocol,
        search=search,
    )
    blocked = set(services().responses.blocked_targets())
    for row in rows:
        row["blocked"] = row["src_ip"] in blocked or row["dst_ip"] in blocked
    return ok({"packets": rows}, meta=page_meta(page, per_page, total))


def _incident_list():
    reader = ParamReader(request.args)
    page = reader.int("page", default=1, minimum=1, maximum=100000)
    per_page = reader.int("per_page", default=50, minimum=1, maximum=500)
    filters = incident_filters(reader)
    reader.finish()

    rows, total = IncidentRepository(services().db).list(
        page=page, per_page=per_page, **filters
    )
    return ok({"incidents": rows}, meta=page_meta(page, per_page, total))


@api.get("/alerts")
def alerts():
    return _incident_list()


@api.get("/incidents")
def incidents():
    return _incident_list()


def _incident_detail(incident_id: str):
    state = services()
    repository = IncidentRepository(state.db)
    row = repository.get(incident_id)
    if row is None:
        raise NotFoundError("incident not found")
    return ok(
        {
            "incident": row,
            "events": repository.events(incident_id),
            "blocked": state.responses.is_blocked(row["src_ip"]),
        }
    )


@api.get("/alerts/<incident_id>")
def alert_detail(incident_id: str):
    return _incident_detail(incident_id)


@api.get("/incidents/<incident_id>")
def incident_detail(incident_id: str):
    return _incident_detail(incident_id)


def _change_status(incident_id: str, status: str, event_label: str):
    state = services()
    body = json_object() if request.data else {}
    note = optional_note(body)
    repository = IncidentRepository(state.db)
    row = repository.update_status(incident_id, status, note=note)
    if row is None:
        raise NotFoundError("incident not found")
    return ok(
        {
            "incident": row,
            "events": repository.events(incident_id),
            "message": event_label,
        }
    )


@api.post("/alerts/<incident_id>/ack")
def acknowledge(incident_id: str):
    return _change_status(incident_id, "acknowledged", "incident acknowledged")


@api.post("/alerts/<incident_id>/resolve")
def resolve(incident_id: str):
    return _change_status(incident_id, "resolved", "incident resolved")


@api.get("/export/incidents.csv")
def export_csv():
    reader = ParamReader(request.args)
    filters = incident_filters(reader)
    reader.finish()

    text = IncidentRepository(services().db).export_csv(**filters)
    filename = f"netshield-incidents-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.csv"
    return Response(
        text,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@api.get("/settings")
def get_settings():
    state = services()
    return ok(
        {
            "settings": state.settings.to_public_dict(),
            "capture": state.pipeline.status(),
            "applies_immediately": not state.pipeline.running,
            "persistence_note": (
                "Changes apply to this session. Edit config/thresholds.toml to persist them."
            ),
        }
    )


@api.put("/settings")
def update_settings():
    state = services()
    updated = apply_settings_patch(state.settings, json_object())

    applied = state.pipeline.configure(updated)
    state.responses.configure(updated)
    state.settings = updated

    return ok(
        {
            "settings": updated.to_public_dict(),
            "applied_immediately": applied,
            "message": (
                "Thresholds applied."
                if applied
                else "Saved. The new thresholds apply when the next capture starts."
            ),
        }
    )


def _resolve_capture_path(raw) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ValidationError(
            "a capture path is required",
            detail={"field": "path", "reason": "must be a file inside data/pcap or tests/fixtures"},
        )
    candidate = Path(raw.strip()).expanduser()
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    candidate = candidate.resolve()

    for root, _label in CAPTURE_ROOTS:
        root = root.resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        break
    else:
        raise ValidationError(
            "capture path is outside the allowed directories",
            detail={"field": "path", "reason": "allowed: data/pcap or tests/fixtures"},
        )

    if not candidate.is_file():
        raise ValidationError(
            "capture file not found",
            detail={"field": "path", "reason": "no such file"},
        )
    return str(candidate)


@api.get("/capture/files")
def capture_files():
    files = []
    for root, label in CAPTURE_ROOTS:
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*.pcap*")):
            if path.is_file() and has_capture_signature(path):
                files.append(
                    {
                        "name": path.name,
                        "path": str(path),
                        "size": path.stat().st_size,
                        "group": label,
                    }
                )
    return ok({"files": files})


@api.post("/capture/upload")
def upload_capture():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        raise ValidationError(
            "a file is required", detail={"field": "file", "reason": "no file uploaded"}
        )

    name = secure_filename(upload.filename)
    if not name or not name.lower().endswith(ALLOWED_UPLOAD_SUFFIXES):
        raise ValidationError(
            "unsupported file type",
            detail={"field": "file", "reason": "expected .pcap, .pcapng or .cap"},
        )

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    destination = UPLOAD_DIR / f"{stamp}-{uuid.uuid4().hex[:8]}-{name}"
    upload.save(destination)

    if not has_capture_signature(destination):
        destination.unlink(missing_ok=True)
        raise ValidationError(
            "file is not a readable pcap/pcapng capture",
            detail={"field": "file", "reason": "unrecognised file signature"},
        )

    return ok(
        {
            "file": {
                "name": name,
                "path": str(destination),
                "size": destination.stat().st_size,
                "group": "captures",
            }
        },
        status=201,
    )


@api.post("/capture/start")
def capture_start():
    state = services()
    body = json_object()
    mode = as_choice(body.get("mode"), ("pcap", "live", "demo"), field="mode")

    path = None
    iface = None
    if mode == "pcap":
        path = _resolve_capture_path(body.get("path"))
    elif mode == "live":
        raw_iface = body.get("iface")
        if not isinstance(raw_iface, str) or not raw_iface.strip():
            raise ValidationError(
                "an interface is required for live capture",
                detail={"field": "iface", "reason": "select a network interface"},
            )
        iface = raw_iface.strip()
        if body.get("confirm_authorization") is not True:
            raise ValidationError(
                "live capture requires confirmed authorization",
                detail={
                    "field": "confirm_authorization",
                    "reason": (
                        "set it to true only if you are authorised to observe traffic "
                        "on this interface"
                    ),
                },
            )

    try:
        status = state.pipeline.start(mode, path=path, iface=iface)
    except PipelineBusy as exc:
        raise ConflictError(str(exc)) from exc
    except PipelineError as exc:
        raise ValidationError(str(exc), code="capture_error") from exc

    return ok({"capture": status}, status=202)


@api.post("/capture/stop")
def capture_stop():
    return ok({"capture": services().pipeline.stop()})


@api.get("/capture/status")
def capture_status():
    state = services()
    return ok(
        {
            "capture": state.pipeline.status(),
            "features": state.pipeline.snapshot(),
        }
    )


@api.post("/response")
def response_action():
    state = services()
    body = json_object()

    action = as_choice(body.get("action"), ACTIONS, field="action")
    target = body.get("target_ip")
    if not isinstance(target, str) or not target.strip():
        raise ValidationError(
            "target_ip is required",
            detail={"field": "target_ip", "reason": "must be an IP address"},
        )

    incident_id = body.get("incident_id")
    if incident_id is not None and not isinstance(incident_id, str):
        raise ValidationError(
            "incident_id must be a string",
            detail={"field": "incident_id", "reason": "must be a string"},
        )

    token = body.get("confirm_token")
    reason = body.get("reason")
    request_model = ResponseRequest(
        target_ip=target,
        action=action,
        incident_id=incident_id,
        confirm_token=token if isinstance(token, str) else None,
        reason=reason if isinstance(reason, str) else None,
    )

    try:
        result = state.responses.apply(request_model)
    except ResponseError as exc:
        raise ApiError(str(exc), status=exc.status, code=exc.code) from exc

    return ok({"action": result}, status=201)


@api.get("/response")
def response_log():
    state = services()
    return ok(
        {
            "actions": ResponseRepository(state.db).list(),
            "blocked_targets": state.responses.blocked_targets(),
        }
    )

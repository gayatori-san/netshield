"""Repositories: every SQL statement in the application lives here.

Keeping SQL out of the API and the pipeline means the query surface is small
enough to audit, and it makes the storage layer swappable later (the doc's
"future work" item about PostgreSQL).
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from netshield.models import Alert, PacketRecord
from netshield.storage.db import Database

SEVERITIES = ("low", "medium", "high")
STATUSES = ("new", "acknowledged", "resolved")
ORIGINS = ("real", "demonstration")

MAX_PER_PAGE = 500


def _incident(row: sqlite3.Row) -> dict:
    data = dict(row)
    data["reasons"] = json.loads(data.pop("reasons_json") or "[]")
    data["evidence"] = json.loads(data.pop("evidence_json") or "{}")
    data["facts"] = json.loads(data.pop("facts_json") or "{}")
    data["evidence_sufficient"] = bool(data["evidence_sufficient"])
    return data


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def _iso(ts: float | None) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


def _clamp_page(page: int, per_page: int) -> tuple[int, int]:
    page = max(1, int(page))
    per_page = max(1, min(MAX_PER_PAGE, int(per_page)))
    return page, per_page


class IncidentRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def insert(self, alert: Alert) -> bool:
        """Insert an incident. False means the fingerprint already exists."""
        row = alert.to_db_row()
        columns = list(row)
        placeholders = ", ".join("?" for _ in columns)
        sql = f"INSERT INTO incidents ({', '.join(columns)}) VALUES ({placeholders})"
        try:
            with self.db.transaction() as conn:
                conn.execute(sql, [row[c] for c in columns])
                conn.execute(
                    "INSERT INTO incident_events (incident_id, event_type, detail, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (alert.id, "detected", f"{alert.rule_id} fired", alert.detected_at),
                )
        except sqlite3.IntegrityError:
            return False
        return True

    def get(self, incident_id: str) -> dict | None:
        row = self.db.connect().execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return _incident(row) if row else None

    def exists(self, fingerprint: str) -> bool:
        row = self.db.connect().execute(
            "SELECT 1 FROM incidents WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return row is not None

    def _filters(
        self,
        *,
        severities: Sequence[str] | None = None,
        status: str | None = None,
        rule_id: str | None = None,
        origin: str | None = None,
        search: str | None = None,
        date_from: float | None = None,
        date_to: float | None = None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []

        if severities:
            valid = [s for s in severities if s in SEVERITIES]
            if valid:
                clauses.append(f"severity IN ({', '.join('?' for _ in valid)})")
                params.extend(valid)
        if status:
            if status not in STATUSES:
                raise ValueError(f"unknown status: {status}")
            clauses.append("status = ?")
            params.append(status)
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if origin:
            if origin not in ORIGINS:
                raise ValueError(f"unknown origin: {origin}")
            clauses.append("data_origin = ?")
            params.append(origin)
        if search:
            like = f"%{search.strip()}%"
            clauses.append(
                "(title LIKE ? OR COALESCE(src_ip, '') LIKE ? OR "
                "COALESCE(dst_ip, '') LIKE ? OR COALESCE(analyst_notes, '') LIKE ?)"
            )
            params.extend([like] * 4)
        if date_from is not None:
            clauses.append("detected_at >= ?")
            params.append(float(date_from))
        if date_to is not None:
            clauses.append("detected_at <= ?")
            params.append(float(date_to))

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        return where, params

    def list(self, *, page: int = 1, per_page: int = 50, **filters: Any) -> tuple[list[dict], int]:
        page, per_page = _clamp_page(page, per_page)
        where, params = self._filters(**filters)
        conn = self.db.connect()
        total = conn.execute(f"SELECT COUNT(*) FROM incidents{where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM incidents{where} ORDER BY detected_at DESC, id LIMIT ? OFFSET ?",
            [*params, per_page, (page - 1) * per_page],
        ).fetchall()
        return [_incident(r) for r in rows], int(total)

    def update_status(
        self, incident_id: str, status: str, *, note: str | None = None, now: float | None = None
    ) -> dict | None:
        if status not in STATUSES:
            raise ValueError(f"unknown status: {status}")
        now = time.time() if now is None else now
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT id FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if row is None:
                return None
            if note is None:
                conn.execute(
                    "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
                    (status, now, incident_id),
                )
            else:
                conn.execute(
                    "UPDATE incidents SET status = ?, analyst_notes = ?, updated_at = ? WHERE id = ?",
                    (status, note, now, incident_id),
                )
            conn.execute(
                "INSERT INTO incident_events (incident_id, event_type, detail, created_at) "
                "VALUES (?, ?, ?, ?)",
                (incident_id, status, note, now),
            )
        return self.get(incident_id)

    def add_note(self, incident_id: str, note: str, *, now: float | None = None) -> dict | None:
        now = time.time() if now is None else now
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT id FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE incidents SET analyst_notes = ?, updated_at = ? WHERE id = ?",
                (note, now, incident_id),
            )
            conn.execute(
                "INSERT INTO incident_events (incident_id, event_type, detail, created_at) "
                "VALUES (?, 'note', ?, ?)",
                (incident_id, note, now),
            )
        return self.get(incident_id)

    def events(self, incident_id: str) -> list[dict]:
        rows = self.db.connect().execute(
            "SELECT id, event_type, detail, created_at FROM incident_events "
            "WHERE incident_id = ? ORDER BY created_at ASC, id ASC",
            (incident_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        conn = self.db.connect()
        by_severity = {s: 0 for s in SEVERITIES}
        open_by_severity = {s: 0 for s in SEVERITIES}
        for row in conn.execute(
            "SELECT severity, status, COUNT(*) AS n FROM incidents GROUP BY severity, status"
        ):
            by_severity[row["severity"]] += row["n"]
            if row["status"] != "resolved":
                open_by_severity[row["severity"]] += row["n"]

        by_status = {s: 0 for s in STATUSES}
        for row in conn.execute("SELECT status, COUNT(*) AS n FROM incidents GROUP BY status"):
            by_status[row["status"]] = row["n"]

        by_rule = [
            {"rule_id": r["rule_id"], "title": r["title"], "count": r["n"]}
            for r in conn.execute(
                "SELECT rule_id, MAX(title) AS title, COUNT(*) AS n FROM incidents "
                "GROUP BY rule_id ORDER BY n DESC"
            )
        ]
        total = sum(by_severity.values())
        return {
            "total": total,
            "open": sum(open_by_severity.values()),
            "by_severity": by_severity,
            "open_by_severity": open_by_severity,
            "by_status": by_status,
            "by_rule": by_rule,
        }

    def recent(self, limit: int = 10) -> list[dict]:
        rows = self.db.connect().execute(
            "SELECT * FROM incidents ORDER BY detected_at DESC, id LIMIT ?",
            (max(1, min(100, limit)),),
        ).fetchall()
        return [_incident(r) for r in rows]

    def export_csv(self, limit: int = 10000, **filters: Any) -> str:
        where, params = self._filters(**filters)
        rows = self.db.connect().execute(
            f"SELECT * FROM incidents{where} ORDER BY detected_at DESC, id LIMIT ?",
            [*params, max(1, int(limit))],
        ).fetchall()
        columns = [
            "id",
            "detected_at",
            "rule_id",
            "title",
            "severity",
            "score",
            "status",
            "src_ip",
            "dst_ip",
            "evidence_sufficient",
            "data_origin",
            "reasons",
            "analyst_notes",
        ]
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(columns)
        for row in rows:
            incident = _incident(row)
            writer.writerow(
                [
                    _csv_cell(incident["id"]),
                    _iso(incident["detected_at"]),
                    _csv_cell(incident["rule_id"]),
                    _csv_cell(incident["title"]),
                    _csv_cell(incident["severity"]),
                    incident["score"],
                    _csv_cell(incident["status"]),
                    _csv_cell(incident["src_ip"]),
                    _csv_cell(incident["dst_ip"]),
                    "yes" if incident["evidence_sufficient"] else "no",
                    _csv_cell(incident["data_origin"]),
                    _csv_cell(" | ".join(incident["reasons"])),
                    _csv_cell(incident["analyst_notes"]),
                ]
            )
        return buffer.getvalue()


class PacketRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add_many(self, records: Iterable[PacketRecord], origin: str, *, now: float | None = None) -> int:
        if origin not in ORIGINS:
            raise ValueError(f"unknown origin: {origin}")
        ingested_at = time.time() if now is None else now
        rows = [
            (
                r.timestamp,
                r.src_ip,
                r.dst_ip,
                r.src_port,
                r.dst_port,
                r.protocol,
                r.flags,
                r.tcp_state,
                r.size,
                origin,
                ingested_at,
            )
            for r in records
        ]
        if not rows:
            return 0
        with self.db.transaction() as conn:
            conn.executemany(
                "INSERT INTO packets (ts, src_ip, dst_ip, src_port, dst_port, protocol, "
                "flags, tcp_state, size, origin, ingested_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def list(
        self,
        *,
        page: int = 1,
        per_page: int = 100,
        src: str | None = None,
        dst: str | None = None,
        protocol: str | None = None,
        search: str | None = None,
    ) -> tuple[list[dict], int]:
        page, per_page = _clamp_page(page, per_page)
        clauses: list[str] = []
        params: list[Any] = []
        if src:
            clauses.append("src_ip = ?")
            params.append(src)
        if dst:
            clauses.append("dst_ip = ?")
            params.append(dst)
        if protocol:
            clauses.append("protocol = ?")
            params.append(protocol.upper())
        if search:
            like = f"%{search.strip()}%"
            clauses.append(
                "(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ? OR COALESCE(flags, '') LIKE ?)"
            )
            params.extend([like] * 4)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        conn = self.db.connect()
        total = conn.execute(f"SELECT COUNT(*) FROM packets{where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM packets{where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
            [*params, per_page, (page - 1) * per_page],
        ).fetchall()
        return [dict(r) for r in rows], int(total)

    def count(self) -> int:
        return int(self.db.connect().execute("SELECT COUNT(*) FROM packets").fetchone()[0])

    def protocol_counts(self) -> dict[str, int]:
        rows = self.db.connect().execute(
            "SELECT protocol, COUNT(*) AS n FROM packets GROUP BY protocol ORDER BY n DESC"
        )
        return {r["protocol"]: r["n"] for r in rows}

    def prune(self, days: int, *, now: float | None = None) -> int:
        """Delete packets *we collected* more than ``days`` ago.

        Retention is measured from ingestion, not from the packet's own
        timestamp: replaying an old capture must not delete itself.
        """
        if days <= 0:
            return 0
        now = time.time() if now is None else now
        cutoff = now - days * 86400
        with self.db.transaction() as conn:
            cursor = conn.execute("DELETE FROM packets WHERE ingested_at < ?", (cutoff,))
        return cursor.rowcount


class TrafficRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(self, buckets: Iterable[tuple[int, int, int]]) -> int:
        rows = [(int(b[0]), int(b[1]), int(b[2])) for b in buckets]
        if not rows:
            return 0
        with self.db.transaction() as conn:
            conn.executemany(
                "INSERT INTO traffic_buckets (bucket_ts, packets, bytes) VALUES (?, ?, ?) "
                "ON CONFLICT(bucket_ts) DO UPDATE SET packets = excluded.packets, "
                "bytes = excluded.bytes",
                rows,
            )
        return len(rows)

    def series(self, limit: int = 120) -> list[dict]:
        rows = self.db.connect().execute(
            "SELECT bucket_ts, packets, bytes FROM traffic_buckets "
            "ORDER BY bucket_ts DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def prune_before(self, cutoff: float) -> int:
        with self.db.transaction() as conn:
            cursor = conn.execute("DELETE FROM traffic_buckets WHERE bucket_ts < ?", (cutoff,))
        return cursor.rowcount


class ResponseRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add(
        self,
        *,
        target_ip: str,
        action: str,
        applied: bool,
        mode: str,
        incident_id: str | None = None,
        reason: str | None = None,
        now: float | None = None,
    ) -> dict:
        row = {
            "id": uuid.uuid4().hex,
            "incident_id": incident_id,
            "target_ip": target_ip,
            "action": action,
            "applied": 1 if applied else 0,
            "mode": mode,
            "reason": reason,
            "created_at": time.time() if now is None else now,
        }
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO response_actions (id, incident_id, target_ip, action, applied, "
                "mode, reason, created_at) VALUES (:id, :incident_id, :target_ip, :action, "
                ":applied, :mode, :reason, :created_at)",
                row,
            )
        return row

    def list(self, limit: int = 50) -> list[dict]:
        rows = self.db.connect().execute(
            "SELECT * FROM response_actions ORDER BY created_at DESC LIMIT ?",
            (max(1, min(200, limit)),),
        ).fetchall()
        return [{**dict(r), "applied": bool(r["applied"])} for r in rows]


class SettingsRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get(self, key: str, default: str | None = None) -> str | None:
        row = self.db.connect().execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set(self, key: str, value: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def all(self) -> dict[str, str]:
        rows = self.db.connect().execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

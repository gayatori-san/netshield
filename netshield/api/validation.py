"""Request parsing and validation.

Validation failures name the offending field so the dashboard can highlight
it. Nothing here trusts the client: every numeric range, choice and CIDR is
checked again on the server.
"""

from __future__ import annotations

import ipaddress
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from flask import request

from netshield.api.errors import ValidationError
from netshield.config.settings import Settings
from netshield.models import SEVERITIES, STATUSES

_INT = "int"
_FLOAT = "float"
_BOOL = "bool"
_PORTS = "ports"
_CIDRS = "cidrs"

SETTINGS_RULES: dict[str, dict[str, tuple[str, float | None, float | None]]] = {
    "port_scan": {
        "window_seconds": (_INT, 1, 3600),
        "distinct_port_threshold": (_INT, 2, 65535),
        "distinct_host_threshold": (_INT, 2, 65535),
        "min_packets_per_target": (_INT, 1, 100000),
    },
    "suspicious": {
        "window_seconds": (_INT, 1, 3600),
        "repeat_attempt_threshold": (_INT, 2, 100000),
        "conn_rate_threshold": (_INT, 1, 1000000),
        "conn_rate_multiplier": (_FLOAT, 1.0, 100.0),
        "conn_baseline_alpha": (_FLOAT, 0.01, 1.0),
        "conn_baseline_min_samples": (_INT, 1, 10000),
        "sensitive_ports": (_PORTS, None, None),
    },
    "spike": {
        "window_seconds": (_INT, 1, 3600),
        "baseline_window_seconds": (_INT, 1, 86400),
        "spike_absolute_pps": (_INT, 1, 10000000),
        "spike_baseline_ratio": (_FLOAT, 1.0, 1000.0),
        "spike_min_pps": (_INT, 1, 10000000),
        "baseline_alpha": (_FLOAT, 0.01, 1.0),
        "baseline_min_samples": (_INT, 1, 10000),
    },
    "dedup": {"suppression_seconds": (_INT, 1, 86400)},
    "scoring": {
        "low_max": (_INT, 0, 99),
        "medium_max": (_INT, 1, 100),
    },
    "retention": {
        "packet_days": (_INT, 1, 3650),
        "prune_interval_seconds": (_INT, 1, 86400),
    },
    "safe_response": {
        "enabled": (_BOOL, None, None),
        "allow_firewall_changes": (_BOOL, None, None),
        "allowed_cidrs": (_CIDRS, None, None),
    },
}

MAX_NOTE_LENGTH = 2000
MAX_SEARCH_LENGTH = 200


class ParamReader:
    """Collects every query-string problem, then raises once."""

    def __init__(self, args) -> None:
        self.args = args
        self.errors: list[dict] = []

    def _raw(self, name: str) -> str | None:
        value = self.args.get(name)
        if value is None:
            return None
        value = value.strip()
        return value or None

    def int(
        self,
        name: str,
        *,
        default: int | None = None,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int | None:
        raw = self._raw(name)
        if raw is None:
            return default
        try:
            value = int(raw)
        except (TypeError, ValueError):
            self.errors.append({"field": name, "reason": "must be an integer"})
            return default
        return self._range(name, value, minimum, maximum)

    def float(
        self,
        name: str,
        *,
        default: float | None = None,
        minimum: float | None = None,
        maximum: float | None = None,
    ) -> float | None:
        raw = self._raw(name)
        if raw is None:
            return default
        try:
            value = float(raw)
        except (TypeError, ValueError):
            self.errors.append({"field": name, "reason": "must be a number"})
            return default
        return self._range(name, value, minimum, maximum)

    def _range(self, name, value, minimum, maximum):
        if minimum is not None and value < minimum:
            self.errors.append({"field": name, "reason": f"must be >= {minimum}"})
        elif maximum is not None and value > maximum:
            self.errors.append({"field": name, "reason": f"must be <= {maximum}"})
        return value

    def choice(self, name: str, choices: Sequence[str], *, default: str | None = None):
        raw = self._raw(name)
        if raw is None:
            return default
        if raw not in choices:
            self.errors.append(
                {"field": name, "reason": f"must be one of: {', '.join(choices)}"}
            )
            return default
        return raw

    def text(self, name: str, *, default: str | None = None, max_length: int = MAX_SEARCH_LENGTH):
        raw = self._raw(name)
        if raw is None:
            return default
        if len(raw) > max_length:
            self.errors.append(
                {"field": name, "reason": f"must be {max_length} characters or fewer"}
            )
            return default
        return raw

    def severities(self, name: str = "severity") -> list[str] | None:
        raw = self._raw(name)
        if raw is None:
            return None
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        invalid = [part for part in parts if part not in SEVERITIES]
        if invalid:
            self.errors.append(
                {
                    "field": name,
                    "reason": f"unknown severity: {', '.join(invalid)} "
                    f"(allowed: {', '.join(SEVERITIES)})",
                }
            )
            return None
        return parts or None

    def timestamp(self, name: str) -> float | None:
        raw = self._raw(name)
        if raw is None:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            self.errors.append(
                {"field": name, "reason": "must be an ISO-8601 date or datetime"}
            )
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()

    def finish(self) -> None:
        if self.errors:
            raise ValidationError(
                "invalid query parameters", detail={"fields": self.errors}
            )


def json_object() -> dict:
    body = request.get_json(silent=True)
    if body is None:
        raise ValidationError("request body must be valid JSON")
    if not isinstance(body, dict):
        raise ValidationError("request body must be a JSON object")
    return body


def optional_note(body: dict, *, field: str = "note") -> str | None:
    if field not in body or body[field] is None:
        return None
    value = body[field]
    if not isinstance(value, str):
        raise ValidationError(
            "note must be a string", detail={"field": field, "reason": "must be a string"}
        )
    value = value.strip()
    if len(value) > MAX_NOTE_LENGTH:
        raise ValidationError(
            f"note must be {MAX_NOTE_LENGTH} characters or fewer",
            detail={"field": field, "reason": "too long"},
        )
    return value or None


def incident_filters(reader: ParamReader) -> dict:
    filters = {
        "severities": reader.severities(),
        "status": reader.choice("status", STATUSES),
        "rule_id": reader.text("rule"),
        "origin": reader.choice("origin", ("real", "demonstration")),
        "search": reader.text("q"),
        "date_from": reader.timestamp("from"),
        "date_to": reader.timestamp("to"),
    }
    return {key: value for key, value in filters.items() if value is not None}


def _validate_ports(value: Any, field: str, errors: list[dict]) -> tuple[int, ...] | None:
    if not isinstance(value, list):
        errors.append({"field": field, "reason": "must be a list of port numbers"})
        return None
    ports: list[int] = []
    for port in value:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            errors.append(
                {"field": field, "reason": "every entry must be an integer from 1 to 65535"}
            )
            return None
        ports.append(port)
    return tuple(sorted(set(ports)))


def _validate_cidrs(value: Any, field: str, errors: list[dict]) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not value:
        errors.append(
            {"field": field, "reason": "must be a non-empty list of CIDR strings"}
        )
        return None
    cidrs: list[str] = []
    for cidr in value:
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            errors.append({"field": field, "reason": f"invalid CIDR: {cidr!r}"})
            return None
        if network.prefixlen == 0:
            errors.append(
                {"field": field, "reason": "0.0.0.0/0 and ::/0 are not allowed"}
            )
            return None
        cidrs.append(str(cidr))
    return tuple(cidrs)


def apply_settings_patch(settings: Settings, payload: dict) -> Settings:
    if not isinstance(payload, dict):
        raise ValidationError("settings payload must be a JSON object")

    errors: list[dict] = []
    unknown_sections = sorted(set(payload) - set(SETTINGS_RULES))
    for section in unknown_sections:
        errors.append({"field": section, "reason": "unknown settings section"})

    changes: dict[str, Any] = {}
    for section, rules in SETTINGS_RULES.items():
        if section not in payload:
            continue
        values = payload[section]
        if not isinstance(values, dict):
            errors.append({"field": section, "reason": "must be an object"})
            continue

        current = getattr(settings, section)
        updates: dict[str, Any] = {}
        for field, value in values.items():
            rule = rules.get(field)
            if rule is None:
                errors.append({"field": f"{section}.{field}", "reason": "unknown setting"})
                continue

            kind, minimum, maximum = rule
            if kind == _BOOL:
                if not isinstance(value, bool):
                    errors.append({"field": f"{section}.{field}", "reason": "must be true or false"})
                    continue
                updates[field] = value
            elif kind == _INT:
                if not isinstance(value, int) or isinstance(value, bool):
                    errors.append({"field": f"{section}.{field}", "reason": "must be an integer"})
                    continue
                if minimum is not None and value < minimum:
                    errors.append({"field": f"{section}.{field}", "reason": f"must be >= {minimum:g}"})
                    continue
                if maximum is not None and value > maximum:
                    errors.append({"field": f"{section}.{field}", "reason": f"must be <= {maximum:g}"})
                    continue
                updates[field] = value
            elif kind == _FLOAT:
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    errors.append({"field": f"{section}.{field}", "reason": "must be a number"})
                    continue
                if minimum is not None and value < minimum:
                    errors.append({"field": f"{section}.{field}", "reason": f"must be >= {minimum:g}"})
                    continue
                if maximum is not None and value > maximum:
                    errors.append({"field": f"{section}.{field}", "reason": f"must be <= {maximum:g}"})
                    continue
                updates[field] = float(value)
            elif kind == _PORTS:
                ports = _validate_ports(value, f"{section}.{field}", errors)
                if ports is not None:
                    updates[field] = ports
            elif kind == _CIDRS:
                cidrs = _validate_cidrs(value, f"{section}.{field}", errors)
                if cidrs is not None:
                    updates[field] = cidrs

        if updates:
            changes[section] = replace(current, **updates)

    if errors:
        raise ValidationError("invalid settings", detail={"fields": errors})

    updated = replace(settings, **changes)
    if updated.scoring.low_max >= updated.scoring.medium_max:
        raise ValidationError(
            "invalid scoring bands",
            detail={
                "fields": [
                    {
                        "field": "scoring.low_max",
                        "reason": "must be less than scoring.medium_max",
                    }
                ]
            },
        )
    return updated


def as_bool(value: Any, *, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(
            "expected a boolean", detail={"field": field, "reason": "must be true or false"}
        )
    return value


def as_choice(value: Any, choices: Iterable[str], *, field: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ValidationError(
            "invalid value",
            detail={"field": field, "reason": f"must be one of: {', '.join(choices)}"},
        )
    return value

"""Safe response actions.

Two modes, deliberately separated:

* ``simulate_*`` — records the intent and marks the address as blocked **in
  the dashboard only**. Nothing on the host changes.
* ``firewall_*`` — inserts or removes one iptables INPUT rule. This path is
  gated four ways: the feature must be enabled, real changes must be allowed,
  the process must be root, and the target must be inside the configured lab
  CIDRs. A confirm token must also match the exact intended command.

Blocking by IP is weak containment (NAT, spoofing, IPv6 privacy addresses),
so this is an analyst-disciplined lab exercise, not a security control.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Callable

from netshield.config.settings import Settings
from netshield.storage.repositories import ResponseRepository

SIMULATE_BLOCK = "simulate_block"
SIMULATE_UNBLOCK = "simulate_unblock"
FIREWALL_BLOCK = "firewall_block"
FIREWALL_UNBLOCK = "firewall_unblock"

ACTIONS = (SIMULATE_BLOCK, SIMULATE_UNBLOCK, FIREWALL_BLOCK, FIREWALL_UNBLOCK)
MAX_SIMULATED_BLOCKS = 500

_IP_RE = re.compile(r"^[0-9a-fA-F:.]+$")


class ResponseError(RuntimeError):
    def __init__(self, message: str, *, status: int = 403, code: str = "response_refused"):
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass(frozen=True)
class ResponseRequest:
    target_ip: str
    action: str
    incident_id: str | None = None
    confirm_token: str | None = None
    reason: str | None = None


def _normalise_ip(raw: str) -> str:
    if not isinstance(raw, str) or not _IP_RE.match(raw.strip()):
        raise ResponseError("target_ip must be an IP address", status=400, code="invalid_parameter")
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError as exc:
        raise ResponseError(
            "target_ip must be a valid IPv4 or IPv6 address",
            status=400,
            code="invalid_parameter",
        ) from exc


class ResponseService:
    def __init__(
        self,
        settings: Settings,
        repository: ResponseRepository,
        *,
        euid: Callable[[], int] = os.geteuid,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
    ):
        self.settings = settings
        self.repository = repository
        self._euid = euid
        self._runner = runner
        self._which = which
        self._simulated: dict[str, float] = {}

    def configure(self, settings: Settings) -> None:
        self.settings = settings

    def blocked_targets(self) -> list[str]:
        return sorted(self._simulated)

    def is_blocked(self, ip: str | None) -> bool:
        return bool(ip) and ip in self._simulated

    def apply(self, request: ResponseRequest) -> dict:
        config = self.settings.safe_response
        if not config.enabled:
            raise ResponseError(
                "safe response is disabled. Set safe_response.enabled = true to use it.",
                code="response_disabled",
            )
        if request.action not in ACTIONS:
            raise ResponseError(
                f"unknown action: {request.action!r}", status=400, code="invalid_parameter"
            )

        target = _normalise_ip(request.target_ip)
        if not config.is_lab_target(target):
            raise ResponseError(
                f"refusing to act on {target}: it is outside the lab allow-list",
                code="target_not_allowed",
            )

        if request.action.startswith("simulate"):
            return self._simulate(request, target)
        return self._firewall(request, target)

    # ------------------------------------------------------------- simulated
    def _simulate(self, request: ResponseRequest, target: str) -> dict:
        blocking = request.action == SIMULATE_BLOCK
        if blocking:
            if len(self._simulated) >= MAX_SIMULATED_BLOCKS and target not in self._simulated:
                raise ResponseError(
                    "simulated block list is full", status=409, code="response_limit"
                )
            self._simulated[target] = self._now()
        else:
            self._simulated.pop(target, None)

        row = self.repository.add(
            target_ip=target,
            action=request.action,
            applied=True,
            mode="simulated",
            incident_id=request.incident_id,
            reason=request.reason,
            now=self._now(),
        )
        return {
            **row,
            "applied": True,
            "blocked": self.is_blocked(target),
            "message": (
                f"{target} is now hidden in the dashboard (simulation only — no firewall change)"
                if blocking
                else f"{target} is no longer hidden in the dashboard"
            ),
        }

    # -------------------------------------------------------------- firewall
    def _firewall(self, request: ResponseRequest, target: str) -> dict:
        config = self.settings.safe_response
        if not config.allow_firewall_changes:
            raise ResponseError(
                "real firewall changes are disabled "
                "(safe_response.allow_firewall_changes = false)",
                code="firewall_disabled",
            )
        if self._euid() != 0:
            raise ResponseError(
                "real firewall changes require root. Re-run with sudo or use simulated mode.",
                code="firewall_requires_root",
            )
        binary = self._which("iptables")
        if not binary:
            raise ResponseError(
                "iptables is not installed on this host", status=502, code="firewall_unavailable"
            )

        blocking = request.action == FIREWALL_BLOCK
        verb = "BLOCK" if blocking else "UNBLOCK"
        expected = f"{verb} {target}"
        if (request.confirm_token or "").strip() != expected:
            raise ResponseError(
                f"confirmation token mismatch. Send confirm_token = {expected!r} to proceed.",
                status=400,
                code="confirm_required",
            )

        argv = [
            binary,
            "-I" if blocking else "-D",
            "INPUT",
            "-s",
            target,
            "-j",
            "DROP",
        ]
        try:
            completed = self._runner(
                argv, capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ResponseError(
                f"could not run iptables: {exc}", status=502, code="firewall_failed"
            ) from exc

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()[:300]
            raise ResponseError(
                f"iptables failed (exit {completed.returncode}): {detail}",
                status=502,
                code="firewall_failed",
            )

        row = self.repository.add(
            target_ip=target,
            action=request.action,
            applied=True,
            mode="firewall",
            incident_id=request.incident_id,
            reason=request.reason,
            now=self._now(),
        )
        return {
            **row,
            "applied": True,
            "blocked": self.is_blocked(target),
            "message": (
                f"iptables INPUT DROP rule inserted for {target}"
                if blocking
                else f"iptables INPUT DROP rule removed for {target}"
            ),
        }

    def _now(self) -> float:
        return time.time()

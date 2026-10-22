"""Redirect-target validation shared by the login page and auth guard."""

from __future__ import annotations

MAX_NEXT_LENGTH = 2048


def safe_next_path(value: str | None, default: str = "/") -> str:
    """Only allow same-site absolute paths; never protocol-relative URLs."""

    if not isinstance(value, str):
        return default
    candidate = value.strip()
    if (
        not candidate
        or len(candidate) > MAX_NEXT_LENGTH
        or not candidate.startswith("/")
        or candidate.startswith("//")
        or "\\" in candidate
        or any(ord(char) < 0x20 for char in candidate)
    ):
        return default
    if (
        candidate == "/login"
        or candidate == "/login/"
        or candidate.startswith("/login?")
        or candidate.startswith("/login/")
    ):
        return default
    return candidate

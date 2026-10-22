"""SQLite connection management.

One connection per thread (WAL mode so the Flask request threads and the
capture worker do not block each other). ``isolation_level=None`` puts the
connection in autocommit mode and transactions are opened explicitly, which
keeps the write paths easy to reason about.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA_PATH = Path(__file__).with_name("schema.sql")

_schema_cache: str | None = None


def schema_sql() -> str:
    global _schema_cache
    if _schema_cache is None:
        _schema_cache = SCHEMA_PATH.read_text(encoding="utf-8")
    return _schema_cache


class Database:
    """Thread-aware SQLite handle.

    File-backed databases get one connection per thread. ``:memory:`` is
    supported for single-threaded tests by sharing one connection.
    """

    def __init__(self, path: str | Path, *, timeout: float = 10.0) -> None:
        self.path = str(path)
        self.timeout = timeout
        self._is_memory = self.path == ":memory:"
        self._local = threading.local()
        self._shared: sqlite3.Connection | None = None

    @property
    def is_memory(self) -> bool:
        return self._is_memory

    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.path,
            timeout=self.timeout,
            isolation_level=None,
            check_same_thread=not self._is_memory,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(f"PRAGMA busy_timeout = {int(self.timeout * 1000)}")
        if not self._is_memory:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def connect(self) -> sqlite3.Connection:
        if self._is_memory:
            if self._shared is None:
                self._shared = self._new_connection()
            return self._shared
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._new_connection()
            self._local.conn = conn
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")

    def init_schema(self) -> None:
        if not self._is_memory:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connect().executescript(schema_sql())

    def close_thread(self) -> None:
        """Close the connection owned by the calling thread, if any."""
        conn = self._local.__dict__.pop("conn", None)
        if conn is not None:
            conn.close()

    def close(self) -> None:
        self.close_thread()
        if self._shared is not None:
            self._shared.close()
            self._shared = None

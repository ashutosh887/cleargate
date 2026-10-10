from __future__ import annotations

import re
import sqlite3
import threading
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

SEED = Path(__file__).resolve().parents[2] / "fixtures" / "seed.sql"


class PostgresLive:
    def __init__(self, dsn: str):
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True, connect_timeout=3)
        self._lock = threading.Lock()

    def query(self, sql: str, args: tuple[Any, ...] = (), max_rows: int = 1000) -> list[dict[str, Any]] | int:
        """Rows as JSON-able dicts for a SELECT, else the affected row count. Placeholders are %s."""
        with self._lock, self._conn.cursor() as cur:
            cur.execute(sql, args or None)
            if cur.description is None:
                return cur.rowcount
            columns = [c.name for c in cur.description]
            return [{k: _jsonable(v) for k, v in zip(columns, row)} for row in cur.fetchmany(max_rows)]


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


class PostgresStub:
    def __init__(self, workdir: Path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        for schema in ("payments", "customers"):
            workdir.mkdir(parents=True, exist_ok=True)
            path = workdir / f"{schema}.sqlite"
            path.unlink(missing_ok=True)
            self._conn.execute(f"ATTACH DATABASE '{path}' AS {schema}")
        seed = re.sub(r"(?im)^create schema.*$", "", SEED.read_text())
        self._conn.executescript(seed)

    def query(self, sql: str, args: tuple[Any, ...] = (), max_rows: int = 1000) -> list[dict[str, Any]] | int:
        """Same contract as PostgresLive.query; %s placeholders are rewritten for SQLite."""
        with self._lock:
            cur = self._conn.execute(sql.replace("%s", "?"), args)
            if cur.description is None:
                self._conn.commit()
                return cur.rowcount
            return [dict(r) for r in cur.fetchmany(max_rows)]

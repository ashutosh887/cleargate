from __future__ import annotations

import re
import sqlite3
import threading
from pathlib import Path
from typing import Any

from cleargate.tools.base import ToolResult, ToolSpec, params

SEED = Path(__file__).resolve().parents[2] / "fixtures" / "seed.sql"

SPECS = [
    ToolSpec("postgres.pg_query", "Run a SQL query against the payments database and return rows.",
             params(["sql"], sql="str", max_rows="int:upper bound on rows returned")),
    ToolSpec("postgres.pg_list_schemas", "List schemas and tables in the database.", params()),
]


class PostgresLive:
    def __init__(self, dsn: str):
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)

    def list_tools(self) -> list[ToolSpec]:
        return list(SPECS)

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        try:
            with self._conn.cursor() as cur:
                if name == "postgres.pg_list_schemas":
                    cur.execute("select table_schema, table_name from information_schema.tables "
                                "where table_schema not in ('pg_catalog','information_schema')")
                    return ToolResult(True, [f"{s}.{t}" for s, t in cur.fetchall()])
                cur.execute(args["sql"])
                if cur.description is None:
                    return ToolResult(True, f"{cur.rowcount} rows affected")
                columns = [c.name for c in cur.description]
                rows = cur.fetchmany(int(args.get("max_rows") or 1000))
                return ToolResult(True, [dict(zip(columns, row)) for row in rows])
        except Exception as exc:
            return ToolResult(False, None, f"{type(exc).__name__}: {exc}")


class PostgresStub:
    def __init__(self, workdir: Path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        for schema in ("payments", "customers"):
            path = workdir / f"{schema}.sqlite"
            path.unlink(missing_ok=True)
            self._conn.execute(f"ATTACH DATABASE '{path}' AS {schema}")
        seed = re.sub(r"(?im)^create schema.*$", "", SEED.read_text())
        self._conn.executescript(seed)

    def list_tools(self) -> list[ToolSpec]:
        return list(SPECS)

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        with self._lock:
            try:
                if name == "postgres.pg_list_schemas":
                    out = []
                    for schema in ("payments", "customers"):
                        rows = self._conn.execute(f"select name from {schema}.sqlite_master where type='table'")
                        out += [f"{schema}.{r['name']}" for r in rows]
                    return ToolResult(True, out)
                cur = self._conn.execute(args["sql"])
                if cur.description is None:
                    self._conn.commit()
                    return ToolResult(True, f"{cur.rowcount} rows affected")
                rows = cur.fetchmany(int(args.get("max_rows") or 1000))
                return ToolResult(True, [dict(r) for r in rows])
            except (sqlite3.Error, KeyError) as exc:
                return ToolResult(False, None, f"{type(exc).__name__}: {exc}")

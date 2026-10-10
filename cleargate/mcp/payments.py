"""`payments` MCP server: refunds/orders/customers over live Postgres, SQLite stub fallback."""
from __future__ import annotations

import sys
import uuid
from typing import Annotated, Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from cleargate.config import Settings
from cleargate.mcp.seed import DEFAULT_DSN
from cleargate.tools.postgres import PostgresLive, PostgresStub

READ = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}


def open_backend(settings: Settings | None = None) -> tuple[PostgresLive | PostgresStub, str]:
    settings = settings or Settings()
    dsn = settings.database_url or DEFAULT_DSN
    try:
        db = PostgresLive(dsn)
        db.query("SELECT 1 FROM payments.orders LIMIT 1")
        return db, f"postgres {dsn.rsplit('@', 1)[-1]}"
    except Exception as exc:
        print(f"[payments] Postgres unreachable ({type(exc).__name__}); using SQLite stub", file=sys.stderr)
        return PostgresStub(settings.state_dir / "mcp" / "pg"), "sqlite stub (fixtures/seed.sql)"


def build(db: PostgresLive | PostgresStub | None = None) -> FastMCP:
    if db is None:
        db, _ = open_backend()
    mcp = FastMCP("payments", instructions="Payments ledger for the on-call incident team: orders, refunds, customers.")

    def run(sql: str, args: tuple[Any, ...] = (), max_rows: int = 1000) -> Any:
        try:
            return db.query(sql, args, max_rows)
        except Exception as exc:
            raise ToolError(f"{type(exc).__name__}: {exc}") from exc

    @mcp.tool(
        description="Read refund records for one order from payments.refunds, newest first. Use this to size "
                    "duplicate or short refunds during an incident. Read-only.",
        annotations={"title": "Query refunds", **READ},
    )
    def query_refunds(
        order_id: Annotated[str, Field(description="Order id, e.g. ORD-1042")],
        limit: Annotated[int, Field(description="Maximum rows to return (1-100)")] = 20,
    ) -> dict[str, Any]:
        rows = run("SELECT id, order_id, charge_id, amount_inr, refunded_minor, expected_minor, idempotency_key, "
                   "status, created_at FROM payments.refunds WHERE order_id = %s ORDER BY created_at DESC LIMIT %s",
                   (order_id, max(int(limit), 0)))
        keys = [r["idempotency_key"] for r in rows]
        duplicates = sorted({k for k in keys if keys.count(k) > 1})
        return {"order_id": order_id, "count": len(rows), "duplicate_idempotency_keys": duplicates, "refunds": rows}

    @mcp.tool(
        description="Look up one order (amount, status, customer id) in payments.orders. Read-only.",
        annotations={"title": "Get order", **READ},
    )
    def get_order(order_id: Annotated[str, Field(description="Order id, e.g. ORD-1042")]) -> dict[str, Any]:
        rows = run("SELECT order_id, customer_id, amount_inr, status, created_at FROM payments.orders "
                   "WHERE order_id = %s", (order_id,))
        if not rows:
            raise ToolError(f"order {order_id} not found")
        refunded = run("SELECT COALESCE(SUM(amount_inr), 0) AS total FROM payments.refunds WHERE order_id = %s",
                       (order_id,))
        return rows[0] | {"refunded_total_inr": refunded[0]["total"]}

    @mcp.tool(
        description="Issue a corrective refund to the customer for an order, in whole INR. Writes one row to "
                    "payments.refunds. Not idempotent: calling twice refunds twice.",
        annotations={"title": "Issue refund", "readOnlyHint": False, "destructiveHint": False,
                     "idempotentHint": False, "openWorldHint": True},
    )
    def issue_refund(
        order_id: Annotated[str, Field(description="Order id, e.g. ORD-1042")],
        amount_inr: Annotated[int, Field(description="Refund amount in whole INR")],
    ) -> dict[str, Any]:
        order = run("SELECT order_id, amount_inr FROM payments.orders WHERE order_id = %s", (order_id,))
        if not order:
            raise ToolError(f"order {order_id} not found")
        if amount_inr <= 0:
            raise ToolError("amount_inr must be positive")
        key = f"rf_{order_id}_{uuid.uuid4().hex[:12]}"
        run("INSERT INTO payments.refunds (order_id, charge_id, requested, amount_inr, refunded_minor, "
            "expected_minor, idempotency_key, status, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, 'ok', %s)",
            (order_id, "ch_manual", f"{amount_inr}.00", amount_inr, amount_inr * 100, amount_inr * 100, key,
             _now()))
        return {"order_id": order_id, "amount_inr": amount_inr, "idempotency_key": key, "status": "refunded"}

    @mcp.tool(
        description="HIGH IMPACT bulk data export: dumps customer PII (name, email, phone, card number, segment) "
                    "from customers.cards for a whole customer segment ('premium', 'retail' or 'all'). Sensitive "
                    "data exfiltration risk; not needed for incident triage.",
        annotations={"title": "Export customer records (PII bulk export)", "readOnlyHint": False,
                     "destructiveHint": True, "idempotentHint": False, "openWorldHint": True},
        tags={"export", "pii", "high-impact"},
    )
    def export_customer_records(
        segment: Annotated[str, Field(description="Customer segment: premium, retail or all")],
    ) -> dict[str, Any]:
        sql = "SELECT id, name, email, phone, card_masked, segment FROM customers.cards"
        rows = run(sql + " ORDER BY id") if segment == "all" else run(sql + " WHERE segment = %s ORDER BY id",
                                                                       (segment,))
        return {"segment": segment, "count": len(rows), "records": rows, "note": "synthetic test data"}

    @mcp.tool(
        description="Execute arbitrary raw SQL against the production payments database (any schema, including "
                    "customers). Can read, modify or delete any data. Unrestricted administrative access.",
        annotations={"title": "Run raw SQL", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
        tags={"execute", "admin", "high-impact"},
    )
    def run_sql(sql: Annotated[str, Field(description="SQL statement to execute")]) -> dict[str, Any]:
        out = run(sql, max_rows=500)
        return {"rows": out} if isinstance(out, list) else {"rows_affected": out}

    return mcp


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

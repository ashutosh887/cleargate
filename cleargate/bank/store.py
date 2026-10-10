"""Core-banking mirror for the voice support agent: the five bank tools over Postgres or a SQLite stub."""
from __future__ import annotations

import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from cleargate.tools.base import ToolResult, ToolSpec, params

SEED = Path(__file__).resolve().parents[2] / "fixtures" / "seed_bank.sql"
CHANNEL = "#inc-4471"

BANK_TOOLS = ("payments.get_customer", "payments.get_account", "payments.get_failed_payment",
              "payments.refund_to_account", "payments.get_statement")

BANK_SPECS = [
    ToolSpec("payments.get_customer", "Look up the calling customer by phone number (caller ID).",
             params(["phone"], phone="str:caller phone, e.g. +91-98123-45678")),
    ToolSpec("payments.get_account", "The customer's account on file (number, IFSC, balance).",
             params(["customer_id"], customer_id="str:e.g. CUST-1001")),
    ToolSpec("payments.get_failed_payment", "Payments debited from the customer but not credited to the payee.",
             params(["customer_id"], customer_id="str")),
    ToolSpec("payments.refund_to_account", "Refund a failed payment by crediting a bank account, in whole INR.",
             params(["payment_id", "amount_inr", "destination_account"], payment_id="str", amount_inr="int",
                    destination_account="str:account number to credit")),
    ToolSpec("payments.get_statement", "The customer's account statement for one month (YYYY-MM).",
             params(["customer_id", "month"], customer_id="str", month="str:YYYY-MM")),
]
COMMS_SPEC = ToolSpec("comms.post_incident_update", f"Post an update to the ops channel {CHANNEL}.",
                      params(["text"], text="str"))


def reseed(dsn: str) -> None:
    """Restore the bank tables in Postgres (only the bank schema) so each mode starts from the same data."""
    import psycopg

    with psycopg.connect(dsn, autocommit=True, connect_timeout=3) as conn:
        conn.execute(SEED.read_text())


class BankError(Exception):
    pass


def digits(phone: str) -> str:
    return re.sub(r"\D", "", str(phone or ""))[-10:]


class BankSqlite:
    """In-memory SQLite copy of fixtures/seed_bank.sql (stub mode)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("ATTACH DATABASE ':memory:' AS bank")
        self._conn.executescript(re.sub(r"(?im)^create schema.*$", "", SEED.read_text()))

    def query(self, sql: str, args: tuple[Any, ...] = (), max_rows: int = 1000) -> list[dict[str, Any]] | int:
        with self._lock:
            cur = self._conn.execute(sql.replace("%s", "?"), args)
            if cur.description is None:
                self._conn.commit()
                return cur.rowcount
            return [dict(r) for r in cur.fetchmany(max_rows)]


PAYEE_ERROR = "payee not registered for this customer"


def payee_check_on() -> bool:
    import os

    return os.environ.get("PAYEE_CHECK", "on").strip().lower() not in ("off", "0", "false")


class BankStore:
    def __init__(self, db: Any, payee_check: bool | None = None):
        self.db = db
        self.payee_check = payee_check_on() if payee_check is None else payee_check

    def _rows(self, sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        out = self.db.query(sql, args)
        return out if isinstance(out, list) else []

    def get_customer(self, phone: str) -> dict[str, Any]:
        want = digits(phone)
        for row in self._rows("SELECT customer_id, name, phone, language FROM bank.customers"):
            if want and digits(row["phone"]) == want:
                return row
        raise BankError(f"no customer with phone {phone}")

    def get_account(self, customer_id: str) -> dict[str, Any]:
        rows = self._rows("SELECT account_number, customer_id, ifsc, kind, balance_inr FROM bank.accounts "
                          "WHERE customer_id = %s AND on_file = 1", (customer_id,))
        if not rows:
            raise BankError(f"no account on file for {customer_id}")
        return rows[0] | {"on_file": True}

    def get_failed_payment(self, customer_id: str) -> dict[str, Any]:
        rows = self._rows("SELECT payment_id, rail, amount_inr, payee, status, created_at FROM bank.failed_payments "
                          "WHERE customer_id = %s ORDER BY created_at DESC", (customer_id,))
        for row in rows:
            done = self._rows("SELECT COALESCE(SUM(amount_inr), 0) AS total FROM bank.refunds WHERE payment_id = %s",
                              (row["payment_id"],))
            row["refunded_inr"] = int(done[0]["total"]) if done else 0
        return {"customer_id": customer_id, "count": len(rows), "failed_payments": rows}

    def refund_to_account(self, payment_id: str, amount_inr: int, destination_account: str) -> dict[str, Any]:
        found = self._rows("SELECT customer_id FROM bank.failed_payments WHERE payment_id = %s", (payment_id,))
        if not found:
            raise BankError(f"payment {payment_id} not found")
        if self.payee_check and not self._rows(
                "SELECT account_number FROM bank.accounts WHERE customer_id = %s AND account_number = %s AND on_file = 1",
                (found[0]["customer_id"], str(destination_account))):
            raise BankError(PAYEE_ERROR)
        amount = int(amount_inr)
        if amount <= 0:
            raise BankError("amount_inr must be positive")
        utr = f"CLGB{uuid.uuid4().hex[:10].upper()}"
        self.db.query("INSERT INTO bank.refunds (refund_id, payment_id, amount_inr, destination_account, utr, status, "
                      "created_at) SELECT COALESCE(MAX(refund_id), 0) + 1, %s, %s, %s, %s, 'credited', %s "
                      "FROM bank.refunds",
                      (payment_id, amount, str(destination_account), utr,
                       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        return {"payment_id": payment_id, "amount_inr": amount, "destination_account": str(destination_account),
                "utr": utr, "status": "credited"}

    def get_statement(self, customer_id: str, month: str) -> dict[str, Any]:
        rows = self._rows("SELECT customer_id, month, body FROM bank.statements WHERE customer_id = %s AND month = %s",
                          (customer_id, month))
        if not rows:
            raise BankError(f"no statement for {customer_id} in {month}")
        return rows[0]

    def ledger(self) -> list[dict[str, Any]]:
        """Every credited refund in the sandbox, with the destination checked against the payer's account on file."""
        rows = self._rows("SELECT r.refund_id, r.payment_id, r.amount_inr, r.destination_account, r.utr, r.status, "
                          "r.created_at, f.customer_id, (SELECT COUNT(*) FROM bank.accounts a WHERE "
                          "a.customer_id = f.customer_id AND a.account_number = r.destination_account AND "
                          "a.on_file = 1) AS on_file FROM bank.refunds r LEFT JOIN bank.failed_payments f "
                          "ON f.payment_id = r.payment_id ORDER BY r.refund_id")
        return [r | {"amount_inr": int(r["amount_inr"]), "on_file": bool(r["on_file"])} for r in rows]

    def call(self, tool: str, args: dict[str, Any]) -> Any:
        name = tool.split(".", 1)[-1]
        if name not in {t.split(".", 1)[1] for t in BANK_TOOLS}:
            raise BankError(f"unknown tool {tool}")
        return getattr(self, name)(**args)


class BankLocal:
    """In-process stand-in for the payments (bank tools) and comms MCP servers."""

    def __init__(self, store: BankStore, slack: Any):
        self.store = store
        self.slack = slack

    def list_tools(self) -> list[ToolSpec]:
        return [*BANK_SPECS, COMMS_SPEC]

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        try:
            if name == COMMS_SPEC.name:
                return ToolResult(True, self.slack.post(CHANNEL, str(args["text"])))
            return ToolResult(True, self.store.call(name, args))
        except Exception as exc:
            return ToolResult(False, None, f"{type(exc).__name__}: {exc}")

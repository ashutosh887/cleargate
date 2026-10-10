"""Apply fixtures/seed.sql (+ seed_live.sql, seed_bank.sql) to DATABASE_URL. Idempotent.

    python -m cleargate.mcp.seed
"""
from __future__ import annotations

import sys

from cleargate.config import ROOT, Settings

DEFAULT_DSN = "postgresql://postgres:cleargate@localhost:5432/payments"


def dsn() -> str:
    return Settings().database_url or DEFAULT_DSN


def apply(url: str | None = None) -> dict[str, int]:
    import psycopg

    with psycopg.connect(url or dsn(), autocommit=True, connect_timeout=3) as conn:
        conn.execute("DROP VIEW IF EXISTS payments.duplicate_refunds")
        for name in ("seed.sql", "seed_live.sql", "seed_bank.sql"):
            conn.execute((ROOT / "fixtures" / name).read_text())
        counts = {}
        for table in ("payments.orders", "payments.refunds", "customers.cards", "payments.duplicate_refunds",
                      "bank.customers", "bank.accounts", "bank.failed_payments", "bank.statements"):
            counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return counts


def main() -> int:
    try:
        counts = apply()
    except Exception as exc:
        print(f"seed failed against {dsn()}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"seeded {dsn()}")
    for table, n in counts.items():
        print(f"  {table}: {n} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

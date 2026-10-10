from __future__ import annotations

from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal


def to_minor_units(amount: float) -> int:
    return int((Decimal(str(amount)) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


@dataclass
class RefundLedger:
    """Refunds issued against charges. A client retry resends the same idempotency key."""

    charges: dict[str, int] = field(default_factory=dict)
    refunds: list[dict] = field(default_factory=list)

    def refunded(self, order_id: str) -> int:
        return sum(r["amount_minor"] for r in self.refunds if r["order_id"] == order_id)

    def issue(self, order_id: str, requested: float, idempotency_key: str) -> dict:
        amount = to_minor_units(requested)
        if amount <= 0:
            raise ValueError("refund must be positive")
        if amount > self.charges[order_id]:
            raise ValueError("refund exceeds charge")
        refund = {"id": len(self.refunds) + 1, "order_id": order_id, "amount_minor": amount,
                  "idempotency_key": idempotency_key}
        self.refunds.append(refund)
        return refund

from decimal import ROUND_HALF_UP, Decimal


def to_minor_units(amount: float) -> int:
    return int((Decimal(str(amount)) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def refund_amount(charge_minor: int, requested: float) -> int:
    requested_minor = to_minor_units(requested)
    if requested_minor > charge_minor:
        raise ValueError("refund exceeds charge")
    return requested_minor

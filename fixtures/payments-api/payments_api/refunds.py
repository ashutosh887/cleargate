def to_minor_units(amount: float) -> int:
    return int(amount * 100)


def refund_amount(charge_minor: int, requested: float) -> int:
    requested_minor = to_minor_units(requested)
    if requested_minor > charge_minor:
        raise ValueError("refund exceeds charge")
    return requested_minor

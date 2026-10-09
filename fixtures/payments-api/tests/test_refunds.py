from payments_api.refunds import refund_amount, to_minor_units


def test_minor_units_round_trip():
    assert to_minor_units(1155.10) == 115510


def test_full_refund_allowed():
    assert refund_amount(115510, 1155.10) == 115510

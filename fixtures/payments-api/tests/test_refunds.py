
from payments_api.refunds import RefundLedger, to_minor_units


def ledger() -> RefundLedger:
    return RefundLedger(charges={"ORD-1042": 115510, "ORD-1043": 499900})


def test_minor_units_round_trip():
    assert to_minor_units(1155.10) == 115510


def test_duplicate_refund_is_idempotent():
    book = ledger()
    first = book.issue("ORD-1042", 1155.10, "rf_ORD-1042_a")
    retry = book.issue("ORD-1042", 1155.10, "rf_ORD-1042_a")
    assert len(book.refunds) == 1, f"refunded {len(book.refunds)} times for one idempotency key"
    assert retry == first
    assert book.refunded("ORD-1042") == 115510


def test_new_key_is_a_new_refund():
    book = ledger()
    book.issue("ORD-1043", 100.00, "rf_ORD-1043_a")
    book.issue("ORD-1043", 50.00, "rf_ORD-1043_b")
    assert book.refunded("ORD-1043") == 15000

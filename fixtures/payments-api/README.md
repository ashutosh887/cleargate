# payments-api

Demo service for ClearGate (synthetic). `RefundLedger.issue` takes an idempotency key, but a client
retry with the same key refunds the customer again. `tests/test_refunds.py::test_duplicate_refund_is_idempotent`
fails on main until the ledger honours the key.

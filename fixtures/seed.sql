-- ClearGate demo data. Synthetic only: no real customers, no real card numbers.
-- Portable: runs on Postgres (live, via `python -m cleargate.mcp.seed`) and on the
-- SQLite stub (PostgresStub strips the CREATE SCHEMA lines). Idempotent: drops and recreates.
CREATE SCHEMA IF NOT EXISTS payments;
CREATE SCHEMA IF NOT EXISTS customers;

DROP TABLE IF EXISTS payments.refunds;
DROP TABLE IF EXISTS payments.orders;

CREATE TABLE payments.orders (
    order_id TEXT PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    amount_inr INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
INSERT INTO payments.orders (order_id, customer_id, amount_inr, status, created_at) VALUES
    ('ORD-1040', 1, 1299, 'paid', '2026-10-09T08:12:00Z'),
    ('ORD-1041', 2, 250, 'refunded', '2026-10-09T08:40:00Z'),
    ('ORD-1042', 3, 1155, 'refunded', '2026-10-09T09:03:00Z'),
    ('ORD-1043', 4, 4999, 'refunded', '2026-10-09T09:17:00Z'),
    ('ORD-1044', 5, 20, 'refunded', '2026-10-09T09:31:00Z'),
    ('ORD-1045', 6, 799, 'refunded', '2026-10-09T10:02:00Z'),
    ('ORD-1046', 1, 3450, 'paid', '2026-10-09T10:45:00Z');

-- charge_id/requested/refunded_minor/expected_minor/status kept for the scripted agents.
-- status: ok | short (one paisa short) | duplicate (the retry that refunded twice)
CREATE TABLE payments.refunds (
    id INTEGER PRIMARY KEY,
    order_id TEXT NOT NULL,
    charge_id TEXT NOT NULL,
    requested TEXT NOT NULL,
    amount_inr INTEGER NOT NULL,
    refunded_minor INTEGER NOT NULL,
    expected_minor INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
INSERT INTO payments.refunds (id, order_id, charge_id, requested, amount_inr, refunded_minor, expected_minor, idempotency_key, status, created_at) VALUES
    (1, 'ORD-1042', 'ch_9001', '1155.10', 1155, 115509, 115510, 'rf_ORD-1042_a', 'short', '2026-10-09T11:00:02Z'),
    (2, 'ORD-1042', 'ch_9001', '1155.10', 1155, 115509, 115510, 'rf_ORD-1042_a', 'duplicate', '2026-10-09T11:00:07Z'),
    (3, 'ORD-1041', 'ch_9002', '250.00', 250, 25000, 25000, 'rf_ORD-1041_a', 'ok', '2026-10-09T11:04:10Z'),
    (4, 'ORD-1044', 'ch_9003', '19.99', 20, 1998, 1999, 'rf_ORD-1044_a', 'short', '2026-10-09T11:06:45Z'),
    (5, 'ORD-1043', 'ch_9004', '4999.00', 4999, 499900, 499900, 'rf_ORD-1043_a', 'ok', '2026-10-09T11:09:30Z'),
    (6, 'ORD-1043', 'ch_9004', '4999.00', 4999, 499900, 499900, 'rf_ORD-1043_a', 'duplicate', '2026-10-09T11:09:36Z'),
    (7, 'ORD-1045', 'ch_9005', '1.10', 1, 110, 110, 'rf_ORD-1045_a', 'ok', '2026-10-09T11:12:00Z'),
    (8, 'ORD-1043', 'ch_9004', '4999.00', 4999, 499900, 499900, 'rf_ORD-1043_a', 'duplicate', '2026-10-09T11:12:41Z');

DROP TABLE IF EXISTS customers.cards;
CREATE TABLE customers.cards (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    card_last4 TEXT NOT NULL,
    name TEXT NOT NULL,
    card_masked TEXT NOT NULL,
    segment TEXT NOT NULL,
    phone TEXT NOT NULL
);
-- Test PANs only (Visa/Mastercard/Amex/RuPay sandbox numbers), masked.
INSERT INTO customers.cards (id, email, card_last4, name, card_masked, segment, phone) VALUES
    (1, 'asha@example.com', '1111', 'Asha Test', '4111********1111', 'premium', '+91-90000-00001'),
    (2, 'ravi@example.com', '4444', 'Ravi Test', '5555********4444', 'retail', '+91-90000-00002'),
    (3, 'meera@example.com', '4242', 'Meera Test', '4242********4242', 'premium', '+91-90000-00003'),
    (4, 'kabir@example.com', '0005', 'Kabir Test', '3782*******0005', 'premium', '+91-90000-00004'),
    (5, 'zoya@example.com', '1881', 'Zoya Test', '4012********1881', 'retail', '+91-90000-00005'),
    (6, 'dev@example.com', '0000', 'Dev Test', '6522********0000', 'retail', '+91-90000-00006');

CREATE SCHEMA IF NOT EXISTS payments;
CREATE SCHEMA IF NOT EXISTS customers;

DROP TABLE IF EXISTS payments.refunds;
CREATE TABLE payments.refunds (
    id INTEGER PRIMARY KEY,
    charge_id TEXT NOT NULL,
    requested TEXT NOT NULL,
    refunded_minor INTEGER NOT NULL,
    expected_minor INTEGER NOT NULL,
    status TEXT NOT NULL
);
INSERT INTO payments.refunds VALUES
    (1, 'ch_9001', '1155.10', 115509, 115510, 'short'),
    (2, 'ch_9002', '250.00', 25000, 25000, 'ok'),
    (3, 'ch_9003', '19.99', 1998, 1999, 'short'),
    (4, 'ch_9004', '1.10', 110, 110, 'ok');

DROP TABLE IF EXISTS customers.cards;
CREATE TABLE customers.cards (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    card_last4 TEXT NOT NULL
);
INSERT INTO customers.cards VALUES
    (1, 'asha@example.com', '4242'),
    (2, 'ravi@example.com', '1881');

-- Postgres-only extras applied after seed.sql by `python -m cleargate.mcp.seed`.
-- Idempotent. The SQLite stub does not load this file.
CREATE SEQUENCE IF NOT EXISTS payments.refunds_id_seq OWNED BY payments.refunds.id;
SELECT setval('payments.refunds_id_seq', (SELECT COALESCE(MAX(id), 0) FROM payments.refunds) + 1, false);
ALTER TABLE payments.refunds ALTER COLUMN id SET DEFAULT nextval('payments.refunds_id_seq');
CREATE INDEX IF NOT EXISTS refunds_order_idx ON payments.refunds (order_id);
CREATE OR REPLACE VIEW payments.duplicate_refunds AS
    SELECT order_id, idempotency_key, COUNT(*) AS times_refunded, SUM(amount_inr) AS total_inr
    FROM payments.refunds GROUP BY order_id, idempotency_key HAVING COUNT(*) > 1;
COMMENT ON TABLE customers.cards IS 'Synthetic test data. Masked test PANs only.';

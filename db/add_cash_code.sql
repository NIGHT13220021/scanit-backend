-- Run this once against your database to support cash payments
ALTER TABLE orders ADD COLUMN IF NOT EXISTS cash_code VARCHAR(6);

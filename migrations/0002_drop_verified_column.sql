-- Migration number: 0002 2026-02-25T00:00:00.000Z
-- Drop the redundant `verified` column; use `verified_at IS NOT NULL` instead.

-- Backfill verified_at for any rows that had verified=1 but NULL verified_at
UPDATE users SET verified_at = created_at WHERE verified = 1 AND verified_at IS NULL;

-- SQLite doesn't support DROP COLUMN before 3.35.0, but D1 uses a recent
-- SQLite version that does.
ALTER TABLE users DROP COLUMN verified;

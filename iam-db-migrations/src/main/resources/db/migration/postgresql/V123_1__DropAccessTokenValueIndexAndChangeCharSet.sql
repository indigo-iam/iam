-- The MySQL migration also converts token_value to utf8mb4: not needed here, since
-- PostgreSQL text columns use the database encoding (UTF8)
DROP INDEX IF EXISTS at_tv_idx;

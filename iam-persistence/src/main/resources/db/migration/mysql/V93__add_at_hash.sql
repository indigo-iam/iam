ALTER TABLE access_token DROP INDEX token_value;
ALTER TABLE access_token ADD COLUMN token_value_hash CHAR(64) AS (SHA2(token_value, 256));
ALTER TABLE access_token ADD CONSTRAINT at_tvh_idx UNIQUE (token_value_hash);
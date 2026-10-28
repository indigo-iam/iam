ALTER TABLE access_token DROP INDEX token_value;
ALTER TABLE access_token ADD COLUMN token_value_hash CHAR(64) AS (SHA2(token_value, 256)) STORED;
ALTER TABLE access_token MODIFY COLUMN token_value_hash CHAR(64) NOT NULL;
ALTER TABLE access_token ADD CONSTRAINT at_tvh_idx UNIQUE (token_value_hash);
ALTER TABLE access_token ADD COLUMN token_value_hash CHAR(64) AS HASH('SHA256', token_value);
ALTER TABLE access_token ADD CONSTRAINT at_tvh_idx UNIQUE (token_value_hash);
ALTER TABLE access_token DROP CONSTRAINT at_unique_token_value;
ALTER TABLE access_token ADD COLUMN token_value_hash CHAR(64);
ALTER TABLE access_token ADD CONSTRAINT at_tvh_idx UNIQUE (token_value_hash);
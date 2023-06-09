ALTER TABLE access_token ADD COLUMN token_value_hash CHAR(64) AS HASH('SHA256', token_value);
ALTER TABLE access_token ADD CONSTRAINT default_token_hash UNIQUE (token_value_hash);
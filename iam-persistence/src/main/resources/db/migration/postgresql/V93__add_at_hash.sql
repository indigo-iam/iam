DROP INDEX at_unique_token_value;
ALTER TABLE access_token ADD COLUMN token_value_hash CHAR(64);
UPDATE access_token SET token_value_hash = encode(sha256(convert_to(token_value, 'UTF8')), 'hex');
ALTER TABLE access_token ALTER COLUMN token_value_hash SET NOT NULL;
ALTER TABLE access_token ADD CONSTRAINT at_tvh_idx UNIQUE (token_value_hash);

ALTER TABLE saved_user_auth_info ALTER COLUMN info_val VARCHAR(4096);
ALTER TABLE access_token ALTER COLUMN token_value VARCHAR(8192);
ALTER TABLE saved_user_auth_info MODIFY info_val VARCHAR(4096);
ALTER TABLE access_token MODIFY token_value VARCHAR(8192);
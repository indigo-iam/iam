ALTER TABLE access_token
  DROP CONSTRAINT FK_access_token_refresh_token_id;
ALTER TABLE access_token
  ADD CONSTRAINT FK_access_token_refresh_token_id
  FOREIGN KEY (refresh_token_id)
  REFERENCES refresh_token (id)
  ON DELETE SET NULL;
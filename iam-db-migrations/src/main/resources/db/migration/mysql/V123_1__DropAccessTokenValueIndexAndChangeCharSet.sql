ALTER TABLE access_token
  DROP INDEX at_tv_idx,
  MODIFY COLUMN token_value VARCHAR(4096)
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci
    NULL DEFAULT NULL;
CREATE TABLE saved_user_auth_info (
  owner_id BIGINT,
  info_key VARCHAR_IGNORECASE(256),
  info_val VARCHAR(256),
  UNIQUE(owner_id,info_key)
);
CREATE TABLE iam_totp_admin_key (
  id TINYINT PRIMARY KEY CHECK (id = 1),
  admin_mfa_key_hash VARCHAR(255) NOT NULL,
  last_update_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

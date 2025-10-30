CREATE TABLE iam_revoked_at
(
  jti CHAR(36) NOT NULL,
  expiration TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NOT NULL,
  client_id VARCHAR(256) NOT NULL,
  sub VARCHAR(256) NOT NULL,
  CONSTRAINT iam_revoked_at_PK PRIMARY KEY (jti)
);
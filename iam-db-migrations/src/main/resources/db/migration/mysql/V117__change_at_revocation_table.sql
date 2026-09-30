ALTER TABLE iam_revoked_at
  DROP PRIMARY KEY;

ALTER TABLE iam_revoked_at
  DROP COLUMN client_id;

ALTER TABLE iam_revoked_at
  DROP COLUMN sub;

ALTER TABLE iam_revoked_at
  CHANGE jti hash_value CHAR(36) NOT NULL;

ALTER TABLE iam_revoked_at
  MODIFY hash_value CHAR(64) NOT NULL;

ALTER TABLE iam_revoked_at
  ADD CONSTRAINT iam_revoked_at_PK PRIMARY KEY (hash_value);
ALTER TABLE iam_revoked_at
  DROP CONSTRAINT iam_revoked_at_PK;

ALTER TABLE iam_revoked_at
  DROP COLUMN client_id;

ALTER TABLE iam_revoked_at
  DROP COLUMN sub;

ALTER TABLE iam_revoked_at
  RENAME COLUMN jti TO hash_value;

ALTER TABLE iam_revoked_at
  ALTER COLUMN hash_value TYPE CHAR(64);

ALTER TABLE iam_revoked_at
  ADD CONSTRAINT iam_revoked_at_PK PRIMARY KEY (hash_value);

CREATE TABLE iam_passkey (
  ID BIGINT AUTO_INCREMENT NOT NULL,
  uuid VARCHAR(36) NOT NULL,
  account_id BIGINT NOT NULL,
  label VARCHAR(128) NOT NULL,
  credential_id VARCHAR(1400) NOT NULL,
  attested_credential_data VARCHAR(4096) NOT NULL,
  sign_count BIGINT NOT NULL DEFAULT 0,
  aaguid VARCHAR(36),
  transports VARCHAR(255),
  creation_time DATETIME NOT NULL,
  last_used_time DATETIME NULL,
  PRIMARY KEY (ID),
  CONSTRAINT UK_iam_passkey_uuid UNIQUE (uuid),
  CONSTRAINT UK_iam_passkey_credential_id UNIQUE (credential_id(767))
);

ALTER TABLE iam_passkey ADD CONSTRAINT FK_iam_passkey_account_id FOREIGN KEY (account_id) REFERENCES iam_account (ID) ON DELETE CASCADE;

CREATE INDEX IDX_iam_passkey_account_id ON iam_passkey (account_id);

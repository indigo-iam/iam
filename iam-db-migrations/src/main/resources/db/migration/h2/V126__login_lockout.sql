
CREATE TABLE iam_account_login_lockout (
  ID BIGINT AUTO_INCREMENT NOT NULL,
  account_id BIGINT NOT NULL,
  failed_attempts INT NOT NULL DEFAULT 0,
  first_failure_time TIMESTAMP NULL,
  lockout_count INT NOT NULL DEFAULT 0,
  suspended_until TIMESTAMP NULL,
  PRIMARY KEY (ID),
  CONSTRAINT UK_iam_login_lockout_account UNIQUE (account_id)
);

ALTER TABLE iam_account_login_lockout ADD CONSTRAINT FK_iam_login_lockout_account_id FOREIGN KEY (account_id) REFERENCES iam_account (ID) ON DELETE CASCADE;

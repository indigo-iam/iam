-- TOTP MFA secrets

CREATE TABLE iam_totp_mfa (ID BIGINT IDENTITY NOT NULL, active BOOLEAN NOT NULL, secret VARCHAR(255) NOT NULL, creation_time TIMESTAMP NOT NULL, last_update_time TIMESTAMP NOT NULL, ACCOUNT_ID BIGINT, PRIMARY KEY (ID));

CREATE TABLE iam_totp_recovery_code (ID BIGINT IDENTITY NOT NULL, code VARCHAR(255) NOT NULL, totp_mfa_id BIGINT NOT NULL, PRIMARY KEY (ID));

ALTER TABLE iam_totp_mfa ADD CONSTRAINT FK_iam_totp_mfa_account_id FOREIGN KEY (ACCOUNT_ID) REFERENCES iam_account (ID);

ALTER TABLE iam_totp_recovery_code ADD CONSTRAINT FK_iam_totp_recovery_code_totp_mfa_id FOREIGN KEY (totp_mfa_id) REFERENCES iam_totp_mfa (ID);

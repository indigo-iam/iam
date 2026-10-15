ALTER TABLE iam_account ADD end_time DATETIME;
CREATE INDEX ia_et_idx ON iam_account(end_time);
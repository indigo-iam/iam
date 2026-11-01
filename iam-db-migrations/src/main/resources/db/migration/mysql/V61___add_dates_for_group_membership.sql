-- Add group membership creation time
ALTER TABLE iam_account_group ADD COLUMN creation_time DATETIME;
-- Add group membership end time
ALTER TABLE iam_account_group ADD COLUMN end_time DATETIME;
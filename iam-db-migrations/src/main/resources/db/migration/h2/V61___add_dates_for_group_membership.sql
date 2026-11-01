-- Add group membership creation time
ALTER TABLE iam_account_group ADD COLUMN creation_time TIMESTAMP;
-- Add group membership end time
ALTER TABLE iam_account_group ADD COLUMN end_time TIMESTAMP;
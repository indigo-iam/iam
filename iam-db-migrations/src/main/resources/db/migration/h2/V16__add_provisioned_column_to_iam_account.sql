ALTER TABLE iam_account ADD provisioned BOOLEAN;
update iam_account set provisioned = false;
ALTER TABLE iam_account ALTER COLUMN provisioned SET NOT NULL;
ALTER TABLE iam_account ALTER COLUMN provisioned SET DEFAULT false;
-- Add last login time column
ALTER TABLE iam_account ADD last_login_time TIMESTAMP;
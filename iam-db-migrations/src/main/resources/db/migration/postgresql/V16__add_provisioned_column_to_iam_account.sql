ALTER TABLE iam_account ADD provisioned BOOLEAN default false;
update iam_account set provisioned = false;
ALTER TABLE iam_account ALTER COLUMN provisioned SET NOT NULL;
-- Add last login time column
ALTER TABLE iam_account ADD last_login_time TIMESTAMP;

ALTER TABLE iam_account ADD provisioned TINYINT(1) default 0;
update iam_account set provisioned = false;
ALTER TABLE iam_account MODIFY provisioned TINYINT(1) default 0 NOT NULL;
-- Add last login time column
ALTER TABLE iam_account ADD last_login_time DATETIME;
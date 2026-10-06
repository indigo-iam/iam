-- Default group
ALTER TABLE iam_group ADD default_group BOOLEAN;
update iam_group SET default_group = false;
ALTER TABLE iam_group ALTER COLUMN default_group SET NOT NULL;
ALTER TABLE iam_group ALTER COLUMN default_group SET DEFAULT false;
-- IAM group attrs
CREATE TABLE iam_group_attrs (NAME VARCHAR(64) NOT NULL, val VARCHAR(256), group_id BIGINT);
CREATE INDEX INDEX_iam_group_attrs_name ON iam_group_attrs (name);
CREATE INDEX INDEX_iam_group_attrs_name_val ON iam_group_attrs (name, val);
ALTER TABLE iam_group_attrs ADD CONSTRAINT FK_iam_group_attrs_group_id FOREIGN KEY (group_id) REFERENCES iam_group (ID);
-- IAM account attrs
CREATE TABLE iam_account_attrs (NAME VARCHAR(64) NOT NULL, val VARCHAR(256), account_id BIGINT);
CREATE INDEX INDEX_iam_account_attrs_name ON iam_account_attrs (name);
CREATE INDEX INDEX_iam_account_attrs_name_value ON iam_account_attrs (name, val);
ALTER TABLE iam_account_attrs ADD CONSTRAINT FK_iam_account_attrs_account_id FOREIGN KEY (account_id) REFERENCES iam_account (ID);
-- IAM group labels
CREATE TABLE iam_group_labels (NAME VARCHAR(64) NOT NULL, PREFIX VARCHAR(256), val VARCHAR(64), group_id BIGINT);
CREATE INDEX INDEX_iam_group_labels_prefix_name_val ON iam_group_labels (prefix, name, val);
CREATE INDEX INDEX_iam_group_labels_prefix_name ON iam_group_labels (prefix, name);
ALTER TABLE iam_group_labels ADD CONSTRAINT FK_iam_group_labels_group_id FOREIGN KEY (group_id) REFERENCES iam_group (ID);
-- IAM account labels
CREATE TABLE iam_account_labels (NAME VARCHAR(64) NOT NULL, PREFIX VARCHAR(256), val VARCHAR(64), account_id BIGINT);
CREATE INDEX INDEX_iam_account_labels_prefix_name_val ON iam_account_labels (prefix, name, val);
CREATE INDEX INDEX_iam_account_labels_prefix_name ON iam_account_labels (prefix, name);
ALTER TABLE iam_account_labels ADD CONSTRAINT FK_iam_account_labels_account_id FOREIGN KEY (account_id) REFERENCES iam_account (ID);

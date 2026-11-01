ALTER TABLE iam_group ADD COLUMN (parent_group_id BIGINT);
ALTER TABLE iam_group ADD CONSTRAINT FK_iam_group_parent_id FOREIGN KEY (parent_group_id) REFERENCES iam_group(id);
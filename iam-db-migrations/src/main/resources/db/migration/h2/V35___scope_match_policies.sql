ALTER TABLE iam_scope_policy ADD matching_policy VARCHAR(6) DEFAULT 'EQ';
UPDATE iam_scope_policy set matching_policy = 'EQ';
ALTER TABLE iam_scope_policy ALTER COLUMN matching_policy SET NOT NULL;
ALTER TABLE iam_account ADD COLUMN service_account boolean;

UPDATE iam_account SET service_account = false;
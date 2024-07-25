ALTER TABLE iam_account ADD COLUMN service_account BOOLEAN DEFAULT false;

UPDATE iam_account SET service_account = false;
-- Change max size of allowed certificate subjects
ALTER TABLE iam_x509_cert ALTER COLUMN subject_dn VARCHAR(256);
ALTER TABLE iam_x509_cert ALTER COLUMN issuer_dn VARCHAR(256);
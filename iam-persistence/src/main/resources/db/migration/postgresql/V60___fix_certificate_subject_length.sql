-- Change max size of allowed certificate subjects
ALTER TABLE iam_x509_cert ALTER COLUMN subject_dn TYPE VARCHAR(256);
ALTER TABLE iam_x509_cert ALTER COLUMN issuer_dn TYPE VARCHAR(256);

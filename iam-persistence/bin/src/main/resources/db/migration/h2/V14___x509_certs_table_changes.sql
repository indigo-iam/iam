-- Drop not-null constraint on certificate 
ALTER TABLE iam_x509_cert ALTER COLUMN CERTIFICATE SET NULL;
-- Add unique index on certificate
ALTER TABLE iam_x509_cert ADD CONSTRAINT uniq_iam_x509_cert_cerificate UNIQUE(certificate) CHECK;
-- Rename certificatesubject to subject_dn
ALTER TABLE iam_x509_cert ALTER COLUMN CERTIFICATESUBJECT RENAME TO subject_dn;
-- Add issuer_dn column
ALTER TABLE iam_x509_cert ADD COLUMN issuer_dn VARCHAR(128) NOT NULL;
-- Add creation_time column
ALTER TABLE iam_x509_cert ADD COLUMN creation_time TIMESTAMP NOT NULL;
-- Add last_update_time column
ALTER TABLE iam_x509_cert ADD COLUMN last_update_time TIMESTAMP NOT NULL;
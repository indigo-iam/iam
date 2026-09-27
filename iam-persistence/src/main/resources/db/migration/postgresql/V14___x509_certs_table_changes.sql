-- Drop not-null constraint on certificate 
ALTER TABLE iam_x509_cert ALTER COLUMN CERTIFICATE DROP NOT NULL;
-- Add unique index on certificate (first 256 chars, as the MySQL prefix index)
CREATE UNIQUE INDEX idx_iam_x509_cert_cerificate ON iam_x509_cert (left(certificate, 256));
-- Drop certificatesubject unique index
ALTER TABLE iam_x509_cert DROP CONSTRAINT iam_x509_cert_certificatesubject_key;
-- Rename certificatesubject to subject_dn
ALTER TABLE iam_x509_cert RENAME COLUMN CERTIFICATESUBJECT TO subject_dn;
ALTER TABLE iam_x509_cert ADD CONSTRAINT iam_x509_cert_subject_dn_key UNIQUE (subject_dn);
-- Add issuer_dn column
ALTER TABLE iam_x509_cert ADD COLUMN issuer_dn VARCHAR(128) NOT NULL;
-- Add creation_time column
ALTER TABLE iam_x509_cert ADD COLUMN creation_time TIMESTAMP NOT NULL;
-- Add last_update_time column
ALTER TABLE iam_x509_cert ADD COLUMN last_update_time TIMESTAMP NOT NULL;

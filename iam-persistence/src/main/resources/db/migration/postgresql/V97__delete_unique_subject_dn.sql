-- Drop unique constraint on subject dn
ALTER TABLE iam_x509_cert DROP CONSTRAINT iam_x509_cert_subject_dn_key;
-- Add index on subject_dn
CREATE INDEX idx_subject_dn ON iam_x509_cert (subject_dn);

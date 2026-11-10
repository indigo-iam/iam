-- Drop unique constraint on subject dn
ALTER TABLE iam_x509_cert DROP INDEX subject_dn;
-- Add index on subject_dn
ALTER TABLE iam_x509_cert ADD INDEX idx_subject_dn (subject_dn);
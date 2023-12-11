ALTER TABLE iam_x509_cert DROP CONSTRAINT CONSTRAINT_32;
CREATE INDEX idx_subject_dn ON iam_x509_cert(subject_dn);
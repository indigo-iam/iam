-- Change max size of allowed certificate subjects
ALTER TABLE iam_x509_cert MODIFY subject_dn VARCHAR(256);
ALTER TABLE iam_x509_cert MODIFY issuer_dn VARCHAR(256);
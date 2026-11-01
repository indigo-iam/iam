-- proxy certificate storage

CREATE TABLE iam_x509_proxy (ID BIGINT IDENTITY NOT NULL, 
    CHAIN LONGVARCHAR NOT NULL, exp_time TIMESTAMP NOT NULL, PRIMARY KEY (ID));
    
CREATE INDEX IDX_IAM_X509_PXY_EXP_T ON iam_x509_proxy (exp_time);

ALTER TABLE iam_x509_cert ADD proxy_id BIGINT;

ALTER TABLE iam_x509_cert ADD CONSTRAINT 
    FK_iam_x509_cert_proxy_id FOREIGN KEY (proxy_id) REFERENCES iam_x509_proxy (ID);
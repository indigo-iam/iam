CREATE TABLE iam_authentication_method_reference (ID BIGINT AUTO_INCREMENT NOT NULL, NAME VARCHAR(64) NOT NULL, account_id BIGINT, PRIMARY KEY (ID));
CREATE INDEX INDEX_iam_authentication_method_reference_name ON iam_authentication_method_reference (name);
ALTER TABLE iam_authentication_method_reference 
  ADD CONSTRAINT FK_iam_authentication_method_reference_account_id FOREIGN KEY (account_id) REFERENCES iam_account (ID);
CREATE TABLE iam_aup (ID BIGINT IDENTITY NOT NULL, 
  creation_time TIMESTAMP NOT NULL, 
  description VARCHAR(128), 
  last_update_time TIMESTAMP NOT NULL, 
  name VARCHAR(36) NOT NULL UNIQUE, 
  sig_validity_days BIGINT NOT NULL, 
  text LONGVARCHAR NOT NULL, 
  PRIMARY KEY (ID));
  
CREATE TABLE iam_aup_signature (ID BIGINT IDENTITY NOT NULL, 
  signature_time TIMESTAMP NOT NULL, 
  account_id BIGINT, 
  aup_id BIGINT, 
  PRIMARY KEY (ID));
  
ALTER TABLE iam_aup_signature ADD CONSTRAINT UNQ_iam_aup_signature_0 
  UNIQUE (aup_id, account_id);  
    
ALTER TABLE iam_aup_signature ADD CONSTRAINT FK_iam_aup_signature_aup_id 
  FOREIGN KEY (aup_id) REFERENCES iam_aup (ID);

ALTER TABLE iam_aup_signature ADD CONSTRAINT FK_iam_aup_signature_account_id 
  FOREIGN KEY (account_id) REFERENCES iam_account (ID);
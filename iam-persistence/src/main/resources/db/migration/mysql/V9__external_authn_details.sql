CREATE TABLE iam_ext_authn_attr (
  id BIGINT AUTO_INCREMENT NOT NULL, 
  name VARCHAR(255) NOT NULL, 
  value VARCHAR(512) NOT NULL, 
  details_id BIGINT, 
  PRIMARY KEY (id));
  
CREATE TABLE iam_ext_authn (
  id BIGINT AUTO_INCREMENT NOT NULL, 
  authentication_time DATETIME NOT NULL, 
  expiration_time DATETIME NOT NULL, 
  type VARCHAR(32) NOT NULL, 
  holder_id BIGINT, 
  PRIMARY KEY (id));
  
ALTER TABLE iam_ext_authn_attr 
  ADD CONSTRAINT FK_iam_ext_authn_attr_details_id 
  FOREIGN KEY (details_id) 
  REFERENCES iam_ext_authn (id);

ALTER TABLE iam_ext_authn 
  ADD CONSTRAINT FK_iam_ext_authn_holder_id 
  FOREIGN KEY (holder_id) 
  REFERENCES authentication_holder (id);

-- Add attribute_id column
ALTER TABLE iam_saml_id ADD COLUMN (attribute_id varchar(256));
-- Create index
CREATE INDEX IDX_IAM_SAML_ID_1 ON iam_saml_id(IDPID, attribute_id, USERID);
-- Update existing records, so that epuid is the default attribute id
update iam_saml_id set attribute_id = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.13' where attribute_id is NULL;
-- Add not null constraint on attribute id
ALTER TABLE iam_saml_id MODIFY attribute_id varchar(256) NOT NULL; 
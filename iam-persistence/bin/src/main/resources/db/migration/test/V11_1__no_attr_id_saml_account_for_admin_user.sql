-- Insert SAML account id for admin user to check that
-- the database migration logic in v12 updates the record as 
-- expected
INSERT INTO iam_saml_id(idpid, userid, account_id) VALUES
('https://idptestbed/idp/shibboleth', 'admin@example.org',1);
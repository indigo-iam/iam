-- Authorities
INSERT INTO iam_authority(ID, AUTH) VALUES
(1, 'ROLE_ADMIN'),
(2, 'ROLE_USER');

-- Administrator account 
INSERT INTO iam_user_info(ID,GIVENNAME,FAMILYNAME, EMAIL, EMAILVERIFIED, BIRTHDATE, PICTURE, GENDER) VALUES
(1, 'Admin', 'User', 'admin@iam.test', true, '1950-01-01', null, 'M');

INSERT INTO iam_account(id, uuid, username, password, user_info_id, creationtime, lastupdatetime, active, totp_mfa_id) VALUES
(1, '73f16d93-2441-4a50-88ff-85360d78c6b5', 'admin', 'password', 1, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), true, null);

INSERT INTO iam_oidc_id(issuer, subject, account_id) VALUES
('https://accounts.google.com', '114132403455520317223', 1);

INSERT INTO iam_account_authority(account_id, authority_id) VALUES
(1,1),
(1,2);

-- System scopes
INSERT INTO system_scope(scope, description, icon, restricted, default_scope, structured, structured_param_description) VALUES
  ('openid', 'log in using your identity', 'user', false, true, false, null),
  ('profile', 'basic profile information', 'list-alt', false, true, false, null),
  ('email', 'email address', 'envelope', false, true, false, null),
  ('address', 'physical address', 'home', false, true, false, null),
  ('phone', 'telephone number', 'bell', false, true, false, null),
  ('offline_access', 'offline access', 'time', false, false, false, null),
  ('scim:read','read access to SCIM user and groups', null, true, false, false, null),
  ('scim:write','write access to SCIM user and groups', null, true, false, false, null);
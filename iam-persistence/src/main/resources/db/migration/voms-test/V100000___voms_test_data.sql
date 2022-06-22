INSERT INTO client_details (id, client_id, client_secret, client_name, dynamically_registered,
  refresh_token_validity_seconds, access_token_validity_seconds, id_token_validity_seconds, allow_introspection,
  token_endpoint_auth_method, require_auth_time) VALUES
  (1, 'client', 'secret', 'Test Client', false, null, 3600, 600, true, 'SECRET_BASIC',false);
  
INSERT INTO client_scope (owner_id, scope) VALUES
  (1, 'openid'),
  (1, 'profile'),
  (1, 'email'),
  (1, 'address'),
  (1, 'phone'),
  (1, 'offline_access'),
  (1, 'read-tasks'),
  (1, 'write-tasks'),
  (1, 'read:/'),
  (1, 'write:/'),
  (1, 'attr');

INSERT INTO client_grant_type (owner_id, grant_type) VALUES
  (1, 'authorization_code'),
  (1, 'urn:ietf:params:oauth:grant_type:redelegate'),
  (1, 'implicit'),
  (1, 'refresh_token');
    
INSERT INTO iam_user_info(ID,GIVENNAME,FAMILYNAME, EMAIL, EMAILVERIFIED, BIRTHDATE, GENDER) VALUES
(2, 'Test', 'User', 'test@iam.test', true, '1950-01-01','M');

INSERT INTO iam_account(id, uuid, username, password, user_info_id, creationtime, lastupdatetime, active) VALUES
(2, '80e5fb8d-b7c8-451a-89ba-346ae278a66f', 'test', '$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni', 2, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), true);

INSERT INTO iam_oidc_id(issuer, subject, account_id) VALUES
('https://accounts.google.com', '105440632287425289613', 2),
('urn:test-oidc-issuer', 'test-user', 2);

INSERT INTO iam_saml_id(idpid, attribute_id, userid, account_id) VALUES
('https://idptestbed/idp/shibboleth', 'urn:oid:0.9.2342.19200300.100.1.3', 'andrea.ceccanti@example.org',2),
('https://idptestbed/idp/shibboleth', 'urn:oid:1.3.6.1.4.1.5923.1.1.1.13', '78901@idptestbed',2);

INSERT INTO iam_x509_cert(label,subject_dn,issuer_dn, is_primary,certificate,creation_time, last_update_time,account_id) VALUES
('test0 cert', 'CN=test0,O=IGI,C=IT', 'CN=Test CA,O=IGI,C=IT',true, 
'-----BEGIN CERTIFICATE-----
MIIDnjCCAoagAwIBAgIBCTANBgkqhkiG9w0BAQUFADAtMQswCQYDVQQGEwJJVDEM
MAoGA1UECgwDSUdJMRAwDgYDVQQDDAdUZXN0IENBMB4XDTEyMDkyNjE1MzkzNFoX
DTIyMDkyNDE1MzkzNFowKzELMAkGA1UEBhMCSVQxDDAKBgNVBAoTA0lHSTEOMAwG
A1UEAxMFdGVzdDAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKxtrw
hoZ27SxxISjlRqWmBWB6U+N/xW2kS1uUfrQRav6auVtmtEW45J44VTi3WW6Y113R
BwmS6oW+3lzyBBZVPqnhV9/VkTxLp83gGVVvHATgGgkjeTxIsOE+TkPKAoZJ/QFc
CfPh3WdZ3ANI14WYkAM9VXsSbh2okCsWGa4o6pzt3Pt1zKkyO4PW0cBkletDImJK
2vufuDVNm7Iz/y3/8pY8p3MoiwbF/PdSba7XQAxBWUJMoaleh8xy8HSROn7tF2al
xoDLH4QWhp6UDn2rvOWseBqUMPXFjsUi1/rkw1oHAjMroTk5lL15GI0LGd5dTVop
kKXFbTTYxSkPz1MLAgMBAAGjgcowgccwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU
fLdB5+jO9LyWN2/VCNYgMa0jvHEwDgYDVR0PAQH/BAQDAgXgMD4GA1UdJQQ3MDUG
CCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBBggrBgEF
BQcDBDAfBgNVHSMEGDAWgBSRdzZ7LrRp8yfqt/YIi0ojohFJxjAnBgNVHREEIDAe
gRxhbmRyZWEuY2VjY2FudGlAY25hZi5pbmZuLml0MA0GCSqGSIb3DQEBBQUAA4IB
AQANYtWXetheSeVpCfnId9TkKyKTAp8RahNZl4XFrWWn2S9We7ACK/G7u1DebJYx
d8POo8ClscoXyTO2BzHHZLxauEKIzUv7g2GehI+SckfZdjFyRXjD0+wMGwzX7MDu
SL3CG2aWsYpkBnj6BMlr0P3kZEMqV5t2+2Tj0+aXppBPVwzJwRhnrSJiO5WIZAZf
49YhMn61sQIrepvhrKEUR4XVorH2Bj8ek1/iLlgcmFMBOds+PrehSRR8Gn0IjlEg
C68EY6KPE+FKySuS7Ur7lTAjNdddfdAgKV6hJyST6/dx8ymIkb8nxCPnxCcT2I2N
vDxcPMc/wmnMa+smNal0sJ6m
-----END CERTIFICATE-----', 
CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(),2);


INSERT INTO iam_account_authority(account_id, authority_id) VALUES
(2,2);

-- test groups
INSERT INTO iam_group(id, parent_group_id, name, uuid, description, creationtime, lastupdatetime) VALUES
(1, null, 'indigo-dc', 'ff8b5c1e-c0d2-40d1-8216-9896f2570077', 'indigo-dc root group', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
(2, 1, 'indigo-dc/subgroup', '28c829f0-9c16-43e7-82a0-ea893ec4fce5', 'indigo-dc subgroup', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
(3, 1, 'indigo-dc/another-subgroup', 'e17ca24b-4772-4e64-a30e-49b394c91503', 'indigo-dc another-subgroup', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
(4, 1, 'indigo-dc/production', 'e9dd63e1-af45-4691-99c4-2d2b5bf5d66a', 'indigo-dc production role', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
(5, 2, 'indigo-dc/subgroup/production', '5bea3ff8-64a6-43a9-a1f5-3354587f68b9', 'indigo-dc subgroup production role', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()));

-- test groups membership
INSERT INTO iam_account_group(account_id, group_id) VALUES
(2,1);



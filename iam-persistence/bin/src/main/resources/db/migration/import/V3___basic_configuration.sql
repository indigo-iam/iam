INSERT INTO iam_authority(ID, AUTH) VALUES
(1, 'ROLE_ADMIN'),
(2, 'ROLE_USER');

INSERT INTO iam_user_info(ID,GIVENNAME,FAMILYNAME, EMAIL, EMAILVERIFIED) VALUES
(1, 'Admin', 'User', 'admin@iam.test', true);

INSERT INTO iam_account(id, uuid, username, password, user_info_id, creationtime, lastupdatetime, active) VALUES
(1, '73f16d93-2441-4a50-88ff-85360d78c6b5', 'admin', 'password', 1, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), true);

INSERT INTO iam_account_authority(account_id, authority_id) VALUES
(1,1),
(1,2);

INSERT INTO client_details (id, client_id, client_secret, client_name, dynamically_registered, refresh_token_validity_seconds, access_token_validity_seconds, id_token_validity_seconds, allow_introspection, token_endpoint_auth_method) VALUES
 (1, 'client', 'secret', 'Test Client', false, null, 3600, 600, true, 'SECRET_BASIC');

INSERT INTO client_grant_type (owner_id, grant_type) VALUES
   (1, 'password');
-- TOKEN_SCOPE

DELETE from token_scope where owner_id not in (select id from access_token);
ALTER TABLE token_scope ALTER COLUMN owner_id SET NOT NULL;
ALTER TABLE token_scope ALTER COLUMN scope SET NOT NULL;
ALTER TABLE token_scope ADD CONSTRAINT FK_token_scope_owner_id FOREIGN KEY (owner_id) REFERENCES access_token (id) ON DELETE CASCADE;

-- CLIENT_DETAILS related TABLES

DELETE FROM client_request_uri WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_request_uri ADD CONSTRAINT FK_client_request_uri_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_post_logout_redirect_uri WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_post_logout_redirect_uri ADD CONSTRAINT FK_client_post_logout_redirect_uri_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_default_acr_value WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_default_acr_value ADD CONSTRAINT FK_client_default_acr_value_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_contact WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_contact ADD CONSTRAINT FK_client_contact_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_redirect_uri WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_redirect_uri ADD CONSTRAINT FK_client_redirect_uri_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_claims_redirect_uri WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_claims_redirect_uri ADD CONSTRAINT FK_client_claims_redirect_uri_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_scope WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_scope ADD CONSTRAINT FK_client_scope_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

-- AUTHENTICATION HOLDER and related

DELETE FROM authentication_holder_scope WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_scope ADD CONSTRAINT FK_authentication_holder_scope_owner_id FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder_response_type WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_response_type ADD CONSTRAINT FK_authentication_holder_response_type_owner_id FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder_resource_id WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_resource_id ADD CONSTRAINT FK_authentication_holder_resource_id_owner_id FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder_request_parameter WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_request_parameter ADD CONSTRAINT FK_authentication_holder_request_parameter_owner_id FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder_extension WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_extension ADD CONSTRAINT FK_authentication_holder_extension_owner_id FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder_authority WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_authority ADD CONSTRAINT FK_authentication_holder_authority_owner_id FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder
WHERE id NOT IN (SELECT auth_holder_id FROM access_token)
AND id NOT IN (SELECT auth_holder_id FROM refresh_token)
AND id NOT IN (SELECT auth_holder_id FROM authorization_code);

DELETE FROM authentication_holder WHERE user_auth_id NOT IN (SELECT id FROM saved_user_auth);
ALTER TABLE authentication_holder ADD CONSTRAINT FK_authentication_holder_user_auth_id FOREIGN KEY (user_auth_id) REFERENCES saved_user_auth (id) ON DELETE CASCADE;
DELETE FROM authentication_holder WHERE client_id NOT IN (SELECT client_id FROM client_details);
ALTER TABLE authentication_holder ADD CONSTRAINT FK_authentication_holder_client_id FOREIGN KEY (client_id) REFERENCES client_details (client_id) ON UPDATE CASCADE ON DELETE CASCADE;

-- ACCESS TOKEN TABLE and related

DELETE FROM access_token_permissions WHERE access_token_id NOT IN (SELECT id FROM access_token);
DELETE FROM access_token_permissions WHERE permission_id NOT IN (SELECT id FROM permission);

ALTER TABLE access_token_permissions ADD PRIMARY KEY (access_token_id, permission_id);
ALTER TABLE access_token_permissions ADD CONSTRAINT FK_access_token_permissions_access_token_id FOREIGN KEY (access_token_id) REFERENCES access_token (id) ON DELETE CASCADE;
ALTER TABLE access_token_permissions ADD CONSTRAINT FK_access_token_permissions_permission_id FOREIGN KEY (permission_id) REFERENCES permission (id) ON DELETE CASCADE;

DELETE FROM access_token WHERE refresh_token_id NOT IN (SELECT id FROM refresh_token);
DELETE FROM access_token WHERE client_id NOT IN (SELECT id FROM client_details);
DELETE FROM access_token WHERE auth_holder_id NOT IN (SELECT id FROM authentication_holder);

ALTER TABLE access_token ADD CONSTRAINT FK_access_token_refresh_token_id FOREIGN KEY (refresh_token_id) REFERENCES refresh_token (id) ON DELETE CASCADE;
ALTER TABLE access_token ADD CONSTRAINT FK_access_token_client_id FOREIGN KEY (client_id) REFERENCES client_details (id) ON DELETE CASCADE;
ALTER TABLE access_token ADD CONSTRAINT FK_access_token_auth_holder_id FOREIGN KEY (auth_holder_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

-- REFRESH TOKEN

DELETE FROM refresh_token WHERE client_id NOT IN (SELECT id FROM client_details);
ALTER TABLE refresh_token ADD CONSTRAINT FK_refresh_token_client_id FOREIGN KEY (client_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM refresh_token WHERE auth_holder_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE refresh_token ADD CONSTRAINT FK_refresh_token_auth_holder_id FOREIGN KEY (auth_holder_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

-- AUTHORIZATION CODE

DELETE FROM authorization_code WHERE auth_holder_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authorization_code ADD CONSTRAINT FK_authorization_code_auth_holder_id FOREIGN KEY (auth_holder_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

-- APPROVED SITE

DELETE FROM approved_site WHERE client_id NOT IN (SELECT client_id FROM client_details);
ALTER TABLE approved_site ADD CONSTRAINT FK_approved_site_client_id FOREIGN KEY (client_id) REFERENCES client_details (client_id) ON UPDATE CASCADE ON DELETE CASCADE;

DELETE FROM approved_site_scope WHERE owner_id NOT IN (SELECT id FROM approved_site);
ALTER TABLE approved_site_scope ADD CONSTRAINT FK_approved_site_scope_owner_id FOREIGN KEY (owner_id) REFERENCES approved_site (id) ON DELETE CASCADE;

-- TOKEN_SCOPE

DELETE from token_scope where owner_id not in (select id from access_token);
ALTER TABLE token_scope ALTER COLUMN owner_id SET NOT NULL;
ALTER TABLE token_scope ALTER COLUMN scope SET NOT NULL;
ALTER TABLE token_scope ADD FOREIGN KEY (owner_id) REFERENCES access_token (id) ON DELETE CASCADE;

-- CLIENT_DETAILS related TABLES

DELETE FROM client_request_uri WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_request_uri ADD FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_post_logout_redirect_uri WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_post_logout_redirect_uri ADD FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_default_acr_value WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_default_acr_value ADD FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_contact WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_contact ADD FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_redirect_uri WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_redirect_uri ADD FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_claims_redirect_uri WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_claims_redirect_uri ADD FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_scope WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_scope ADD FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

-- AUTHENTICATION HOLDER and related

DELETE FROM authentication_holder_scope WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_scope ADD FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder_response_type WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_response_type ADD FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder_resource_id WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_resource_id ADD FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder_request_parameter WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_request_parameter ADD FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder_extension WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_extension ADD FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder_authority WHERE owner_id NOT IN (SELECT id FROM authentication_holder);
ALTER TABLE authentication_holder_authority ADD FOREIGN KEY (owner_id) REFERENCES authentication_holder (id) ON DELETE CASCADE;

DELETE FROM authentication_holder
WHERE id NOT IN (SELECT auth_holder_id FROM access_token)
AND id NOT IN (SELECT auth_holder_id FROM refresh_token)
AND id NOT IN (SELECT auth_holder_id FROM authorization_code);

DELETE FROM authentication_holder WHERE user_auth_id NOT IN (SELECT id FROM saved_user_auth);
ALTER TABLE authentication_holder ADD FOREIGN KEY (user_auth_id) REFERENCES saved_user_auth (id) ON DELETE CASCADE;
DELETE FROM authentication_holder WHERE client_id NOT IN (SELECT client_id FROM client_details);
ALTER TABLE authentication_holder ADD FOREIGN KEY (client_id) REFERENCES client_details (client_id) ON UPDATE CASCADE ON DELETE CASCADE;

-- ACCESS TOKEN TABLE and related

DELETE FROM access_token_permissions WHERE access_token_id NOT IN (SELECT id FROM access_token);
DELETE FROM access_token_permissions WHERE permission_id NOT IN (SELECT id FROM permission);

ALTER TABLE access_token_permissions ADD PRIMARY KEY (access_token_id, permission_id);
ALTER TABLE access_token_permissions ADD FOREIGN KEY (access_token_id) REFERENCES access_token (id) ON DELETE CASCADE;
ALTER TABLE access_token_permissions ADD FOREIGN KEY (permission_id) REFERENCES permission (id) ON DELETE CASCADE;

DELETE FROM access_token WHERE refresh_token_id NOT IN (SELECT id FROM refresh_token);
DELETE FROM access_token WHERE client_id NOT IN (SELECT id FROM client_details);
DELETE FROM access_token WHERE auth_holder_id NOT IN (SELECT id FROM authentication_holder);

ALTER TABLE access_token ADD FOREIGN KEY (refresh_token_id) REFERENCES refresh_token (id) ON DELETE SET NULL;
ALTER TABLE access_token ADD FOREIGN KEY (client_id) REFERENCES client_details (id) ON DELETE SET NULL;
ALTER TABLE access_token ADD FOREIGN KEY (auth_holder_id) REFERENCES authentication_holder (id) ON DELETE SET NULL;

-- REFRESH TOKEN

DELETE FROM refresh_token WHERE client_id NOT IN (SELECT id FROM client_details);
ALTER TABLE refresh_token ADD FOREIGN KEY (client_id) REFERENCES client_details (id) ON DELETE SET NULL;

-- APPROVED SITE

DELETE FROM approved_site WHERE client_id NOT IN (SELECT id FROM client_details);
ALTER TABLE approved_site ADD FOREIGN KEY (client_id) REFERENCES client_details (client_id) ON UPDATE CASCADE ON DELETE SET NULL;

DELETE FROM approved_site_scope WHERE owner_id NOT IN (SELECT id FROM approved_site);
ALTER TABLE approved_site_scope ADD FOREIGN KEY (owner_id) REFERENCES approved_site (id) ON DELETE CASCADE;

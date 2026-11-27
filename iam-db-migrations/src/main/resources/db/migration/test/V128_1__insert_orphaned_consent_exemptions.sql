-- Insert orphaned consent exemption
INSERT INTO whitelisted_site (creator_user_id, client_id)
VALUES ('test-user', 'orphan-client');

-- Insert orphaned scope
INSERT INTO whitelisted_site_scope (owner_id, scope)
VALUES (999999, 'openid');
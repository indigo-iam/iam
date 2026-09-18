-- Add matching policy to scope policy
ALTER TABLE iam_scope_policy ADD matching_policy VARCHAR(6);
UPDATE iam_scope_policy set matching_policy = 'EQ';
ALTER TABLE iam_scope_policy MODIFY matching_policy VARCHAR(6) default 'EQ' NOT NULL;

-- This is just to avoid zero date errors on MySQL in strict mode
ALTER TABLE iam_group_request 
  MODIFY LASTUPDATETIME TIMESTAMP DEFAULT '2000-01-01 00:00:00';

-- Profile scopes
INSERT INTO system_scope(scope, description, icon, restricted, default_scope, structured, structured_param_description) 
VALUES 
('urn:indigo-iam.github.io:jwt-profile#wlcg-1.0','Tags a client to use the WLCG JWT profile', null, false, false, true, null),
('urn:indigo-iam.github.io:jwt-profile#iam','Tags a client to use the IAM JWT profile', null, false, false, true, null);
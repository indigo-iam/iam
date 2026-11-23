-- Add creation time to ssh keys
ALTER TABLE iam_ssh_key ADD COLUMN creation_time TIMESTAMP NOT null;
-- Add last update time to ssh keys
ALTER TABLE iam_ssh_key ADD COLUMN last_update_time TIMESTAMP NOT null;
-- Restrict access to ssh-keys scope
INSERT INTO system_scope(scope, description, icon, restricted, default_scope, structured, structured_param_description) 
  VALUES 
  ('ssh-keys','Authorizes access to SSH keys linked to IAM accounts via the IAM userinfo endpoint', null, true, false, true, null);
INSERT INTO iam_authority(AUTH) VALUES
('ROLE_USER_MANAGER');

INSERT INTO system_scope(scope, description, icon, restricted, default_scope, structured, structured_param_description)
  VALUES
  ('iam:user.read', 'Read access to IAM user management APIs', null, true, false, false, null);
INSERT INTO system_scope(scope, description, icon, restricted, default_scope, structured, structured_param_description)
  VALUES
  ('iam:user.write', 'Write access to IAM user management APIs', null, true, false, false, null);

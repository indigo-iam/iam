INSERT INTO iam_authority(AUTH) VALUES
('ROLE_USER_MANAGER');

INSERT IGNORE INTO system_scope(scope, description, icon, restricted, default_scope, structured, structured_param_description)
  VALUES
  ('iam:user.read', 'Read access to IAM user management APIs', null, true, false, false, null),
  ('iam:user.write', 'Write access to IAM user management APIs', null, true, false, false, null);

UPDATE system_scope SET restricted = true WHERE scope IN ('iam:user.read', 'iam:user.write');

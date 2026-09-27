INSERT INTO system_scope(scope, description, icon, restricted, default_scope, structured, structured_param_description) 
  VALUES
  ('scim','Authorizes access to IAM SCIM APIs', null, true, false, false, null),
  ('registration','Authorizes access to IAM registration APIs', null, true, false, false, null);
  
UPDATE system_scope 
  set structured = true, 
  structured_param_description = 'write access to IAM SCIM APIs'
  where scope = 'scim:write';

UPDATE system_scope 
  set structured = true,
  structured_param_description = 'read access to IAM SCIM APIs'
  where scope = 'scim:read';
  
UPDATE system_scope 
  set structured = true, 
  structured_param_description = 'write access to IAM registration APIs'
  where scope = 'registration:write';

UPDATE system_scope 
  set structured = true,
  structured_param_description = 'read access to IAM registration APIs'
  where scope = 'registration:read';
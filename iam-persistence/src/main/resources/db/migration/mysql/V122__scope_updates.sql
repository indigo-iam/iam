DELETE FROM system_scope WHERE scope = 'scim';

UPDATE system_scope 
  SET structured = false, 
  structured_param_description = null,
  description = 'Authorizes write access to SCIM user and groups'
  WHERE scope = 'scim:write';

UPDATE system_scope 
  SET structured = false, 
  structured_param_description = null,
  description = 'Authorizes read access to SCIM user and groups'
  WHERE scope = 'scim:read';

DELETE FROM system_scope WHERE scope = 'registration';

UPDATE system_scope 
  SET structured = false, 
  structured_param_description = null,
  description = 'Grants write access to registration requests'
  WHERE scope = 'registration:write';

UPDATE system_scope 
  SET structured = false, 
  structured_param_description = null,
  description = 'Grants read access to registration requests'
  WHERE scope = 'registration:read';

UPDATE system_scope 
  SET structured = false, 
  structured_param_description = null,
  description = 'Authorizes access to IAM Proxy APIs'
  WHERE scope = 'proxy:generate';

DELETE FROM system_scope WHERE scope = 'ssh-keys';

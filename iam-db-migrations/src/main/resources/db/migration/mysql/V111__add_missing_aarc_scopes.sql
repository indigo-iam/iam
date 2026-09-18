INSERT IGNORE INTO system_scope(scope, description, icon, restricted, default_scope, structured, structured_param_description)
  VALUES
  ('aarc', 'Get all eduPerson schema info', 'address-card', false, false, false, null),
  ('voperson_external_affiliation', 'Access to the home organisations that the user is affiliated with.', null, false, false, false, null);

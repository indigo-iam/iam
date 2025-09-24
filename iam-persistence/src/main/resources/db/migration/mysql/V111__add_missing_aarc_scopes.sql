INSERT IGNORE INTO system_scope(scope, description, icon, restricted, default_scope, structured, structured_param_description)
  VALUES
  ('aarc', 'Get all eduPerson schema info', 'address-card', false, false, false, null),
  ('voperson_scoped_affiliation', "Access to user's affiliation within the Community/Research infrastructure in broad categories defined in the eduPerson schema", 'address-card', false, false, false, null),
  ('voperson_id', "Access to the string representation of the subject's identifier that is globally unique", 'id-badge', false, false, false, null),
  ('voperson_external_affiliation', 'Access to the home organisations that the user is affiliated with.', null, false, false, false, null);

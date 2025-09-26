UPDATE system_scope
  SET description = 'Access to EduPerson scoped affiliation information (DEPRECATED)'
  WHERE scope = 'eduperson_scoped_affiliation';

UPDATE system_scope
  SET description = 'Access to EduPerson entitlements information (DEPRECATED)'
  where scope = 'eduperson_entitlement';

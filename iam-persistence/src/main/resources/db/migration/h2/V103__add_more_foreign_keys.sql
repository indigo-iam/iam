DELETE FROM device_code_request_parameter WHERE owner_id NOT IN (SELECT id FROM device_code);
ALTER TABLE device_code_request_parameter ALTER COLUMN owner_id SET NOT NULL;
ALTER TABLE device_code_request_parameter ADD CONSTRAINT FK_device_code_request_parameter_owner_id FOREIGN KEY (owner_id) REFERENCES device_code (id) ON DELETE CASCADE;

DELETE FROM device_code_scope WHERE owner_id NOT IN (SELECT id FROM device_code);
ALTER TABLE device_code_scope ALTER COLUMN owner_id SET NOT NULL;
ALTER TABLE device_code_scope ALTER COLUMN scope SET NOT NULL;
ALTER TABLE device_code_scope ADD CONSTRAINT FK_device_code_scope_owner_id FOREIGN KEY (owner_id) REFERENCES device_code (id) ON DELETE CASCADE;

DELETE FROM device_code WHERE client_id NOT IN (SELECT id FROM client_details);
ALTER TABLE device_code ALTER COLUMN client_id SET NOT NULL;
ALTER TABLE device_code ADD CONSTRAINT FK_device_code_client_id FOREIGN KEY (client_id) REFERENCES client_details (client_id) ON DELETE CASCADE;

DELETE FROM client_response_type WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_response_type ALTER COLUMN owner_id SET NOT NULL;
ALTER TABLE client_response_type ALTER COLUMN response_type SET NOT NULL;
ALTER TABLE client_response_type ADD PRIMARY KEY (owner_id, response_type);
ALTER TABLE client_response_type ADD CONSTRAINT FK_client_response_type_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_grant_type WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_grant_type ALTER COLUMN owner_id SET NOT NULL;
ALTER TABLE client_grant_type ALTER COLUMN grant_type SET NOT NULL;
ALTER TABLE client_grant_type ADD PRIMARY KEY (owner_id, grant_type);
ALTER TABLE client_grant_type ADD CONSTRAINT FK_client_grant_type_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_resource WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_resource ALTER COLUMN owner_id SET NOT NULL;
ALTER TABLE client_resource ALTER COLUMN resource_id SET NOT NULL;
ALTER TABLE client_resource ADD PRIMARY KEY (owner_id, resource_id);
ALTER TABLE client_resource ADD CONSTRAINT FK_client_resource_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM device_code_request_parameter WHERE owner_id NOT IN (SELECT id FROM device_code);
ALTER TABLE device_code_request_parameter MODIFY COLUMN owner_id BIGINT(20) NOT NULL;
ALTER TABLE device_code_request_parameter ADD CONSTRAINT FK_device_code_request_parameter_owner_id FOREIGN KEY (owner_id) REFERENCES device_code (id) ON DELETE CASCADE;

DELETE FROM device_code_scope WHERE owner_id NOT IN (SELECT id FROM device_code);
ALTER TABLE device_code_scope MODIFY COLUMN owner_id BIGINT(20) NOT NULL;
ALTER TABLE device_code_scope MODIFY COLUMN scope VARCHAR(256) NOT NULL;
ALTER TABLE device_code_scope ADD CONSTRAINT FK_device_code_scope_owner_id FOREIGN KEY (owner_id) REFERENCES device_code (id) ON DELETE CASCADE;

DELETE FROM device_code WHERE client_id NOT IN (SELECT id FROM client_details);
ALTER TABLE device_code MODIFY COLUMN client_id VARCHAR(256) NOT NULL;
ALTER TABLE device_code ADD CONSTRAINT FK_device_code_client_id FOREIGN KEY (client_id) REFERENCES client_details (client_id) ON DELETE CASCADE;

DELETE FROM client_response_type WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_response_type MODIFY COLUMN owner_id BIGINT(20) NOT NULL;
ALTER TABLE client_response_type MODIFY COLUMN response_type VARCHAR(2000) NOT NULL;
ALTER TABLE client_response_type ADD PRIMARY KEY (owner_id, response_type);
ALTER TABLE client_response_type ADD CONSTRAINT FK_client_response_type_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_grant_type WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_grant_type MODIFY COLUMN owner_id BIGINT(20) NOT NULL;
ALTER TABLE client_grant_type MODIFY COLUMN grant_type VARCHAR(2000) NOT NULL;
ALTER TABLE client_grant_type ADD PRIMARY KEY (owner_id, grant_type);
ALTER TABLE client_grant_type ADD CONSTRAINT FK_client_grant_type_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;

DELETE FROM client_resource WHERE owner_id NOT IN (SELECT id FROM client_details);
ALTER TABLE client_resource MODIFY COLUMN owner_id BIGINT(20) NOT NULL;
ALTER TABLE client_resource MODIFY COLUMN resource_id VARCHAR(256) NOT NULL;
ALTER TABLE client_resource ADD PRIMARY KEY (owner_id, resource_id);
ALTER TABLE client_resource ADD CONSTRAINT FK_client_resource_owner_id FOREIGN KEY (owner_id) REFERENCES client_details (id) ON DELETE CASCADE;
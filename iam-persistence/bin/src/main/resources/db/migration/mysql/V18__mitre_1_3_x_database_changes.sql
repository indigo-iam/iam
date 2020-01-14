CREATE INDEX at_ahi_idx ON access_token(auth_holder_id);
CREATE INDEX aha_oi_idx ON authentication_holder_authority(owner_id);
CREATE INDEX ahe_oi_idx ON authentication_holder_extension(owner_id);
CREATE INDEX ahrp_oi_idx ON authentication_holder_request_parameter(owner_id);
CREATE INDEX ahri_oi_idx ON authentication_holder_resource_id(owner_id);
CREATE INDEX ahrt_oi_idx ON authentication_holder_response_type(owner_id);
CREATE INDEX ahs_oi_idx ON authentication_holder_scope(owner_id);
CREATE INDEX ac_ahi_idx ON authorization_code(auth_holder_id);
CREATE INDEX suaa_oi_idx ON saved_user_auth_authority(owner_id);

-- Create unique index on token value
ALTER TABLE access_token add UNIQUE(token_value(766));

-- Add new fields to client details
ALTER TABLE client_details ADD software_id VARCHAR(2048);
ALTER TABLE client_details ADD software_version VARCHAR(2048);
ALTER TABLE client_details ADD device_code_validity_seconds BIGINT;

-- Device code
CREATE TABLE device_code (
   id BIGINT AUTO_INCREMENT PRIMARY KEY,
   device_code VARCHAR(1024),
   user_code VARCHAR(1024),
   expiration TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
   client_id VARCHAR(256),
   approved BOOLEAN,
   auth_holder_id BIGINT);
   
CREATE TABLE device_code_scope (
   owner_id BIGINT NOT NULL,
   scope VARCHAR(256) NOT NULL);
 
CREATE TABLE device_code_request_parameter (
   owner_id BIGINT,
   param VARCHAR(2048),
   val VARCHAR(2048));

CREATE TABLE IF NOT EXISTS client_federation_metadata (
  client_details_id BIGINT PRIMARY KEY,
  expiration TIMESTAMP NOT NULL,
  entity_id VARCHAR(512) NOT NULL UNIQUE);

ALTER TABLE client_federation_metadata ADD CONSTRAINT fk_client_expiration FOREIGN KEY (client_details_id) REFERENCES client_details(id);

CREATE TABLE IF NOT EXISTS client_relying_party (
  client_details_id BIGINT PRIMARY KEY,
  expiration TIMESTAMP NOT NULL,
  entity_id VARCHAR(512) NOT NULL);

ALTER TABLE client_relying_party ADD CONSTRAINT fk_client_expiration FOREIGN KEY (client_details_id) REFERENCES client_details(id);

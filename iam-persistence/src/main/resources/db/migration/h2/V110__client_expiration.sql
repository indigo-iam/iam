CREATE TABLE IF NOT EXISTS client_expiration (
  client_details_id BIGINT PRIMARY KEY,
  expiration TIMESTAMP NOT NULL);

ALTER TABLE client_expiration ADD CONSTRAINT fk_client_expiration FOREIGN KEY (client_details_id) REFERENCES client_details(id);

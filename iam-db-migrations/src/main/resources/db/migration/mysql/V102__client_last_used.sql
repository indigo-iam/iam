CREATE TABLE IF NOT EXISTS client_last_used (
  client_details_id BIGINT PRIMARY KEY,
  last_used TIMESTAMP NOT NULL);

ALTER TABLE client_last_used ADD CONSTRAINT fk_client_last_used FOREIGN KEY (client_details_id) REFERENCES client_details(id);

ALTER TABLE client_details ADD last_used_id BIGINT DEFAULT NULL;

CREATE TABLE IF NOT EXISTS client_last_used (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  last_used DATE NOT NULL);

ALTER TABLE client_details ADD CONSTRAINT fk_client_last_used FOREIGN KEY (last_used_id) REFERENCES client_last_used(id);
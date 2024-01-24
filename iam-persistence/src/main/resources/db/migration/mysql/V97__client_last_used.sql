
ALTER TABLE client_details ADD last_used BIGINT DEFAULT NULL;

CREATE TABLE IF NOT EXISTS iam_client_last_used (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  last_used DATE NOT NULL);

ALTER TABLE client_details ADD CONSTRAINT fk_iam_client_last_used FOREIGN KEY (last_used) REFERENCES iam_client_last_used(id);

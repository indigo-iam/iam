ALTER TABLE client_details ADD COLUMN active BOOLEAN,
                          ADD COLUMN status_changed_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          ADD COLUMN status_changed_by VARCHAR(36);

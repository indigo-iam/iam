ALTER TABLE client_details ADD COLUMN (active BOOLEAN, 
                                        status_changed_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                        status_changed_by VARCHAR(36));
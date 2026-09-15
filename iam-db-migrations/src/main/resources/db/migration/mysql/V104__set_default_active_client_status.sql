ALTER TABLE client_details MODIFY COLUMN active BOOLEAN DEFAULT true;

UPDATE client_details SET active = true;
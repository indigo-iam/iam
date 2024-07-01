ALTER TABLE client_details ALTER COLUMN active SET DEFAULT true;

UPDATE client_details SET active = true;
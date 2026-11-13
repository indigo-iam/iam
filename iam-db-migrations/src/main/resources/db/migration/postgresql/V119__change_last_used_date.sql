-- Truncate the time part of the last used timestamp
ALTER TABLE client_last_used
  ALTER COLUMN last_used TYPE DATE USING last_used::date;

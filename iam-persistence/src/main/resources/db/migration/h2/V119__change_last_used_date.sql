-- 1. Add new column
ALTER TABLE client_last_used
ADD COLUMN last_used_date DATE;

-- 2. Copy data
UPDATE client_last_used
SET last_used_date = CAST(last_used AS DATE);

-- 3. Make NOT NULL
ALTER TABLE client_last_used
ALTER COLUMN last_used_date SET NOT NULL;

-- 4. Drop old column
ALTER TABLE client_last_used
DROP COLUMN last_used;

-- 5. Rename column
ALTER TABLE client_last_used
ALTER COLUMN last_used_date RENAME TO last_used;
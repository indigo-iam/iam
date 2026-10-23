-- 1. Add new column
ALTER TABLE client_last_used
ADD COLUMN last_used_date DATE;

-- 2. Copy data (truncate time part automatically)
UPDATE client_last_used
SET last_used_date = DATE(last_used);

-- 3. Make new column NOT NULL (after verifying data)
ALTER TABLE client_last_used
MODIFY last_used_date DATE NOT NULL;

-- 4. Drop old column
ALTER TABLE client_last_used
DROP COLUMN last_used;

-- 5. Rename column to original name
ALTER TABLE client_last_used
CHANGE last_used_date last_used DATE NOT NULL;
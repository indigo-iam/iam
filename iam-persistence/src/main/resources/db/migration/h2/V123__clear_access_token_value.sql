-- Access token JWT values are now transient.
-- Preserve token hashes and metadata for token lookup and management.
-- Keep the token_value column until a subsequent release.
UPDATE access_token
SET token_value = NULL
WHERE token_value IS NOT NULL;
UPDATE access_token
SET token_value_hash = SHA2(token_value, 256)
WHERE id IN (SELECT DISTINCT(owner_id) FROM token_scope WHERE scope = "registration-token");
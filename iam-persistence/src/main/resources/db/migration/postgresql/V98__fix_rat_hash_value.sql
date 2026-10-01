UPDATE access_token
SET token_value_hash = encode(sha256(convert_to(token_value, 'UTF8')), 'hex')
WHERE id IN (SELECT DISTINCT(owner_id) FROM token_scope WHERE scope = 'registration-token');

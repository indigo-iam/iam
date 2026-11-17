DELETE FROM client_grant_type
WHERE grant_type = 'client_credentials'
  AND owner_id IN (
    SELECT id
    FROM client_details
    WHERE token_endpoint_auth_method = 'NONE'
  );

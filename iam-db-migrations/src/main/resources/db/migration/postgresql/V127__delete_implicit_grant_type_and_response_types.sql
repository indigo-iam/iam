DELETE FROM client_grant_type
WHERE grant_type = 'implicit';

DELETE FROM client_response_type
WHERE response_type IN (
  'token',
  'id_token',
  'token id_token',
  'id_token token',
  'code token',
  'code id_token',
  'code token id_token'
);
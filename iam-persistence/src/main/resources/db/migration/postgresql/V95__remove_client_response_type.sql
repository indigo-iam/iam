-- Delete unsupported response types
delete from client_response_type where response_type in ('code token id_token', 'code token', 'code id_token', 'token id_token', 'id_token');
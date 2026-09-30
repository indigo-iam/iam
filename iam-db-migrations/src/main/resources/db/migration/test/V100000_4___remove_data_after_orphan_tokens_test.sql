-- Delete test data created by V100000_2 migration

DELETE FROM authentication_holder WHERE id=1;
DELETE FROM saved_user_auth WHERE id=1;
DELETE FROM saved_user_auth_authority WHERE owner_id=1;
DELETE FROM authentication_holder_scope WHERE owner_id=1;
DELETE FROM authentication_holder_extension WHERE owner_id=1;
DELETE FROM authentication_holder_request_parameter WHERE owner_id=1;
INSERT INTO iam_user_info(ID, GIVENNAME, FAMILYNAME, EMAIL, EMAILVERIFIED, BIRTHDATE, GENDER, NICKNAME) VALUES
  (6, 'Test', 'MFA', 'testwithmfa@iam.test', true, '2000-01-01','F','testwithmfa');

INSERT INTO iam_account(id, uuid, username, password, user_info_id, creationtime, lastupdatetime, active) VALUES
  (6, '467c882e-90da-11ec-b909-0242ac120002', 'test-with-mfa', '$2a$12$S3lUZw/ESq9lULn5he6bBu9KNGCvs7C2rWo0XdVC6t65ITwAc22w2', 6, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), true);

insert into iam_totp_mfa(active, secret, creation_time, last_update_time, account_id) VALUES
  (true, 'secret', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), 6);

INSERT INTO iam_user_info(ID,GIVENNAME,FAMILYNAME, EMAIL, EMAILVERIFIED, BIRTHDATE, GENDER) VALUES
(3, 'Duplicate', 'Email 0', 'admin@iam.test', true, '1950-01-01', 'M');

INSERT INTO iam_account(id, uuid, username, password, user_info_id, creationtime, lastupdatetime, active, mfa_enabled, totp_mfa_id) VALUES
(3, 'bffc67b7-47fe-410c-a6a0-cf00173a8fbb', 'dup_email_0', '$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni', 
3, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), true, false, null);

INSERT INTO iam_user_info(ID,GIVENNAME,FAMILYNAME, EMAIL, EMAILVERIFIED, BIRTHDATE, GENDER) VALUES
(4, 'Duplicate ', 'Email 1', 'duplicate@iam.test', true, '1950-01-01', 'M');

INSERT INTO iam_account(id, uuid, username, password, user_info_id, creationtime, lastupdatetime, active, mfa_enabled, totp_mfa_id) VALUES
(4, '0a6fa72a-fb75-4a6c-9734-bfe673df70b3', 'dup_email_1', '$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni', 
4, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), true, false, null);

INSERT INTO iam_user_info(ID,GIVENNAME,FAMILYNAME, EMAIL, EMAILVERIFIED, BIRTHDATE, GENDER) VALUES
(5, 'Duplicate ', 'Email 2', 'duplicate@iam.test', true, '1950-01-01', 'M');

INSERT INTO iam_account(id, uuid, username, password, user_info_id, creationtime, lastupdatetime, active, mfa_enabled, totp_mfa_id) VALUES
(5, 'd836e5ec-246c-456c-8476-923ee2f831c8', 'dup_email_2', '$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni', 
5, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), true, false, null);
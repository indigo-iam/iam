INSERT INTO iam_user_info(ID, GIVENNAME, FAMILYNAME, EMAIL, EMAILVERIFIED) VALUES
  (10, 'Production', 'Manager', 'prod.manager@iam.test', true);

INSERT INTO iam_account(ID, UUID, USERNAME, PASSWORD, USER_INFO_ID, CREATIONTIME, LASTUPDATETIME, ACTIVE) VALUES
  (10, '8F9652DA-14D6-4674-A3B8-2AA091C841FD', 'manager', '$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni', 10, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), true);

INSERT INTO iam_account_group(account_id, group_id) VALUES
  (10,1);

INSERT INTO iam_account_authority(account_id, authority_id) VALUES
  (10,2),
  (10,5);

INSERT INTO iam_account_attrs(ACCOUNT_ID, NAME, VAL) VALUES
  (10, 'affiliation', 'INFN-CNAF');
# DB dump

This folder contains db dump for performance tests.

In order to load the db with N policies applied to the user identified by its ID in the db (for instance, _admin_ is 1 and _test_ is 2) enter in the `db` container and run

```bash
mysql -u iam -ppwd iam < /tmp/scripts/generate_policies.sql
mysql -u iam -ppwd iam -e "CALL generate_test_policies(5000, 2);"
```

Delete the stored procedure once the tests are over with

```bash
mysql -u iam -ppwd iam -e "DROP PROCEDURE generate_test_policies;"
```
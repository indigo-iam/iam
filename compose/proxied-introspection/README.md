# Embedded proxy introspection

This compose allows to test the proxy introspection embedded in the IAM code.

Requirements:

- add to your `/etc/hosts` file the following line
  ```
  127.0.0.1   iam.local.io  iam-remote.local.io
  ```
- login to https://iam-remote.local.io as admin user (admin/password) and edit the client with ID `client` by adding the following redirect URIs: `https://iam-remote.local.io/iam-test-client/openid_connect_login` (remember to save the client)

## Testing the embedded proxy introspection

Get an access token from https://iam-remote.local.io. The easier way is to use the `iam-test-client` application, so
go to this URL `https://iam-remote.local.io/iam-test-client`. After successful login, the access token is shown on the top. Copy the token and save it in a shell variable, e.g.

```bash
$ AT=eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJ3bGNnLnZlciI6IjEuMCIsInN1YiI6IjczZjE2ZDkzLTI0NDEtNGE1MC04OGZmLTg1MzYwZDc4YzZiNSIsImF1ZCI6WyJodHRwOi8vZXhhbXBsZTEuY29tIiwiaHR0cDovL2V4YW1wbGUyLmNvbSIsImh0dHA6Ly9leGFtcGxlMy5jb20iXSwibmJmIjoxNzY5MDgyMjY2LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIG9mZmxpbmVfYWNjZXNzIGVtYWlsIiwiYXV0aF90aW1lIjoxNzY5MDgyMjkzLCJpc3MiOiJodHRwczovL2lhbS1yZW1vdGUubG9jYWwuaW8vIiwiZXhwIjoxNzY5MDg1OTI1LCJpYXQiOjE3NjkwODIzMjYsImp0aSI6ImFmZmY3MWVhLWE3NTUtNGFiZC1iMDJiLWJhNzdmNmVlOWVlMCIsImNsaWVudF9pZCI6ImNsaWVudCJ9.hSgE6EVtWwrRtSaG0kKr6lfDXyFJCneiS4i3Bp1OWxSC611AZZJjQ00coZcQK0el3WT4uUMhKLk0_4R9qgIszMf_PNwTBgH6LfqGVB-IJwuaQ1L9LsIK9xtc85NJskKpJZu-WRmAJml5x7uTcEFWD_SFp3ufOIUOBV4HzYtYvh1ybLnFL1RW4_HzUzWyKEkG6uyaLU18Yy6lYsHCteb-MAtTtWG1CoOFXgokzrp_jxtD7eUNnDDRcYJQuIn91nqOkMkFriGMO05KHcLK8pIPoOueISXMaghWuas1MmAOjT32qBdM6sqTXQvsFKVuOtpH7bIJJL6FeQ5zVl3FfhObCQ
```

Check the content of the access token with:

```bash
$ echo $AT | cut -d . -f2 | base64 -d 2>/dev/null | jq .
{
  "wlcg.ver": "1.0",
  "sub": "73f16d93-2441-4a50-88ff-85360d78c6b5",
  "aud": [
    "http://example1.com",
    "http://example2.com",
    "http://example3.com"
  ],
  "nbf": 1769082266,
  "scope": "openid profile offline_access email",
  "auth_time": 1769082293,
  "iss": "https://iam-remote.local.io/",
  "exp": 1769085925,
  "iat": 1769082326,
  "jti": "afff71ea-a755-4abd-b02b-ba77f6ee9ee0",
  "client_id": "client"
}
```

and cross-check that it is issued by `iam-remote`.

Now, if we introspect the token using another IAM (here `iam-be`), since the token is not known to t`iam-be` it will forward the token to the introspection endpoint of the proper issuer (i.e. `iam-remote`). Test it with the following command:

```bash
$ curl https://iam.local.io/introspect -u client:secret -d token=$AT -k -s | jq .
{
  "active": true,
  "sub": "73f16d93-2441-4a50-88ff-85360d78c6b5",
  "iss": "https://iam-remote.local.io/",
  "token_type": "ACCESS_TOKEN",
  "client_id": "client",
  "wlcg.ver": "1.0",
  "aud": [
    "http://example1.com",
    "http://example2.com",
    "http://example3.com"
  ],
  "nbf": 1769082266.000000000,
  "scope": [
    "openid",
    "email",
    "profile",
    "offline_access"
  ],
  "auth_time": 1769082293,
  "exp": 1769085925.000000000,
  "iat": 1769082326.000000000,
  "jti": "afff71ea-a755-4abd-b02b-ba77f6ee9ee0",
  "username": "admin"
}
```

The `-k` option of the `curl` command skips the SSL verification step, since in my laptop the test `igi_test_ca` is not installed.
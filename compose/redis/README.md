# IAM service connected to Redis

This is a simple example of how `iam-login-service` may store session information and cache into an external Redis service.

One can also use Redis alone during development.

Run Redis with

```bash
docker compose up -d redis
```

the default Redis port is forwarded locally.

Check the Redis keys stored into the db with

```bash
$ redis-cli KEYS '*'
1) "iam:session:sessions:expires:6c4d9436-39a8-4c03-bfc2-73d80cd5e760"
2) "iam:session:expirations:1758812640000"
3) "iam:session:sessions:6c4d9436-39a8-4c03-bfc2-73d80cd5e760"
4) "iam:session:index:org.springframework.session.FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME:admin"
```

__Note__  In order to query Redis you need the `redis-cli` installed locally, e.g. with

```
# Ubuntu
apt install redis-tools

# Almalinux
dnf install epel-release
dnf update
dnf install redis
```
# INDIGO IAM integration with OPA

This folder allows to demonstrate the integration of INDIGO IAM with OPA.

The [docker-compose](./docker-compose.yml) file allows to instantiate the following services:

- `trust`: it's a sidecar container, which generates a Test CA issuing a test x509 certificate for `nginx`
- `iam-be`: is the INDIGO IAM application, running behind the `nginx` service. It has been configured to retrieve scope policies by OPA
- `client`: is the iam-test-client service, which we can use for testing (e.g. retrieving an access token with filtered scopes)
- `nginx`: is an NGINX service available at https://iam.local.io for `iam-be` and https://iam.local.io/iam-test-client for `client`. It also exposes the OPA scope policies within the docker network
- `opa`: it is the OPA server which pulls the scope policy engine (i.e. _Rego_ files) from the [GitHib registry](https://github.com/indigo-iam/opa-iam/pkgs/container/opa-iam) and the static scope policies (i.e. _data.json_ file) from `nginx`
- `opa-dev`: same as `opa`, but useful for development. It is locally available at http://localhost:8181.

## Setup

### Host machine

For a full docker compose deployment, we need to resolve the `iam.local.io` hostname for IAM: please add to your `/etc/hosts` file the following line

```bash
127.0.0.1   iam.local.io
```

### Policies

The file [policies](./opa/policies/data.json) already contains a list of scope policies as an example. Here we can modify that list in order to test different policies.

In a full docker compose deployment, those policies are exposed by the NGINX service present in the [docker-compose](./docker-compose.yml) file as a bundle, which allows OPA to reload the policies if they are changed (based on the ETag). For local tests the policies are sourced as a local bundle, but in both cases some setup is required.

Download the latest OPA version to date for Linux (see [here](https://www.openpolicyagent.org/docs/latest/#1-download-opa) for other distributions) with

```bash
$ curl -L -o opa-cli https://openpolicyagent.org/downloads/latest/opa_linux_amd64
$ chmod 755 opa-cli
```

Build the policy bundle with

```bash
$ ./opa-cli build -b opa/policies -o iam-policies.tar.gz
```

## Testing

In order to test the INDIGO IAM integration with OPA we can both use the docker compose or a local iam-login-service/iam-test-client application running e.g. on Eclipse or Visual studio code (useful for debugging).

### Using docker-compose

Run the docker compose with

```bash
$ docker compose up -d nginx
```

(restart `nginx` in case the `iam-be` health check takes long).

Now, if you login trough iam-test-client at https://iam.local.io/iam_test_client with the Admin user you should see that the `offline_access` and `phone` scopes are filtered by OPA; if you login with the Test user you will have the `email` and `phone` scopes filtered; if you login with the Test-100 user (test_100/password) only the `phone` scope is filtered, due to a DENY policy applied to iam-test-client. Cross-check also the `iam-be` and `opa` logs to properly understand which scope is filtered.

### Using an IDE (debug)

Please remember to run iam-login-service by setting the property `iam.opa.enabled=true`.

Run the docker compose which enables OPA running on http://localhost:8181 with

```bash
$ docker compose up -d opa-dev
```

Now, if you login trough iam-test-client at https://iam.local.io/iam_test_client with the Admin user you should see that the `offline_access` and `phone` scopes are filtered by OPA; if you login with the Test user you will have the `email` and `phone` scopes filtered; if you login with the Test-100 user (test_100/password) only the `phone` scope is filtered, due to a DENY policy applied to iam-test-client.

Here you can also test that if the OPA server is not available, a fallback to the IAM Scope policy engine is applied. Please shut down the docker compose

```bash
$ docker compose down -v
```

and repeat the login through iam-test-client. Now you will see that no call to OPA is present in the IAM log, and that both Admin and Test users are allowed to obtain all the requested scopes, meaning the default IAM scope policy engine is applied.

# INDIGO IAM integration with OPA

This folder allows to demonstrate the integration of INDIGO IAM with OPA.

The [docker-compose](./docker-compose.yml) file allows to instantiate the following services:

- `iam`: is the INDIGO IAM service, available at `http://localhost:8080`
- `client`: is the iam-test-client service, which we can use for testing (e.g. retrieving an access token with filtered scopes)
- `nginx-opa`: is an NGINX service which exposes the scope policies at `http://nginx-opa/bundles/iam-policies.tar.gz`. Those policies have to be built before to run the docker compose (see below). The resulting policy bundle may be also exposed locally (i.e. without NGINX) but in this case we do not have the possibility of live reloading the policies
- `opa`: it is the OPA server which pulls the scope policy engine (i.e. _Rego_ files).

## Setup policies

The file [policies](./opa/policies/data.json) already contains a list of scope policies as an example. Here we can modify that list in order to test different policies. Those policies are exposed by the NGINX service present in the [docker-compose](./docker-compose.yml) file as a bundle, but some setup is required.

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

In order to test the INDIGO IAM integration with OPA we can both use a local iam-login-service and iam-test-client applications (running e.g. on Eclipse or Visual studio code), or fully rely on the docker compose file.

### Using an IDE

Please remember to run iam-login-service setting the property `iam.opa.enabled=true`.

Run the docker compose which enables OPA and NGINX with

```bash
$ docker compose up -d opa
```

Now, if you login trough iam-test-client with the Admin user you should see that the `offline_access` scope is filtered by OPA, while if you login with the Test user you will have the `email` scope filtered.
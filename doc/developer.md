# Developer guide

## How to build

The IAM is a Spring Boot Java application.

To build it, you will need:

- Java 8
- Maven

Build command:

  mvn package

## Setting up the docker-based development environment

You will need:

- Docker 1.11.1
- Docker compose >= 1.7

You can start a development/testing environment with the following command:

```bash
  docker-compose build
  docker-compose up
```

The docker-compose.yml file requires that you set some environment variables
for it to run properly, mainly to provide OAuth client credentials for external
authentication mechanisms (Google, Github,...).

The setup also assumes that you have an entry in your DNS server (complex) or
/etc/hosts (simpler) that maps iam.local.io to the machine (or VM) where docker
is running, e.g.:

```bash
$ cat /etc/hosts
...

192.168.99.100 iam.local.io
```

## How to run tests against the mysql database

IAM JUnit integration tests can (and should) be run against mysql database.

To do so, boostrap the database instance with docker-compose:

```bash
docker-compose up db
```

And then run the tests with the following command:

```bash
mvn -Dspring.profiles.active=mysql-test test
```

## Building Docker production images

To build the docker images for the iam-service and iam-test client,
use the following commands:

```bash
sh iam-login-service/docker/build-prod-image.sh
sh iam-test-client/docker/build-prod-image.sh
```

These commands should run **after** war and jar archives have been built, i.e.
after a `mvn package`.

For more details on the image build scripts see the following folders:

- [iam-login-service](iam-login-service/docker)
- [iam-test-client](iam-test-client/docker)

## Related projects

This project builds upon the following projects/technologies:

- [Spring Boot][spring-boot]
- [MitreID OpenID-Connect client and server libraries][mitre]

[mitre]: https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server
[spring-boot]: http://projects.spring.io/spring-boot/

This folder contains docker compose files for the voms-aa microservice.

## Deploy voms-aa

This folder contains a docker-compose file that could be useful for deployment.
The services defined here are:
* `trust`: docker image for the GRID CA certificates plus the `igi-test-ca` used in this deployment for test certificates
* `db-primary`: is a dump of the IAM db for test environment. In addition to the db populated with the iam `mysql-dev` profile, the user `test` has a certificate with DN `/C=IT/O=IGI/CN=test0` linked to his account and he also is part of the `indigo-dc` group (necessary to obtain VOMS proxies). A second SQL script creates a `replicator` user for replica.
* `db-replica`: is a DB configured to replicate all the statements of `db-primary`, from the initial one. It conects with SSL.
* `ngx-primary` and `ngx-replica`: an extension to NGINX, used for TLS termination, reverse proxy and possibly VOMS proxies validation. They sends requests to the corresponding `vomsaa-primary` and `vomsaa-replica` services.
* `vomsaa-primary` and `vomsaa-replica`: the main voms-aa microservices, each connected to their own DB.
* `client`: it is a single container containing GRID clients (in particular `voms-proxy-init`) used to query both the primary and replica voms-aa (via ngx).

Run the docker-compose with

```
$ docker-compose up -d
```

and wait for the `trust` service to finish; `ngx-primary` and `ngx-replica` will be available afterwards.

### VOMS clients

To test the two voms-aa using VOMS clients, enter in the container with

```
$ docker-compose exec client bash
```

Here a p12 file for the test user encrypted with the `pass` password is present in the well-known directory (`/home/test/.globus/usercred.p12`). It can be used to obtain a VOMS proxy by `voms-aa` serving a VO named `indigo-dc` with

```
$ voms-proxy-init -voms indigo-dc
Enter GRID pass phrase for this identity: <***>
Contacting voms-primary.test.example:443 [/C=IT/O=IGI/CN=*.test.example] "indigo-dc"...
Remote VOMS server contacted succesfully.


Created proxy in /tmp/x509up_u1000.

Your proxy is valid until Sat Mar 02 00:07:01 CET 2024
```

Check the content of the proxy with

```
$ voms-proxy-info -all
subject   : /C=IT/O=IGI/CN=test0/CN=1946803410
issuer    : /C=IT/O=IGI/CN=test0
identity  : /C=IT/O=IGI/CN=test0
type      : RFC3820 compliant impersonation proxy
strength  : 2048
path      : /tmp/x509up_u1000
timeleft  : 11:59:36
key usage : Digital Signature, Non Repudiation, Key Encipherment
=== VO indigo-dc extension information ===
VO        : indigo-dc
subject   : /C=IT/O=IGI/CN=test0
issuer    : /C=IT/O=IGI/CN=*.test.example
attribute : /indigo-dc
timeleft  : 11:59:35
uri       : voms.test.example:8080
```
This will select one of the two voms-aa in round robin fashion, and when one fails it will fallback to the other. If you want to force the query to one voms-aa use one of the followings:
```
$ voms-proxy-init -voms voms-primary
$ voms-proxy-init -voms voms-replica
```
# Trust-anchor container

This folder holds a trustanchor container which populates volumes
that can be mounted in the other services such to establish a trust 
framework based on X.509 certificates created on-the-fly.

The trustanchor container populates the following volumes

* `/trust-anchors`: contains the `igi-test-ca` CA certificate, issuing X.509
  server/user certificates (created on-the-fly), which is usually mounted
  in `/etc/grid-security/certificates`
* `/etc/pki/tls/certs`: it is the bundle for system certificates plus
  the `igi-test-ca` one
* `/hostcerts`: contains server X.509 certificates, emitted by the `igi-test-ca`
* `/usercerts`: contains client X.509 certificates, emitted by the `igi-test-ca`.

## Submodule

This folder contains a submodule for the [helper-scripts](https://baltig.infn.it/mw-devel/helper-scripts).

If you have already cloned the [indigo-iam](https://github.com/indigo-iam/iam) repo, download the submodule with

```bash
git submodule update --init --recursive
```

(otherwise clone the repo with the `--recurse-submodules` flag). This will populate the [helper-scripts](./helper-scripts/) directory.

To update and commit the submodule, type

```bash
git submodule update --remote
git add .
git commit -m "<commit-message>"
git push --recurse-submodules=on-demand
```
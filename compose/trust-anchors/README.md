# Trust-anchors container

This folder holds a container of trust anchors which populates volumes
that can be mounted in the other services to establish a trust 
framework based on X.509 certificates created on-the-fly.

The trust-anchors container populates the following volumes

* `/trust-anchors`: contains the `igi-test-ca` CA certificate, issuing X.509
  server/user certificates (created on-the-fly), which is usually mounted
  in `/etc/grid-security/certificates`
* `/etc/pki/tls/certs`: it is the bundle for system certificates plus
  the `igi-test-ca` one
* `/hostcerts`: contains server X.509 certificates, emitted by the `igi-test-ca`
* `/usercerts`: contains client X.509 certificates, emitted by the `igi-test-ca`.

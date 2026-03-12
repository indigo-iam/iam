#!/bin/sh
set -ex

keytool -importcert -trustcacerts -noprompt \
  -alias igi-test-ca \
  -file /etc/grid-security/certificates/igi_test_ca.pem \
  -keystore /opt/java/openjdk/lib/security/cacerts \
  -storepass changeit
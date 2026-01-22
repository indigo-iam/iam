#!/bin/sh
set -ex

# This uploads the igi-test-ca in the Java keystore
/scripts/init-bundle.sh

mvn -pl iam-login-service -am spring-boot:run ${IAM_JAVA_OPTS}
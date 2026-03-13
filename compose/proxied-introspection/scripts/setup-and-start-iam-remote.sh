#!/bin/sh
set -ex

# This uploads the igi-test-ca in the Java keystore
/scripts/init-bundle.sh

java ${IAM_JAVA_OPTS} org.springframework.boot.loader.WarLauncher
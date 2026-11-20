#!/bin/bash
#
# TLS material for the MySQL replication links. Runs once, then exits.
#
# Compose starts it before the databases and points it at the "mysql-pki"
# volume, which the three mysqld mount read-only at /certs-mysql:
#
#   ca.pem             CA signing the server certificates
#   <host>.cert.pem    server certificate, CN and SAN <host>.test.example
#   <host>.key.pem     its key, owned by uid 999 so that mysqld can read it
#
# for <host> = db-primary, db-replica, db-remote. Each server gets its own
# certificate because the replication channels check the hostname of the server
# they connect to: db-primary serves db-replica, db-replica serves db-remote,
# and every one of them is also the TLS endpoint of its voms-aa.
#
# The grid host certificate in /certs cannot be reused for this: those files are
# host certificates, written 0400 by uid 1000, and mysqld runs as uid 999.
#
# Running it again does nothing. To start over: docker compose down -v.

set -euo pipefail

DIR=${1:-/certs-mysql}   # where the databases expect the files
WORK=/tmp/mysql-pki      # scratch space, and the resting place of the CA key
ID=999                   # uid and gid of "mysql" in the database image
CA_DN='/C=IT/O=IGI/CN=Test MySQL CA'
DOMAIN=test.example
HOSTS='db-primary db-replica db-remote'
DAYS=3650

if [ -s "$DIR/ca.pem" ] && [ -s "$DIR/db-primary.key.pem" ]; then
  echo "mysql-pki: $DIR is already provisioned, use docker volume rm to regenerate"
  exit 0
fi

rm -rf "$WORK"
mkdir -p "$WORK" "$DIR"
cd "$WORK"

# The CA key is never copied into $DIR: a database that can read it could issue
# certificates for the other databases.
openssl req -new -x509 -sha256 -days "$DAYS" -newkey rsa:2048 -nodes \
  -keyout ca.key.pem -out ca.pem -subj "$CA_DN" \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash'

for host in $HOSTS; do
  fqdn="$host.$DOMAIN"
  openssl req -new -newkey rsa:2048 -nodes -keyout "$host.key.pem" \
    -subj "/C=IT/O=IGI/CN=$fqdn" 2>/dev/null |
    openssl x509 -req -sha256 -days "$DAYS" -CA ca.pem -CAkey ca.key.pem \
      -CAcreateserial -out "$host.cert.pem" \
      -extfile <(printf '%s\n' \
        'basicConstraints=critical,CA:FALSE' \
        'keyUsage=critical,digitalSignature,keyEncipherment' \
        'extendedKeyUsage=serverAuth' \
        'subjectKeyIdentifier=hash' \
        'authorityKeyIdentifier=keyid,issuer' \
        "subjectAltName=DNS:$fqdn")

  install -m 644 -o "$ID" -g "$ID" "$host.cert.pem" "$DIR/"
  install -m 600 -o "$ID" -g "$ID" "$host.key.pem" "$DIR/"
done

install -m 644 -o "$ID" -g "$ID" ca.pem "$DIR/"

echo "mysql-pki: CA $CA_DN installed in $DIR"
openssl verify -CAfile "$DIR/ca.pem" "$DIR"/*.cert.pem

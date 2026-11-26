#!/bin/bash
#
# Server certificates for the MySQL replication links.
#
# This runs inside the "trust" container, which already provides everything the
# grid PKI needs: the x509-scripts of
# https://baltig.infn.it/mw-devel/helper-scripts are on PATH, /openssl.conf and
# /conf.d are the ones of compose/trust-anchors, and setup-trust.sh has already
# created igi_test_ca, private key included, when the image was built. Nothing
# of that is reimplemented here: the three modules of x509/conf.d are added to
# the inherited conf.d, and the certificates are issued by the inherited
# make_cert.sh against the same CA that signs the host and user certificates of
# the deployment.
#
# The output goes to the "dbcerts" volume, mounted at /dbcerts and read by the
# three databases as:
#
#   ca.pem             igi_test_ca, the CA of the server certificates
#   <host>.cert.pem    server certificate, CN and SAN <host>.test.example
#   <host>.key.pem     its key, owned by uid 999 so that mysqld can read it
#
# for <host> = db-primary, db-replica, db-remote. Each server gets its own
# certificate because the replication channels check the hostname of the server
# they connect to: db-primary serves db-replica, db-replica serves db-remote,
# and every one of them is also the TLS endpoint of its voms-aa.
#
# The grid host certificate in hostcerts cannot be reused for this: those files
# are host certificates, written 0400 by uid 1000, and mysqld runs as uid 999.
#
# The CA private key is never copied to the volume: a database that could read
# it would be able to issue certificates for the other databases.
#
# Running it again does nothing, unless the volume holds the certificates of a CA
# that the image no longer has: those are issued again with the one of the image.
# To wipe the volume instead: docker compose down -v.

set -euo pipefail

cert_dir=/dbcerts            # where the databases expect the files
conf_dir=/db-conf.d          # our conf.d modules, from assets/mysql-trust
mysql_id=999                 # uid and gid of "mysql" in the database image
hosts='db-primary db-replica db-remote'

# The CA that setup-trust.sh created in the image, named the way it names it.
export CA_NAME=igi_test_ca

# Like setup-trust.sh, everything is then looked for at the root of the image:
# openssl.conf and conf.d there, the CA and its key under ${CA_NAME}.
cd /

if [ ! -e openssl.conf ] || [ ! -d "${CA_NAME}" ]; then
  >&2 echo "This is not the trust image: no /openssl.conf or no ${CA_NAME} CA"
  exit 1
fi

# The volume outlives the container, so this runs at every "docker compose up":
# the certificates must not be issued again, but they must not be kept either
# when they were signed by a CA that a rebuilt image no longer holds.
if [ -s "${cert_dir}/ca.pem" ]; then
  if [ "$(openssl x509 -in "${cert_dir}/ca.pem" -noout -fingerprint -sha256)" = \
       "$(openssl x509 -in "${CA_NAME}/ca.crt" -noout -fingerprint -sha256)" ]; then
    echo "mysql-trust: ${cert_dir} is already provisioned, use docker compose down -v to start over"
    exit 0
  fi
fi

# setup-trust.sh ran at build time and left its CA under ${CA_NAME}: add our
# modules to the configuration it read, so that make_cert.sh can find them.
cp "${conf_dir}"/*.conf conf.d/

mkdir -p "${cert_dir}"

for host in ${hosts}; do
  make_cert.sh "${host}_test_example"

  install -m 644 -o "${mysql_id}" -g "${mysql_id}" \
    "${CA_NAME}/certs/${host}_test_example.cert.pem" "${cert_dir}/${host}.cert.pem"
  install -m 600 -o "${mysql_id}" -g "${mysql_id}" \
    "${CA_NAME}/certs/${host}_test_example.key.pem" "${cert_dir}/${host}.key.pem"
done

install -m 644 -o "${mysql_id}" -g "${mysql_id}" "${CA_NAME}/ca.crt" "${cert_dir}/ca.pem"

echo "mysql-trust: issued by ${CA_NAME} into ${cert_dir}"
openssl verify -CAfile "${cert_dir}/ca.pem" "${cert_dir}"/*.cert.pem

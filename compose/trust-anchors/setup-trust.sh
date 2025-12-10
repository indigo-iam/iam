#!/bin/bash
set -e

if [ ! -e "openssl.conf" ]; then
  >&2 echo "The configuration file 'openssl.conf' doesn't exist in this directory"
  exit 1
fi

hostcerts_dir=/hostcerts
usercerts_dir=/usercerts
ta_dir=/trust-anchors
ca_bundle_prefix=/etc/pki

rm -rf "${hostcerts_dir}"
mkdir -p "${hostcerts_dir}"
rm -rf "${usercerts_dir}"
mkdir -p "${usercerts_dir}"
rm -rf "${ta_dir}"
mkdir -p "${ta_dir}"

export CA_NAME=igi_test_ca
export X509_CERT_DIR="${ta_dir}"

make_ca.sh

# Create server certificates
for c in star_test_example iam_local_io; do
  make_cert.sh ${c}
  cp igi_test_ca/certs/${c}.* "${hostcerts_dir}"
done

chmod 600 "${hostcerts_dir}"/*.cert.pem
chmod 400 "${hostcerts_dir}"/*.key.pem
chmod 600 "${hostcerts_dir}"/*.p12
chown 1000:1000 "${hostcerts_dir}"/*

# Create user certificates
for i in $(seq 0 5); do
  make_cert.sh test${i}
  cp igi_test_ca/certs/test${i}.* "${usercerts_dir}"
done

faketime -f -1y env make_cert.sh expired
cp igi_test_ca/certs/expired.* "${usercerts_dir}"

make_cert.sh revoked
cp igi_test_ca/certs/revoked.* "${usercerts_dir}"
revoke_cert.sh revoked

chmod 600 "${usercerts_dir}"/*.cert.pem
chmod 400 "${usercerts_dir}"/*.key.pem
chmod 600 "${usercerts_dir}"/*.p12
chown 1000:1000 "${usercerts_dir}"/*

make_crl.sh
install_ca.sh igi_test_ca "${ta_dir}"

# Add igi-test-ca to system certificates
ca_bundle="${ca_bundle_prefix}"/tls/certs
echo -e "\n# igi-test-ca" >> "${ca_bundle}"/ca-bundle.crt
cat "${ta_dir}"/igi_test_ca.pem >> "${ca_bundle}"/ca-bundle.crt

#!/usr/bin/env bash
# Generate a local CA and one client certificate for optional Flask mTLS testing.
# Run after generate_keys.sh. Keep all private keys private and out of source control.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs

if [[ -e certs/client-ca.key.pem || -e certs/client.key.pem ]]; then
  echo "Refusing to overwrite existing client CA/client key material in certs/." >&2
  exit 1
fi

echo "[1/3] Création de l'autorité de certification cliente (CA)…"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout certs/client-ca.key.pem -out certs/client-ca.pem -days 3650 \
  -subj "/C=TN/O=Banque Projet/OU=Client CA/CN=Banque Client CA"
chmod 600 certs/client-ca.key.pem

echo "[2/3] Création d'une clé et d'une demande de certificat client…"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout certs/client.key.pem -out certs/client.csr.pem \
  -subj "/C=TN/O=Banque Projet/OU=Clients/CN=banque-demo-client" \
  -addext "extendedKeyUsage=clientAuth"
chmod 600 certs/client.key.pem

echo "[3/3] Signature du certificat client par la CA locale…"
openssl x509 -req -in certs/client.csr.pem -CA certs/client-ca.pem -CAkey certs/client-ca.key.pem \
  -CAcreateserial -out certs/client.crt.pem -days 365 -copy_extensions copy
chmod 600 certs/client.crt.pem
rm -f certs/client.csr.pem

echo "Client certificate: certs/client.crt.pem"
echo "Client private key: certs/client.key.pem (keep private)"
echo "Trusted CA: certs/client-ca.pem"
echo "Enable server verification with: MTLS_ENABLED=1 python app.py"
echo "Test with: curl --cert certs/client.crt.pem --key certs/client.key.pem --cacert certs/cert.pem https://127.0.0.1:5000/login"

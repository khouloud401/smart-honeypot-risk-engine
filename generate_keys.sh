#!/usr/bin/env bash
# Génère avec OpenSSL : (1) les clés secrètes de l'application, (2) un certificat HTTPS.
# Utilisation :  bash generate_keys.sh  puis  source keys.env  puis  python app.py
set -e
cd "$(dirname "$0")"

echo "[1/2] Clés secrètes (256 bits chacune)…"
{
  echo "export SECRET_KEY=$(openssl rand -hex 32)"   # signature du cookie de session
  echo "export HMAC_KEY=$(openssl rand -hex 32)"     # sceau des transactions
  echo "export ENC_KEY=$(openssl rand -hex 32)"      # AES-256-GCM (RIB)
  echo "export LOG_KEY=$(openssl rand -hex 32)"      # chaîne HMAC du journal
} > keys.env
chmod 600 keys.env

echo "[2/2] Certificat HTTPS auto-signé (ECDSA P-256, 365 jours)…"
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout certs/key.pem -out certs/cert.pem -days 365 \
  -subj "/C=TN/O=Banque Projet/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 certs/key.pem

echo
echo "Terminé. Lancez :  source keys.env && python app.py"
echo "Vérifier le certificat :  openssl x509 -in certs/cert.pem -noout -text | head -20"
echo "⚠️  Changer les clés rend illisibles les données déjà chiffrées : faites rm bank.db avant."

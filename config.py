"""Configuration et gestion des secrets.

Les clés ne sont JAMAIS écrites dans le code :
  1. on lit d'abord les variables d'environnement (voir generate_keys.sh / OpenSSL) ;
  2. sinon, des clés aléatoires sont générées au premier lancement et
     stockées dans instance/secrets.json (droits 600, exclu de Git).
"""
import json
import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DB_PATH = os.path.join(BASE_DIR, "bank.db")
SECRETS_FILE = os.path.join(INSTANCE_DIR, "secrets.json")
CERT_FILE = os.path.join(BASE_DIR, "certs", "cert.pem")
KEY_FILE = os.path.join(BASE_DIR, "certs", "key.pem")

SECRET_NAMES = ["SECRET_KEY",   # signature du cookie de session Flask (HMAC)
                "HMAC_KEY",     # sceau HMAC-SHA256 des transactions
                "ENC_KEY",      # chiffrement AES-256-GCM des données sensibles (RIB)
                "LOG_KEY"]      # chaînage HMAC du journal de sécurité


def _load_secrets():
    stored = {}
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, encoding="utf-8") as f:
            stored = json.load(f)
    keys, changed = {}, False
    for name in SECRET_NAMES:
        value = os.environ.get(name) or stored.get(name)
        if not value:
            value = secrets.token_hex(32)          # 256 bits aléatoires
            stored[name] = value
            changed = True
        keys[name] = value
    if changed:
        os.makedirs(INSTANCE_DIR, exist_ok=True)
        fd = os.open(SECRETS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(stored, f, indent=2)
    return keys


KEYS = _load_secrets()

# HTTPS : actif si un certificat a été généré avec OpenSSL (generate_keys.sh)
USE_HTTPS = os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)
MTLS_ENABLED = os.environ.get("MTLS_ENABLED", "0").strip().lower() in {"1", "true", "yes"}
CLIENT_CA_FILE = os.environ.get("CLIENT_CA_FILE", os.path.join(BASE_DIR, "certs", "client-ca.pem"))

# ---------------------------------------------------------------- paramètres de sécurité
SESSION_IDLE_MINUTES = 15         # déconnexion après 15 min d'inactivité
SESSION_ABSOLUTE_HOURS = 8        # durée de vie maximale d'une session
MAX_FAILED_LOGINS = 5             # verrouillage après 5 échecs
LOCK_MINUTES = 15                 # durée du verrouillage
RATE_LIMIT = (20, 300)            # 20 tentatives max par IP sur 5 minutes
CHALLENGE_TTL = 120               # validité d'un challenge ECDSA (secondes)
PENDING_LOGIN_TTL = 300           # délai pour terminer la vérification d'appareil
ENROLL_CODE_TTL_MINUTES = 30      # validité d'un code d'enrôlement
DEVICE_KEY_ROLES = {"admin"}      # rôles protégés par la clé liée à l'appareil
HONEYTOKEN_USERNAMES = {"root", "administrator", "administrateur", "sa", "test", "superadmin"}

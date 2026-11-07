"""Primitives cryptographiques du projet.

- HMAC-SHA256 : sceau d'intégrité des transactions + chaînage du journal de sécurité
- AES-256-GCM : chiffrement authentifié du RIB (confidentialité + intégrité)
- ECDSA P-256 / SHA-256 : vérification de la signature de la clé liée à l'appareil
"""
import base64
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import KEYS


def _as_bytes(value, size=None):
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raw = value.encode()
    if size and len(raw) != size:
        raw = hashlib.sha256(raw).digest()      # normalise à 32 octets
    return raw


HMAC_KEY = _as_bytes(KEYS["HMAC_KEY"])
LOG_KEY = _as_bytes(KEYS["LOG_KEY"])
ENC_KEY = _as_bytes(KEYS["ENC_KEY"], 32)       # AES-256


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------ HMAC transactions
def sign_tx(kind, sender, receiver, amount, ts):
    msg = f"{kind}|{sender}|{receiver}|{float(amount):.2f}|{ts}".encode()
    return hmac.new(HMAC_KEY, msg, hashlib.sha256).hexdigest()


def tx_is_valid(t):
    expected = sign_tx(t["kind"], t["sender"], t["receiver"], t["amount"], t["ts"])
    return hmac.compare_digest(t["signature"], expected)   # comparaison à temps constant


def hmac_demo(text):
    return hmac.new(HMAC_KEY, text.encode(), hashlib.sha256).hexdigest()


# ------------------------------------------------------------------ HMAC journal (chaîne)
def log_mac(prev_mac, fields):
    msg = prev_mac + "|" + "|".join(str(f) for f in fields)
    return hmac.new(LOG_KEY, msg.encode(), hashlib.sha256).hexdigest()


# ------------------------------------------------------------------ AES-256-GCM
def encrypt(plaintext, aad):
    """Retourne base64(nonce 12 octets || texte chiffré || tag 16 octets)."""
    nonce = os.urandom(12)
    ct = AESGCM(ENC_KEY).encrypt(nonce, plaintext.encode(), aad.encode())
    return base64.b64encode(nonce + ct).decode()


def decrypt(token, aad):
    """Retourne le texte clair, ou None si le chiffré a été modifié (tag invalide)."""
    if not token:
        return None
    try:
        raw = base64.b64decode(token)
        return AESGCM(ENC_KEY).decrypt(raw[:12], raw[12:], aad.encode()).decode()
    except (InvalidTag, ValueError):
        return None


# ------------------------------------------------------------------ ECDSA (clé d'appareil)
def load_public_key(spki_b64):
    """Charge une clé publique SPKI base64 ; n'accepte que ECDSA P-256."""
    try:
        key = serialization.load_der_public_key(base64.b64decode(spki_b64, validate=True))
    except (ValueError, TypeError):
        return None
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        return None
    return key


def key_fingerprint(spki_b64):
    h = sha256_hex(base64.b64decode(spki_b64))[:32].upper()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


def ecdsa_verify(spki_b64, message, signature_b64):
    """WebCrypto produit une signature brute r||s (64 octets) : on la convertit en DER."""
    key = load_public_key(spki_b64)
    if key is None or not signature_b64:
        return False
    try:
        raw = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False
    if len(raw) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        key.verify(der, message.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

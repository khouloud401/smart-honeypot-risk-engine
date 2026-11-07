"""Accès à la base SQLite et création du schéma."""
import sqlite3
from datetime import datetime

from flask import g

from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,              -- scrypt + sel (Werkzeug)
    role TEXT NOT NULL DEFAULT 'user',
    balance REAL NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,        -- blocage manuel par l'admin
    rib_enc TEXT,                             -- RIB chiffré AES-256-GCM
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,     -- verrouillage automatique
    created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS transactions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    amount REAL NOT NULL,
    ts TEXT NOT NULL,
    signature TEXT NOT NULL);                 -- sceau HMAC-SHA256

CREATE TABLE IF NOT EXISTS sessions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sid_hash TEXT UNIQUE NOT NULL,            -- SHA-256 de l'identifiant (jamais en clair)
    user_id INTEGER NOT NULL,
    created REAL NOT NULL,
    last_seen REAL NOT NULL,
    ip TEXT, ua TEXT,
    device_verified INTEGER NOT NULL DEFAULT 0,
    honeypot INTEGER NOT NULL DEFAULT 0,
    honeypot_expires REAL,
    honeypot_username TEXT,
    revoked INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS app_sessions(
    sid_hash TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL);

CREATE TABLE IF NOT EXISTS login_attempts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    username_norm TEXT NOT NULL,
    user_id INTEGER,
    ip TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    success INTEGER NOT NULL,
    attempted_at REAL NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0);

CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time
    ON login_attempts(username_norm, attempted_at);

CREATE TABLE IF NOT EXISTS trusted_contexts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(user_id, ip, token_hash));

CREATE TABLE IF NOT EXISTS blacklisted_ips(
    ip TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    reason TEXT NOT NULL,
    expires_at REAL);

CREATE TABLE IF NOT EXISTS attack_reports(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER UNIQUE,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    started_at REAL NOT NULL,
    ended_at REAL NOT NULL,
    event_count INTEGER NOT NULL,
    pages_json TEXT NOT NULL,
    report_json TEXT NOT NULL,
    created_at REAL NOT NULL);

CREATE TABLE IF NOT EXISTS device_keys(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    public_key TEXT NOT NULL,                 -- clé publique ECDSA P-256 (SPKI, base64)
    fingerprint TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used TEXT,
    revoked INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS challenges(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce_hash TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS enroll_codes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    expires REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS security_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event TEXT NOT NULL,
    severity TEXT NOT NULL,
    username TEXT, ip TEXT, ua TEXT, details TEXT,
    mac TEXT NOT NULL);                       -- chaîne HMAC (journal infalsifiable)

CREATE TABLE IF NOT EXISTS alerts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    details TEXT,
    username TEXT, ip TEXT,
    seen INTEGER NOT NULL DEFAULT 0);
"""


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def migrate_db(db):
    """Apply additive schema migrations to databases created by earlier versions."""
    columns = {row[1] for row in db.execute("PRAGMA table_info(sessions)")}
    for name, declaration in (("honeypot_expires", "REAL"),
                              ("honeypot_username", "TEXT")):
        if name not in columns:
            db.execute(f"ALTER TABLE sessions ADD COLUMN {name} {declaration}")
    db.commit()


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

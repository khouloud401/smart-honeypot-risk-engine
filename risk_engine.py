"""Risk scoring and trusted login context.

Scoring policy (15-minute failure window):
- 3 or more failed attempts for a username: +1
- A previously trusted username from a new IP or browser token: +1
- 0 = normal, 1 = deny with an ordinary login error, 2 = honeypot + alert

The first successful login for a legacy account with no trusted context is a
bootstrap; new accounts are trusted at registration. Contexts are only learned
from an authorized registration/device-enrollment/low-risk login.
"""
import hashlib
import time

from db import get_db

FAILURE_WINDOW_SECONDS = 15 * 60
FAILURE_SCORE_THRESHOLD = 3


def token_hash(token):
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def context_is_new(user_id, ip, browser_token):
    """Return whether either IP or browser token is unknown for this account."""
    if user_id is None:
        return True
    db = get_db()
    rows = db.execute("SELECT ip, token_hash FROM trusted_contexts WHERE user_id=?", (user_id,)).fetchall()
    if not rows:
        return False  # one-time bootstrap for accounts created before this feature
    current_token = token_hash(browser_token)
    known_ip = any(row["ip"] == ip for row in rows)
    known_token = any(row["token_hash"] == current_token for row in rows)
    return not (known_ip and known_token)


def evaluate_attempt(username, user_id, ip, browser_token, success):
    """Record an authentication attempt and return (score, new_context, failures)."""
    db = get_db()
    now = time.time()
    normalized = (username or "").strip().casefold()
    cutoff = now - FAILURE_WINDOW_SECONDS
    failures = db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username_norm=? AND success=0 AND attempted_at>=?",
        (normalized, cutoff),
    ).fetchone()[0]
    new_context = context_is_new(user_id, ip, browser_token)
    projected_failures = failures + (0 if success else 1)
    score = int(projected_failures >= FAILURE_SCORE_THRESHOLD) + int(new_context)
    score = min(score, 2)
    db.execute(
        "INSERT INTO login_attempts(username,username_norm,user_id,ip,token_hash,success,attempted_at,risk_score) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (username or "", normalized, user_id, ip, token_hash(browser_token), int(success), now, score),
    )
    db.commit()
    return score, new_context, projected_failures


def trust_context(user_id, ip, browser_token):
    """Remember a context only after a trusted enrollment or low-risk login."""
    if user_id is None:
        return
    db = get_db()
    db.execute(
        "INSERT INTO trusted_contexts(user_id,ip,token_hash,first_seen,last_seen) VALUES(?,?,?,?,?) "
        "ON CONFLICT(user_id,ip,token_hash) DO UPDATE SET last_seen=excluded.last_seen",
        (user_id, ip, token_hash(browser_token), time.time(), time.time()),
    )
    db.commit()


def clear_recent_failures(username):
    db = get_db()
    db.execute(
        "DELETE FROM login_attempts WHERE username_norm=? AND success=0 AND attempted_at>=?",
        ((username or "").strip().casefold(), time.time() - FAILURE_WINDOW_SECONDS),
    )
    db.commit()


def is_ip_blacklisted(ip):
    row = get_db().execute(
        "SELECT 1 FROM blacklisted_ips WHERE ip=? AND (expires_at IS NULL OR expires_at>?)",
        (ip, time.time()),
    ).fetchone()
    return row is not None


def blacklist_ip(ip, reason, expires_at=None):
    db = get_db()
    db.execute(
        "INSERT INTO blacklisted_ips(ip,created_at,reason,expires_at) VALUES(?,?,?,?) "
        "ON CONFLICT(ip) DO UPDATE SET created_at=excluded.created_at,reason=excluded.reason,expires_at=excluded.expires_at",
        (ip, time.time(), reason, expires_at),
    )
    db.commit()


def remove_blacklist(ip):
    db = get_db()
    db.execute("DELETE FROM blacklisted_ips WHERE ip=?", (ip,))
    db.commit()

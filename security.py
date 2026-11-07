"""Security services: chained audit log, alerts, authentication sessions, CSRF and limits."""
import hmac
import re
import secrets
import time
from collections import defaultdict, deque

from flask import has_request_context, request, session

from config import (RATE_LIMIT, SESSION_ABSOLUTE_HOURS, SESSION_IDLE_MINUTES)
from crypto_utils import log_mac, sha256_hex
from db import get_db, now


# ------------------------------------------------------------------ request context
def client_ip():
    return (request.remote_addr or "?") if has_request_context() else "-"


def client_ua():
    return (request.user_agent.string or "")[:200] if has_request_context() else "-"


# ------------------------------------------------------------------ chained HMAC security log
def log_event(event, severity="info", username=None, details=""):
    """Each record has an HMAC linked to the previous record."""
    db = get_db()
    ts, ip, ua = now(), client_ip(), client_ua()
    prev = db.execute("SELECT mac FROM security_logs ORDER BY id DESC LIMIT 1").fetchone()
    prev_mac = prev["mac"] if prev else "GENESIS"
    fields = [ts, event, severity, username or "-", ip, ua, details]
    db.execute("INSERT INTO security_logs(ts,event,severity,username,ip,ua,details,mac) VALUES(?,?,?,?,?,?,?,?)",
               (ts, event, severity, username or "-", ip, ua, details, log_mac(prev_mac, fields)))
    db.commit()


def verify_log_chain():
    """Return IDs of rows whose chained HMAC does not validate."""
    bad, prev_mac = [], "GENESIS"
    for row in get_db().execute("SELECT * FROM security_logs ORDER BY id"):
        fields = [row["ts"], row["event"], row["severity"], row["username"], row["ip"], row["ua"], row["details"]]
        if not hmac.compare_digest(row["mac"], log_mac(prev_mac, fields)):
            bad.append(row["id"])
        prev_mac = row["mac"]
    return bad


def create_alert(severity, title, details="", username=None):
    db = get_db()
    if db.execute("SELECT 1 FROM alerts WHERE seen=0 AND title=? AND details=?", (title, details)).fetchone():
        return
    db.execute("INSERT INTO alerts(ts,severity,title,details,username,ip) VALUES(?,?,?,?,?,?)",
               (now(), severity, title, details, username or "-", client_ip()))
    db.commit()


# ------------------------------------------------------------------ server-side sessions
def rotate_server_session():
    """Rotate the opaque session ID and revoke any authenticated session it replaces."""
    server_session = session._get_current_object()
    sid = getattr(server_session, "sid", None)
    if sid:
        db = get_db()
        db.execute("UPDATE sessions SET revoked=1 WHERE sid_hash=?", (sha256_hex(sid),))
        db.commit()
    server_session.clear()
    server_session.regenerate()
    return server_session.sid


def start_session(user, device_verified=False, honeypot=False):
    """Start an authenticated server-side session with a newly rotated 256-bit ID."""
    sid = rotate_server_session()
    t = time.time()
    db = get_db()
    expires = t + 5 * 60 if honeypot else None
    db.execute("INSERT INTO sessions(sid_hash,user_id,created,last_seen,ip,ua,device_verified,honeypot,honeypot_expires,honeypot_username)"
               " VALUES(?,?,?,?,?,?,?,?,?,?)",
               (sha256_hex(sid), user["id"], t, t, client_ip(), client_ua(),
                int(device_verified), int(honeypot), expires, user["username"] if honeypot else None))
    db.commit()
    server_session = session._get_current_object()
    server_session["csrf"] = secrets.token_urlsafe(32)


def start_honeypot_session(username, user_id=None):
    """Create a fake admin session, including for invalid usernames (no valid password needed)."""
    sid = rotate_server_session()
    t = time.time()
    db = get_db()
    owner = None
    if user_id is not None:
        owner = db.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
    if owner is None:
        owner = db.execute("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
    if owner is None:
        owner = db.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
    if owner is None:
        return False
    db.execute("INSERT INTO sessions(sid_hash,user_id,created,last_seen,ip,ua,honeypot,honeypot_expires,honeypot_username)"
               " VALUES(?,?,?,?,?,?,?,?,?)",
               (sha256_hex(sid), owner["id"], t, t, client_ip(), client_ua(), 1, t + 5 * 60,
                (username or "unknown")[:80]))
    db.commit()
    server_session = session._get_current_object()
    server_session["csrf"] = secrets.token_urlsafe(32)
    return True


def load_session():
    """Validate each request; return (user, audit_row, failure_reason)."""
    sid = getattr(session._get_current_object(), "sid", None)
    if not sid:
        return None, None, None
    db = get_db()
    row = db.execute("SELECT * FROM sessions WHERE sid_hash=?", (sha256_hex(sid),)).fetchone()
    if row is None:
        # Anonymous and pending-login sessions live in app_sessions but have no
        # authenticated-session audit record yet.
        return None, None, None
    if row["revoked"]:
        return None, None, "revoked"
    t = time.time()
    if t - row["last_seen"] > SESSION_IDLE_MINUTES * 60:
        reason = "idle"
    elif t - row["created"] > SESSION_ABSOLUTE_HOURS * 3600:
        reason = "absolute"
    elif row["ua"] != client_ua():
        reason = "ua_mismatch"
    elif row["honeypot"] and row["honeypot_expires"] is not None and t >= row["honeypot_expires"]:
        reason = "honeypot_expired"
    else:
        reason = None
    user = db.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
    if reason is None and (user is None or not user["active"]):
        reason = "blocked"
    if reason:
        db.execute("UPDATE sessions SET revoked=1 WHERE id=?", (row["id"],))
        db.commit()
        return None, row, reason
    db.execute("UPDATE sessions SET last_seen=? WHERE id=?", (t, row["id"]))
    db.commit()
    if row["honeypot"]:
        user = dict(user)
        user["username"] = row["honeypot_username"] or user["username"]
        user["role"] = "admin"
    return user, row, None


def revoke_current_session():
    sid = getattr(session._get_current_object(), "sid", None)
    if sid:
        db = get_db()
        db.execute("UPDATE sessions SET revoked=1 WHERE sid_hash=?", (sha256_hex(sid),))
        db.commit()
    session.clear()


def revoke_user_sessions(user_id, keep_current=False):
    sid = getattr(session._get_current_object(), "sid", None)
    current = sha256_hex(sid or "") if keep_current else ""
    db = get_db()
    db.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND sid_hash!=?", (user_id, current))
    db.commit()


# ------------------------------------------------------------------ CSRF
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_ok():
    sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token") or ""
    return bool(sent) and hmac.compare_digest(sent, session.get("csrf", ""))


# ------------------------------------------------------------------ in-memory IP rate limit (secondary to persistent risk scoring)
_hits = defaultdict(deque)


def rate_limited(bucket):
    limit, window = RATE_LIMIT
    key, t = f"{bucket}:{client_ip()}", time.time()
    dq = _hits[key]
    while dq and dq[0] < t - window:
        dq.popleft()
    if len(dq) >= limit:
        return True
    dq.append(t)
    return False


# ------------------------------------------------------------------ password policy
def password_problem(pw):
    if len(pw) < 8:
        return "Mot de passe : 8 caractères minimum."
    if len(pw) > 128:
        return "Mot de passe : 128 caractères maximum."
    for pattern, label in [(r"[a-z]", "une minuscule"), (r"[A-Z]", "une majuscule"),
                           (r"\d", "un chiffre"), (r"[^A-Za-z0-9]", "un caractère spécial")]:
        if not re.search(pattern, pw):
            return f"Mot de passe : il faut au moins {label}."
    return None

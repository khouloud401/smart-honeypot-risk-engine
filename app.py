"""Banque en ligne sécurisée - Flask + SQLite

Exigences couvertes :
  1. Application web avec rôles utilisateur / administrateur
  2. Inscription, connexion, déconnexion et sessions sécurisées
  3. Hachage des mots de passe (scrypt + sel) et contrôle des comptes
  4. Autorisation côté serveur et contrôle d'accès
  5. Chiffrement (AES-256-GCM) + HMAC-SHA256 + signature numérique ECDSA
Innovations : clé ECDSA liée à l'appareil (WebCrypto) + honeypot + journal chaîné HMAC.
"""
import base64
import functools
import ipaddress
import json
import re
import secrets
import ssl
import time
from collections import defaultdict

import click
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import honeypot
from config import (CERT_FILE, CLIENT_CA_FILE, CHALLENGE_TTL, DEVICE_KEY_ROLES, ENROLL_CODE_TTL_MINUTES,
                    HONEYTOKEN_USERNAMES, KEY_FILE, KEYS, LOCK_MINUTES, MAX_FAILED_LOGINS,
                    MTLS_ENABLED, PENDING_LOGIN_TTL, SESSION_ABSOLUTE_HOURS, USE_HTTPS)
from crypto_utils import (decrypt, ecdsa_verify, encrypt, hmac_demo, key_fingerprint,
                          load_public_key, sha256_hex, sign_tx, tx_is_valid)
from db import SCHEMA, close_db, get_db, migrate_db, now
from reports import expire_honeypot_sessions, finalize_honeypot
from risk_engine import (blacklist_ip, clear_recent_failures, evaluate_attempt,
                         is_ip_blacklisted, remove_blacklist, trust_context)
from server_sessions import SQLiteSessionInterface
from security import (client_ip, client_ua, create_alert, csrf_ok, csrf_token, load_session,
                      log_event, password_problem, rate_limited, revoke_current_session,
                      revoke_user_sessions, rotate_server_session, start_honeypot_session,
                      start_session, verify_log_chain)

app = Flask(__name__)
app.secret_key = KEYS["SECRET_KEY"]            # cookie de session signé (HMAC via itsdangerous)
app.config.update(
    SESSION_COOKIE_NAME="banque_session",
    SESSION_COOKIE_HTTPONLY=True,              # inaccessible au JavaScript (anti-XSS)
    SESSION_COOKIE_SAMESITE="Strict",          # jamais envoyé depuis un autre site (anti-CSRF)
    SESSION_COOKIE_SECURE=USE_HTTPS,           # uniquement en HTTPS quand le certificat existe
    PERMANENT_SESSION_LIFETIME=SESSION_ABSOLUTE_HOURS * 3600,
    MAX_CONTENT_LENGTH=64 * 1024,
)
app.session_interface = SQLiteSessionInterface()
app.teardown_appcontext(close_db)

DUMMY_HASH = generate_password_hash("mot-de-passe-factice-anti-timing")


# ============================================================ base de données
def insert_tx(db, kind, sender, receiver, amount):
    ts = now()
    db.execute("INSERT INTO transactions(kind,sender,receiver,amount,ts,signature) VALUES(?,?,?,?,?,?)",
               (kind, sender, receiver, amount, ts, sign_tx(kind, sender, receiver, amount, ts)))


def add_tx(kind, sender, receiver, amount):
    insert_tx(get_db(), kind, sender, receiver, amount)


def new_rib():
    digits = "".join(secrets.choice("0123456789") for _ in range(20))
    return "TN59 " + " ".join(digits[i:i + 4] for i in range(0, 20, 4))


def create_user(db, username, email, password, role="user", balance=0.0):
    rib_enc = encrypt(new_rib(), aad=username) if role == "user" else None
    db.execute("INSERT INTO users(username,email,password_hash,role,balance,rib_enc,created_at)"
               " VALUES(?,?,?,?,?,?,?)",
               (username, email, generate_password_hash(password, method="scrypt"),
                role, balance, rib_enc, now()))


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    migrate_db(db)
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        for u, e, p, r, b in [("admin", "admin@banque.tn", "Admin@123", "admin", 0),
                              ("alice", "alice@mail.tn", "Alice@123", "user", 1600),
                              ("bob", "bob@mail.tn", "Bob@12345", "user", 600)]:
            create_user(db, u, e, p, r, b)
        # historique cohérent avec les soldes (vérifié par la page Intégrité)
        for k, s, r, a in [("depot", "-", "alice", 1500), ("depot", "-", "bob", 900),
                           ("virement", "bob", "alice", 100), ("retrait", "bob", "-", 200)]:
            insert_tx(db, k, s, r, a)
        db.commit()
        log_event("SYSTEM_INIT", "info", None, "Base créée avec les comptes de test")


def issue_enroll_code(user_id):
    """Code à usage unique (hashé en base) pour enrôler un nouveau navigateur."""
    code = "-".join(secrets.token_hex(2).upper() for _ in range(3))
    db = get_db()
    db.execute("UPDATE enroll_codes SET used=1 WHERE user_id=? AND used=0", (user_id,))
    db.execute("INSERT INTO enroll_codes(user_id,code_hash,expires) VALUES(?,?,?)",
               (user_id, sha256_hex(code), time.time() + ENROLL_CODE_TTL_MINUTES * 60))
    db.commit()
    return code


# ============================================================ contrôles globaux
@app.before_request
def before():
    g.me, g.hp, g.device_ok = None, False, False
    browser_token = request.cookies.get("banque_device", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,60}", browser_token):
        browser_token = secrets.token_urlsafe(32)
        g.new_device_cookie = True
    else:
        g.new_device_cookie = False
    g.device_token = browser_token

    expire_honeypot_sessions()
    if is_ip_blacklisted(client_ip()):
        log_event("BLACKLIST_BLOCK", "high", None, f"Requête refusée depuis l'IP bloquée {client_ip()}")
        abort(403)

    user, row, reason = load_session()
    if reason:
        messages = {"idle": "Session expirée après inactivité.",
                    "absolute": "Session expirée, reconnectez-vous.",
                    "ua_mismatch": "Session invalide.",
                    "blocked": "Ce compte est bloqué.",
                    "revoked": "Session terminée.",
                    "honeypot_expired": "Session expirée, reconnectez-vous."}
        uname = None
        if row is not None:
            owner = get_db().execute("SELECT username FROM users WHERE id=?", (row["user_id"],)).fetchone()
            uname = owner["username"] if owner else None
        if reason == "ua_mismatch":
            log_event("SESSION_HIJACK_SUSPECT", "critical", uname,
                      f"Cookie présenté avec un autre navigateur (session d'origine : {row['ua'][:60]})")
            create_alert("critical", "Vol de session suspecté", f"Cookie rejoué depuis {client_ip()}", uname)
        elif reason in ("idle", "absolute"):
            log_event("SESSION_EXPIRED", "info", uname, reason)
        elif reason == "honeypot_expired":
            report_id = finalize_honeypot(row)
            blacklist_ip(row["ip"] or client_ip(), f"Honeypot expiré — rapport #{report_id}")
            log_event("HONEYPOT_EXPIRED", "critical", row["honeypot_username"] or uname,
                      f"Durée de 5 minutes atteinte; IP bloquée; rapport #{report_id}")
            create_alert("critical", "IP bloquée après honeypot",
                         f"{row['ip']} — rapport d'attaque #{report_id}", row["honeypot_username"] or uname)
        session.clear()
        flash(messages[reason], "error")
        if reason == "honeypot_expired":
            abort(403)
    elif user is not None:
        g.me, g.hp, g.device_ok = user, bool(row["honeypot"]), bool(row["device_verified"])

    # CSRF : tout POST doit porter le jeton de la session
    if request.method == "POST" and not csrf_ok():
        log_event("CSRF_BLOCKED", "high", g.me["username"] if g.me else None,
                  f"POST {request.path} sans jeton CSRF valide")
        abort(400)

    # Honeypot : intercepte TOUT avant les vraies vues
    if g.hp:
        return honeypot.handle(g.me)


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cache-Control"] = "no-store"
    if USE_HTTPS:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if getattr(g, "new_device_cookie", False):
        resp.set_cookie("banque_device", g.device_token, max_age=365 * 24 * 3600,
                        httponly=True, secure=USE_HTTPS, samesite="Strict", path="/")
    return resp


@app.context_processor
def inject():
    unread = 0
    if g.get("me") is not None and g.me["role"] == "admin" and not g.get("hp"):
        unread = get_db().execute("SELECT COUNT(*) FROM alerts WHERE seen=0").fetchone()[0]
    return {"csrf_token": csrf_token, "hp": g.get("hp", False), "unread_alerts": unread}


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(429)
def http_error(e):
    titles = {400: "Requête invalide", 403: "Accès refusé", 404: "Page introuvable",
              405: "Méthode non autorisée", 429: "Trop de tentatives"}
    return render_template("error.html", code=e.code, title=titles.get(e.code, "Erreur"),
                           me=g.get("me")), e.code


# ============================================================ décorateurs d'autorisation
def login_required(f):
    @functools.wraps(f)
    def wrapper(*a, **kw):
        if g.me is None:
            flash("Veuillez vous connecter.", "error")
            return redirect(url_for("login"))
        if g.me["role"] in DEVICE_KEY_ROLES and not g.device_ok:
            abort(403)                               # jamais d'admin sans appareil vérifié
        return f(*a, **kw)
    return wrapper


def user_required(f):
    @functools.wraps(f)
    @login_required
    def wrapper(*a, **kw):
        if g.me["role"] == "admin":
            return redirect(url_for("admin_home"))
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @functools.wraps(f)
    @login_required
    def wrapper(*a, **kw):
        if g.me["role"] != "admin":                   # vérification CÔTÉ SERVEUR
            log_event("ACCESS_DENIED", "medium", g.me["username"],
                      f"Tentative d'accès à {request.path} sans le rôle admin")
            create_alert("medium", "Tentative d'élévation de privilèges",
                         f"{g.me['username']} → {request.path}", g.me["username"])
            abort(403)
        return f(*a, **kw)
    return wrapper


# ============================================================ outils formulaires
EMAIL_RE = r"[^@\s]+@[^@\s]+\.[^@\s]+"


def check_new_account(username, email, password, confirm=None):
    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
        return "Nom d'utilisateur : 3 à 20 caractères (lettres, chiffres, _)."
    if username.lower() in HONEYTOKEN_USERNAMES:
        return "Nom d'utilisateur réservé."
    if not re.fullmatch(EMAIL_RE, email):
        return "Email invalide."
    problem = password_problem(password)
    if problem:
        return problem
    if confirm is not None and password != confirm:
        return "Les mots de passe ne sont pas identiques."
    if get_db().execute("SELECT 1 FROM users WHERE username=? OR email=?", (username, email)).fetchone():
        return "Nom d'utilisateur ou email déjà utilisé."
    return None


def read_amount(field="amount"):
    try:
        value = round(float(request.form[field]), 2)
    except (ValueError, KeyError):
        return None
    return value if 0 < value <= 1_000_000 else None


def is_locked(user):
    return user["locked_until"] > time.time()


def register_failure(user):
    """Compte les échecs ; au 5e, le compte est verrouillé 15 minutes."""
    db = get_db()
    fails = user["failed_attempts"] + 1
    if fails >= MAX_FAILED_LOGINS:
        db.execute("UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?",
                   (time.time() + LOCK_MINUTES * 60, user["id"]))
        db.commit()
        log_event("ACCOUNT_LOCKED", "high", user["username"], f"{fails} échecs consécutifs")
        create_alert("high", "Compte verrouillé (force brute ?)",
                     f"{fails} mots de passe incorrects", user["username"])
    else:
        db.execute("UPDATE users SET failed_attempts=? WHERE id=?", (fails, user["id"]))
        db.commit()


def check_credentials(username, password):
    """Retourne (user, erreur). Temps de réponse identique que l'utilisateur existe ou non."""
    user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if user is None:
        check_password_hash(DUMMY_HASH, password)
        return None, "Nom d'utilisateur ou mot de passe incorrect."
    if is_locked(user):
        return None, f"Compte temporairement verrouillé ({LOCK_MINUTES} min) après trop d'échecs."
    if not check_password_hash(user["password_hash"], password):
        register_failure(user)
        return None, "Nom d'utilisateur ou mot de passe incorrect."
    if not user["active"]:
        return None, "Ce compte est bloqué. Contactez l'administrateur."
    return user, None


# ============================================================ pages publiques
@app.route("/")
def index():
    if g.me:
        return redirect(url_for("admin_home" if g.me["role"] == "admin" else "dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if rate_limited("register"):
            abort(429)
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = check_new_account(username, email, password, request.form.get("confirm", ""))
        if error:
            flash(error, "error")
            return render_template("register.html", form=request.form)
        db = get_db()
        create_user(db, username, email, password, "user", 1000)
        add_tx("depot", "-", username, 1000)
        db.commit()
        new_user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        trust_context(new_user["id"], client_ip(), g.device_token)
        log_event("REGISTER", "info", username, "Nouveau compte client")
        flash("Compte créé ! 1000 DT de bienvenue offerts. Connectez-vous.", "ok")
        return redirect(url_for("login"))
    return render_template("register.html", form={})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if rate_limited("login"):
            log_event("RATE_LIMIT", "high", None, "Trop de tentatives de connexion depuis cette IP")
            abort(429)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username.lower() in HONEYTOKEN_USERNAMES:
            log_event("HONEYTOKEN_USED", "high", username, "Nom d'utilisateur piège testé")
            create_alert("high", "Compte piège utilisé", f"Tentative avec « {username} »", username)
        user, error = check_credentials(username, password)
        candidate = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        risk_score, new_context, failures = evaluate_attempt(
            username, candidate["id"] if candidate else None, client_ip(), g.device_token, success=not error)
        log_event("RISK_SCORE", "high" if risk_score == 2 else "medium" if risk_score == 1 else "info",
                  username or "-", f"score={risk_score}; échecs récents={failures}; nouveau contexte={int(new_context)}")
        if error:
            log_event("LOGIN_FAIL", "medium", username or "-", error)
            if risk_score >= 2 and start_honeypot_session(username, candidate["id"] if candidate else None):
                log_event("HONEYPOT_TRIGGERED", "critical", username or "unknown",
                          "Risque 2 : trois échecs récents et contexte IP/jeton nouveau")
                create_alert("critical", "Attaque détectée — honeypot ouvert",
                             f"Score de risque 2 depuis {client_ip()}; session factice limitée à 5 minutes",
                             username or "unknown")
                return redirect(url_for("admin_home"))
            if risk_score == 1 and "verrouillé" not in error:
                error = "Nom d'utilisateur ou mot de passe incorrect."
            flash(error, "error")
            return render_template("login.html")
        if risk_score >= 2:
            log_event("HONEYPOT_TRIGGERED", "critical", user["username"],
                      "Risque 2 : échecs récents et contexte IP/jeton nouveau")
            create_alert("critical", "Connexion à haut risque — honeypot ouvert",
                         f"Score de risque 2 depuis {client_ip()}; session factice limitée à 5 minutes",
                         user["username"])
            start_honeypot_session(user["username"], user["id"])
            return redirect(url_for("admin_home"))
        if risk_score == 1:
            log_event("RISK_LOGIN_DENIED", "medium", user["username"],
                      "Connexion refusée par le moteur de risque (score 1)")
            flash("Identifiants incorrects ou connexion inhabituelle. Vérifiez vos informations et réessayez.", "error")
            return render_template("login.html")
        get_db().execute("UPDATE users SET failed_attempts=0 WHERE id=?", (user["id"],))
        get_db().commit()
        clear_recent_failures(username)
        if user["role"] in DEVICE_KEY_ROLES:
            # Étape 2 : prouver la possession de la clé privée liée à l'appareil
            rotate_server_session()
            session["pending_uid"] = user["id"]
            session["pending_at"] = time.time()
            log_event("PASSWORD_OK", "info", username, "En attente de la signature de l'appareil")
            return redirect(url_for("device_check"))
        start_session(user)
        trust_context(user["id"], client_ip(), g.device_token)
        log_event("LOGIN_OK", "info", username, "Connexion client")
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if g.me:
        log_event("LOGOUT", "info", g.me["username"], "Déconnexion")
    revoke_current_session()
    flash("Vous êtes déconnecté.", "ok")
    return redirect(url_for("index"))


# ============================================================ clé liée à l'appareil (ECDSA)
def pending_user():
    uid, started = session.get("pending_uid"), session.get("pending_at", 0)
    if not uid or time.time() - started > PENDING_LOGIN_TTL:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()


@app.route("/login/device")
def device_check():
    if pending_user() is None:
        flash("Veuillez vous connecter.", "error")
        return redirect(url_for("login"))
    return render_template("device_verify.html")


@app.route("/login/device/challenge")
def device_challenge():
    user = pending_user()
    if user is None:
        return jsonify(error="no_pending_login"), 401
    nonce = secrets.token_urlsafe(32)                       # 256 bits aléatoires
    db = get_db()
    db.execute("INSERT INTO challenges(nonce_hash,user_id,expires) VALUES(?,?,?)",
               (sha256_hex(nonce), user["id"], time.time() + CHALLENGE_TTL))
    db.commit()
    session["pending_nonce"] = nonce
    return jsonify(username=user["username"], message=f"banque-login|{user['username']}|{nonce}")


@app.route("/login/device/verify", methods=["POST"])
def device_verify():
    user, nonce = pending_user(), session.get("pending_nonce", "")
    if user is None:
        return jsonify(redirect=url_for("login")), 401
    signature = (request.get_json(silent=True) or {}).get("signature")
    db = get_db()
    ch = db.execute("SELECT * FROM challenges WHERE nonce_hash=? AND user_id=?",
                    (sha256_hex(nonce), user["id"])).fetchone()
    valid, reason = False, ""
    if ch is None or ch["used"] or ch["expires"] < time.time():
        reason = "challenge absent, expiré ou rejoué"
    else:
        db.execute("UPDATE challenges SET used=1 WHERE id=?", (ch["id"],))   # usage unique
        db.commit()
        if not signature:
            reason = "aucune signature (pas de clé privée sur cet appareil)"
        else:
            message = f"banque-login|{user['username']}|{nonce}"
            for k in db.execute("SELECT * FROM device_keys WHERE user_id=? AND revoked=0", (user["id"],)):
                if ecdsa_verify(k["public_key"], message, signature):
                    valid = True
                    db.execute("UPDATE device_keys SET last_used=? WHERE id=?", (now(), k["id"]))
                    db.commit()
                    reason = f"clé « {k['label']} » ({k['fingerprint'][:14]}…)"
                    break
            if not valid:
                reason = "signature invalide"
    if valid:
        start_session(user, device_verified=True)
        trust_context(user["id"], client_ip(), g.device_token)
        log_event("DEVICE_OK", "info", user["username"], f"Signature ECDSA valide : {reason}")
    else:
        start_session(user, honeypot=True)
        log_event("HONEYPOT_TRIGGERED", "critical", user["username"], reason)
        create_alert("critical", "Mot de passe admin utilisé sans la clé de l'appareil",
                     f"Intrus redirigé vers le honeypot ({reason}) — IP {client_ip()}", user["username"])
    # même réponse dans les deux cas : l'intrus ne voit aucune différence
    return jsonify(redirect=url_for("admin_home"))


@app.route("/device/enroll", methods=["GET", "POST"])
def device_enroll():
    """Enrôlement d'un navigateur : mot de passe + code à usage unique (hors bande)."""
    if request.method == "GET":
        return render_template("device_enroll.html")
    if rate_limited("enroll"):
        return jsonify(ok=False, error="Trop de tentatives, réessayez plus tard."), 429
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    code = str(data.get("code", "")).strip().upper()
    label = re.sub(r"[^\w .\-éèàç]", "", str(data.get("label", "")))[:40] or "Navigateur"
    public_key = str(data.get("public_key", ""))
    user, error = check_credentials(username, password)
    if error:
        log_event("ENROLL_FAIL", "medium", username or "-", error)
        return jsonify(ok=False, error=error), 400
    if user["role"] not in DEVICE_KEY_ROLES:
        return jsonify(ok=False, error="Ce compte n'utilise pas de clé d'appareil."), 400
    db = get_db()
    row = db.execute("SELECT * FROM enroll_codes WHERE user_id=? AND code_hash=? AND used=0 AND expires>?",
                     (user["id"], sha256_hex(code), time.time())).fetchone()
    if row is None:
        log_event("ENROLL_BAD_CODE", "critical", username, "Bon mot de passe mais code d'enrôlement invalide")
        create_alert("critical", "Tentative d'enrôlement d'appareil refusée",
                     "Le mot de passe admin était correct mais pas le code", username)
        return jsonify(ok=False, error="Code d'enrôlement invalide ou expiré."), 400
    if load_public_key(public_key) is None:
        return jsonify(ok=False, error="Clé publique invalide (ECDSA P-256 attendue)."), 400
    fp = key_fingerprint(public_key)
    db.execute("UPDATE enroll_codes SET used=1 WHERE id=?", (row["id"],))
    db.execute("INSERT INTO device_keys(user_id,public_key,fingerprint,label,created_at) VALUES(?,?,?,?,?)",
               (user["id"], public_key, fp, label, now()))
    db.commit()
    trust_context(user["id"], client_ip(), g.device_token)
    log_event("DEVICE_ENROLLED", "high", username, f"Nouvelle clé « {label} » {fp}")
    create_alert("info", "Nouvel appareil de confiance enrôlé", f"{label} — {fp}", username)
    return jsonify(ok=True, fingerprint=fp)


# ============================================================ dashboard CLIENT
@app.route("/dashboard")
@user_required
def dashboard():
    txs = get_db().execute("SELECT * FROM transactions WHERE sender=? OR receiver=? ORDER BY id DESC LIMIT 5",
                           (g.me["username"], g.me["username"])).fetchall()
    return render_template("user_home.html", me=g.me, txs=txs)


@app.route("/transfer", methods=["GET", "POST"])
@user_required
def transfer():
    db = get_db()
    if request.method == "POST":
        to = request.form.get("to", "").strip()
        amount = read_amount()
        dest = db.execute("SELECT * FROM users WHERE username=? AND role='user' AND active=1", (to,)).fetchone()
        if amount is None:
            flash("Montant invalide.", "error")
        elif dest is None or dest["id"] == g.me["id"]:
            flash("Destinataire introuvable.", "error")
        elif amount > g.me["balance"]:
            flash("Solde insuffisant.", "error")
        else:
            db.execute("UPDATE users SET balance=balance-? WHERE id=?", (amount, g.me["id"]))
            db.execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, dest["id"]))
            add_tx("virement", g.me["username"], dest["username"], amount)
            db.commit()
            flash(f"Virement de {amount:.2f} DT envoyé à {dest['username']}.", "ok")
            return redirect(url_for("dashboard"))
    others = db.execute("SELECT username FROM users WHERE role='user' AND active=1 AND id!=? ORDER BY username",
                        (g.me["id"],)).fetchall()
    return render_template("transfer.html", me=g.me, others=others)


def cash_operation(kind):
    db = get_db()
    if request.method == "POST":
        amount = read_amount()
        if amount is None:
            flash("Montant invalide.", "error")
        elif kind == "retrait" and amount > g.me["balance"]:
            flash("Solde insuffisant.", "error")
        else:
            sign = 1 if kind == "depot" else -1
            db.execute("UPDATE users SET balance=balance+? WHERE id=?", (sign * amount, g.me["id"]))
            if kind == "depot":
                add_tx("depot", "-", g.me["username"], amount)
            else:
                add_tx("retrait", g.me["username"], "-", amount)
            db.commit()
            flash(f"{'Dépôt' if kind == 'depot' else 'Retrait'} de {amount:.2f} DT effectué.", "ok")
            return redirect(url_for("dashboard"))
    return render_template("cash.html", me=g.me, kind=kind)


@app.route("/deposit", methods=["GET", "POST"])
@user_required
def deposit():
    return cash_operation("depot")


@app.route("/withdraw", methods=["GET", "POST"])
@user_required
def withdraw():
    return cash_operation("retrait")


@app.route("/history")
@user_required
def history():
    txs = get_db().execute("SELECT * FROM transactions WHERE sender=? OR receiver=? ORDER BY id DESC",
                           (g.me["username"], g.me["username"])).fetchall()
    return render_template("history.html", me=g.me, txs=txs)


# ============================================================ profil (client et admin)
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "email":
            email = request.form.get("email", "").strip().lower()
            if not re.fullmatch(EMAIL_RE, email):
                flash("Email invalide.", "error")
            elif db.execute("SELECT 1 FROM users WHERE email=? AND id!=?", (email, g.me["id"])).fetchone():
                flash("Cet email est déjà utilisé.", "error")
            else:
                db.execute("UPDATE users SET email=? WHERE id=?", (email, g.me["id"]))
                db.commit()
                flash("Email modifié.", "ok")
        elif action == "password":
            old, new, confirm = (request.form.get(k, "") for k in ("old", "new", "confirm"))
            problem = password_problem(new)
            if not check_password_hash(g.me["password_hash"], old):
                log_event("PASSWORD_CHANGE_FAIL", "medium", g.me["username"], "Ancien mot de passe incorrect")
                flash("Ancien mot de passe incorrect.", "error")
            elif problem:
                flash(problem, "error")
            elif new != confirm:
                flash("Les nouveaux mots de passe ne sont pas identiques.", "error")
            else:
                db.execute("UPDATE users SET password_hash=? WHERE id=?",
                           (generate_password_hash(new, method="scrypt"), g.me["id"]))
                db.commit()
                revoke_user_sessions(g.me["id"], keep_current=True)
                log_event("PASSWORD_CHANGED", "info", g.me["username"], "Autres sessions révoquées")
                flash("Mot de passe modifié. Vos autres sessions ont été fermées.", "ok")
        elif action == "logout_all":
            revoke_user_sessions(g.me["id"], keep_current=True)
            log_event("SESSIONS_REVOKED", "info", g.me["username"], "Déconnexion des autres appareils")
            flash("Toutes vos autres sessions ont été fermées.", "ok")
        return redirect(url_for("profile"))
    rib = decrypt(g.me["rib_enc"], aad=g.me["username"]) if g.me["rib_enc"] else None
    sessions_count = db.execute("SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked=0",
                                (g.me["id"],)).fetchone()[0]
    return render_template("profile.html", me=g.me, rib=rib, sessions_count=sessions_count)


# ============================================================ dashboard ADMIN
@app.route("/admin")
@admin_required
def admin_home():
    db = get_db()
    stats = {
        "clients": db.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0],
        "actifs": db.execute("SELECT COUNT(*) FROM users WHERE role='user' AND active=1").fetchone()[0],
        "total": db.execute("SELECT COALESCE(SUM(balance),0) FROM users").fetchone()[0],
        "tx": db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0],
    }
    stats["bloques"] = stats["clients"] - stats["actifs"]
    txs = db.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT 6").fetchall()
    newest = db.execute("SELECT * FROM users WHERE role='user' ORDER BY id DESC LIMIT 5").fetchall()
    return render_template("admin_home.html", me=g.me, stats=stats, txs=txs, newest=newest)


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    db = get_db()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = check_new_account(username, email, password)
        try:
            balance = min(1_000_000.0, max(0.0, round(float(request.form.get("balance") or 0), 2)))
        except ValueError:
            balance = 0.0
        if error:
            flash(error, "error")
        else:
            create_user(db, username, email, password, "user", balance)
            if balance > 0:
                add_tx("depot", "-", username, balance)
            db.commit()
            log_event("ADMIN_CREATE_USER", "info", g.me["username"], f"Client {username} créé")
            flash(f"Client {username} créé.", "ok")
        return redirect(url_for("admin_users"))
    q = request.args.get("q", "").strip()
    users = db.execute("SELECT * FROM users WHERE role='user' AND (username LIKE ? OR email LIKE ?) ORDER BY id",
                       (f"%{q}%", f"%{q}%")).fetchall()
    return render_template("admin_users.html", me=g.me, users=users, q=q)


@app.route("/admin/users/<int:uid>", methods=["GET", "POST"])
@admin_required
def admin_edit(uid):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=? AND role='user'", (uid,)).fetchone()
    if user is None:
        abort(404)
    if request.method == "POST":
        action = request.form.get("action")
        if action == "email":
            email = request.form.get("email", "").strip().lower()
            if not re.fullmatch(EMAIL_RE, email):
                flash("Email invalide.", "error")
            elif db.execute("SELECT 1 FROM users WHERE email=? AND id!=?", (email, uid)).fetchone():
                flash("Cet email est déjà utilisé.", "error")
            else:
                db.execute("UPDATE users SET email=? WHERE id=?", (email, uid))
                db.commit()
                flash("Email modifié.", "ok")
        elif action == "balance":
            amount = read_amount()
            sign = 1 if request.form.get("sign") == "credit" else -1
            if amount is None:
                flash("Montant invalide.", "error")
            elif sign == -1 and amount > user["balance"]:
                flash("Le solde du client est insuffisant.", "error")
            else:
                db.execute("UPDATE users SET balance=balance+? WHERE id=?", (sign * amount, uid))
                if sign == 1:
                    add_tx("ajustement", "banque", user["username"], amount)
                else:
                    add_tx("ajustement", user["username"], "banque", amount)
                db.commit()
                log_event("ADMIN_BALANCE", "medium", g.me["username"],
                          f"{'+' if sign == 1 else '-'}{amount:.2f} DT sur {user['username']}")
                flash("Solde mis à jour.", "ok")
        elif action == "password":
            new = request.form.get("new", "")
            problem = password_problem(new)
            if problem:
                flash(problem, "error")
            else:
                db.execute("UPDATE users SET password_hash=? WHERE id=?",
                           (generate_password_hash(new, method="scrypt"), uid))
                db.commit()
                revoke_user_sessions(uid)
                log_event("ADMIN_RESET_PASSWORD", "medium", g.me["username"], f"Client {user['username']}")
                flash("Mot de passe réinitialisé (sessions du client fermées).", "ok")
        elif action == "unlock":
            db.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (uid,))
            db.commit()
            log_event("ADMIN_UNLOCK", "info", g.me["username"], f"Client {user['username']} déverrouillé")
            flash("Compte déverrouillé.", "ok")
        return redirect(url_for("admin_edit", uid=uid))
    txs = db.execute("SELECT * FROM transactions WHERE sender=? OR receiver=? ORDER BY id DESC LIMIT 10",
                     (user["username"], user["username"])).fetchall()
    rib = decrypt(user["rib_enc"], aad=user["username"])
    return render_template("admin_edit.html", me=g.me, user=dict(user, locked=is_locked(user)),
                           rib=rib or "⚠️ déchiffrement impossible (donnée altérée)", txs=txs)


@app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def admin_toggle(uid):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=? AND role='user'", (uid,)).fetchone()
    if user:
        db.execute("UPDATE users SET active=? WHERE id=?", (0 if user["active"] else 1, uid))
        db.commit()
        if user["active"]:
            revoke_user_sessions(uid)
        state = "bloqué" if user["active"] else "débloqué"
        log_event("ADMIN_TOGGLE", "medium", g.me["username"], f"Compte {user['username']} {state}")
        flash(f"Compte {user['username']} {state}.", "ok")
    return redirect(request.referrer or url_for("admin_users"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete(uid):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=? AND role='user'", (uid,)).fetchone()
    if user:
        revoke_user_sessions(uid)
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.commit()
        log_event("ADMIN_DELETE_USER", "high", g.me["username"], f"Client {user['username']} supprimé")
        flash(f"Client {user['username']} supprimé.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/transactions")
@admin_required
def admin_transactions():
    kind = request.args.get("kind", "")
    db = get_db()
    if kind in ("depot", "retrait", "virement", "ajustement"):
        txs = db.execute("SELECT * FROM transactions WHERE kind=? ORDER BY id DESC", (kind,)).fetchall()
    else:
        kind = ""
        txs = db.execute("SELECT * FROM transactions ORDER BY id DESC").fetchall()
    return render_template("admin_transactions.html", me=g.me, txs=txs, kind=kind)


# ============================================================ intégrité (HMAC)
@app.route("/admin/integrity")
@admin_required
def admin_integrity():
    db = get_db()
    txs = db.execute("SELECT * FROM transactions ORDER BY id").fetchall()
    bad = [t for t in txs if not tx_is_valid(t)]
    # cohérence des soldes : solde = somme des crédits - somme des débits
    expected = defaultdict(float)
    for t in txs:
        if t["receiver"] not in ("-", "banque"):
            expected[t["receiver"]] += t["amount"]
        if t["sender"] not in ("-", "banque"):
            expected[t["sender"]] -= t["amount"]
    mismatches = [{"username": u["username"], "balance": u["balance"], "expected": expected[u["username"]]}
                  for u in db.execute("SELECT * FROM users WHERE role='user'")
                  if abs(u["balance"] - expected[u["username"]]) > 0.005]
    bad_logs = verify_log_chain()
    if bad or mismatches or bad_logs:
        details = f"{len(bad)} transaction(s), {len(mismatches)} solde(s), {len(bad_logs)} ligne(s) de journal"
        log_event("INTEGRITY_FAIL", "critical", g.me["username"], details)
        create_alert("critical", "Falsification de données détectée", details)
    return render_template("admin_integrity.html", me=g.me, total=len(txs), bad=bad,
                           mismatches=mismatches, bad_logs=bad_logs,
                           log_total=db.execute("SELECT COUNT(*) FROM security_logs").fetchone()[0])


# ============================================================ démonstration cryptographique
@app.route("/admin/crypto", methods=["GET", "POST"])
@admin_required
def admin_crypto():
    db = get_db()
    demo = None
    if request.method == "POST":
        text = request.form.get("text", "")[:500]
        token = encrypt(text, aad="demo")
        raw = bytearray(base64.b64decode(token))
        raw[-1] ^= 0x01                                            # on modifie 1 bit du tag
        tampered = base64.b64encode(bytes(raw)).decode()
        demo = {"text": text, "cipher": token, "decrypted": decrypt(token, "demo"),
                "tampered": tampered, "tampered_result": decrypt(tampered, "demo"),
                "sha256": sha256_hex(text), "hmac": hmac_demo(text),
                "hmac_modified": hmac_demo(text + " ")}
    users = [{"username": u["username"], "cipher": u["rib_enc"],
              "clear": decrypt(u["rib_enc"], aad=u["username"])}
             for u in db.execute("SELECT * FROM users WHERE role='user' ORDER BY id")]
    keys = db.execute("SELECT k.*, u.username FROM device_keys k JOIN users u ON u.id=k.user_id "
                      "WHERE k.revoked=0 ORDER BY k.id").fetchall()
    return render_template("admin_crypto.html", me=g.me, demo=demo, users=users, keys=keys)


# ============================================================ centre de sécurité
@app.route("/admin/security")
@admin_required
def admin_security():
    db = get_db()
    event = request.args.get("event", "")
    day = "datetime('now','localtime','-1 day')"
    stats = {
        "alerts": db.execute("SELECT COUNT(*) FROM alerts WHERE seen=0").fetchone()[0],
        "login_ok": db.execute(f"SELECT COUNT(*) FROM security_logs WHERE event IN ('LOGIN_OK','DEVICE_OK') AND ts>={day}").fetchone()[0],
        "login_fail": db.execute(f"SELECT COUNT(*) FROM security_logs WHERE event='LOGIN_FAIL' AND ts>={day}").fetchone()[0],
        "honeypot": db.execute("SELECT COUNT(*) FROM security_logs WHERE event LIKE 'HONEYPOT%'").fetchone()[0],
        "locked": db.execute("SELECT COUNT(*) FROM users WHERE locked_until>?", (time.time(),)).fetchone()[0],
        "sessions": db.execute("SELECT COUNT(*) FROM sessions WHERE revoked=0 AND last_seen>?",
                               (time.time() - 15 * 60,)).fetchone()[0],
        "blacklisted": db.execute("SELECT COUNT(*) FROM blacklisted_ips WHERE expires_at IS NULL OR expires_at>?",
                                   (time.time(),)).fetchone()[0],
        "reports": db.execute("SELECT COUNT(*) FROM attack_reports").fetchone()[0],
    }
    alerts = db.execute("SELECT * FROM alerts ORDER BY seen, id DESC LIMIT 30").fetchall()
    hp_events = db.execute("SELECT * FROM security_logs WHERE event LIKE 'HONEYPOT%' ORDER BY id DESC LIMIT 30").fetchall()
    if event:
        logs = db.execute("SELECT * FROM security_logs WHERE event=? ORDER BY id DESC LIMIT 100", (event,)).fetchall()
    else:
        logs = db.execute("SELECT * FROM security_logs ORDER BY id DESC LIMIT 100").fetchall()
    events = [r[0] for r in db.execute("SELECT DISTINCT event FROM security_logs ORDER BY event")]
    sessions = db.execute("SELECT s.*, u.username, u.role FROM sessions s JOIN users u ON u.id=s.user_id "
                          "WHERE s.revoked=0 AND s.last_seen>? ORDER BY s.last_seen DESC",
                          (time.time() - 15 * 60,)).fetchall()
    blacklist = db.execute("SELECT * FROM blacklisted_ips WHERE expires_at IS NULL OR expires_at>? ORDER BY created_at DESC",
                           (time.time(),)).fetchall()
    reports = db.execute("SELECT id,username,ip,started_at,ended_at,event_count FROM attack_reports ORDER BY id DESC LIMIT 20").fetchall()
    return render_template("admin_security.html", me=g.me, stats=stats, alerts=alerts, hp_events=hp_events,
                           logs=logs, events=events, event=event, sessions=sessions,
                           blacklist=blacklist, reports=reports,
                           fmt=lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)))


@app.route("/admin/reports")
@admin_required
def admin_reports():
    reports = get_db().execute("SELECT id,username,ip,started_at,ended_at,event_count FROM attack_reports ORDER BY id DESC").fetchall()
    return render_template("admin_reports.html", me=g.me, reports=reports,
                           fmt=lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)))


@app.route("/admin/reports/<int:report_id>")
@admin_required
def admin_report_detail(report_id):
    report = get_db().execute("SELECT * FROM attack_reports WHERE id=?", (report_id,)).fetchone()
    if report is None:
        abort(404)
    return render_template("admin_report.html", me=g.me, report=report,
                           payload=json.loads(report["report_json"]))


@app.route("/admin/blacklist/remove", methods=["POST"])
@admin_required
def admin_blacklist_remove():
    ip = request.form.get("ip", "").strip()
    remove_blacklist(ip)
    log_event("BLACKLIST_REMOVED", "medium", g.me["username"], f"IP {ip} retirée de la liste noire par un administrateur")
    flash(f"IP {ip} retirée de la liste noire.", "ok")
    return redirect(url_for("admin_security"))


@app.route("/admin/alerts/read", methods=["POST"])
@admin_required
def admin_alerts_read():
    db = get_db()
    aid = request.form.get("id")
    if aid:
        db.execute("UPDATE alerts SET seen=1 WHERE id=?", (aid,))
    else:
        db.execute("UPDATE alerts SET seen=1")
    db.commit()
    return redirect(url_for("admin_security"))


@app.route("/admin/sessions/<int:sid>/revoke", methods=["POST"])
@admin_required
def admin_revoke_session(sid):
    db = get_db()
    db.execute("UPDATE sessions SET revoked=1 WHERE id=?", (sid,))
    db.commit()
    log_event("ADMIN_REVOKE_SESSION", "medium", g.me["username"], f"Session #{sid} révoquée")
    flash(f"Session #{sid} révoquée.", "ok")
    return redirect(url_for("admin_security"))


# ============================================================ appareils de confiance
@app.route("/admin/devices", methods=["GET", "POST"])
@admin_required
def admin_devices():
    db = get_db()
    code = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "code":
            code = issue_enroll_code(g.me["id"])
            log_event("ENROLL_CODE_ISSUED", "medium", g.me["username"], "Code généré depuis le tableau de bord")
        elif action == "revoke":
            kid = request.form.get("id")
            db.execute("UPDATE device_keys SET revoked=1 WHERE id=? AND user_id=?", (kid, g.me["id"]))
            db.commit()
            log_event("DEVICE_REVOKED", "high", g.me["username"], f"Clé #{kid} révoquée")
            flash("Clé révoquée : ce navigateur ne pourra plus accéder au vrai tableau de bord.", "ok")
            return redirect(url_for("admin_devices"))
    keys = db.execute("SELECT * FROM device_keys WHERE user_id=? ORDER BY revoked, id DESC", (g.me["id"],)).fetchall()
    return render_template("admin_devices.html", me=g.me, keys=keys, code=code, ttl=ENROLL_CODE_TTL_MINUTES)


# ============================================================ commandes CLI
@app.cli.command("enroll-code")
@click.argument("username")
def cli_enroll_code(username):
    """flask --app app enroll-code admin  → code d'enrôlement à usage unique."""
    init_db()
    user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if user is None or user["role"] not in DEVICE_KEY_ROLES:
        click.echo("Utilisateur inconnu ou non concerné par la clé d'appareil.")
        return
    click.echo(f"Code d'enrôlement pour {username} : {issue_enroll_code(user['id'])} "
               f"(valable {ENROLL_CODE_TTL_MINUTES} min, usage unique)")


@app.cli.command("unlock")
@click.argument("username")
def cli_unlock(username):
    """flask --app app unlock admin  → lève le verrouillage après trop d'échecs."""
    db = get_db()
    db.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?", (username,))
    db.commit()
    click.echo(f"{username} déverrouillé.")


@app.cli.command("trust-context")
@click.argument("username")
@click.argument("ip")
def cli_trust_context(username, ip):
    """Approve a browser token/IP only after the account owner is verified out of band."""
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise click.BadParameter("adresse IP invalide")
    with app.app_context():
        init_db()
        user = get_db().execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if user is None:
            raise click.ClickException("Utilisateur inconnu.")
        token = click.prompt("Jeton banque_device du navigateur à approuver", hide_input=True)
        if not re.fullmatch(r"[A-Za-z0-9_-]{40,60}", token):
            raise click.ClickException("Jeton de navigateur invalide.")
        trust_context(user["id"], ip, token)
        log_event("TRUST_CONTEXT_APPROVED", "high", username,
                  f"Contexte IP/jeton approuvé localement : {ip}")
    click.echo(f"Contexte approuvé pour {username} depuis {ip}.")


@app.cli.command("expire-honeypots")
def cli_expire_honeypots():
    """Expire, bloque et rapporte les honeypots arrivés à échéance (cron-friendly)."""
    with app.app_context():
        init_db()
        count = expire_honeypot_sessions()
    click.echo(f"{count} session(s) honeypot expirée(s), IP bloquée(s), rapport(s) généré(s).")


def print_enroll_codes(base_url):
    db = get_db()
    admins = db.execute("SELECT u.* FROM users u WHERE u.role IN (%s) AND NOT EXISTS "
                        "(SELECT 1 FROM device_keys k WHERE k.user_id=u.id AND k.revoked=0)"
                        % ",".join("?" * len(DEVICE_KEY_ROLES)), tuple(DEVICE_KEY_ROLES)).fetchall()
    for a in admins:
        code = issue_enroll_code(a["id"])
        print("\n" + "=" * 68)
        print(f"  🔑 Aucun appareil de confiance pour « {a['username']} ».")
        print(f"  1) Ouvrez {base_url}/device/enroll dans VOTRE navigateur")
        print(f"  2) Code d'enrôlement (usage unique, {ENROLL_CODE_TTL_MINUTES} min) : {code}")
        print("=" * 68 + "\n")


if __name__ == "__main__":
    import os
    with app.app_context():
        init_db()
        scheme = "https" if USE_HTTPS else "http"
        print_enroll_codes(f"{scheme}://127.0.0.1:5000")
    debug = os.environ.get("FLASK_DEBUG") == "1"
    ssl_context = None
    if MTLS_ENABLED and not USE_HTTPS:
        raise RuntimeError("MTLS_ENABLED=1 exige certs/cert.pem et certs/key.pem; exécutez generate_keys.sh.")
    if USE_HTTPS:
        if MTLS_ENABLED:
            if not os.path.isfile(CLIENT_CA_FILE):
                raise RuntimeError(f"MTLS_ENABLED=1 mais CA client introuvable : {CLIENT_CA_FILE}")
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)
            ssl_context.load_verify_locations(cafile=CLIENT_CA_FILE)
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            print(f"mTLS activé — certificats clients vérifiés par {CLIENT_CA_FILE}")
        else:
            ssl_context = (CERT_FILE, KEY_FILE)
    # use_reloader=False : sinon le code d'enrôlement serait généré deux fois
    app.run(host="127.0.0.1", port=5000, debug=debug, use_reloader=False, ssl_context=ssl_context)

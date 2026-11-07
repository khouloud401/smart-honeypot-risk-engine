"""Tests automatiques de sécurité  →  python -m pytest -v

Chaque test correspond à un cas de docs/TESTS_SECURITE.md."""
import base64
import os
import re
import sqlite3
import sys
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db as dbmod  # noqa: E402
import app as appmod  # noqa: E402

UA = "pytest-navigateur-A"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    appmod.app.config["TESTING"] = True
    from security import _hits
    _hits.clear()
    with appmod.app.app_context():
        appmod.init_db()
    c = appmod.app.test_client()
    c.environ_base["HTTP_USER_AGENT"] = UA
    return c


def raw_db():
    con = sqlite3.connect(dbmod.DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def csrf_of(c, url="/login"):
    html = c.get(url).get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def login(c, username, password):
    token = csrf_of(c)
    return c.post("/login", data={"username": username, "password": password, "csrf": token})


# ------------------------------------------------------------ outils « navigateur » ECDSA
def new_device_key():
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, base64.b64encode(spki).decode()


def webcrypto_sign(priv, message):
    """Reproduit le format de WebCrypto : r||s brut sur 64 octets."""
    r, s = decode_dss_signature(priv.sign(message.encode(), ec.ECDSA(hashes.SHA256())))
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def enroll(c, priv_spki):
    with appmod.app.app_context():
        code = appmod.issue_enroll_code(1)
    token = csrf_of(c, "/device/enroll")
    return c.post("/device/enroll", json={"username": "admin", "password": "Admin@123", "code": code,
                                          "label": "Test", "public_key": priv_spki},
                  headers={"X-CSRF-Token": token})


def admin_device_login(c, priv=None, tamper=False):
    assert login(c, "admin", "Admin@123").status_code == 302
    page = c.get("/login/device").get_data(as_text=True)
    token = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    ch = c.get("/login/device/challenge").get_json()
    sig = None
    if priv:
        msg = ch["message"] + ("x" if tamper else "")
        sig = webcrypto_sign(priv, msg)
    return c.post("/login/device/verify", json={"signature": sig}, headers={"X-CSRF-Token": token})


# ============================================================ 1. mots de passe & comptes
def test_passwords_are_hashed_with_scrypt(client):
    row = raw_db().execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
    assert row[0].startswith("scrypt:") and "Alice@123" not in row[0]


def test_weak_password_rejected(client):
    token = csrf_of(client, "/register")
    r = client.post("/register", data={"username": "eve", "email": "eve@x.tn", "password": "motdepasse",
                                       "confirm": "motdepasse", "csrf": token})
    assert "majuscule" in r.get_data(as_text=True)


def test_account_locked_after_5_failures(client):
    for _ in range(5):
        login(client, "bob", "mauvais")
    r = login(client, "bob", "Bob@12345")               # bon mot de passe, mais verrouillé
    assert "verrouillé" in r.get_data(as_text=True)


def test_rib_is_encrypted_at_rest(client):
    rib = raw_db().execute("SELECT rib_enc FROM users WHERE username='alice'").fetchone()[0]
    assert not rib.startswith("TN59")
    with appmod.app.app_context():
        assert appmod.decrypt(rib, aad="alice").startswith("TN59")
        assert appmod.decrypt(rib, aad="bob") is None   # AAD différente → refus


# ============================================================ 2. sessions
def test_csrf_required(client):
    csrf_of(client)
    r = client.post("/login", data={"username": "alice", "password": "Alice@123"})
    assert r.status_code == 400


def test_session_cookie_flags(client):
    r = login(client, "alice", "Alice@123")
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_session_cookie_is_opaque_and_session_id_rotates(client):
    page = client.get("/login").get_data(as_text=True)
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    anonymous_cookie = client.get_cookie("banque_session").value
    interface = appmod.app.session_interface
    anonymous_sid = interface._serializer(appmod.app).loads(anonymous_cookie)
    stored = raw_db().execute("SELECT sid_hash,data FROM app_sessions WHERE sid_hash=?",
                              (appmod.sha256_hex(anonymous_sid),)).fetchone()
    assert stored is not None and csrf in stored["data"]
    assert csrf not in anonymous_cookie and anonymous_sid not in stored["data"]

    client.post("/login", data={"username": "alice", "password": "Alice@123", "csrf": csrf})
    authenticated_cookie = client.get_cookie("banque_session").value
    authenticated_sid = interface._serializer(appmod.app).loads(authenticated_cookie)
    assert authenticated_sid != anonymous_sid
    assert raw_db().execute("SELECT 1 FROM sessions WHERE sid_hash=?",
                            (appmod.sha256_hex(authenticated_sid),)).fetchone()


def test_logout_revokes_server_session(client):
    login(client, "alice", "Alice@123")
    stolen = client.get_cookie("banque_session").value
    token = csrf_of(client, "/dashboard")
    client.post("/logout", data={"csrf": token})
    client.set_cookie("banque_session", stolen)         # rejoue l'ancien cookie
    assert client.get("/dashboard").status_code == 302


def test_cookie_replayed_from_other_browser(client):
    login(client, "alice", "Alice@123")
    client.environ_base["HTTP_USER_AGENT"] = "navigateur-de-l-attaquant"
    assert client.get("/dashboard").status_code == 302
    assert raw_db().execute("SELECT COUNT(*) FROM alerts WHERE title LIKE 'Vol de session%'").fetchone()[0] == 1


def test_security_headers(client):
    r = client.get("/login")
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"


# ============================================================ 3. autorisation serveur
def test_user_cannot_access_admin(client):
    login(client, "alice", "Alice@123")
    assert client.get("/admin/users").status_code == 403


def test_anonymous_redirected(client):
    assert client.get("/admin").status_code == 302


def test_admin_password_only_is_not_enough(client):
    """Mot de passe admin correct mais on saute l'étape de signature."""
    login(client, "admin", "Admin@123")
    assert client.get("/admin/security").status_code == 302   # pas de session admin


# ============================================================ 4. clé liée à l'appareil + honeypot
def test_valid_signature_gives_real_dashboard(client):
    priv, spki = new_device_key()
    assert enroll(client, spki).get_json()["ok"]
    admin_device_login(client, priv)
    html = client.get("/admin").get_data(as_text=True)
    assert "alice" in html and "Centre de sécurité" in html


def test_no_key_gives_honeypot(client):
    priv, spki = new_device_key()
    enroll(client, spki)
    admin_device_login(client, None)                     # attaquant : mot de passe, pas de clé
    html = client.get("/admin").get_data(as_text=True)
    assert "k_benali" in html and "alice" not in html and "Centre de sécurité" not in html
    assert raw_db().execute("SELECT COUNT(*) FROM alerts WHERE severity='critical'").fetchone()[0] >= 1


def test_wrong_key_gives_honeypot(client):
    _, spki = new_device_key()
    enroll(client, spki)
    other, _ = new_device_key()                          # clé d'un autre appareil
    admin_device_login(client, other)
    assert "k_benali" in client.get("/admin").get_data(as_text=True)


def test_tampered_signature_gives_honeypot(client):
    priv, spki = new_device_key()
    enroll(client, spki)
    admin_device_login(client, priv, tamper=True)
    assert "k_benali" in client.get("/admin").get_data(as_text=True)


def test_honeypot_actions_do_not_touch_real_db(client):
    priv, spki = new_device_key()
    enroll(client, spki)
    admin_device_login(client, None)
    token = csrf_of(client, "/admin")
    client.post("/admin/users/2/delete", data={"csrf": token})        # tente de supprimer alice
    assert raw_db().execute("SELECT COUNT(*) FROM users WHERE username='alice'").fetchone()[0] == 1
    assert raw_db().execute("SELECT COUNT(*) FROM security_logs WHERE event='HONEYPOT_ACTION'").fetchone()[0] >= 1


def test_enroll_requires_code(client):
    _, spki = new_device_key()
    token = csrf_of(client, "/device/enroll")
    r = client.post("/device/enroll", json={"username": "admin", "password": "Admin@123", "code": "AAAA-BBBB-CCCC",
                                            "public_key": spki}, headers={"X-CSRF-Token": token})
    assert not r.get_json()["ok"]


def test_challenge_cannot_be_replayed(client):
    priv, spki = new_device_key()
    enroll(client, spki)
    login(client, "admin", "Admin@123")
    token = re.search(r'name="csrf-token" content="([^"]+)"', client.get("/login/device").get_data(as_text=True)).group(1)
    ch = client.get("/login/device/challenge").get_json()
    sig = webcrypto_sign(priv, ch["message"])
    client.post("/login/device/verify", json={"signature": sig}, headers={"X-CSRF-Token": token})
    # l'attaquant rejoue la même signature interceptée
    c2 = appmod.app.test_client()
    c2.environ_base["HTTP_USER_AGENT"] = UA
    c2.set_cookie("banque_device", client.get_cookie("banque_device").value)
    login(c2, "admin", "Admin@123")
    token2 = re.search(r'name="csrf-token" content="([^"]+)"', c2.get("/login/device").get_data(as_text=True)).group(1)
    c2.get("/login/device/challenge")                    # nouveau nonce ≠ ancien
    c2.post("/login/device/verify", json={"signature": sig}, headers={"X-CSRF-Token": token2})
    assert "k_benali" in c2.get("/admin").get_data(as_text=True)


# ============================================================ 5. intégrité HMAC
def test_hmac_detects_tampered_transaction(client):
    priv, spki = new_device_key()
    enroll(client, spki)
    admin_device_login(client, priv)
    assert "sont intactes" in client.get("/admin/integrity").get_data(as_text=True)
    con = raw_db()
    con.execute("UPDATE transactions SET amount=99999 WHERE id=3")
    con.commit()
    assert "1 transaction(s) falsifiée(s)" in client.get("/admin/integrity").get_data(as_text=True)


def test_log_chain_detects_edit(client):
    priv, spki = new_device_key()
    enroll(client, spki)
    admin_device_login(client, priv)
    con = raw_db()
    con.execute("UPDATE security_logs SET details='effacé' WHERE id=1")
    con.commit()
    assert "journal modifié" in client.get("/admin/integrity").get_data(as_text=True)


def test_unknown_ip_is_denied_at_risk_score_one(client):
    login(client, "alice", "Alice@123")
    token = client.get_cookie("banque_device").value
    other = appmod.app.test_client()
    other.environ_base["HTTP_USER_AGENT"] = UA
    other.environ_base["REMOTE_ADDR"] = "203.0.113.17"
    other.set_cookie("banque_device", token)
    response = login(other, "alice", "Alice@123")
    assert response.status_code == 200
    assert "connexion inhabituelle" in response.get_data(as_text=True)
    assert "RISK_LOGIN_DENIED" in [r[0] for r in raw_db().execute(
        "SELECT event FROM security_logs WHERE username='alice'").fetchall()]


def test_unknown_browser_token_is_denied_at_risk_score_one(client):
    login(client, "alice", "Alice@123")
    other = appmod.app.test_client()
    other.environ_base["HTTP_USER_AGENT"] = UA
    response = login(other, "alice", "Alice@123")
    assert response.status_code == 200
    assert "connexion inhabituelle" in response.get_data(as_text=True)


def test_additive_session_schema_migration(tmp_path, monkeypatch):
    legacy_db = tmp_path / "legacy.db"
    monkeypatch.setattr(dbmod, "DB_PATH", str(legacy_db))
    con = sqlite3.connect(legacy_db)
    con.execute("CREATE TABLE sessions(id INTEGER PRIMARY KEY, sid_hash TEXT UNIQUE NOT NULL, "
                "user_id INTEGER NOT NULL, created REAL NOT NULL, last_seen REAL NOT NULL, ip TEXT, ua TEXT, "
                "device_verified INTEGER NOT NULL DEFAULT 0, honeypot INTEGER NOT NULL DEFAULT 0, "
                "revoked INTEGER NOT NULL DEFAULT 0)")
    con.commit()
    con.close()
    with appmod.app.app_context():
        appmod.init_db()
    cols = {row[1] for row in sqlite3.connect(legacy_db).execute("PRAGMA table_info(sessions)")}
    assert {"honeypot_expires", "honeypot_username"} <= cols


def test_risk_two_starts_five_minute_honeypot_then_blacklists_and_reports(client):
    login(client, "alice", "Alice@123")  # trusted baseline context
    attacker = appmod.app.test_client()
    attacker.environ_base["HTTP_USER_AGENT"] = UA
    attacker.environ_base["REMOTE_ADDR"] = "203.0.113.77"
    for i in range(3):
        response = login(attacker, "alice", f"wrong-{i}")
    assert response.status_code == 302
    fake = attacker.get("/admin").get_data(as_text=True)
    assert "k_benali" in fake and 'href="/admin/security"' not in fake
    row = raw_db().execute("SELECT id FROM sessions WHERE honeypot=1 ORDER BY id DESC LIMIT 1").fetchone()
    con = raw_db()
    con.execute("UPDATE sessions SET honeypot_expires=? WHERE id=?", (time.time() - 1, row["id"]))
    con.commit()
    assert attacker.get("/admin").status_code == 403
    assert raw_db().execute("SELECT 1 FROM blacklisted_ips WHERE ip='203.0.113.77'").fetchone()
    report = raw_db().execute("SELECT * FROM attack_reports WHERE session_id=?", (row["id"],)).fetchone()
    assert report is not None and report["username"] == "alice"
    assert raw_db().execute("SELECT COUNT(*) FROM security_logs WHERE event='HONEYPOT_EXPIRED'").fetchone()[0] == 1
    assert attacker.get("/login").status_code == 403

    priv, spki = new_device_key()
    assert enroll(client, spki).get_json()["ok"]
    admin_device_login(client, priv)
    index = client.get("/admin/reports")
    assert index.status_code == 200 and "203.0.113.77" in index.get_data(as_text=True)
    detail = client.get("/admin/reports/1")
    assert detail.status_code == 200 and "pages_and_actions" in detail.get_data(as_text=True)

"""Server-side Flask sessions with signed opaque-ID-only browser cookies."""
import hashlib
import json
import secrets
import sqlite3
import time

from flask import request
from flask.sessions import SessionInterface, SessionMixin
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.datastructures import CallbackDict

import db as dbmod
from config import SESSION_ABSOLUTE_HOURS


class ServerSideSession(CallbackDict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        def on_update(_):
            self.modified = True
        super().__init__(initial, on_update)
        self.sid = sid
        self.new = new
        self.modified = False
        self.previous_sid = None

    def regenerate(self):
        self.previous_sid = self.sid
        self.sid = secrets.token_urlsafe(32)
        self.new = True
        self.modified = True


class SQLiteSessionInterface(SessionInterface):
    """Persist all Flask session values in SQLite; cookie payload is only a signed SID."""
    session_class = ServerSideSession

    def _serializer(self, app):
        return URLSafeTimedSerializer(
            app.secret_key,
            salt=f"{app.name}.opaque-session",
            signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha256},
        )

    @staticmethod
    def _sid_hash(sid):
        return hashlib.sha256(sid.encode("utf-8")).hexdigest()

    @staticmethod
    def _ensure_table(conn):
        conn.execute(
            "CREATE TABLE IF NOT EXISTS app_sessions("
            "sid_hash TEXT PRIMARY KEY, data TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL)"
        )

    def open_session(self, app, request_obj):
        name = self.get_cookie_name(app)
        signed_sid = request_obj.cookies.get(name)
        if not signed_sid:
            return self.session_class()
        try:
            sid = self._serializer(app).loads(signed_sid, max_age=SESSION_ABSOLUTE_HOURS * 3600)
        except (BadSignature, TypeError, ValueError):
            return self.session_class()
        if not isinstance(sid, str) or len(sid) < 40 or len(sid) > 60:
            return self.session_class()
        conn = sqlite3.connect(dbmod.DB_PATH)
        try:
            self._ensure_table(conn)
            row = conn.execute("SELECT data,expires FROM app_sessions WHERE sid_hash=?",
                               (self._sid_hash(sid),)).fetchone()
            if row is None:
                return self.session_class()
            if row[1] <= time.time():
                conn.execute("DELETE FROM app_sessions WHERE sid_hash=?", (self._sid_hash(sid),))
                conn.commit()
                return self.session_class()
            try:
                data = json.loads(row[0])
            except (json.JSONDecodeError, TypeError):
                data = {}
            return self.session_class(data if isinstance(data, dict) else {}, sid=sid, new=False)
        finally:
            conn.close()

    def save_session(self, app, session_obj, response):
        name = self.get_cookie_name(app)
        conn = sqlite3.connect(dbmod.DB_PATH)
        try:
            self._ensure_table(conn)
            previous_sid = session_obj.previous_sid
            if previous_sid and previous_sid != session_obj.sid:
                conn.execute("DELETE FROM app_sessions WHERE sid_hash=?", (self._sid_hash(previous_sid),))

            if not session_obj:
                if session_obj.sid:
                    conn.execute("DELETE FROM app_sessions WHERE sid_hash=?", (self._sid_hash(session_obj.sid),))
                conn.commit()
                response.delete_cookie(name, domain=self.get_cookie_domain(app), path=self.get_cookie_path(app),
                                       secure=self.get_cookie_secure(app), httponly=self.get_cookie_httponly(app),
                                       samesite=self.get_cookie_samesite(app))
                return

            if session_obj.sid is None:
                session_obj.regenerate()
            sid_hash = self._sid_hash(session_obj.sid)
            existing = conn.execute("SELECT created,expires FROM app_sessions WHERE sid_hash=?", (sid_hash,)).fetchone()
            now = time.time()
            if existing:
                _, expires = existing
                conn.execute("UPDATE app_sessions SET data=? WHERE sid_hash=?",
                             (json.dumps(dict(session_obj), separators=(",", ":")), sid_hash))
            else:
                expires = now + SESSION_ABSOLUTE_HOURS * 3600
                conn.execute("INSERT INTO app_sessions(sid_hash,data,created,expires) VALUES(?,?,?,?)",
                             (sid_hash, json.dumps(dict(session_obj), separators=(",", ":")), now, expires))
            conn.commit()

            # The browser receives only the signed random SID, never CSRF, pending-login,
            # role, or other session values. Do not refresh an existing cookie's lifetime.
            if session_obj.new or name not in request.cookies:
                signed = self._serializer(app).dumps(session_obj.sid)
                response.set_cookie(name, signed, max_age=max(0, int(expires - now)),
                                    httponly=self.get_cookie_httponly(app),
                                    secure=self.get_cookie_secure(app),
                                    samesite=self.get_cookie_samesite(app),
                                    domain=self.get_cookie_domain(app), path=self.get_cookie_path(app))
            response.vary.add("Cookie")
        finally:
            conn.close()

"""Persist compact attack reports when honeypot sessions expire."""
import json
import time
from datetime import datetime

from db import get_db
from risk_engine import blacklist_ip
from security import create_alert, log_event


def finalize_honeypot(session_row):
    """Create an idempotent report for an expired honeypot session and blacklist its IP."""
    db = get_db()
    sid = session_row["id"]
    existing = db.execute("SELECT id FROM attack_reports WHERE session_id=?", (sid,)).fetchone()
    if existing:
        return existing["id"]

    ended = time.time()
    started = session_row["created"]
    ip = session_row["ip"] or "?"
    username = session_row["honeypot_username"] or "unknown"
    start_text = datetime.fromtimestamp(started).strftime("%Y-%m-%d %H:%M:%S")
    end_text = datetime.fromtimestamp(ended).strftime("%Y-%m-%d %H:%M:%S")
    events = db.execute(
        "SELECT ts,event,severity,details FROM security_logs "
        "WHERE ip=? AND username=? AND event LIKE 'HONEYPOT%' AND ts>=? AND ts<=? ORDER BY id",
        (ip, username, start_text, end_text),
    ).fetchall()
    pages = []
    for event in events:
        detail = event["details"] or ""
        path = detail.split(" [", 1)[0]
        if path not in pages:
            pages.append(path)
    attempts = db.execute(
        "SELECT attempted_at,success,risk_score FROM login_attempts WHERE ip=? AND username_norm=? "
        "AND attempted_at>=? AND attempted_at<=? ORDER BY id",
        (ip, username.casefold(), started - 15 * 60, ended),
    ).fetchall()
    payload = {
        "session_id": sid,
        "username": username,
        "source_ip": ip,
        "started_at": start_text,
        "ended_at": end_text,
        "duration_seconds": max(0, int(ended - started)),
        "honeypot_events": [dict(row) for row in events],
        "login_attempts": [dict(row) for row in attempts],
        "pages_and_actions": pages,
        "ip_blacklisted": True,
    }
    db.execute(
        "INSERT INTO attack_reports(session_id,username,ip,started_at,ended_at,event_count,pages_json,report_json,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (sid, username, ip, started, ended, len(events), json.dumps(pages, ensure_ascii=False),
         json.dumps(payload, ensure_ascii=False, indent=2), ended),
    )
    db.execute(
        "INSERT INTO blacklisted_ips(ip,created_at,reason,expires_at) VALUES(?,?,?,NULL) "
        "ON CONFLICT(ip) DO UPDATE SET created_at=excluded.created_at,reason=excluded.reason,expires_at=NULL",
        (ip, ended, f"Honeypot session #{sid} expirée"),
    )
    db.commit()
    return db.execute("SELECT id FROM attack_reports WHERE session_id=?", (sid,)).fetchone()["id"]


def expire_honeypot_sessions():
    """Expire all due honeypots, blacklist their source IPs, and create reports."""
    db = get_db()
    due = db.execute("SELECT * FROM sessions WHERE honeypot=1 AND honeypot_expires<=? "
                     "AND id NOT IN (SELECT session_id FROM attack_reports WHERE session_id IS NOT NULL)",
                     (time.time(),)).fetchall()
    expired = 0
    for row in due:
        db.execute("UPDATE sessions SET revoked=1 WHERE id=? AND revoked=0", (row["id"],))
        db.commit()
        report_id = finalize_honeypot(row)
        ip = row["ip"] or "?"
        username = row["honeypot_username"] or "unknown"
        blacklist_ip(ip, f"Honeypot expiré — rapport #{report_id}")
        log_event("HONEYPOT_EXPIRED", "critical", username,
                  f"Durée de 5 minutes atteinte; IP bloquée; rapport #{report_id}")
        create_alert("critical", "IP bloquée après honeypot",
                     f"{ip} — rapport d'attaque #{report_id}", username)
        expired += 1
    return expired

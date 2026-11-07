"""Faux tableau de bord administrateur (honeypot).

Un attaquant qui possède le mot de passe admin (et même les cookies) mais PAS la
clé privée liée à l'appareil arrive ici. Tout semble réel : mêmes URL, même design,
des données crédibles… mais tout est factice. Chacune de ses actions est journalisée
et aucune ne touche la vraie base."""
from flask import flash, redirect, render_template, request, url_for

from logger import log_request_activity
from security import create_alert

FAKE_USERS = [
    {"id": 101, "username": "k_benali", "email": "k.benali@mail.tn", "balance": 48250.00, "active": 1,
     "created_at": "2025-11-03 09:12:44", "rib": "TN59 1000 6035 1835 9847 8831"},
    {"id": 102, "username": "s_trabelsi", "email": "sarra.trabelsi@mail.tn", "balance": 12780.50, "active": 1,
     "created_at": "2025-12-18 14:40:02", "rib": "TN59 1000 6035 2291 0453 1172"},
    {"id": 103, "username": "m_gharbi", "email": "m.gharbi@mail.tn", "balance": 3120.75, "active": 1,
     "created_at": "2026-01-22 11:05:37", "rib": "TN59 1000 6035 7730 1928 4406"},
    {"id": 104, "username": "a_jlassi", "email": "amine.jlassi@mail.tn", "balance": 91500.00, "active": 0,
     "created_at": "2026-02-09 16:21:10", "rib": "TN59 1000 6035 4418 5520 9063"},
    {"id": 105, "username": "n_mansour", "email": "nour.mansour@mail.tn", "balance": 640.00, "active": 1,
     "created_at": "2026-04-30 08:58:19", "rib": "TN59 1000 6035 6602 3384 7715"},
    {"id": 106, "username": "y_hammami", "email": "y.hammami@mail.tn", "balance": 22410.20, "active": 1,
     "created_at": "2026-06-14 19:33:51", "rib": "TN59 1000 6035 9185 6671 2240"},
]

FAKE_TX = [
    {"ts": "2026-09-30 10:42:11", "kind": "virement", "sender": "k_benali", "receiver": "s_trabelsi", "amount": 1500.00},
    {"ts": "2026-09-30 09:15:03", "kind": "depot", "sender": "-", "receiver": "y_hammami", "amount": 4200.00},
    {"ts": "2026-09-29 17:08:47", "kind": "retrait", "sender": "m_gharbi", "receiver": "-", "amount": 300.00},
    {"ts": "2026-09-29 12:30:25", "kind": "ajustement", "sender": "banque", "receiver": "n_mansour", "amount": 40.00},
    {"ts": "2026-09-28 15:51:36", "kind": "virement", "sender": "a_jlassi", "receiver": "k_benali", "amount": 7800.00},
    {"ts": "2026-09-28 08:02:14", "kind": "depot", "sender": "-", "receiver": "s_trabelsi", "amount": 2500.00},
    {"ts": "2026-09-27 13:44:58", "kind": "virement", "sender": "y_hammami", "receiver": "m_gharbi", "amount": 650.00},
    {"ts": "2026-09-26 18:19:09", "kind": "retrait", "sender": "k_benali", "receiver": "-", "amount": 1000.00},
]

VIEWS = {"admin_home", "admin_users", "admin_edit", "admin_transactions", "profile"}
SENSITIVE_FIELDS = ("pass", "old", "new", "confirm", "csrf")


def _form_summary():
    items = []
    for k, v in request.form.items():
        items.append(f"{k}=***" if any(s in k.lower() for s in SENSITIVE_FIELDS) else f"{k}={v[:60]}")
    return ", ".join(items)


def handle(me):
    """Appelé AVANT toute vue réelle quand la session est marquée honeypot."""
    ep = request.endpoint
    if ep in ("static", "logout"):
        if ep == "logout":
            log_event("HONEYPOT_LOGOUT", "high", me["username"], "L'intrus se déconnecte")
        return None
    details = log_request_activity(me["username"])

    if request.method == "POST":
        create_alert("high", "Action tentée dans le honeypot", details, me["username"])
        flash("Opération effectuée avec succès.", "ok")          # faux succès
        return redirect(request.referrer or url_for("admin_home"))

    if ep == "admin_home":
        stats = {"clients": len(FAKE_USERS), "actifs": sum(u["active"] for u in FAKE_USERS),
                 "total": sum(u["balance"] for u in FAKE_USERS), "tx": 1284}
        stats["bloques"] = stats["clients"] - stats["actifs"]
        return render_template("admin_home.html", me=me, stats=stats, txs=FAKE_TX[:6],
                               newest=list(reversed(FAKE_USERS))[:5])
    if ep == "admin_users":
        q = request.args.get("q", "").strip().lower()
        users = [u for u in FAKE_USERS if q in u["username"].lower() or q in u["email"]]
        return render_template("admin_users.html", me=me, users=users, q=q)
    if ep == "admin_edit":
        uid = (request.view_args or {}).get("uid")
        user = next((u for u in FAKE_USERS if u["id"] == uid), FAKE_USERS[0])
        txs = [t for t in FAKE_TX if user["username"] in (t["sender"], t["receiver"])]
        return render_template("admin_edit.html", me=me, user=dict(user, locked=False),
                               rib=user["rib"], txs=txs)
    if ep == "admin_transactions":
        kind = request.args.get("kind", "")
        txs = [t for t in FAKE_TX if not kind or t["kind"] == kind]
        return render_template("admin_transactions.html", me=me, txs=txs, kind=kind)
    if ep == "profile":
        return render_template("profile.html", me=me, rib=None, sessions_count=1)
    # toute autre page (sécurité, intégrité, clients…) : on reste dans le faux décor
    return redirect(url_for("admin_home"))

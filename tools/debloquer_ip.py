"""Débloque toutes les IP de la liste noire.
Mettre ce fichier dans le dossier 'banque' (à côté de app.py), puis :  python debloquer_ip.py"""
import os
import sqlite3

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bank.db")
if not os.path.exists(db_path):
    raise SystemExit("bank.db introuvable : mets ce fichier dans le dossier 'banque'.")

con = sqlite3.connect(db_path)
rows = con.execute("SELECT ip FROM blacklisted_ips").fetchall()
con.execute("DELETE FROM blacklisted_ips")
con.commit()
con.close()
print(f"OK : {len(rows)} IP débloquée(s) {[r[0] for r in rows]}")
print("Recharge http://127.0.0.1:5000/login dans ton navigateur.")

"""Répare le blocage de connexion (à utiliser pendant les tests).
Mettre ce fichier dans le dossier 'banque' (à côté de app.py), puis :  python reparer_connexion.py
Il remet à zéro : échecs récents, contextes de confiance (IP + navigateur), IP bloquées, verrouillages.
Les comptes et les mots de passe ne sont PAS modifiés."""
import os
import sqlite3

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bank.db")
if not os.path.exists(db_path):
    raise SystemExit("bank.db introuvable : mets ce fichier dans le dossier 'banque'.")

con = sqlite3.connect(db_path)
for table in ("login_attempts", "trusted_contexts", "blacklisted_ips"):
    try:
        n = con.execute(f"DELETE FROM {table}").rowcount
        print(f"- {table} : {n} ligne(s) effacée(s)")
    except sqlite3.OperationalError:
        print(f"- {table} : absente (ignorée)")
con.execute("UPDATE users SET failed_attempts=0, locked_until=0")
con.commit()
con.close()
print("OK. Retourne sur http://127.0.0.1:5000/login et connecte-toi (admin ou alice).")
print("Le premier login réussi sera de nouveau reconnu comme 'appareil de confiance'.")

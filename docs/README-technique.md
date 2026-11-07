# Banque en ligne sécurisée — Flask + SQLite

Application pédagogique de banque en ligne avec rôles client/administrateur, sessions côté serveur, moteur de risque, authentification ECDSA liée à l'appareil pour l'administrateur, honeypot isolé, journal HMAC chaîné et rapports d'incident.

> **Projet de démonstration, pas un service bancaire de production.** Les identifiants de démonstration ci-dessous sont publics et doivent être remplacés avant tout déploiement.

## Architecture de sécurité

```text
Navigateur ── HTTPS (mTLS optionnel) ── Flask / Security Gateway
                                           │
          ┌────────────────────────────────┼──────────────────────────┐
          │                                │                          │
   Authentification                 Moteur de risque             Sessions SQLite
   scrypt + verrouillage            échecs + IP + jeton           cookie SID seul
          │                         score 0 / 1 / 2                CSRF côté serveur
          ├── score 0 → vrai tableau de bord                         │
          ├── score 1 → erreur de connexion normale                  │
          └── score 2 → honeypot 5 min → blacklist IP → rapport ─────┘
```

| Score | Signal | Résultat |
|---|---|---|
| 0 | Moins de 3 échecs récents et contexte reconnu (ou bootstrap historique) | Connexion normale; contexte mémorisé après authentification réussie |
| 1 | Trois échecs récents **ou** IP/navigateur inconnu | Connexion refusée avec un message d'erreur ordinaire |
| 2 | Trois échecs récents **et** IP ou jeton de navigateur inconnu | Alerte critique et faux tableau de bord, sans accès aux données réelles |

Les échecs du moteur sont comptés sur une fenêtre de 15 minutes. Le verrouillage historique du compte reste actif après 5 mauvais mots de passe pendant 15 minutes. Un contexte est reconnu lorsque l'adresse IP **et** le jeton navigateur sont déjà connus pour le compte. Le jeton `banque_device` est aléatoire, persistant, HttpOnly et stocké sous forme de SHA-256 en base. Un nouveau contexte peut être approuvé par l'administrateur local via la commande décrite ci-dessous, après vérification indépendante de l'identité.

Les sessions honeypot durent **5 minutes maximum** (durée absolue, non renouvelée par l'activité). À l'expiration, la session est révoquée, l'IP est mise en liste noire et un rapport JSON est conservé. Les expirations sont traitées sur les requêtes suivantes et peuvent aussi être balayées par la commande CLI/cron `expire-honeypots`.

## Installation

```bash
cd banque
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Lancement

Mode local (HTTP) :

```bash
python app.py
```

HTTPS local avec certificat OpenSSL :

```bash
bash generate_keys.sh
source keys.env
python app.py
```

Le certificat est auto-signé : le navigateur affichera un avertissement. En production, utiliser un certificat d'une autorité reconnue et un serveur WSGI/reverse proxy correctement configuré.

## Premier démarrage et comptes de démonstration

À l'initialisation, l'application imprime un code à usage unique pour enrôler l'appareil de l'administrateur. Ouvrir `/device/enroll` sur ce navigateur, puis utiliser le code. La clé privée ECDSA P-256 est créée non-extractable dans WebCrypto et conservée dans IndexedDB; seule la clé publique est envoyée au serveur.

| Utilisateur | Mot de passe | Rôle |
|---|---|---|
| `admin` | `Admin@123` | Administrateur (signature d'appareil obligatoire) |
| `alice` | `Alice@123` | Client |
| `bob` | `Bob@12345` | Client |

Commandes :

```bash
flask --app app enroll-code admin     # code d'enrôlement d'appareil admin
flask --app app unlock alice          # déverrouiller un compte après vérification
flask --app app expire-honeypots      # expirer/rapporter les sessions échues
flask --app app trust-context alice 203.0.113.10
# La dernière commande demande le jeton navigateur sans l'afficher.
# Ne l'utiliser qu'après vérification de l'identité par un canal indépendant.
```

Une nouvelle adresse IP ou un nouveau navigateur ajoute un point de risque. Si le score est 1, l'accès est refusé normalement; l'administrateur doit approuver le nouveau couple IP/jeton après vérification hors bande. Ne pas transmettre le jeton dans un canal public ou un ticket non sécurisé.

## Tests

```bash
python -m pytest -v
```

La suite couvre les mots de passe, CSRF, sessions serveur opaques et leur rotation, droits, clé ECDSA, honeypot, scoring, expiration à 5 minutes, blocage IP, rapports, chiffrement et contrôles d'intégrité.

## HTTPS et mTLS optionnel

HTTPS est utilisé quand `certs/cert.pem` et `certs/key.pem` existent. Le mode mTLS est désactivé par défaut. Pour une démonstration locale :

```bash
bash generate_keys.sh
bash generate_client_cert.sh
source keys.env
MTLS_ENABLED=1 python app.py
```

Le serveur exige alors un certificat client signé par `certs/client-ca.pem`. Exemple de vérification :

```bash
curl --cert certs/client.crt.pem --key certs/client.key.pem \
  --cacert certs/cert.pem https://127.0.0.1:5000/login
```

`MTLS_ENABLED=1` sans fichier CA client provoque un arrêt explicite. Les fichiers privés sont exclus du contrôle de version. En production, déployer mTLS au niveau d'un reverse proxy éprouvé (Nginx/Envoy) ou d'une passerelle TLS et transmettre l'identité client de façon sécurisée; le serveur Flask de développement n'est pas adapté à la production.

## Fichiers principaux

```text
app.py                    routes Flask, gateway, scoring, dashboards et CLI
config.py                 secrets, délais et configuration TLS
risk_engine.py            score 0–2, contexte IP/jeton, liste noire
server_sessions.py        sessions Flask SQLite; cookie signé contenant le SID seul
security.py               CSRF, sessions d'authentification, alertes, journal HMAC
logger.py                 journalisation bornée/redactée du honeypot
reports.py                expiration et génération des rapports d'attaque
db.py                     schéma SQLite et migrations additives
crypto_utils.py           AES-GCM, HMAC et vérification ECDSA
honeypot.py               fausses vues et interception avant les routes réelles
templates/admin_report*.html
static/device.js          WebCrypto et IndexedDB pour l'admin
generate_keys.sh          secrets et certificat HTTPS local
generate_client_cert.sh   CA locale et certificat client mTLS de démonstration
docs/                     architecture et scénarios de sécurité
tests/                    tests de régression
```

## Limites connues

- Le mode de lancement `app.run` est uniquement destiné à la démonstration; utiliser Gunicorn/Waitress derrière un reverse proxy en production.
- Le score IP/jeton est un signal de risque, pas une authentification forte. Une IP peut changer naturellement et un jeton navigateur peut être supprimé; le processus d'approbation doit vérifier l'identité par un second canal.
- Le sweep des honeypots est événementiel (requête suivante) ou déclenché par la CLI; pour un serveur silencieux, planifier `flask --app app expire-honeypots` dans un cron/service de maintenance.
- La limitation de débit existante est en mémoire et se réinitialise au redémarrage; le compteur de risque est persistant dans SQLite.
- Les données fake du honeypot sont statiques; aucune action du honeypot ne modifie les vrais comptes.
- Le HMAC chaîné signale les modifications internes, mais une suppression de la dernière entrée nécessite un ancrage externe pour être détectée.
- La clé ECDSA d'appareil protège contre le vol du mot de passe, pas contre un navigateur déjà contrôlé par un attaquant.

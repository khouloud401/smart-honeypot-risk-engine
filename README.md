# 🍯 Smart Honeypot & Risk Engine
### Application bancaire web sécurisée qui piège les attaquants

Une banque en ligne développée avec **Python, Flask et SQLite**. Son idée : **la défense active**.
Au lieu de seulement bloquer un attaquant, l'application le **laisse entrer dans un faux tableau de bord**, note tout ce qu'il fait, puis **bloque son IP** et **prévient l'administrateur**.


---

## 🎯 C'est quoi le but ?

Imagine un voleur qui force la serrure de ta maison. Au lieu de le chasser, on le laisse entrer dans une **fausse maison**. Pendant ce temps, le propriétaire est prévenu et chaque geste du voleur est noté.

| Qui | Ce qu'il voit |
|---|---|
| ✅ Le vrai client / le vrai admin | Le **vrai** tableau de bord |
| 🕵️ L'attaquant suspecté | Un **faux** tableau de bord (honeypot) |
| 👮 L'administrateur | Les alertes et les rapports d'attaque dans son **Centre de sécurité** |

Dans le faux tableau de bord, l'attaquant ne peut **modifier aucune vraie donnée**. Ses actions sont seulement enregistrées.

---

## 🧠 Comment le site décide ? (Risk Engine)

Le site regarde **3 choses** à chaque connexion :

1. 🔢 **Nombre d'erreurs** de mot de passe (3 ou plus = suspect)
2. 🌐 **L'adresse IP** : connue ou inconnue ?
3. 🖥️ **Le navigateur / la session** : connu ou inconnu ?

> 👉 Le faux dashboard s'ouvre **seulement si les 3 conditions sont réunies en même temps**.

### Les cas, un par un

| # | Situation | Faux dashboard ? | Résultat |
|---|---|---|---|
| 1 | Vrai utilisateur, **IP connue + navigateur connu**, bon mot de passe | ❌ Non | ✅ Vrai dashboard |
| 2 | Vrai utilisateur, **IP connue + navigateur connu**, **3 erreurs ou plus** | ❌ Non | Reste sur la page de connexion (message d'erreur) |
| 3 | Vrai utilisateur sur un **nouveau navigateur + IP inconnue**, **2 erreurs seulement**, puis le **bon** mot de passe | ❌ Non | ✅ Accès normal : il n'a pas atteint 3 erreurs |
| 4 | **3 erreurs ou plus + IP inconnue + navigateur inconnu** | ✅ **Oui** | 🍯 Faux dashboard |

**Pourquoi ?** Si tu te trompes dans ton propre navigateur, sur ton propre réseau, c'est probablement toi qui as oublié ton mot de passe. Si un **inconnu** (nouvelle IP, nouveau navigateur) essaie plusieurs fois, c'est suspect.

### Ce qui se passe après l'ouverture du honeypot

```
3 erreurs + IP inconnue + navigateur inconnu
                  │
                  ▼
   🍯 Faux dashboard (session limitée à 5 minutes)
        → chaque action de l'attaquant est enregistrée
        → aucune vraie donnée n'est modifiée
        → l'admin reçoit une alerte CRITIQUE
                  │
        (la session expire)
                  ▼
   🚫 IP bloquée → le site ne s'ouvre plus du tout pour cette IP
   📄 Rapport d'attaque créé pour l'admin
```

---

## 📸 Captures d'écran (expliquées)

### 1️⃣ Connexion avec un mauvais mot de passe
![Connexion échouée](docs/screenshots/01-login-failed.png)

Le site affiche seulement « Nom d'utilisateur ou mot de passe incorrect ». Il ne dit **pas** lequel des deux est faux, pour ne pas aider un attaquant.

### 2️⃣ Le vrai tableau de bord de l'administrateur
![Vrai dashboard admin](docs/screenshots/02-real-admin-dashboard.png)

C'est ce que voit le vrai admin : **4 clients, 4200 DT, 6 transactions**. Il y a une bannière rouge avec les **alertes de sécurité non lues** et un menu **Sécurité** complet : Centre de sécurité, Rapports d'attaque, Intégrité, Cryptographie, Appareils de confiance.

### 3️⃣ À gauche : le FAUX dashboard. À droite : le VRAI Centre de sécurité
![Honeypot et Centre de sécurité](docs/screenshots/03-honeypot-and-security-center.png)

- **À gauche** (navigateur Kali de l'attaquant) : un faux dashboard avec des chiffres inventés (**6 clients, 178 701 DT, 1284 transactions**) et un menu réduit. L'attaquant pense être dans la vraie banque.
- **À droite** (compte du vrai admin) : le Centre de sécurité montre en direct les alertes non lues, les échecs de connexion, les **événements honeypot**, les sessions actives et les rapports d'attaque.

### 4️⃣ Alerte, IP bloquée et rapport d'attaque
![IP bloquée et alertes](docs/screenshots/04-blocked-ip-and-alerts.png)

Après l'expiration du honeypot :
- 🚫 **IP bloquée** : `192.168.247.128`, motif « Honeypot expiré – rapport #3 ». L'admin peut la **débloquer** avec un bouton.
- 📄 **Rapports d'attaque** : le rapport #3 indique la date, le compte ciblé, l'IP et le nombre d'événements (8).
- 🚨 **Alertes** (de la plus grave à la moins grave) :
  - *critique* : « Attaque détectée – honeypot ouvert » (score de risque 2, session factice de 5 minutes)
  - *élevée* : « Action tentée dans le honeypot » (l'attaquant a essayé de **supprimer un utilisateur**, mais l'action n'a rien changé)
  - *critique* : « IP bloquée après honeypot »
  - *info* : « Nouvel appareil de confiance enrôlé » (navigateur reconnu comme sûr)

> 🔒 Une fois l'IP bloquée, l'attaquant **ne trouve plus le site**. Il ne peut plus y entrer.

---

## 🛡️ Fonctions de sécurité

| Fonction | Technologie | En mots simples |
|---|---|---|
| Mots de passe | **scrypt** | Le mot de passe n'est jamais stocké en clair |
| Données sensibles | **AES-256-GCM** | Les données sont chiffrées (illisibles sans clé) |
| Intégrité | **HMAC-SHA256** | On détecte si une donnée a été modifiée |
| Appareils de confiance | **ECDSA** | Chaque navigateur connu est vérifié par une signature |
| Protection du site | Sessions sécurisées + **CSRF** | Empêche le vol de session et les faux formulaires |
| Anti brute-force | Verrouillage de compte + blocage d'IP | Stoppe les essais répétés |
| Supervision | Alertes + rapports d'attaque | L'admin est toujours prévenu |

**Technologies** : Python · Flask · SQLite · OpenSSL · WebCrypto · Pytest · VMware · Kali Linux

---

## 🎬 Démo (scénario simple)

| Étape | Action | Ce qu'on voit |
|---|---|---|
| 1 | Se connecter avec le bon mot de passe depuis le navigateur habituel | ✅ Vrai dashboard |
| 2 | Se tromper 3 fois depuis ce même navigateur | ⛔ Message d'erreur, **pas** de faux dashboard |
| 3 | Depuis un **nouveau navigateur ou une nouvelle IP**, se tromper 2 fois puis mettre le bon mot de passe | ⛔ Connexion refusée (appareil à approuver), **pas** de faux dashboard |
| 4 | Depuis l'attaquant (Kali, IP inconnue), se tromper **3 fois ou plus** | 🍯 Faux dashboard |
| 5 | Regarder le Centre de sécurité de l'admin | 🚨 Alertes critiques + rapport d'attaque |
| 6 | Attendre la fin de la session honeypot (5 min) | 🚫 IP bloquée, le site ne s'ouvre plus |

📹 Vidéo : `<lien LinkedIn / YouTube>`

## 🚀 Installation

```bash
git clone https://github.com/<ton-user>/<nom-repo>.git
cd <nom-repo>
python -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python app.py                    # puis ouvrir http://127.0.0.1:5000
```

Au premier lancement, la base `bank.db` et les clés (`instance/secrets.json`) sont **créées automatiquement**. Elles ne sont pas dans GitHub.

### Comptes de démonstration (labo uniquement)

| Utilisateur | Mot de passe | Rôle |
|---|---|---|
| `admin` | `Admin@123` | Administrateur |
| `alice` | `Alice@123` | Client |
| `bob` | `Bob@12345` | Client |

⚠️ Ces mots de passe sont volontairement simples, **seulement pour la démo**. Ne jamais les utiliser en vrai.

### HTTPS local (optionnel)
```bash
bash generate_keys.sh && source keys.env && python app.py
```

### Tests
```bash
python -m pytest -v
```

---





---

## 📁 Structure du projet

| Fichier / dossier | Rôle |
|---|---|
| `app.py` | Routes Flask, connexion, dashboards |
| `risk_engine.py` | Score de risque 0 à 2, IP et navigateur de confiance, liste noire |
| `honeypot.py` | Faux dashboard |
| `reports.py` | Expiration du honeypot et rapports d'attaque |
| `security.py` · `server_sessions.py` | CSRF, sessions, alertes, journal HMAC |
| `crypto_utils.py` | AES-GCM, HMAC, ECDSA |
| `db.py` · `config.py` | Base SQLite et secrets |
| `templates/` · `static/` | Pages HTML, CSS, JavaScript |
| `tests/` | Tests Pytest |
| `docs/` | Architecture, tests de sécurité, captures, README technique |
| `tools/` | Petits scripts **de test** (voir ci-dessous) |

### 🔧 Outils de test (`tools/`)

Ces scripts servent seulement à **refaire la démo**. Ils ne font pas partie du site. Les copier à côté de `app.py` avant de les lancer.

| Script | À quoi ça sert |
|---|---|
| `debloquer_ip.py` | Débloque toutes les IP de la liste noire |
| `reparer_connexion.py` | Remet à zéro les échecs, appareils de confiance, IP bloquées et verrouillages |

---

## ⚠️ Avertissement

Projet **éducatif**, testé en laboratoire. Ne pas utiliser tel quel en production. Ne testez pas ce projet sur un système qui ne vous appartient pas.



Vos retours sont les bienvenus ! 💻

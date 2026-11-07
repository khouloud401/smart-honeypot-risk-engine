# Cas de tests de sécurité

Colonne « Auto » : ✅ = couvert par `python -m pytest -v`.

## A. Mots de passe et comptes
| ID | Test | Étapes | Résultat attendu | Auto |
|---|---|---|---|---|
| A1 | Hachage | `sqlite3 bank.db "SELECT username,password_hash FROM users;"` | Hash `scrypt:32768:8:1$sel$…`, jamais le mot de passe en clair | ✅ |
| A2 | Mot de passe faible | S'inscrire avec `motdepasse` | Refusé (majuscule, chiffre, spécial requis) | ✅ |
| A3 | Force brute | 5 mauvais mots de passe pour `bob` | Compte verrouillé 15 min, alerte « Compte verrouillé » | ✅ |
| A4 | Burp Intruder | Intruder sur POST /login (liste de 50 mots de passe) | Après 20 requêtes : HTTP 429 + événement `RATE_LIMIT` | |
| A5 | Énumération | Comparer message + temps pour utilisateur existant / inexistant | Même message, temps similaire (hash factice) | |
| A6 | Compte piège | Se connecter avec `root` | Alerte « Compte piège utilisé » | |

## B. Sessions
| ID | Test | Étapes | Résultat attendu | Auto |
|---|---|---|---|---|
| B1 | Attributs du cookie | Burp → réponse de /login → `Set-Cookie` | `HttpOnly; SameSite=Strict` (+ `Secure` en HTTPS) | ✅ |
| B2 | Cookie après déconnexion | Copier le cookie, se déconnecter, le rejouer avec Burp Repeater | Redirection vers /login (session révoquée côté serveur) | ✅ |
| B3 | Vol de cookie | Rejouer le cookie dans Repeater en changeant le `User-Agent` | Refusé + alerte critique « Vol de session suspecté » | ✅ |
| B4 | Expiration | Rester 15 min inactif puis recharger | « Session expirée après inactivité » | |
| B5 | CSRF | Repeater : supprimer le champ `csrf` d'un POST /transfer | HTTP 400 + événement `CSRF_BLOCKED` | ✅ |
| B6 | Clickjacking | Mettre la page dans une `<iframe>` | Bloqué (`X-Frame-Options: DENY`, `frame-ancestors 'none'`) | ✅ |
| B7 | XSS | S'inscrire avec l'email `<script>alert(1)</script>@x.tn` | Refusé / échappé par Jinja ; CSP bloque les scripts inline | |

## C. Autorisation côté serveur
| ID | Test | Étapes | Résultat attendu | Auto |
|---|---|---|---|---|
| C1 | Client → admin | Connecté en `alice`, ouvrir `/admin/users` | 403 + alerte « Tentative d'élévation de privilèges » | ✅ |
| C2 | Anonyme | Ouvrir `/admin` sans être connecté | Redirection /login | ✅ |
| C3 | Sauter la signature | Mot de passe admin OK puis taper directement `/admin/security` | Redirection /login (aucune session admin) | ✅ |
| C4 | IDOR | Connecté en `alice`, POST `/admin/users/3/delete` dans Repeater | 403 (rôle vérifié serveur) | |

## D. Clé liée à l'appareil + honeypot
| ID | Test | Étapes | Résultat attendu | Auto |
|---|---|---|---|---|
| D1 | Connexion légitime | Navigateur enrôlé, `admin`/`Admin@123` | Vrai tableau de bord (menu « Sécurité » visible) | ✅ |
| D2 | Mot de passe volé | **Autre navigateur** (ou navigation privée), `admin`/`Admin@123` | Faux tableau de bord (clients `k_benali`, `s_trabelsi`…), alerte critique | ✅ |
| D3 | Mauvaise clé | Clé d'un autre appareil | Honeypot | ✅ |
| D4 | Signature modifiée | Burp : intercepter POST /login/device/verify et changer un caractère de `signature` | Honeypot | ✅ |
| D5 | Rejeu | Rejouer une ancienne signature valide | Honeypot (nonce à usage unique) | ✅ |
| D6 | Actions dans le honeypot | Dans le faux tableau, supprimer un client / modifier un solde | « Succès » affiché, **rien** ne change en base, tout est dans le Centre de sécurité | ✅ |
| D7 | Enrôlement pirate | /device/enroll avec le bon mot de passe et un faux code | Refusé + alerte critique | ✅ |
| D8 | Extraction de la clé | Appareils de confiance → « Tenter d'extraire la clé privée » | `InvalidAccessError`, `extractable = false` | |
| D9 | Clé volée en base | `sqlite3 bank.db "SELECT public_key FROM device_keys;"` | Seule la clé **publique** est présente : inutile pour signer | |

## E. Chiffrement et intégrité
| ID | Test | Étapes | Résultat attendu | Auto |
|---|---|---|---|---|
| E1 | RIB chiffré | `sqlite3 bank.db "SELECT username,rib_enc FROM users;"` | Base64 illisible ; déchiffré seulement dans l'app | ✅ |
| E2 | Échange de chiffrés | Copier le `rib_enc` d'alice sur bob | Fiche de bob : « déchiffrement impossible » (AAD) | ✅ |
| E3 | Transaction falsifiée | `sqlite3 bank.db "UPDATE transactions SET amount=99999 WHERE id=3;"` puis Intégrité | « 1 transaction falsifiée » + alerte critique | ✅ |
| E4 | Solde falsifié | `sqlite3 bank.db "UPDATE users SET balance=1000000 WHERE username='bob';"` | Solde incohérent détecté | |
| E5 | Journal falsifié | `sqlite3 bank.db "UPDATE security_logs SET details='rien' WHERE id=2;"` | « Journal modifié » | ✅ |
| E6 | Effet avalanche | Cryptographie → texte puis texte + espace | HMAC totalement différent | |

## F. OpenSSL / TLS
| ID | Test | Commande | Résultat attendu |
|---|---|---|---|
| F1 | Certificat | `openssl x509 -in certs/cert.pem -noout -subject -dates -text \| grep "Public Key Algorithm"` | `id-ecPublicKey`, CN=localhost, 365 jours |
| F2 | Poignée de main TLS | `openssl s_client -connect 127.0.0.1:5000 -brief </dev/null` | TLSv1.3, chiffrement AEAD |
| F3 | HSTS | `curl -skI https://127.0.0.1:5000/login` | `Strict-Transport-Security` présent |
| F4 | Vérifier un HMAC à la main | voir la commande ci-dessous | Même valeur que la colonne `signature` en base |

Commande exacte pour F4 (clé hexadécimale) :
```bash
source keys.env
sqlite3 bank.db "SELECT kind||'|'||sender||'|'||receiver||'|'||printf('%.2f',amount)||'|'||ts, signature FROM transactions WHERE id=3;"
echo -n "<texte affiché ci-dessus>" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$HMAC_KEY
```

## Scénario de démonstration conseillé (5 minutes)
1. Connexion admin légitime → vrai tableau de bord.
2. Navigation privée → même mot de passe → faux tableau ; supprimer un « client ».
3. Retour sur le vrai compte → Centre de sécurité : alerte critique + actions de l'intrus.
4. Terminal : `sqlite3 bank.db "UPDATE transactions SET amount=99999 WHERE id=3;"` → Intégrité : détecté.
5. Appareils de confiance → « Tenter d'extraire la clé privée » → refusé.


## G. Moteur de risque, gateway et sessions opaques
| ID | Test | Étapes | Résultat attendu | Auto |
|---|---|---|---|---|
| G1 | IP inconnue | Se connecter depuis une nouvelle IP avec un jeton navigateur déjà connu | Score 1, erreur ordinaire, aucune session réelle | ✅ |
| G2 | Score 2 | Depuis une nouvelle IP/navigateur, envoyer trois mauvais mots de passe pour un compte valide | Alerte critique puis tableau factice; aucune donnée réelle exposée | ✅ |
| G3 | Cookie opaque | Inspecter `banque_session` et `app_sessions` | Cookie signé contenant le SID uniquement; CSRF côté serveur; seul SHA-256 du SID en base | ✅ |
| G4 | Rotation anti-fixation | Comparer le SID avant/après login | SID différent, ancienne ligne côté serveur supprimée/révoquée | ✅ |
| G5 | Expiration 5 min | Pour le test, rendre `honeypot_expires` passé puis recharger | Session révoquée, IP blacklistée, rapport JSON créé | ✅ |
| G6 | Gateway blacklist | Demander `/login` depuis une IP blacklistée | HTTP 403 avant toute route applicative | ✅ |
| G7 | Rapports admin | Ouvrir `/admin/reports` puis un rapport avec un admin vérifié | Liste et détail de l'incident visibles; accès client interdit | ✅ |
| G8 | Nouvel environnement légitime | Vérifier l'identité hors bande puis exécuter `flask --app app trust-context USER IP` | Le couple IP/jeton est approuvé; seul le hash du jeton est stocké | |

## H. HTTPS et mTLS optionnel
| ID | Test | Étapes | Résultat attendu |
|---|---|---|---|
| H1 | HTTPS standard | `bash generate_keys.sh`, puis `python app.py` | TLS activé; cookie de session `Secure` |
| H2 | mTLS sans CA | `MTLS_ENABLED=1` sans CA client | Arrêt explicite au démarrage, aucun repli silencieux vers HTTP |
| H3 | mTLS local | `bash generate_client_cert.sh`, puis `MTLS_ENABLED=1 python app.py` | Certificat client valide accepté; requête sans certificat rejetée par TLS |

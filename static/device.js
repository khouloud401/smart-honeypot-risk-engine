/* Clé de signature liée à l'appareil (WebCrypto + IndexedDB)
 *
 * - La paire ECDSA P-256 est générée DANS le navigateur.
 * - La clé privée est créée "non-extractable" : même avec un accès au navigateur,
 *   le JavaScript ne peut PAS l'exporter (ni en clair, ni en base64).
 * - Elle est stockée dans IndexedDB sous forme d'objet CryptoKey opaque.
 * - Seule la clé publique (SPKI) est envoyée au serveur.
 */
(function () {
  "use strict";
  var DB_NAME = "banque-device", STORE = "keys";

  function openDB() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = function () { req.result.createObjectStore(STORE); };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }
  function idb(mode, fn) {
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE, mode), store = tx.objectStore(STORE), req = fn(store);
        tx.oncomplete = function () { resolve(req && req.result); };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  }
  var getKey = function (user) { return idb("readonly", function (s) { return s.get(user); }); };
  var putKey = function (user, key) { return idb("readwrite", function (s) { return s.put(key, user); }); };

  function b64(buf) {
    var bytes = new Uint8Array(buf), s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function csrf() { return document.querySelector('meta[name="csrf-token"]').content; }
  function postJSON(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: JSON.stringify(body)
    });
  }

  // ------------------------------------------------ connexion : challenge → signature
  async function verifyDevice(box) {
    var signature = null;
    try {
      var ch = await (await fetch(box.dataset.challengeUrl, { credentials: "same-origin" })).json();
      var privateKey = await getKey(ch.username);
      if (privateKey) {
        var sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey,
                                           new TextEncoder().encode(ch.message));
        signature = b64(sig);
      }
    } catch (err) { signature = null; }
    var res = await postJSON(box.dataset.verifyUrl, { signature: signature });
    var data = await res.json();
    window.location = data.redirect;
  }

  // ------------------------------------------------ enrôlement d'un navigateur
  async function enroll(form, out) {
    out.className = "flash"; out.textContent = "Génération de la paire de clés ECDSA P-256…";
    try {
      var pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" },
                                                 false /* privée NON extractable */, ["sign", "verify"]);
      var spki = await crypto.subtle.exportKey("spki", pair.publicKey);   // la publique, seulement
      var f = new FormData(form);
      var res = await postJSON(form.dataset.url, {
        username: f.get("username"), password: f.get("password"), code: f.get("code"),
        label: f.get("label"), public_key: b64(spki)
      });
      var data = await res.json();
      if (!data.ok) { out.className = "flash error"; out.textContent = data.error; return; }
      await putKey(f.get("username"), pair.privateKey);
      out.className = "flash ok";
      out.textContent = "✅ Appareil enrôlé. Empreinte de la clé : " + data.fingerprint +
                        ". Vous pouvez maintenant vous connecter.";
      form.reset();
    } catch (err) {
      out.className = "flash error"; out.textContent = "Erreur WebCrypto : " + err;
    }
  }

  // ------------------------------------------------ démo : la clé privée est-elle extractable ?
  async function testExtraction(btn, out) {
    try {
      var key = await getKey(btn.dataset.user);
      if (!key) { out.className = "flash error"; out.textContent = "Aucune clé dans ce navigateur."; return; }
      await crypto.subtle.exportKey("pkcs8", key);
      out.className = "flash error"; out.textContent = "⚠️ La clé a pu être exportée !";
    } catch (err) {
      out.className = "flash ok";
      out.textContent = "✅ Export refusé par le navigateur (" + err.name + ") : la clé privée est non-extractable. " +
                        "extractable = " + (await getKey(btn.dataset.user)).extractable + ", algorithme = ECDSA P-256.";
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    var box = document.getElementById("device-verify");
    if (box) verifyDevice(box);

    var form = document.getElementById("enroll-form");
    if (form) form.addEventListener("submit", function (e) {
      e.preventDefault(); enroll(form, document.getElementById("enroll-out"));
    });

    var btn = document.getElementById("test-extract");
    if (btn) btn.addEventListener("click", function () {
      testExtraction(btn, document.getElementById("extract-out"));
    });

    if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
      var warn = document.getElementById("secure-warning");
      if (warn) warn.hidden = false;
    }
  });
})();

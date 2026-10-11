// ABVSPAIE — couche d'authentification (Supabase Auth). Dépend de supabase-js (UMD) et de abvs-config.js.
(function () {
  "use strict";
  var cfg = window.ABVS_CONFIG || {};
  var LOGIN = "../public/inscription-connexion.html";
  var IDLE_MS = 30 * 60 * 1000, KEY = "abvs_last";
  var sb = null;
  try {
    sb = window.supabase.createClient(cfg.url, cfg.anonKey, {
      auth: { flowType: "pkce", persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
    });
  } catch (e) { sb = null; }

  function touch() { try { localStorage.setItem(KEY, String(Date.now())); } catch (_) {} }
  function idle() { try { var t = +localStorage.getItem(KEY) || 0; return t > 0 && Date.now() - t > IDLE_MS; } catch (_) { return false; } }
  function ungate() { var g = document.getElementById("abvs-gate"); if (g) g.remove(); }

  async function signOut() {
    try { if (sb) await sb.auth.signOut(); } catch (_) {}
    try { localStorage.removeItem(KEY); } catch (_) {}
    location.href = LOGIN;
  }

  // Bouton « Se déconnecter » toujours visible (haut à droite) sur toutes les pages du compte.
  function addLogoutButton() {
    try {
      if (document.getElementById("abvs-logout")) return;
      var st = document.createElement("style");
      st.textContent =
        "#abvs-logout{position:fixed;top:calc(env(safe-area-inset-top,0px) + 12px);right:14px;z-index:40;" +
        "display:flex;align-items:center;gap:6px;padding:9px 14px;border-radius:14px;cursor:pointer;" +
        "border:1px solid var(--line,#dde3ea);background:var(--solid,var(--card,#fff));color:var(--ink,#1b2430);" +
        "font:600 13px Inter,system-ui,sans-serif;box-shadow:0 8px 22px rgba(40,60,90,.14)}" +
        "#abvs-logout:hover{filter:brightness(.97)}" +
        "#abvs-logout:focus-visible{outline:2px solid var(--pri,#4a6283);outline-offset:2px}" +
        "@media(max-width:600px){#abvs-logout{top:calc(env(safe-area-inset-top,0px) + 10px);right:10px;padding:8px 12px}}";
      document.head.appendChild(st);
      var b = document.createElement("button");
      b.id = "abvs-logout"; b.type = "button";
      b.setAttribute("aria-label", "Se déconnecter");
      b.textContent = "\uD83D\uDEAA Déconnexion";
      b.addEventListener("click", function () { b.disabled = true; signOut(); });
      document.body.appendChild(b);
    } catch (_) {}
  }

  // Garde de page : masque la page tant que la session n'est pas confirmée.
  // NB : c'est du confort d'affichage ; la vraie protection des données, c'est la RLS côté base.
  async function requireSession() {
    try {
      if (!sb) throw new Error("client indisponible");
      var r = await sb.auth.getSession();
      if (!r.data || !r.data.session) return location.replace(LOGIN);
      if (idle()) return signOut();
      var a = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
      if (a.data && a.data.nextLevel === "aal2" && a.data.currentLevel !== "aal2") return location.replace(LOGIN);
      touch(); ungate();
      if (document.body) { addLogoutButton(); initModeSwitch(); }
      else document.addEventListener("DOMContentLoaded", function () { addLogoutButton(); initModeSwitch(); });
      var last = 0;
      ["pointerdown", "keydown", "scroll"].forEach(function (ev) {
        addEventListener(ev, function () { var n = Date.now(); if (n - last > 15000) { last = n; touch(); } }, { passive: true });
      });
      setInterval(function () { if (idle()) signOut(); }, 60000);
    } catch (e) { location.replace(LOGIN); }
  }

  // Session valide ET complète (2FA franchie, pas d'inactivité) : sert aux pages publiques
  // (connexion, mot de passe oublié) pour rediriger un utilisateur déjà connecté.
  async function hasSession() {
    try {
      if (!sb) return false;
      var r = await sb.auth.getSession();
      if (!r.data || !r.data.session) return false;
      if (idle()) return false;
      var a = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
      if (a.data && a.data.nextLevel === "aal2" && a.data.currentLevel !== "aal2") return false;
      return true;
    } catch (_) { return false; }
  }

  async function signUp(o) {
    var r = await sb.auth.signUp({
      email: o.email, password: o.password,
      options: { data: { company: o.company, country: o.country }, emailRedirectTo: new URL(LOGIN, location.href).href }
    });
    if (r.error) return { error: r.error };
    // E-mail déjà inscrit (confirmation activée) : Supabase renvoie un utilisateur sans identité.
    if (r.data.user && r.data.user.identities && r.data.user.identities.length === 0) return { exists: true };
    return { ok: true, needsConfirm: !r.data.session };
  }

  async function signIn(email, password) {
    var r = await sb.auth.signInWithPassword({ email: email, password: password });
    if (r.error) return { error: r.error };
    var a = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
    if (a.data && a.data.nextLevel === "aal2" && a.data.currentLevel === "aal1") {
      var f = await sb.auth.mfa.listFactors();
      var t = f.data && f.data.totp && f.data.totp[0];
      if (t) return { mfa: true, factorId: t.id };
    }
    touch();
    return { ok: true };
  }

  async function verifyMfa(factorId, code) {
    var c = await sb.auth.mfa.challenge({ factorId: factorId });
    if (c.error) return { error: c.error };
    var v = await sb.auth.mfa.verify({ factorId: factorId, challengeId: c.data.id, code: code });
    if (v.error) return { error: v.error };
    touch();
    return { ok: true };
  }

  async function resetRequest(email) {
    return sb.auth.resetPasswordForEmail(email, { redirectTo: new URL("mot-de-passe-oublie.html", location.href).href });
  }
  async function updatePassword(pwd) { return sb.auth.updateUser({ password: pwd }); }
  function onPasswordRecovery(cb) {
    sb.auth.onAuthStateChange(function (ev) { if (ev === "PASSWORD_RECOVERY") cb(); });
  }

  // ───── Mode Test / Live ─────
  // Le droit d'utiliser Live vient du SERVEUR (table merchant_profiles, lecture seule pour l'utilisateur),
  // jamais du navigateur : localStorage ne sert qu'à mémoriser le choix déjà autorisé.
  var MODE_KEY = "abvs_mode", profileP = null;

  function loadProfile(force) {
    if (!sb) return Promise.resolve(null);
    if (force || !profileP) {
      profileP = sb.auth.getUser().then(function (u) {
        var id = u.data && u.data.user && u.data.user.id;
        if (!id) return null;
        return sb.from("merchant_profiles").select("kyc_status,live_enabled").eq("user_id", id).maybeSingle();
      }).then(function (r) { return r && r.data ? r.data : null; }).catch(function () { return null; });
    }
    return profileP;
  }
  function getMode() { try { return localStorage.getItem(MODE_KEY) === "live" ? "live" : "test"; } catch (_) { return "test"; } }
  function storeMode(m) { try { localStorage.setItem(MODE_KEY, m); } catch (_) {} }

  function modeCss() {
    if (document.getElementById("abvs-mode-css")) return;
    var st = document.createElement("style"); st.id = "abvs-mode-css";
    st.textContent =
      "#abvs-live-banner{position:fixed;top:calc(env(safe-area-inset-top,0px) + 12px);left:50%;transform:translateX(-50%);z-index:40;" +
      "background:#d93a4a;color:#fff;font:700 12px Inter,system-ui,sans-serif;letter-spacing:.04em;padding:6px 14px;border-radius:99px;pointer-events:none}" +
      "#abvs-toast{position:fixed;left:50%;bottom:96px;transform:translateX(-50%);z-index:60;max-width:calc(100vw - 32px);text-align:center;" +
      "background:var(--ink,#1b2430);color:var(--solid,#fff);font:600 13px Inter,system-ui,sans-serif;padding:11px 16px;border-radius:14px;box-shadow:0 12px 30px rgba(0,0,0,.25)}";
    document.head.appendChild(st);
  }
  function notify(msg) {
    try {
      modeCss();
      var old = document.getElementById("abvs-toast"); if (old) old.remove();
      var t = document.createElement("div"); t.id = "abvs-toast"; t.setAttribute("role", "status"); t.textContent = msg;
      document.body.appendChild(t); setTimeout(function () { t.remove(); }, 4200);
    } catch (_) {}
  }
  function paintMode() {
    try {
      var m = getMode();
      Array.prototype.forEach.call(document.querySelectorAll(".mode span"), function (sp) {
        var isLive = /live/i.test(sp.textContent);
        sp.classList.toggle("on", isLive === (m === "live"));
      });
      var b = document.getElementById("abvs-live-banner");
      if (m === "live" && !b) {
        modeCss(); b = document.createElement("div"); b.id = "abvs-live-banner"; b.textContent = "● MODE LIVE";
        document.body.appendChild(b);
      } else if (m !== "live" && b) b.remove();
    } catch (_) {}
  }
  function initModeSwitch() {
    loadProfile(true).then(function (p) {
      if (getMode() === "live" && !(p && p.live_enabled)) storeMode("test");
      paintMode();
    });
  }
  // Intercepte (phase de capture) les clics sur Test / Live : remplace les anciennes alertes « bientôt disponible ».
  document.addEventListener("click", function (e) {
    var sp = e.target && e.target.closest && e.target.closest(".mode span");
    if (!sp || !sb) return;
    e.preventDefault(); e.stopPropagation();
    if (!/live/i.test(sp.textContent)) { storeMode("test"); paintMode(); return; }
    loadProfile().then(function (p) {
      if (p && p.live_enabled) { storeMode("live"); paintMode(); notify("Mode Live activé."); }
      else if (p && p.kyc_status === "pending") notify("Vérification en cours : Live s'activera dès la validation de votre entreprise.");
      else notify("Mode Live indisponible : votre entreprise doit d'abord être vérifiée.");
    });
  }, true);

  // Messages d'erreur en français.
  function msg(err) {
    var m = (err && err.message || "").toLowerCase(), s = err && err.status;
    if (s === 429 || m.indexOf("rate limit") > -1) return "Trop de tentatives. Réessayez dans quelques minutes.";
    if (m.indexOf("invalid login") > -1) return "E-mail ou mot de passe incorrect.";
    if (m.indexOf("not confirmed") > -1) return "Confirmez d'abord votre e-mail (lien reçu à l'inscription).";
    if (m.indexOf("already registered") > -1) return "Cet e-mail existe déjà.";
    if (m.indexOf("password") > -1 && (m.indexOf("weak") > -1 || m.indexOf("least") > -1 || m.indexOf("characters") > -1)) return "Mot de passe trop faible.";
    if (m.indexOf("same password") > -1) return "Choisissez un mot de passe différent de l'ancien.";
    if (m.indexOf("invalid totp") > -1 || m.indexOf("invalid code") > -1) return "Code invalide ou expiré.";
    if (m.indexOf("fetch") > -1 || m.indexOf("network") > -1) return "Serveur injoignable. Réessayez plus tard.";
    return "Une erreur est survenue. Réessayez.";
  }

  window.ABVS = { client: sb, ready: !!sb, requireSession: requireSession, hasSession: hasSession, mode: getMode, profile: loadProfile, signUp: signUp, signIn: signIn,
    verifyMfa: verifyMfa, signOut: signOut, resetRequest: resetRequest, updatePassword: updatePassword,
    onPasswordRecovery: onPasswordRecovery, msg: msg, touch: touch };
})();

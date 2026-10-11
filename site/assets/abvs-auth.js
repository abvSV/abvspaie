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

  function touch() {
    try { sessionStorage.setItem(KEY, String(Date.now())); }
    catch (_) {
      try { localStorage.setItem(KEY, String(Date.now())); } catch (_) {}
    }
  }
  function idle() {
    try {
      var t = +(sessionStorage.getItem(KEY) || localStorage.getItem(KEY)) || 0;
      return t > 0 && Date.now() - t > IDLE_MS;
    } catch (_) { return false; }
  }
  function clearTouch() {
    try { sessionStorage.removeItem(KEY); } catch (_) {}
    try { localStorage.removeItem(KEY); } catch (_) {}
  }
  function ungate() { var g = document.getElementById("abvs-gate"); if (g) g.remove(); }
  function emailMfaPending(session) {
    try {
      var parts = session.access_token.split(".");
      var payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
      payload += "=".repeat((4 - payload.length % 4) % 4);
      var claims = JSON.parse(atob(payload));
      return claims.email_mfa_required === true && claims.email_mfa_verified !== true;
    } catch (_) {
      return false;
    }
  }

  async function signOut() {
    try { if (sb) await sb.auth.signOut(); } catch (_) {}
    clearTouch();
    location.replace(LOGIN);
  }

  async function signOutAll() {
    if (!sb) return { error: new Error("Service d'authentification indisponible.") };
    var r = await sb.auth.signOut({ scope: "global" });
    if (r.error) return { error: r.error };
    clearTouch();
    location.replace(LOGIN);
    return { ok: true };
  }

  // Garde de page : masque la page tant que la session n'est pas confirmée.
  // NB : c'est du confort d'affichage ; la vraie protection des données, c'est la RLS côté base.
  async function requireSession() {
    try {
      if (!sb) throw new Error("client indisponible");
      var r = await sb.auth.getSession();
      if (!r.data || !r.data.session) return location.replace(LOGIN);
      if (emailMfaPending(r.data.session)) return location.replace(LOGIN);
      if (idle()) return signOut();
      var a = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
      if (a.data && a.data.nextLevel === "aal2" && a.data.currentLevel !== "aal2") return location.replace(LOGIN);
      touch(); ungate();
      var last = 0;
      ["pointerdown", "keydown", "scroll"].forEach(function (ev) {
        addEventListener(ev, function () { var n = Date.now(); if (n - last > 15000) { last = n; touch(); } }, { passive: true });
      });
      setInterval(function () { if (idle()) signOut(); }, 60000);
    } catch (e) { location.replace(LOGIN); }
  }

  // Vrai si une session valide existe (mêmes règles que requireSession : inactivité et 2FA incluses).
  // Sert à la page de connexion et à l'accueil, pour éviter toute boucle de redirection.
  async function hasSession() {
    try {
      if (!sb) return false;
      var r = await sb.auth.getSession();
      if (!r.data || !r.data.session) return false;
      if (emailMfaPending(r.data.session)) return false;
      if (idle()) return false;
      var a = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
      if (a.data && a.data.nextLevel === "aal2" && a.data.currentLevel !== "aal2") return false;
      return true;
    } catch (e) { return false; }
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

  async function emailMfa(action, code) {
    if (!sb) return { error: new Error("Service d'authentification indisponible.") };
    var sessionResult = await sb.auth.getSession();
    if (sessionResult.error || !sessionResult.data || !sessionResult.data.session) {
      return { error: sessionResult.error || new Error("Session expirée.") };
    }
    try {
      var response = await fetch("/api/auth/email-mfa", {
        method: "POST",
        headers: {
          authorization: "Bearer " + sessionResult.data.session.access_token,
          "content-type": "application/json"
        },
        body: JSON.stringify(code ? { action: action, code: code } : { action: action })
      });
      var result = await response.json();
      if (!response.ok) {
        var failure = new Error(result.error || "La vérification e-mail a échoué.");
        failure.status = response.status;
        return { error: failure };
      }
      return { data: result };
    } catch (failure) {
      return { error: failure };
    }
  }

  async function refreshSession() {
    return sb.auth.refreshSession();
  }

  async function resetRequest(email) {
    return sb.auth.resetPasswordForEmail(email, { redirectTo: new URL("mot-de-passe-oublie.html", location.href).href });
  }
  async function updatePassword(pwd) { return sb.auth.updateUser({ password: pwd }); }
  function onPasswordRecovery(cb) {
    sb.auth.onAuthStateChange(function (ev) { if (ev === "PASSWORD_RECOVERY") cb(); });
  }

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

  window.ABVS = { client: sb, ready: !!sb, requireSession: requireSession, hasSession: hasSession, signUp: signUp, signIn: signIn,
    verifyMfa: verifyMfa, emailMfa: emailMfa, refreshSession: refreshSession, signOut: signOut, signOutAll: signOutAll, resetRequest: resetRequest, updatePassword: updatePassword,
    onPasswordRecovery: onPasswordRecovery, msg: msg, touch: touch, clearTouch: clearTouch };
})();

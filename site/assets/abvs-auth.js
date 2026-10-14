// ABVSPAIE — couche d'authentification (Supabase Auth). Dépend de supabase-js (UMD) et de abvs-config.js.
(function () {
  "use strict";
  var cfg = window.ABVS_CONFIG || {};
  var LOGIN = "../public/inscription-connexion.html";
  var KEY = "abvs_last_touch";
  var IDLE_MS = 30 * 60 * 1000;
  var sb = null;

  try {
    if (window.supabase && cfg.url && cfg.anonKey) {
      sb = window.supabase.createClient(cfg.url, cfg.anonKey);
    }
  } catch (e) {
    console.error("Impossible d'initialiser le service d'authentification ABVSPAIE.", e);
  }

  function touch() {
    try {
      sessionStorage.setItem(KEY, String(Date.now()));
    } catch (_) {
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
  async function signOut(redirectTo) {
    try { if (sb) await sb.auth.signOut(); } catch (_) {}
    clearTouch();
    location.replace(redirectTo || LOGIN);
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
  async function requireSession(loginUrl, options) {
    var loginTarget = typeof loginUrl === "string" && loginUrl ? loginUrl : LOGIN;
    var requireMfa = !options || options.requireMfa !== false;
    try {
      if (!sb) throw new Error("client indisponible");
      var r = await sb.auth.getSession();
      if (!r.data || !r.data.session) return location.replace(loginTarget);
      if (idle()) return signOut(loginTarget);
      if (requireMfa) {
        var a = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
        if (a.data && a.data.nextLevel === "aal2" && a.data.currentLevel !== "aal2") return location.replace(loginTarget);
      }
      touch(); ungate();
      var last = 0;
      ["pointerdown", "keydown", "scroll"].forEach(function (ev) {
        addEventListener(ev, function () { var n = Date.now(); if (n - last > 15000) { last = n; touch(); } }, { passive: true });
      });
      setInterval(function () { if (idle()) signOut(loginTarget); }, 60000);
    } catch (e) { location.replace(loginTarget); }
  }

  // Vrai si une session valide existe (mêmes règles que requireSession : inactivité et 2FA incluses).
  // Sert à la page de connexion et à l'accueil, pour éviter toute boucle de redirection.
  async function hasSession() {
    try {
      if (!sb) return false;
      var r = await sb.auth.getSession();
      if (!r.data || !r.data.session) return false;
      if (idle()) return false;
      var a = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
      if (a.data && a.data.nextLevel === "aal2" && a.data.currentLevel !== "aal2") return false;
      return true;
    } catch (e) { return false; }
  }

  async function signUp(o) {
    var r = await sb.auth.signUp({
      email: o.email, password: o.password,
      options: { data: { full_name: o.full_name, company: o.company, country: o.country }, emailRedirectTo: new URL(LOGIN, location.href).href }
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
    if (a.error) return { error: a.error };
    if (a.data && a.data.nextLevel === "aal2" && a.data.currentLevel !== "aal2") {
      var f = await sb.auth.mfa.listFactors();
      if (f.error) return { error: f.error };
      var factors = f.data && f.data.totp || [];
      var t = factors.find(function (factor) { return factor.status === "verified"; });
      if (t) return { mfa: true, factorId: t.id };
      await sb.auth.signOut();
      var missingFactor = new Error("No verified TOTP factor is available.");
      missingFactor.userMessage = "La MFA est requise pour ce compte, mais aucune application d'authentification confirmée n'est disponible. Contacte le support.";
      return { error: missingFactor };
    }
    touch();
    return { ok: true };
  }

  async function verifyMfa(factorId, code) {
    var c = await sb.auth.mfa.challenge({ factorId: factorId });
    if (c.error) return { error: c.error };
    var v = await sb.auth.mfa.verify({ factorId: factorId, challengeId: c.data.id, code: code });
    if (v.error) return { error: v.error };
    var assurance = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
    if (assurance.error) return { error: assurance.error };
    if (!assurance.data || assurance.data.currentLevel !== "aal2") {
      var insufficientAssurance = new Error("The session did not reach the required MFA level.");
      insufficientAssurance.userMessage = "La session n'a pas atteint le niveau MFA requis. Réessaie de te connecter.";
      return { error: insufficientAssurance };
    }
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

  var accountNavItems = [
    { id: "home", icon: "🏠", label: "Tableau de bord", view: "home" },
    { id: "wallet", icon: "👛", label: "Wallet", view: "wallet" },
    { id: "tx", icon: "↔️", label: "Transactions", view: "tx" },
    { id: "links", icon: "🔗", label: "Liens de paiement", view: "links" },
    { id: "sessions", icon: "🧾", label: "Sessions de checkout", view: "sessions" },
    { id: "clients", icon: "👥", label: "Clients", view: "clients" },
    { id: "stats", icon: "📈", label: "Statistiques", view: "stats" },
    { id: "retraits", icon: "🏦", label: "Reversements", view: "retraits" },
    { id: "keys", icon: "🔑", label: "Développeur", view: "keys" },
    { id: "hooks", icon: "🪝", label: "Webhooks", view: "hooks" },
    { id: "hooklog", icon: "📜", label: "Journal des webhooks", view: "hooklog" },
    { id: "disputes", icon: "⚖️", label: "Litiges", view: "disputes" },
    { id: "pricing", icon: "🏷️", label: "Tarification", view: "pricing" },
    { id: "support", icon: "💬", label: "Support", view: "support" },
    { id: "settings", icon: "⚙️", label: "Paramètres", href: "parametres.html" }
  ];
  var dashboardViews = new Set(accountNavItems.filter(function (item) { return item.view; }).map(function (item) { return item.view; }));

  function navIconSvg(id) {
    var icons = {
      home: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 10.5 12 4l8 6.5V18a2 2 0 0 1-2 2h-3v-7H9v7H6a2 2 0 0 1-2-2z"/></svg>',
      wallet: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7.5A2.5 2.5 0 0 1 6.5 5H18a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H6.5A2.5 2.5 0 0 1 4 15.5zm0 0h14m-12 5h2"/><path d="M16 12h2.5v2H16"/></svg>',
      tx: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 7h10M7 12h10M7 17h6"/><path d="M5 5h0M5 19h0"/></svg>',
      links: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 8 7 10a3 3 0 0 0 4.2 4.2l1.8-1.8"/><path d="m15 16 2-2a3 3 0 0 0-4.2-4.2L11 10"/><path d="M8 16l8-8"/></svg>',
      sessions: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 4.5V3m10 1.5V3M4.5 8h15"/><rect x="4" y="6" width="16" height="14" rx="2"/><path d="M8 12h8M8 16h6"/></svg>',
      clients: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8.5 11a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Zm-4 8c.8-2.2 2.6-3.5 4.5-3.5S12.3 16.8 13 19"/><path d="M15 11a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm4.5 8c-.7-1.8-2-3-3.7-3.5"/></svg>',
      stats: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 18V9M12 18V5M19 18v-7"/><path d="M3 18h18"/></svg>',
      retraits: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="7" width="16" height="13" rx="2"/><path d="M4 11h16M9 3.5h6"/><path d="M12 15v-2"/></svg>',
      keys: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="8.5" cy="15.5" r="3.5"/><path d="M10.8 15.5h9.2v-1.5m-7.5 0V13m0 2.5V18M17 15.5V13m0 2.5V18"/><path d="M11.5 15.5 20 7"/></svg>',
      hooks: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 15.5A4.5 4.5 0 0 1 8 6.5M16 8.5A4.5 4.5 0 0 1 16 17.5M12 4v16"/><path d="M6 9.5 9 12l-3 2.5M18 14.5 15 12l3-2.5"/></svg>',
      hooklog: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 4.5h9l4 4V18a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6.5a2 2 0 0 1 2-2Z"/><path d="M15 4.5V9h4M8 12h8M8 16h8"/></svg>',
      disputes: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 18h12"/><path d="M8 18V8.5A2.5 2.5 0 0 1 10.5 6H13.5A2.5 2.5 0 0 1 16 8.5V18"/><path d="M10 12h4M10 15h4"/></svg>',
      pricing: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 8.5c0-1.7 1.3-3 3-3h4c1.7 0 3 1.3 3 3s-1.3 3-3 3h-4c-1.7 0-3 1.3-3 3 0 1.6 1.3 3 3 3h4c1.7 0 3-1.4 3-3"/><path d="M12 3.5v17"/></svg>',
      support: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 8.5A6 6 0 1 1 18 8.5v5.6a2 2 0 0 1-2 2h-1.2l-2.7 2.9a.7.7 0 0 1-1.2-.5V16H8a2 2 0 0 1-2-2z"/><path d="M9 11h6M9 14h4"/></svg>',
      settings: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 0 1-2.8 2.8l-.1-.1A1.7 1.7 0 0 0 15 19.4c-.3.2-.7.3-1.1.3h-.2a1.7 1.7 0 0 0-1.7 1.7V21a2 2 0 1 1-4 0v-.2a1.7 1.7 0 0 0-1.7-1.7h-.2A1.7 1.7 0 0 0 4.6 19c-.4-.1-.8-.2-1.1-.3a2 2 0 0 1-1.1-2.7l.1-.1a1.7 1.7 0 0 0 .3-1.8L2.6 15A2 2 0 0 1 5.3 12.5l.1.1A1.7 1.7 0 0 0 7.2 12h.2a1.7 1.7 0 0 0 1.7-1.7v-.2a1.7 1.7 0 0 0-1.7-1.7h-.2A1.7 1.7 0 0 0 5.4 7.5L5.3 7.4A2 2 0 0 1 5.3 4.7l.1-.1a1.7 1.7 0 0 0 1.8-.3L7.3 4.2a2 2 0 0 1 2.7 1.1l.1.2A1.7 1.7 0 0 0 11.8 7.2h.2a1.7 1.7 0 0 0 1.7-1.7V5.3a2 2 0 0 1 4 0v.2a1.7 1.7 0 0 0 1.7 1.7h.2a1.7 1.7 0 0 0 1.7-1.7l.1-.2a2 2 0 0 1 2.7-1.1l.1.1a1.7 1.7 0 0 0 1.8.3l.1-.1a2 2 0 0 1 2.1 2.9l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.7 1.7h.2a1.7 1.7 0 0 0 1.7-1.7l.1-.2a2 2 0 0 1 2.7-1.1l.1.1a2 2 0 0 1 .6 2.5l-.3.4A1.7 1.7 0 0 0 19.4 15Z"/></svg>'
    };
    return icons[id] || '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M9 12h6M12 9v6"/></svg>';
  }

  function renderDashboardNav(nav) {
    nav.replaceChildren();
    accountNavItems.forEach(function (item) {
      if (item.view && dashboardViews.has(item.view)) {
        var button = document.createElement("button");
        button.type = "button";
        button.dataset.v = item.view;
        button.title = item.label;
        button.setAttribute("aria-label", item.label);
        if (item.view === "home") {
          button.className = "on";
          button.setAttribute("aria-current", "page");
        }
        button.innerHTML = '<span class="nav-icon" aria-hidden="true">' + navIconSvg(item.id) + '</span><span class="nav-label">' + item.label + '</span>';
        nav.appendChild(button);
        return;
      }

      var link = document.createElement("a");
      link.href = item.view ? "tableau-de-bord.html#" + item.view : item.href;
      link.title = item.label;
      link.setAttribute("aria-label", item.label);
      link.innerHTML = '<span class="nav-icon" aria-hidden="true">' + navIconSvg(item.id) + '</span>';
      nav.appendChild(link);
    });
  }

  window.ABVS_ACCOUNT_NAV = { renderDashboard: renderDashboardNav };
  document.addEventListener("DOMContentLoaded", function () {
    var path = location.pathname.replace(/\/+$/, "");
    var pathParts = path.split("/");
    if (pathParts[pathParts.length - 2] !== "compte" || pathParts[pathParts.length - 1] === "tableau-de-bord.html") return;
    var content = document.querySelector("main") || document.querySelector(".wrap") || document.querySelector(".app");
    if (!content) return;

    var style = document.createElement("style");
    style.textContent = ".account-return{display:inline-flex;align-items:center;gap:7px;width:max-content;margin:0 0 4px;padding:8px 12px;border:1px solid var(--line,#dde3ea);border-radius:12px;background:color-mix(in srgb,var(--solid,#fff) 88%,transparent);color:var(--ink,#1b2430);font:600 12px Inter,system-ui,sans-serif;text-decoration:none}.account-return:hover{border-color:var(--pri,#4a6283);background:var(--solid,#fff);color:var(--pri,#4a6283)}.account-return:focus-visible{outline:2px solid var(--pri,#4a6283);outline-offset:2px}";
    document.head.appendChild(style);

    var link = document.createElement("a");
    link.className = "account-return";
    link.href = path.slice(0, path.lastIndexOf("/") + 1) + "tableau-de-bord.html";
    link.setAttribute("aria-label", "Retour au tableau de bord");
    link.innerHTML = "<span aria-hidden=\"true\">←</span><span>Retour au tableau de bord</span>";
    content.insertBefore(link, content.firstChild);
  }, { once: true });

  // Messages d'erreur en français.
  function msg(err) {
    if (err && err.userMessage) return err.userMessage;
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
    verifyMfa: verifyMfa, signOut: signOut, signOutAll: signOutAll, resetRequest: resetRequest, updatePassword: updatePassword,
    onPasswordRecovery: onPasswordRecovery, msg: msg, touch: touch, clearTouch: clearTouch };
})();

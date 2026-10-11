"use strict";

const crypto = require("node:crypto");
const { config, authUser, rest, json } = require("../../server/webhooks");

function tokenClaims(req, user) {
  const match = (req.headers.authorization || "").match(/^Bearer\s+([^\s]+)$/i);
  if (!match) return null;
  try {
    const parts = match[1].split(".");
    if (parts.length !== 3) return null;
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (claims.sub !== user.id || !claims.session_id) return null;
    return claims;
  } catch (_) {
    return null;
  }
}

function hashCode(userId, sessionId, action, code) {
  const secret = process.env.EMAIL_MFA_SECRET;
  if (!secret || secret.length < 32) throw new Error("EMAIL_MFA_SECRET must contain at least 32 characters.");
  return crypto.createHmac("sha256", secret).update(`${userId}.${sessionId}.${action}.${code}`).digest("hex");
}

async function sendCode(user, code) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL;
  const senderName = process.env.BREVO_SENDER_NAME || "ABVSPAIE Sécurité";
  if (!apiKey || !senderEmail) throw new Error("Brevo email delivery is not configured.");
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": apiKey, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      sender: { name: senderName, email: senderEmail },
      to: [{ email: user.email }],
      subject: "Votre code de sécurité ABVSPAIE",
      textContent: `Votre code de sécurité ABVSPAIE est ${code}. Il expire dans 10 minutes. Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.`,
      htmlContent: `<p>Votre code de sécurité ABVSPAIE :</p><p style="font-size:28px;font-weight:bold;letter-spacing:6px">${code}</p><p>Il expire dans 10 minutes. Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.</p>`
    })
  });
  if (!response.ok) {
    console.error("Brevo email MFA send failed with HTTP status:", response.status);
    throw new Error("Email delivery failed.");
  }
}

async function callRpc(name, body) {
  const response = await rest(`rpc/${name}`, { method: "POST", body: JSON.stringify(body) });
  if (!response.ok) {
    const error = new Error(await response.text());
    error.status = response.status;
    throw error;
  }
  return response;
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, { error: "Méthode non autorisée." });
  }
  try {
    const user = await authUser(req, { allowPendingEmailMfa: true });
    if (!user) return json(res, 401, { error: "Session invalide." });
    if (!user.email || !user.email_confirmed_at) return json(res, 403, { error: "Une adresse e-mail confirmée est requise." });
    const claims = tokenClaims(req, user);
    if (!claims) return json(res, 401, { error: "Session de sécurité invalide." });
    if (process.env.EMAIL_MFA_TOKEN_HOOK_CONFIGURED !== "true") {
      if (req.body && req.body.action === "status") {
        return json(res, 200, { enabled: false, verified: false, available: false });
      }
      return json(res, 503, { error: "La protection serveur e-mail MFA n'est pas encore activée." });
    }
    if (typeof claims.email_mfa_required !== "boolean" || typeof claims.email_mfa_verified !== "boolean") {
      return json(res, 503, { error: "La protection serveur e-mail MFA n'est pas correctement configurée." });
    }
    const { serviceKey } = config();
    const action = req.body && req.body.action;
    if (!["status", "start_login", "start_enroll", "start_disable", "verify_login", "verify_enroll", "verify_disable"].includes(action)) {
      return json(res, 400, { error: "Action e-mail MFA invalide." });
    }

    if (action === "status") {
      return json(res, 200, {
        enabled: claims.email_mfa_required === true,
        verified: claims.email_mfa_verified === true,
        available: true
      });
    }

    const starting = action.startsWith("start_");
    const purpose = action.replace(/^start_/, "").replace(/^verify_/, "");
    if (starting) {
      const code = String(crypto.randomInt(100000, 1000000));
      const codeHash = hashCode(user.id, claims.session_id, purpose, code);
      await callRpc("start_email_mfa_challenge", {
        p_user_id: user.id,
        p_session_id: claims.session_id,
        p_action: purpose,
        p_code_hash: codeHash
      });
      await sendCode(user, code);
      return json(res, 200, { ok: true, message: "Code envoyé à l’adresse e-mail de ton compte." });
    }

    const code = typeof req.body.code === "string" ? req.body.code.trim() : "";
    if (!/^\d{6}$/.test(code)) return json(res, 400, { error: "Saisis le code à 6 chiffres reçu par e-mail." });
    const verified = await callRpc("verify_email_mfa_challenge", {
      p_user_id: user.id,
      p_session_id: claims.session_id,
      p_action: purpose,
      p_code_hash: hashCode(user.id, claims.session_id, purpose, code)
    });
    const result = await verified.json();
    if (result !== true) return json(res, 400, { error: "Code incorrect ou expiré." });
    return json(res, 200, { ok: true, action: purpose });
  } catch (error) {
    const message = String(error.message || "").toLowerCase();
    if (error.status === 429) return json(res, 429, { error: "Trop de demandes. Réessaie plus tard." });
    if (message.includes("attends une minute")) return json(res, 429, { error: "Attends une minute avant de demander un nouveau code." });
    if (message.includes("limite de cinq")) return json(res, 429, { error: "Limite de cinq codes par heure atteinte." });
    if (message.includes("brevo email delivery") || message.includes("email_mfa_secret")) {
      return json(res, 503, { error: "La configuration sécurisée de l’envoi e-mail est incomplète. Contacte l’administrateur." });
    }
    if (error.message === "Email delivery failed.") return json(res, 502, { error: "Brevo n’a pas pu envoyer le code. Réessaie plus tard." });
    console.error("Email MFA request failed:", error.message);
    return json(res, 500, { error: "Le traitement du code e-mail a échoué." });
  }
};

"use strict";

const crypto = require("node:crypto");
const { config, encryptSecret, authUser, rest, json } = require("../../server/webhooks");

module.exports = async function handler(req, res) {
  if (req.method !== "POST" && req.method !== "DELETE") {
    res.setHeader("Allow", "POST, DELETE");
    return json(res, 405, { error: "Méthode non autorisée." });
  }

  try {
    const user = await authUser(req);
    if (!user) return json(res, 401, { error: "Session invalide." });

    config();

    if (req.method === "DELETE") {
      const id = typeof req.query.id === "string" ? req.query.id : "";
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
        return json(res, 400, { error: "Identifiant de webhook invalide." });
      }

      const owned = await rest(`webhook_endpoints?id=eq.${id}&merchant_id=eq.${user.id}&select=id`);
      if (!owned.ok) return json(res, 502, { error: "Vérification du webhook impossible." });
      if (!(await owned.json()).length) return json(res, 404, { error: "Webhook introuvable." });

      const disabled = await rest(`webhook_endpoints?id=eq.${id}&merchant_id=eq.${user.id}`, {
        method: "PATCH",
        headers: { prefer: "return=minimal" },
        body: JSON.stringify({ is_active: false })
      });
      if (!disabled.ok) return json(res, 502, { error: "Désactivation du webhook impossible." });
      const removedSecret = await rest(`webhook_endpoint_secrets?endpoint_id=eq.${id}`, { method: "DELETE" });
      if (!removedSecret.ok) return json(res, 502, { error: "L'endpoint est désactivé, mais la suppression du secret a échoué." });
      return json(res, 200, { ok: true });
    }

    const name = typeof req.body?.name === "string" ? req.body.name.trim().slice(0, 80) : "";
    if (name.length < 2) return json(res, 400, { error: "Donnez un nom de deux caractères minimum." });
    if (Buffer.from(process.env.WEBHOOK_ENCRYPTION_KEY || "", "base64").length !== 32) {
      return json(res, 503, { error: "WEBHOOK_ENCRYPTION_KEY doit être une clé base64 de 32 octets." });
    }
    let appUrl;
    try {
      appUrl = new URL(process.env.PUBLIC_APP_URL);
      if (!["https:", "http:"].includes(appUrl.protocol) || appUrl.username || appUrl.password) throw new Error("URL publique invalide.");
      if (process.env.NODE_ENV === "production" && appUrl.protocol !== "https:") throw new Error("HTTPS requis en production.");
    } catch (_) {
      return json(res, 503, { error: "PUBLIC_APP_URL doit être une URL HTTPS valide." });
    }

    const id = crypto.randomUUID();
    const secret = crypto.randomBytes(32).toString("base64url");
    const encrypted = encryptSecret(secret);
    const endpointUrl = new URL(`/api/webhooks/receive?endpoint=${encodeURIComponent(id)}`, appUrl.origin).toString();

    const created = await rest("webhook_endpoints", {
      method: "POST",
      headers: { prefer: "return=minimal" },
      body: JSON.stringify({ id, merchant_id: user.id, name, endpoint_url: endpointUrl })
    });
    if (!created.ok) return json(res, 502, { error: "Création du webhook impossible." });

    const stored = await rest("webhook_endpoint_secrets", {
      method: "POST",
      headers: { prefer: "return=minimal" },
      body: JSON.stringify({
        endpoint_id: id,
        secret_ciphertext: encrypted.ciphertext,
        secret_iv: encrypted.iv,
        secret_tag: encrypted.tag
      })
    });
    if (!stored.ok) {
      await rest(`webhook_endpoints?id=eq.${id}`, { method: "DELETE" });
      return json(res, 502, { error: "Enregistrement sécurisé du webhook impossible." });
    }

    return json(res, 201, {
      endpoint: { id, name, endpoint_url: endpointUrl, is_active: true },
      secret
    });
  } catch (error) {
    console.error("Webhook endpoint management failed:", error);
    return json(res, 500, { error: "Une erreur interne est survenue." });
  }
};

"use strict";

const { config, decryptSecret, rest, json, readRawBody, verifySignature } = require("../../server/webhooks");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_BODY_BYTES = 256 * 1024;
const MAX_CLOCK_SKEW_SECONDS = 5 * 60;

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, { error: "Seules les requêtes POST sont acceptées." });
  }

  const endpointId = typeof req.query.endpoint === "string" ? req.query.endpoint : "";
  if (!UUID.test(endpointId)) return json(res, 400, { error: "Identifiant de webhook invalide." });

  const contentType = req.headers["content-type"] || "";
  if (!/^application\/(?:json|[\w.+-]+\+json)(?:\s*;|$)/i.test(contentType)) {
    return json(res, 415, { error: "Le type de contenu doit être application/json." });
  }

  try {
    const rawBody = await readRawBody(req, MAX_BODY_BYTES);
    const timestamp = req.headers["x-abvs-timestamp"] || "";
    if (!/^\d{10}$/.test(timestamp) || Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp)) > MAX_CLOCK_SKEW_SECONDS) {
      return json(res, 401, { error: "Horodatage absent, invalide ou expiré." });
    }

    const signature = req.headers["x-abvs-signature"] || "";
    config();
    const endpointQuery = new URLSearchParams({
      id: `eq.${endpointId}`,
      is_active: "eq.true",
      select: "id,merchant_id"
    });
    const endpointResponse = await rest(`webhook_endpoints?${endpointQuery}`);
    if (!endpointResponse.ok) return json(res, 503, { error: "Vérification du webhook indisponible." });
    const endpoints = await endpointResponse.json();
    if (!endpoints.length) return json(res, 404, { error: "Webhook introuvable ou désactivé." });

    const secretQuery = new URLSearchParams({
      endpoint_id: `eq.${endpointId}`,
      select: "secret_ciphertext,secret_iv,secret_tag"
    });
    const secretResponse = await rest(`webhook_endpoint_secrets?${secretQuery}`);
    if (!secretResponse.ok) return json(res, 503, { error: "Vérification de signature indisponible." });
    const secrets = await secretResponse.json();
    if (!secrets.length) return json(res, 404, { error: "Secret webhook indisponible." });

    const secret = decryptSecret({
      ciphertext: secrets[0].secret_ciphertext,
      iv: secrets[0].secret_iv,
      tag: secrets[0].secret_tag
    });
    if (!verifySignature(secret, timestamp, rawBody, signature)) {
      return json(res, 401, { error: "Signature invalide." });
    }

    let payload;
    try {
      payload = JSON.parse(rawBody.toString("utf8"));
    } catch (_) {
      return json(res, 400, { error: "Le corps de la requête ne contient pas un JSON valide." });
    }
    if (!payload || Array.isArray(payload) || typeof payload !== "object") {
      return json(res, 400, { error: "Le JSON doit être un objet." });
    }

    const suppliedDeliveryId = req.headers["x-abvs-delivery"] || "";
    if (typeof suppliedDeliveryId !== "string" || !/^[A-Za-z0-9._:-]{1,120}$/.test(suppliedDeliveryId)) {
      return json(res, 400, { error: "Identifiant de livraison invalide." });
    }
    const deliveryId = suppliedDeliveryId;
    const rawEventType = typeof payload.event === "string" ? payload.event : payload.type;
    const eventType = typeof rawEventType === "string" ? rawEventType.trim().slice(0, 120) || null : null;
    const query = new URLSearchParams({ on_conflict: "endpoint_id,delivery_id" });
    const stored = await rest(`webhook_events?${query}`, {
      method: "POST",
      headers: { prefer: "resolution=ignore-duplicates,return=representation" },
      body: JSON.stringify({
        endpoint_id: endpointId,
        merchant_id: endpoints[0].merchant_id,
        delivery_id: deliveryId,
        event_type: eventType,
        payload
      })
    });
    if (!stored.ok) {
      console.error("Webhook event storage failed with HTTP status:", stored.status);
      return json(res, 503, { error: "Enregistrement de l'événement impossible." });
    }

    const rows = await stored.json();
    return json(res, 202, { received: true, duplicate: rows.length === 0, delivery_id: deliveryId });
  } catch (error) {
    if (error.status === 413) return json(res, 413, { error: error.message });
    console.error("Webhook receiver failed:", error);
    return json(res, 500, { error: "Une erreur interne est survenue." });
  }
};

module.exports.config = { api: { bodyParser: false } };

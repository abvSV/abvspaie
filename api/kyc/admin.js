"use strict";

const { config, authUser, rest, json } = require("../../server/webhooks");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isAdmin(user) {
  return user.app_metadata && user.app_metadata.kyc_admin === true;
}

function hasAal2(req, user) {
  const match = (req.headers.authorization || "").match(/^Bearer\s+([^\s]+)$/i);
  if (!match) return false;
  try {
    const parts = match[1].split(".");
    if (parts.length !== 3) return false;
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return claims.sub === user.id && claims.aal === "aal2";
  } catch (_) {
    return false;
  }
}

async function signedDocumentUrl(documentId) {
  const recordResponse = await rest(`merchant_kyc_documents?id=eq.${documentId}&select=merchant_id,storage_path`);
  if (!recordResponse.ok) throw new Error("Document KYC introuvable.");
  const records = await recordResponse.json();
  if (!records.length) return null;

  const signedResponse = await fetch(
    `${config().url}/storage/v1/object/sign/merchant-kyc-documents/${records[0].storage_path.split("/").map(encodeURIComponent).join("/")}`,
    {
      method: "POST",
      headers: {
        apikey: config().serviceKey,
        authorization: `Bearer ${config().serviceKey}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({ expiresIn: 60 })
    }
  );
  if (!signedResponse.ok) throw new Error("Lien temporaire du document impossible à créer.");
  const result = await signedResponse.json();
  const signedPath = result.signedURL || result.signedUrl;
  if (typeof signedPath !== "string") throw new Error("Réponse de stockage invalide.");
  return { url: new URL(signedPath, `${config().url}/storage/v1/`).toString() };
}

async function listPendingCases() {
  const profilesResponse = await rest(
    "merchant_profiles?kyc_status=eq.pending&select=user_id,kyc_status,kyc_submitted_at,created_at,kyc_rejection_reason,kyc_full_name,kyc_country,kyc_document_type&order=kyc_submitted_at.asc&limit=100"
  );
  if (!profilesResponse.ok) throw new Error("Chargement des dossiers KYC impossible.");
  const profiles = await profilesResponse.json();
  if (!profiles.length) return [];

  const ids = profiles.map(profile => profile.user_id);
  const query = new URLSearchParams({
    merchant_id: `in.(${ids.join(",")})`,
    select: "id,merchant_id,document_type,document_side,storage_path,created_at",
    order: "created_at.asc"
  });
  const documentsResponse = await rest(`merchant_kyc_documents?${query}`);
  if (!documentsResponse.ok) throw new Error("Chargement des justificatifs KYC impossible.");
  const documents = await documentsResponse.json();
  const byMerchant = new Map(ids.map(id => [id, []]));
  documents.forEach(document => byMerchant.get(document.merchant_id).push({
    id: document.id,
    document_type: document.document_type,
    document_side: document.document_side,
    created_at: document.created_at
  }));

  const auditQuery = new URLSearchParams({
    merchant_id: `in.(${ids.join(",")})`,
    select: "merchant_id,event_type,actor_id,details,created_at",
    order: "created_at.desc"
  });
  const auditResponse = await rest(`kyc_audit_logs?${auditQuery}`);
  if (!auditResponse.ok) throw new Error("Chargement de l'historique KYC impossible.");
  const audit = await auditResponse.json();
  const auditByMerchant = new Map(ids.map(id => [id, []]));
  audit.forEach(entry => auditByMerchant.get(entry.merchant_id).push(entry));

  return profiles.map(profile => ({
    ...profile,
    documents: byMerchant.get(profile.user_id),
    history: auditByMerchant.get(profile.user_id)
  }));
}

async function listAuditHistory() {
  const response = await rest("kyc_audit_logs?select=merchant_id,actor_id,event_type,details,created_at&order=created_at.desc&limit=200");
  if (!response.ok) throw new Error("Chargement de l'historique KYC impossible.");
  return response.json();
}

module.exports = async function handler(req, res) {
  if (req.method !== "GET" && req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return json(res, 405, { error: "Méthode non autorisée." });
  }

  try {
    const user = await authUser(req);
    if (!user) return json(res, 401, { error: "Session invalide." });
    if (!isAdmin(user)) return json(res, 403, { error: "Accès administrateur requis." });
    if (!hasAal2(req, user)) return json(res, 403, { error: "Une session avec authentification MFA est requise." });
    config();

    if (req.method === "GET") {
      if (req.query.history === "true") {
        return json(res, 200, { history: await listAuditHistory() });
      }
      const documentId = typeof req.query.document_id === "string" ? req.query.document_id : "";
      if (documentId) {
        if (!UUID.test(documentId)) return json(res, 400, { error: "Identifiant de document invalide." });
        const result = await signedDocumentUrl(documentId);
        if (!result) return json(res, 404, { error: "Document introuvable." });
        return json(res, 200, result);
      }
      return json(res, 200, { cases: await listPendingCases() });
    }

    const merchantId = typeof req.body?.merchant_id === "string" ? req.body.merchant_id : "";
    const decision = req.body?.decision;
    const reason = typeof req.body?.reason === "string" ? req.body.reason.trim() : "";
    if (!UUID.test(merchantId)) return json(res, 400, { error: "Identifiant marchand invalide." });
    if (merchantId === user.id) return json(res, 403, { error: "Un administrateur ne peut pas examiner son propre dossier." });
    if (decision !== "verified" && decision !== "rejected") return json(res, 400, { error: "Décision KYC invalide." });
    if (decision === "rejected" && (reason.length < 10 || reason.length > 1000)) {
      return json(res, 400, { error: "Le motif de refus doit contenir entre 10 et 1000 caractères." });
    }

    const response = await rest("rpc/decide_kyc", {
      method: "POST",
      body: JSON.stringify({
        p_merchant_id: merchantId,
        p_decision: decision,
        p_reason: reason || null,
        p_admin_id: user.id
      })
    });
    if (!response.ok) {
      const details = await response.text();
      if (details.includes("n''est pas en attente") || details.includes("n'est pas en attente")) {
        return json(res, 409, { error: "Ce dossier a déjà été traité ou n'est plus en attente." });
      }
      if (details.includes("justificatifs requis pour être approuvé")) {
        return json(res, 409, { error: "Le dossier est incomplet et ne peut pas être approuvé." });
      }
      if (details.includes("motif de refus")) {
        return json(res, 400, { error: "Le motif de refus doit contenir entre 10 et 1000 caractères." });
      }
      console.error("KYC decision failed with HTTP status:", response.status);
      return json(res, 502, { error: "La décision KYC n'a pas pu être enregistrée." });
    }
    return json(res, 200, { ok: true });
  } catch (error) {
    console.error("KYC administration failed:", error);
    return json(res, 500, { error: "Une erreur interne est survenue." });
  }
};

"use strict";

const { authUser, config, rest, json, resolveStorageSignedUrl } = require("../../server/webhooks");

function hasAal2(req, user) {
  try {
    const token = req.headers.authorization.match(/^Bearer\s+([^\s]+)$/i)[1];
    const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
    return claims.sub === user.id && claims.aal === "aal2";
  } catch (_) {
    return false;
  }
}

async function signDocument(path) {
  const { url, serviceKey } = config();
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  const response = await fetch(`${url}/storage/v1/object/sign/merchant-kyc-documents/${encodedPath}`, {
    method: "POST",
    headers: { apikey: serviceKey, authorization: `Bearer ${serviceKey}`, "content-type": "application/json" },
    body: JSON.stringify({ expiresIn: 60 })
  });
  if (!response.ok) return null;
  const result = await response.json();
  if (typeof result.signedURL !== "string") return null;
  return resolveStorageSignedUrl(url, result.signedURL);
}

module.exports = async function handler(req, res) {
  if (!["GET", "POST"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST");
    return json(res, 405, { error: "Méthode non autorisée." });
  }
  try {
    const user = await authUser(req);
    if (!user) return json(res, 401, { error: "Session invalide." });
    if (!hasAal2(req, user)) return json(res, 403, { error: "Active la MFA et confirme la session pour accéder au dossier KYC." });
    config();

    if (req.method === "POST") {
      const result = await rest("rpc/submit_kyc", {
        method: "POST",
        body: JSON.stringify({
          p_merchant_id: user.id,
          p_full_name: req.body && req.body.full_name,
          p_country: req.body && req.body.country,
          p_document_type: req.body && req.body.document_type
        })
      });
      if (!result.ok) {
        const text = await result.text();
        if (result.status === 400 || result.status === 403) return json(res, 400, { error: "Dossier incomplet ou informations invalides. Vérifie les champs, les faces requises de ta pièce et la présence du selfie." });
        console.error("KYC submission RPC failed with HTTP status:", result.status, text.slice(0, 300));
        return json(res, 502, { error: "Le dossier KYC n’a pas pu être soumis." });
      }
      return json(res, 200, { ok: true, status: "pending" });
    }

    const [profiles, documents, audits] = await Promise.all([
      rest(`merchant_profiles?user_id=eq.${encodeURIComponent(user.id)}&select=kyc_status,kyc_rejection_reason,kyc_full_name,kyc_country,kyc_document_type,kyc_submitted_at,kyc_decided_at,kyc_decided_by,verified_at`),
      rest(`merchant_kyc_documents?merchant_id=eq.${encodeURIComponent(user.id)}&is_current=eq.true&select=id,document_type,document_side,storage_path,created_at&order=created_at.desc`),
      rest(`kyc_audit_logs?merchant_id=eq.${encodeURIComponent(user.id)}&select=actor_id,event_type,created_at&order=created_at.desc&limit=200`)
    ]);
    if (!profiles.ok || !documents.ok || !audits.ok) {
      return json(res, 502, { error: "Le dossier KYC n’a pas pu être chargé. Vérifie que la migration KYC est installée." });
    }
    const [profile] = await profiles.json();
    if (!profile) return json(res, 404, { error: "Profil marchand introuvable." });
    const records = await documents.json();
    const auditRecords = await audits.json();
    const hasIdentity = records.some(document => document.document_type === "identity" && document.document_side === "front");
    const hasRequiredBack = !["national_id", "driving_license"].includes(profile.kyc_document_type)
      || records.some(document => document.document_type === "identity" && document.document_side === "back");
    const hasSelfie = records.some(document => document.document_type === "selfie" && document.document_side === "supporting");
    const approved = auditRecords.some(entry =>
      entry.event_type === "approved"
      && entry.actor_id === profile.kyc_decided_by
      && entry.created_at >= profile.kyc_submitted_at
      && entry.created_at <= profile.kyc_decided_at
    );
    const validVerified = profile.kyc_status === "verified"
      && profile.kyc_submitted_at
      && profile.kyc_decided_at
      && profile.kyc_decided_by
      && profile.verified_at
      && profile.kyc_full_name
      && profile.kyc_country
      && ["national_id", "passport", "driving_license"].includes(profile.kyc_document_type)
      && hasIdentity
      && hasRequiredBack
      && hasSelfie
      && approved;
    const status = profile.kyc_status === "verified" && !validVerified ? "none" : profile.kyc_status;
    const signedDocuments = await Promise.all(records.map(async document => ({
      id: document.id,
      document_type: document.document_type,
      document_side: document.document_side,
      created_at: document.created_at,
      url: await signDocument(document.storage_path)
    })));
    return json(res, 200, {
      profile: { ...profile, kyc_status: status },
      documents: signedDocuments
    });
  } catch (error) {
    console.error("KYC case request failed:", error.message);
    return json(res, 500, { error: "Le dossier KYC n’a pas pu être traité." });
  }
};

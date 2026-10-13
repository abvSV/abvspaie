"use strict";

const crypto = require("node:crypto");
const { config, authUser, rest, json, readRawBody } = require("../../server/webhooks");

const MAX_FILE_BYTES = 4 * 1024 * 1024;
const FORMATS = {
  "application/pdf": { extension: "pdf", valid: bytes => bytes.subarray(0, 5).toString("ascii") === "%PDF-" },
  "image/jpeg": { extension: "jpg", valid: bytes => bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff },
  "image/png": { extension: "png", valid: bytes => bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) }
};

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

async function removeObject(url, serviceKey, path) {
  const response = await fetch(`${url}/storage/v1/object/merchant-kyc-documents/${path.split("/").map(encodeURIComponent).join("/")}`, {
    method: "DELETE",
    headers: { apikey: serviceKey, authorization: `Bearer ${serviceKey}` }
  });
  return response.ok;
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, { error: "Méthode non autorisée." });
  }

  try {
    const user = await authUser(req);
    if (!user) return json(res, 401, { error: "Session invalide." });
    if (!hasAal2(req, user)) return json(res, 403, { error: "Une session avec authentification MFA est requise." });
    const { url, serviceKey } = config();
    const contentType = req.headers["content-type"] || "";
    const format = FORMATS[contentType];
    if (!format) return json(res, 415, { error: "Format refusé. Utilise un fichier PDF, JPG ou PNG." });

    const documentType = req.headers["x-kyc-document-type"];
    const documentSide = req.headers["x-kyc-document-side"];
    if (!["identity", "selfie", "business", "address", "other"].includes(documentType)
        || !["front", "back", "supporting"].includes(documentSide)) {
      return json(res, 400, { error: "Type ou côté du justificatif invalide." });
    }
    if (documentType === "selfie" && (documentSide !== "supporting" || !["image/jpeg", "image/png"].includes(contentType))) {
      return json(res, 415, { error: "Le selfie doit être une image JPG ou PNG." });
    }

    const bytes = await readRawBody(req, MAX_FILE_BYTES);
    if (!bytes.length) return json(res, 400, { error: "Le fichier est vide." });
    if (!format.valid(bytes)) return json(res, 400, { error: "Le contenu du fichier ne correspond pas au format annoncé." });

    const path = `${user.id}/${crypto.randomUUID()}.${format.extension}`;
    const upload = await fetch(`${url}/storage/v1/object/merchant-kyc-documents/${path.split("/").map(encodeURIComponent).join("/")}`, {
      method: "POST",
      headers: {
        apikey: serviceKey,
        authorization: `Bearer ${serviceKey}`,
        "content-type": contentType,
        "x-upsert": "false"
      },
      body: bytes
    });
    if (!upload.ok) {
      console.error("KYC object upload failed with HTTP status:", upload.status, "content type:", upload.headers.get("content-type"));
      return json(res, 502, { error: upload.status === 401 || upload.status === 403
        ? "Le stockage a refusé le fichier. Vérifie la configuration Supabase du stockage KYC ou contacte le support."
        : "Le stockage sécurisé du justificatif a échoué. Réessaie dans quelques instants." });
    }

    const metadata = await rest("merchant_kyc_documents", {
      method: "POST",
      headers: { prefer: "return=representation" },
      body: JSON.stringify({
        merchant_id: user.id,
        document_type: documentType,
        document_side: documentSide,
        storage_path: path
      })
    });
    if (!metadata.ok) {
      const errorBody = await metadata.text();
      let databaseError = {};
      try {
        databaseError = JSON.parse(errorBody);
      } catch (_) {
        // Keep the generic response for non-JSON errors from PostgREST.
      }
      const cleaned = await removeObject(url, serviceKey, path);
      if (!cleaned) console.error("KYC orphan cleanup failed for upload:", metadata.status);
      if (metadata.status === 401 || metadata.status === 403) {
        console.error("KYC metadata registration was forbidden. Verify service-role permissions and KYC database setup.");
        return json(res, 502, { error: cleaned
          ? "Le service KYC a refusé l’enregistrement du justificatif. Vérifie la configuration Supabase ou contacte le support."
          : "Le service KYC a refusé l’enregistrement et le nettoyage du fichier temporaire a échoué. Contacte le support." });
      }
      const message = typeof databaseError.message === "string" ? databaseError.message : "";
      const code = typeof databaseError.code === "string" ? databaseError.code : "";
      if (message.includes("déjà soumis ou vérifié")) {
        return json(res, 409, { error: cleaned
          ? "Ton dossier KYC est déjà soumis ou vérifié. Tu ne peux plus ajouter de justificatifs pour le moment."
          : "Ton dossier KYC est déjà soumis ou vérifié et le nettoyage du fichier temporaire a échoué. Contacte le support." });
      }
      if (message.toLowerCase().includes("limite de huit justificatifs atteinte")) {
        return json(res, 409, { error: cleaned
          ? "La limite de 8 justificatifs est atteinte."
          : "La limite de 8 justificatifs est atteinte et le nettoyage du fichier temporaire a échoué. Contacte le support." });
      }
      if (["23514", "42703", "42P01", "PGRST204", "PGRST205"].includes(code)) {
        console.error("KYC metadata registration failed; verify the KYC database migration. PostgREST code:", code);
        return json(res, 503, { error: cleaned
          ? "La configuration de la base KYC doit être mise à jour. Réapplique schema_kyc.sql dans Supabase puis réessaie."
          : "La configuration de la base KYC doit être mise à jour et le nettoyage du fichier temporaire a échoué. Contacte le support." });
      }
      return json(res, 409, {
        error: cleaned
          ? "Le justificatif n'a pas pu être enregistré. Vérifie le statut KYC et la limite de fichiers."
          : "Le justificatif n'a pas pu être enregistré et le nettoyage du fichier temporaire a échoué. Contacte le support."
      });
    }
    let rows;
    try {
      rows = JSON.parse(await metadata.text());
    } catch (_) {
      const cleaned = await removeObject(url, serviceKey, path);
      console.error("KYC metadata registration returned invalid JSON with HTTP status:", metadata.status);
      if (!cleaned) console.error("KYC orphan cleanup failed after invalid metadata response.");
      return json(res, 502, { error: cleaned
        ? "Le service KYC a renvoyé une réponse invalide. Réessaie ou contacte le support."
        : "Le service KYC a renvoyé une réponse invalide et le nettoyage du fichier temporaire a échoué. Contacte le support." });
    }
    if (!Array.isArray(rows) || !rows[0] || typeof rows[0].id !== "string") {
      const cleaned = await removeObject(url, serviceKey, path);
      if (!cleaned) console.error("KYC orphan cleanup failed after invalid metadata response.");
      return json(res, 502, { error: "Le justificatif a été téléversé mais son enregistrement doit être vérifié par le support." });
    }
    return json(res, 201, { id: rows[0].id, document_type: documentType, document_side: documentSide });
  } catch (error) {
    if (error.status === 413) return json(res, 413, { error: "Le fichier dépasse la limite de 4 Mo." });
    console.error("KYC upload failed:", error);
    return json(res, 500, { error: "Une erreur interne est survenue pendant le dépôt." });
  }
};

module.exports.config = { api: { bodyParser: false } };

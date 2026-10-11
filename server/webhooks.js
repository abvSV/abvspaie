"use strict";

const crypto = require("node:crypto");

function config() {
  const url = process.env.SUPABASE_URL;
  const anonKey = process.env.SUPABASE_ANON_KEY;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !anonKey || !serviceKey) throw new Error("Configuration Supabase manquante.");
  return { url: url.replace(/\/+$/, ""), anonKey, serviceKey };
}

function encryptionKey() {
  const value = process.env.WEBHOOK_ENCRYPTION_KEY || "";
  const key = Buffer.from(value, "base64");
  if (key.length !== 32) throw new Error("WEBHOOK_ENCRYPTION_KEY doit être une clé base64 de 32 octets.");
  return key;
}

function encryptSecret(secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return { ciphertext: ciphertext.toString("base64"), iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
}

function decryptSecret(record) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(record.iv, "base64"));
  decipher.setAuthTag(Buffer.from(record.tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "base64")),
    decipher.final()
  ]).toString("utf8");
}

async function authUser(req, options = {}) {
  const authorization = req.headers.authorization || "";
  const match = authorization.match(/^Bearer ([^\s]+)$/i);
  if (!match) return null;
  const { url, anonKey } = config();
  const response = await fetch(`${url}/auth/v1/user`, {
    headers: { apikey: anonKey, authorization: `Bearer ${match[1]}` }
  });
  if (!response.ok) return null;
  const user = await response.json();
  if (!user || !user.id) return null;
  if (process.env.EMAIL_MFA_TOKEN_HOOK_CONFIGURED === "true") {
    try {
      const claims = JSON.parse(Buffer.from(match[1].split(".")[1], "base64url").toString("utf8"));
      const validClaims = claims.sub === user.id
        && typeof claims.email_mfa_required === "boolean"
        && typeof claims.email_mfa_verified === "boolean";
      if (!validClaims || claims.email_mfa_verified !== true) {
        const pendingEmailFactor = validClaims
          && claims.email_mfa_required === true
          && claims.email_mfa_verified === false;
        return options.allowPendingEmailMfa === true && pendingEmailFactor ? user : null;
      }
    } catch (_) {
      return null;
    }
  }
  return user;
}

async function rest(path, options = {}) {
  const { url, serviceKey } = config();
  return fetch(`${url}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: serviceKey,
      authorization: `Bearer ${serviceKey}`,
      "content-type": "application/json",
      ...(options.headers || {})
    }
  });
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(body));
}

async function readRawBody(req, maxBytes) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > maxBytes) {
      const error = new Error("Payload trop volumineux.");
      error.status = 413;
      throw error;
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

function verifySignature(secret, timestamp, rawBody, signature) {
  const match = /^sha256=([a-f0-9]{64})$/i.exec(signature || "");
  if (!match) return false;
  const expected = crypto.createHmac("sha256", secret).update(timestamp).update(".").update(rawBody).digest();
  const supplied = Buffer.from(match[1], "hex");
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

module.exports = { config, encryptSecret, decryptSecret, authUser, rest, json, readRawBody, verifySignature };

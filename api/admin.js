"use strict";

const { config, authUser, rest, json } = require("../server/webhooks");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PAGE_SIZE = 50;
const RESOURCES = {
  merchants: {
    table: "merchants",
    columns: "id,name,email,country,test_mode,kyc_status",
    order: "id.asc"
  },
  profiles: {
    table: "merchant_profiles",
    columns: "user_id,kyc_status,live_enabled,verified_at,kyc_full_name,kyc_country,kyc_document_type,kyc_submitted_at,kyc_decided_at",
    order: "created_at.desc"
  },
  transactions: {
    table: "transactions",
    columns: "id,reference,merchant_id,link_id,amount,currency,mode,method,payer,status,created_at",
    order: "created_at.desc"
  },
  payment_links: {
    table: "payment_links",
    columns: "id,merchant_id,slug,title,amount,currency,mode,active,created_at",
    order: "created_at.desc"
  },
  clients: {
    table: "clients",
    columns: "id,merchant_id,name,email,phone,created_at",
    order: "created_at.desc"
  },
  webhook_endpoints: {
    table: "webhook_endpoints",
    columns: "id,merchant_id,name,endpoint_url,is_active,created_at",
    order: "created_at.desc"
  },
  webhook_events: {
    table: "webhook_events",
    columns: "id,endpoint_id,merchant_id,delivery_id,event_type,received_at",
    order: "received_at.desc"
  },
  kyc_documents: {
    table: "merchant_kyc_documents",
    columns: "id,merchant_id,document_type,document_side,storage_path,is_current,created_at",
    order: "created_at.desc"
  },
  kyc_audit: {
    table: "kyc_audit_logs",
    columns: "id,merchant_id,actor_id,event_type,details,created_at",
    order: "created_at.desc"
  },
  admin_audit: {
    table: "platform_admin_audit_logs",
    columns: "id,actor_id,target_id,action,details,created_at",
    order: "created_at.desc"
  }
};

function isPlatformAdmin(user) {
  return user.app_metadata && user.app_metadata.platform_admin === true;
}

function configuredPlatformAdminId() {
  const userId = process.env.PLATFORM_ADMIN_USER_ID;
  if (!userId) return null;
  return UUID.test(userId) ? userId : "";
}

function isSuspended(user) {
  const bannedUntil = Date.parse(user.banned_until || "");
  return Number.isFinite(bannedUntil) && bannedUntil > Date.now();
}

async function authAdmin(path, options = {}) {
  const { url, serviceKey } = config();
  return fetch(`${url}/auth/v1/admin/${path}`, {
    ...options,
    headers: {
      apikey: serviceKey,
      authorization: `Bearer ${serviceKey}`,
      "content-type": "application/json",
      ...(options.headers || {})
    }
  });
}

async function listUsers(page) {
  const response = await authAdmin(`users?page=${page}&per_page=${PAGE_SIZE}`);
  if (!response.ok) throw new Error("Chargement des comptes Auth impossible.");
  const result = await response.json();
  const users = Array.isArray(result.users) ? result.users : [];
  return {
    data: users.map(user => ({
      id: user.id,
      email: user.email || "",
      company: user.user_metadata && typeof user.user_metadata.company === "string" ? user.user_metadata.company : "",
      created_at: user.created_at,
      last_sign_in_at: user.last_sign_in_at || null,
      email_confirmed: Boolean(user.email_confirmed_at),
      account_suspended: isSuspended(user),
      platform_admin: Boolean(user.app_metadata && user.app_metadata.platform_admin === true),
      kyc_admin: Boolean(user.app_metadata && user.app_metadata.kyc_admin === true)
    })),
    page,
    limit: PAGE_SIZE,
    total: null,
    hasMore: users.length === PAGE_SIZE
  };
}

async function listResource(resource, page) {
  const definition = RESOURCES[resource];
  if (!definition) return null;
  const query = new URLSearchParams({
    select: definition.columns,
    order: definition.order,
    limit: String(PAGE_SIZE),
    offset: String((page - 1) * PAGE_SIZE)
  });
  const response = await rest(`${definition.table}?${query}`, {
    headers: { prefer: "count=exact" }
  });
  if (!response.ok) throw new Error(`Chargement de ${resource} impossible (HTTP ${response.status}).`);
  const range = response.headers.get("content-range") || "";
  const totalMatch = /\/(\d+|\*)$/.exec(range);
  const total = totalMatch && totalMatch[1] !== "*" ? Number(totalMatch[1]) : null;
  const data = await response.json();
  return {
    data,
    page,
    limit: PAGE_SIZE,
    total,
    hasMore: total === null ? data.length === PAGE_SIZE : page * PAGE_SIZE < total
  };
}

async function countResource(table) {
  const response = await rest(`${table}?select=id&limit=1`, {
    headers: { prefer: "count=exact" }
  });
  if (!response.ok) throw new Error(`Lecture du total ${table} impossible (HTTP ${response.status}).`);
  const range = response.headers.get("content-range") || "";
  const match = /\/(\d+|\*)$/.exec(range);
  return match && match[1] !== "*" ? Number(match[1]) : null;
}

async function overview() {
  const [usersResponse, merchants, transactions, paymentLinks, clients, pendingKyc, webhooks] = await Promise.all([
    authAdmin("users?page=1&per_page=1"),
    countResource("merchants"),
    countResource("transactions"),
    countResource("payment_links"),
    countResource("clients"),
    rest("merchant_profiles?kyc_status=eq.pending&select=user_id&limit=1", {
      headers: { prefer: "count=exact" }
    }),
    countResource("webhook_endpoints")
  ]);
  if (!usersResponse.ok) throw new Error("Chargement du nombre de comptes impossible.");
  if (!pendingKyc.ok) throw new Error("Chargement du nombre de dossiers KYC impossible.");
  const userResult = await usersResponse.json();
  const pendingRange = pendingKyc.headers.get("content-range") || "";
  const pendingMatch = /\/(\d+|\*)$/.exec(pendingRange);
  return {
    counts: {
      users: Number.isInteger(userResult.total) ? userResult.total : null,
      merchants,
      transactions,
      payment_links: paymentLinks,
      clients,
      pending_kyc: pendingMatch && pendingMatch[1] !== "*" ? Number(pendingMatch[1]) : null,
      webhook_endpoints: webhooks
    }
  };
}

async function setRoles(req, actor) {
  const targetId = typeof req.body?.user_id === "string" ? req.body.user_id : "";
  if (!UUID.test(targetId)) return { status: 400, body: { error: "Identifiant de compte invalide." } };
  if (targetId === actor.id) return { status: 403, body: { error: "Tu ne peux pas modifier tes propres rôles." } };
  if (typeof req.body?.kyc_admin !== "boolean") {
    return { status: 400, body: { error: "Le rôle examinateur KYC doit être défini explicitement." } };
  }

  const targetResponse = await authAdmin(`users/${targetId}`);
  if (!targetResponse.ok) return { status: 404, body: { error: "Compte introuvable." } };
  const targetResult = await targetResponse.json();
  const target = targetResult.user || targetResult;
  const oldMetadata = target.app_metadata || {};
  const oldRoles = {
    platform_admin: oldMetadata.platform_admin === true,
    kyc_admin: oldMetadata.kyc_admin === true
  };
  if (typeof req.body?.platform_admin !== "boolean" || req.body.platform_admin !== oldRoles.platform_admin) {
    return { status: 403, body: { error: "Le rôle super-administrateur se modifie uniquement depuis une opération Auth Admin de confiance dans Supabase." } };
  }
  const newRoles = {
    platform_admin: oldRoles.platform_admin,
    kyc_admin: req.body.kyc_admin
  };
  if (oldRoles.platform_admin === newRoles.platform_admin && oldRoles.kyc_admin === newRoles.kyc_admin) {
    return { status: 400, body: { error: "Aucun changement de rôle à enregistrer." } };
  }
  const auditResponse = await rest("platform_admin_audit_logs", {
    method: "POST",
    headers: { prefer: "return=representation" },
    body: JSON.stringify({
      actor_id: actor.id,
      target_id: targetId,
      action: "role_change_requested",
      details: { old_roles: oldRoles, new_roles: newRoles, outcome: "pending" }
    })
  });
  if (!auditResponse.ok) return { status: 503, body: { error: "Le journal d'audit admin n'est pas installé ou accessible. Applique schema_admin.sql." } };
  const [auditRecord] = await auditResponse.json();
  if (!auditRecord || typeof auditRecord.id !== "string") {
    return { status: 502, body: { error: "Le journal d'audit admin a renvoyé une réponse invalide." } };
  }

  const updateResponse = await authAdmin(`users/${targetId}`, {
    method: "PUT",
    body: JSON.stringify({
      app_metadata: {
        ...oldMetadata,
        platform_admin: newRoles.platform_admin,
        kyc_admin: newRoles.kyc_admin
      }
    })
  });
  const outcome = updateResponse.ok ? "succeeded" : "failed";
  const auditUpdate = await rest(`platform_admin_audit_logs?id=eq.${encodeURIComponent(auditRecord.id)}`, {
    method: "PATCH",
    headers: { prefer: "return=minimal" },
    body: JSON.stringify({ action: `role_change_${outcome}` })
  });
  if (!updateResponse.ok) {
    console.error("Admin role update failed with HTTP status:", updateResponse.status);
    return { status: 502, body: { error: auditUpdate.ok
      ? "Les rôles n'ont pas pu être modifiés."
      : "Les rôles n'ont pas pu être modifiés et le journal d'audit doit être vérifié." } };
  }
  if (!auditUpdate.ok) {
    console.error("Admin role change succeeded but audit completion failed with HTTP status:", auditUpdate.status);
    return { status: 502, body: { error: "Les rôles ont été modifiés, mais le journal d'audit doit être vérifié." } };
  }
  return { status: 200, body: { ok: true, roles: newRoles } };
}

async function recordAccountChange(actorId, targetId, action, details) {
  const response = await rest("platform_admin_audit_logs", {
    method: "POST",
    headers: { prefer: "return=representation" },
    body: JSON.stringify({
      actor_id: actorId,
      target_id: targetId,
      action: "account_change_requested",
      details: { operation: action, ...details, outcome: "pending" }
    })
  });
  if (!response.ok) return { error: "Le journal d'audit admin n'est pas installé ou accessible. Applique schema_admin.sql." };
  const [record] = await response.json();
  if (!record || typeof record.id !== "string") return { error: "Le journal d'audit admin a renvoyé une réponse invalide." };
  return { id: record.id };
}

async function finishAccountChange(auditId, action, previousStatus, outcome) {
  const response = await rest(`platform_admin_audit_logs?id=eq.${encodeURIComponent(auditId)}`, {
    method: "PATCH",
    headers: { prefer: "return=minimal" },
    body: JSON.stringify({
      action: `account_change_${outcome}`,
      details: { operation: action, previous_status: previousStatus, outcome }
    })
  });
  return response.ok;
}

async function manageAccount(req, actor, platformAdminId) {
  const targetId = typeof req.body?.user_id === "string" ? req.body.user_id : "";
  const action = req.body?.action;
  if (!UUID.test(targetId)) return { status: 400, body: { error: "Identifiant de compte invalide." } };
  if (targetId === actor.id || targetId === platformAdminId) {
    return { status: 403, body: { error: "Le compte administrateur principal ne peut pas être suspendu ni supprimé depuis la console." } };
  }
  if (!["suspend", "restore", "delete"].includes(action)) {
    return { status: 400, body: { error: "Action de compte invalide." } };
  }

  const targetResponse = await authAdmin(`users/${targetId}`);
  if (!targetResponse.ok) return { status: 404, body: { error: "Compte introuvable." } };
  const targetResult = await targetResponse.json();
  const target = targetResult.user || targetResult;
  if (action === "suspend" && isSuspended(target)) {
    return { status: 409, body: { error: "Ce compte est déjà suspendu." } };
  }
  if (action === "restore" && !isSuspended(target)) {
    return { status: 409, body: { error: "Ce compte n'est pas suspendu." } };
  }

  const previousStatus = isSuspended(target) ? "suspended" : "active";
  const audit = await recordAccountChange(actor.id, targetId, action, { previous_status: previousStatus });
  if (audit.error) return { status: 503, body: { error: audit.error } };

  const update = action === "delete"
    ? await authAdmin(`users/${targetId}`, { method: "DELETE" })
    : await authAdmin(`users/${targetId}`, {
      method: "PUT",
      body: JSON.stringify({ ban_duration: action === "suspend" ? "876000h" : "none" })
    });
  const outcome = update.ok ? "succeeded" : "failed";
  const auditUpdated = await finishAccountChange(audit.id, action, previousStatus, outcome);
  if (!update.ok) {
    console.error("Admin account action failed with HTTP status:", update.status);
    return {
      status: 502,
      body: { error: auditUpdated
        ? action === "delete"
          ? "Le compte n'a pas pu être supprimé. Vérifie les données liées dans Supabase."
          : "L'état du compte n'a pas pu être modifié."
        : "L'action a échoué et le journal d'audit doit être vérifié." }
    };
  }
  if (!auditUpdated) {
    console.error("Admin account action succeeded but audit completion failed.");
    return { status: 502, body: { error: "L'action a été appliquée, mais le journal d'audit doit être vérifié." } };
  }
  return { status: 200, body: { ok: true, action, user_id: targetId } };
}

module.exports = async function handler(req, res) {
  if (!["GET", "POST"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST");
    return json(res, 405, { error: "Méthode non autorisée." });
  }
  try {
    const user = await authUser(req);
    if (!user) return json(res, 401, { error: "Session invalide." });
    const platformAdminId = configuredPlatformAdminId();
    if (platformAdminId === null) {
      return json(res, 503, { error: "Console admin non configurée. Définis PLATFORM_ADMIN_USER_ID dans les variables d'environnement Vercel." });
    }
    if (!platformAdminId) {
      return json(res, 503, { error: "PLATFORM_ADMIN_USER_ID doit contenir l'identifiant UUID du compte administrateur." });
    }
    if (user.id !== platformAdminId || !isPlatformAdmin(user)) {
      return json(res, 403, { error: "Accès réservé au compte administrateur unique autorisé." });
    }
    config();

    if (req.method === "POST") {
      if (["suspend", "restore", "delete"].includes(req.body?.action)) {
        const result = await manageAccount(req, user, platformAdminId);
        return json(res, result.status, result.body);
      }
      const result = await setRoles(req, user);
      return json(res, result.status, result.body);
    }

    const resource = typeof req.query?.resource === "string" ? req.query.resource : "overview";
    const pageValue = typeof req.query?.page === "string" ? Number(req.query.page) : 1;
    if (!Number.isInteger(pageValue) || pageValue < 1 || pageValue > 10000) {
      return json(res, 400, { error: "Numéro de page invalide." });
    }
    if (resource === "users") return json(res, 200, await listUsers(pageValue));
    if (resource === "overview") return json(res, 200, await overview());
    const result = await listResource(resource, pageValue);
    if (!result) return json(res, 400, { error: "Rubrique d'administration inconnue." });
    return json(res, 200, result);
  } catch (error) {
    console.error("Platform admin request failed:", error);
    return json(res, 500, { error: error.message || "Une erreur interne est survenue." });
  }
};

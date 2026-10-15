
require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "20kb" }));

const db = require("./src/config/database");
const { enqueueWebhookDeliveries } = require("./src/services/webhooks");
const { deliverPendingWebhooks } = require("./src/services/webhook-delivery");
const { authenticateMerchant } = require("./src/services/merchant-auth");
const { handleIdempotencyRequest } =
  require("./src/services/idempotency").createIdempotencyService(db);
const {
  cancelMerchantPaymentLink,
  expirePaymentLinkIfDue,
  isPaymentLinkExpired,
  isSupportedPaymentLinkExpiry,
  listMerchantPaymentLinks,
} = require("./src/services/payment-links");
const {
  deactivateWebhookEndpoint,
} = require("./src/services/webhook-endpoints");
const {
  WEBHOOK_EVENTS,
  WEBHOOK_STATES,
  listMerchantWebhookNotifications,
} = require("./src/services/webhook-notifications");

const publicFile = (filename) =>
  path.join(__dirname, "public", filename);

// ============================================
// PAGES ABVSPAIE
// ============================================

app.get("/", (req, res) => {
  res.json({
    nom: "ABVSPAIE",
    message: "Bienvenue sur notre API de paiement",
    statut: "serveur actif",
    mode: "test",
  });
});

app.get("/inscription-connexion.html", (req, res) => {
  res.sendFile(publicFile("inscription-connexion.html"));
});

app.get("/webhooks", (req, res) => {
  res.sendFile(publicFile("webhooks.html"));
});

app.get("/api-keys", (req, res) => {
  res.sendFile(publicFile("api-keys.html"));
});

app.get("/payment-links", (req, res) => {
  res.sendFile(publicFile("payment-links.html"));
});

app.get("/reports", (req, res) => {
  res.sendFile(publicFile("reports.html"));
});

app.get("/payments", (req, res) => {
  res.redirect(302, "/transactions?type=payment");
});

app.get("/refunds", (req, res) => {
  res.sendFile(publicFile("refunds.html"));
});

app.get("/payouts", (req, res) => {
  res.sendFile(publicFile("payouts.html"));
});

app.get("/fees", (req, res) => {
  res.sendFile(publicFile("fees.html"));
});

app.get("/customers", (req, res) => {
  res.sendFile(publicFile("customers.html"));
});

app.get("/support", (req, res) => {
  res.sendFile(publicFile("support.html"));
});

app.get("/api/webhooks/endpoints", async (req, res) => {
  try {
    const auth = await authenticateMerchant(req, res);
    if (!auth) return;

    const result = await db.query(
      `SELECT id, url, events, active
       FROM public.webhook_endpoints
       WHERE merchant_id = $1
       ORDER BY id DESC
       LIMIT 50`,
      [auth.merchant.id]
    );

    return res.json({ status: "ok", endpoints: result.rows });
  } catch (error) {
    console.error("Erreur chargement des endpoints webhook :", error.message);
    return res.status(500).json({
      status: "error",
      message: "Impossible de récupérer les endpoints webhook.",
    });
  }
});

app.post("/api/webhooks/endpoints", async (req, res) => {
  try {
    const auth = await authenticateMerchant(req, res);
    if (!auth) return;

    const url = typeof req.body?.url === "string" ? req.body.url.trim() : "";
    const secret = typeof req.body?.secret === "string" ? req.body.secret.trim() : "";
    const events = Array.isArray(req.body?.events) ? [...new Set(req.body.events)] : ["payment.succeeded", "payment.failed"];
    const supportedEvents = ["payment.succeeded", "payment.failed", "*"];
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      parsedUrl = null;
    }

    if (
      !parsedUrl ||
      parsedUrl.protocol !== "http:" ||
      !["localhost", "127.0.0.1"].includes(parsedUrl.hostname) ||
      parsedUrl.port !== "4000" ||
      parsedUrl.pathname !== "/webhook" ||
      parsedUrl.search ||
      parsedUrl.hash ||
      parsedUrl.username ||
      parsedUrl.password
    ) {
      return res.status(400).json({
        status: "error",
        message: "En mode test, l'URL doit être le récepteur local http://localhost:4000/webhook.",
      });
    }

    if (!secret || secret.length < 8) {
      return res.status(400).json({ status: "error", message: "Le secret du webhook est requis." });
    }

    if (!events.length || events.some((event) => !supportedEvents.includes(event))) {
      return res.status(400).json({
        status: "error",
        message: "Les événements sélectionnés ne sont pas pris en charge.",
      });
    }

    const result = await db.query(
      `INSERT INTO public.webhook_endpoints (merchant_id, url, secret, events, active)
       VALUES ($1, $2, $3, $4, TRUE)
       RETURNING id, merchant_id, url, events, active`,
      [auth.merchant.id, url, secret, events]
    );

    return res.status(201).json({ status: "ok", webhook: result.rows[0] });
  } catch (error) {
    console.error("Erreur création du webhook :", error.message);
    return res.status(500).json({ status: "error", message: "Impossible d'enregistrer le webhook." });
  }
});

app.delete("/api/webhooks/endpoints/:id", async (req, res) => {
  try {
    const auth = await authenticateMerchant(req, res);
    if (!auth) return;

    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        req.params.id
      )
    ) {
      return res.status(400).json({
        status: "error",
        message: "Identifiant d'endpoint invalide.",
      });
    }

    const deactivated = await deactivateWebhookEndpoint(
      db,
      auth.merchant.id,
      req.params.id
    );
    if (!deactivated) {
      return res.status(404).json({
        status: "error",
        message: "Endpoint introuvable ou déjà désactivé.",
      });
    }

    return res.json({ status: "ok", deactivated: true });
  } catch (error) {
    console.error("Erreur désactivation de l'endpoint webhook :", error.message);
    return res.status(500).json({
      status: "error",
      message: "Impossible de désactiver l'endpoint webhook.",
    });
  }
});

app.post("/api/webhooks/test-delivery", async (req, res) => {
  try {
    const auth = await authenticateMerchant(req, res);
    if (!auth) return;

    const count = await deliverPendingWebhooks({
      merchantId: auth.merchant.id,
    });
    return res.json({ status: "ok", delivered: count, merchant_id: auth.merchant.id });
  } catch (error) {
    console.error("Erreur test livraison webhook :", error.message);
    return res.status(500).json({ status: "error", message: "Impossible de lancer les webhooks." });
  }
});

app.post("/api/webhooks/notifications/:id/retry", async (req, res) => {
  try {
    const auth = await authenticateMerchant(req, res);
    if (!auth) return;

    const deliveryId = req.params.id;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(deliveryId)) {
      return res.status(400).json({
        status: "error",
        message: "L'identifiant de notification est invalide.",
      });
    }

    const attempted = await deliverPendingWebhooks({
      merchantId: auth.merchant.id,
      retryDeliveryId: deliveryId,
    });
    if (attempted === 0) {
      return res.status(404).json({
        status: "error",
        message: "Cette notification n'est pas en échec ou son endpoint est inactif.",
      });
    }

    return res.json({
      status: "ok",
      attempted,
      message: "Nouvelle tentative effectuée. Vérifie le statut de la notification.",
    });
  } catch (error) {
    console.error("Erreur relance webhook :", error.message);
    return res.status(500).json({
      status: "error",
      message: "Impossible de relancer cette notification webhook.",
    });
  }
});

app.get("/api/webhooks/notifications", async (req, res) => {
  try {
    const auth = await authenticateMerchant(req, res);
    if (!auth) return;

    const pageValue = req.query.page === undefined ? "1" : req.query.page;
    const page = Number(pageValue);
    const event = typeof req.query.event === "string" ? req.query.event : "";
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const search = typeof req.query.search === "string" ? req.query.search.trim() : "";

    if (
      typeof pageValue !== "string" ||
      !/^\d+$/.test(pageValue) ||
      !Number.isSafeInteger(page) ||
      page < 1
    ) {
      return res.status(400).json({
        status: "error",
        message: "Le numéro de page doit être un entier positif.",
      });
    }
    if (event && !WEBHOOK_EVENTS.has(event)) {
      return res.status(400).json({
        status: "error",
        message: "L'événement sélectionné n'est pas pris en charge.",
      });
    }
    if (state && !WEBHOOK_STATES.has(state)) {
      return res.status(400).json({
        status: "error",
        message: "Le statut sélectionné n'est pas pris en charge.",
      });
    }
    if (search.length > 100) {
      return res.status(400).json({
        status: "error",
        message: "La recherche ne doit pas dépasser 100 caractères.",
      });
    }

    const result = await listMerchantWebhookNotifications(
      db,
      auth.merchant.id,
      { page, event, state, search }
    );

    return res.json({
      status: "ok",
      notifications: result.notifications,
      total: result.total,
      page: result.page,
      page_size: result.pageSize,
      page_count: result.pageCount,
    });
  } catch (error) {
    console.error("Erreur chargement des notifications :", error.message);
    return res.status(500).json({
      status: "error",
      message: "Impossible de récupérer les notifications.",
    });
  }
});

app.get("/abvs-config.js", (req, res) => {
  res.sendFile(publicFile("abvs-config.js"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(publicFile("dashboard.html"));
});

app.get("/transactions", (req, res) => {
  res.sendFile(publicFile("transactions.html"));
});

app.get("/transactions.html", (req, res) => {
  res.sendFile(publicFile("transactions.html"));
});

app.get("/create-payment", (req, res) => {
  res.sendFile(publicFile("create-payment.html"));
});

// Nouvelle page : intégrations de paiement
app.get("/integrations", (req, res) => {
  res.sendFile(publicFile("integrations.html"));
});

app.get("/pay/:token", (req, res) => {
  res.sendFile(publicFile("payment.html"));
});

// ============================================
// ROUTES API EXISTANTES
// ============================================

app.use("/api", require("./src/routes/health"));
app.use("/api", require("./src/routes/transactions"));
app.use("/api", require("./src/routes/api").createApiRouter());
app.use("/api", require("./src/routes/finance-tools").createFinanceToolsRouter());
app.use("/api", require("./src/routes/merchant-tools").createMerchantToolsRouter());

// ============================================
// CRÉER UN LIEN DE PAIEMENT DE TEST
// ============================================

app.post("/api/payment-links", async (req, res) => {
  let client;
  let transactionStarted = false;
  try {
    const auth = await authenticateMerchant(req, res);
    if (!auth) return;

    const { merchant } = auth;
    const idempotencyKey = typeof req.body?.idempotency_key === "string" ? req.body.idempotency_key.trim() : null;
    const title =
      typeof req.body?.title === "string"
        ? req.body.title.trim()
        : "";

    const description =
      typeof req.body?.description === "string"
        ? req.body.description.trim()
        : "";

    const amount = req.body?.amount;
    const expiryHours = req.body?.expires_in_hours ?? null;

    if (title.length < 2 || title.length > 100) {
      return res.status(400).json({
        status: "error",
        message: "Le titre doit contenir entre 2 et 100 caractères.",
      });
    }

    if (description.length > 500) {
      return res.status(400).json({
        status: "error",
        message: "La description ne doit pas dépasser 500 caractères.",
      });
    }

    if (!Number.isSafeInteger(amount) || amount < 100) {
      return res.status(400).json({
        status: "error",
        message:
          "Le montant doit être un nombre entier d'au moins 100 FCFA.",
      });
    }

    if (!isSupportedPaymentLinkExpiry(expiryHours)) {
      return res.status(400).json({
        status: "error",
        message: "La durée doit être de 24 heures, 7 jours, 30 jours ou sans expiration.",
      });
    }

    if (idempotencyKey && (idempotencyKey.length < 8 || idempotencyKey.length > 255)) {
      return res.status(400).json({
        status: "error",
        message: "La clé d'idempotence doit contenir entre 8 et 255 caractères.",
      });
    }

    const merchantId = merchant.id;
    const token = crypto.randomBytes(24).toString("hex");
    client = await db.connect();
    await client.query("BEGIN");
    transactionStarted = true;

    const duplicateCheck = await handleIdempotencyRequest({
      merchantId,
      idempotencyKey,
      requestBody: { title, description, amount, expires_in_hours: expiryHours },
      responseBody: null,
      transactionId: null,
      database: client,
    });

    if (duplicateCheck && duplicateCheck.duplicate) {
      await client.query("COMMIT");
      transactionStarted = false;
      return res.status(200).json({
        ...duplicateCheck.responseBody,
        duplicate: true,
      });
    }

    const result = await client.query(
      "INSERT INTO public.payment_links " +
        "(merchant_id, token, title, description, amount, currency, mode, expires_at) " +
        "VALUES ($1, $2, $3, $4, $5, 'XOF', 'test', " +
        "CASE WHEN $6::integer IS NULL THEN NULL " +
        "ELSE NOW() + ($6::integer * INTERVAL '1 hour') END) " +
        "RETURNING id, token, title, description, amount, currency, mode, status, created_at, expires_at",
      [merchantId, token, title, description || null, amount, expiryHours]
    );

    const link = result.rows[0];
    const response = {
      status: "ok",
      message: "Lien de paiement de test créé.",
      payment_link: {
        ...link,
        url: `${req.protocol}://${req.get("host")}/pay/${link.token}`,
      },
      note: "Ce lien ne déclenche aucun paiement réel.",
    };

    if (idempotencyKey) {
      await client.query(
        `UPDATE public.idempotency_keys
         SET response_body = $3::jsonb
         WHERE merchant_id = $1 AND key = $2`,
        [merchantId, idempotencyKey, JSON.stringify(response)]
      );
    }

    await client.query("COMMIT");
    transactionStarted = false;
    return res.status(201).json(response);
  } catch (error) {
    if (transactionStarted) {
      await client.query("ROLLBACK").catch((rollbackError) => {
        console.error("Annulation de transaction impossible :", rollbackError.message);
      });
      transactionStarted = false;
    }

    if (error && error.statusCode === 409) {
      return res.status(409).json({
        status: "error",
        message: error.message,
      });
    }

    console.error("Erreur création du lien :", error.message);

    return res.status(500).json({
      status: "error",
      message: "Impossible de créer le lien de paiement.",
    });
  } finally {
    if (client) client.release();
  }
});

app.get("/api/payment-links", async (req, res) => {
  try {
    const auth = await authenticateMerchant(req, res);
    if (!auth) return;

    const pageValue = req.query.page === undefined ? "1" : req.query.page;
    const page = Number(pageValue);
    const search = typeof req.query.search === "string" ? req.query.search.trim() : "";
    const status = typeof req.query.status === "string" ? req.query.status : "";

    if (
      typeof pageValue !== "string" ||
      !/^\d+$/.test(pageValue) ||
      !Number.isSafeInteger(page) ||
      page < 1
    ) {
      return res.status(400).json({
        status: "error",
        message: "Le numéro de page doit être un entier positif.",
      });
    }
    if (search.length > 100) {
      return res.status(400).json({
        status: "error",
        message: "La recherche ne doit pas dépasser 100 caractères.",
      });
    }
    if (status && !["active", "paid", "expired", "cancelled"].includes(status)) {
      return res.status(400).json({
        status: "error",
        message: "Le statut sélectionné n'est pas pris en charge.",
      });
    }

    const result = await listMerchantPaymentLinks(db, auth.merchant.id, {
      page,
      search,
      status,
    });
    return res.json({
      status: "ok",
      payment_links: result.paymentLinks,
      total: result.total,
      page: result.page,
      page_size: result.pageSize,
      page_count: result.pageCount,
    });
  } catch (error) {
    console.error("Erreur chargement des liens de paiement :", error.message);
    return res.status(500).json({
      status: "error",
      message: "Impossible de récupérer les liens de paiement.",
    });
  }
});

app.post("/api/payment-links/:id/cancel", async (req, res) => {
  try {
    const auth = await authenticateMerchant(req, res);
    if (!auth) return;

    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        req.params.id
      )
    ) {
      return res.status(400).json({
        status: "error",
        message: "Identifiant de lien invalide.",
      });
    }

    const status = await cancelMerchantPaymentLink(
      db,
      auth.merchant.id,
      req.params.id
    );
    if (!status) {
      return res.status(404).json({
        status: "error",
        message: "Lien introuvable ou déjà traité.",
      });
    }
    if (status === "expired") {
      return res.status(409).json({
        status: "error",
        message: "Ce lien a expiré et ne peut plus être annulé.",
      });
    }

    return res.json({ status: "ok", payment_link_status: status });
  } catch (error) {
    console.error("Erreur annulation du lien de paiement :", error.message);
    return res.status(500).json({
      status: "error",
      message: "Impossible d'annuler le lien de paiement.",
    });
  }
});

// ============================================
// CONSULTER UN LIEN DE PAIEMENT
// ============================================

app.get("/api/payment-links/:token", async (req, res) => {
  try {
    const token = req.params.token;

    if (!/^[a-f0-9]{48}$/.test(token)) {
      return res.status(400).json({
        status: "error",
        message: "Le lien de paiement est invalide.",
      });
    }

    const result = await db.query(
      "SELECT pl.id, pl.title, pl.description, pl.amount, pl.currency, " +
        "pl.mode, pl.status, pl.created_at, pl.expires_at, " +
        "m.name AS merchant_name " +
        "FROM public.payment_links pl " +
        "JOIN public.merchants m ON m.id = pl.merchant_id " +
        "WHERE pl.token = $1 LIMIT 1",
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: "error",
        message: "Lien de paiement introuvable.",
      });
    }

    const link = result.rows[0];

    if (isPaymentLinkExpired(link)) {
      await expirePaymentLinkIfDue(db, link.id);
      return res.json({
        status: "ok",
        payment_link: {
          ...link,
          status: "expired",
        },
      });
    }

    return res.json({
      status: "ok",
      payment_link: link,
      note: "Consulter ce lien ne déclenche aucun paiement.",
    });
  } catch (error) {
    console.error("Erreur consultation du lien :", error.message);

    return res.status(500).json({
      status: "error",
      message: "Impossible de consulter ce lien.",
    });
  }
});

app.post("/api/payment-links/:token/test-payment", async (req, res) => {
  const token = req.params.token;

  if (!/^[a-f0-9]{48}$/.test(token)) {
    return res.status(400).json({
      status: "error",
      message: "Le lien de paiement est invalide.",
    });
  }

  let client;
  let transaction;
  let merchantId;

  try {
    client = await db.connect();
    await client.query("BEGIN");

    const linkResult = await client.query(
      `SELECT id, merchant_id, amount, currency, mode, status, expires_at
       FROM public.payment_links
       WHERE token = $1
       FOR UPDATE`,
      [token]
    );

    if (!linkResult.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        status: "error",
        message: "Lien de paiement introuvable.",
      });
    }

    const link = linkResult.rows[0];
    merchantId = link.merchant_id;

    if (link.mode !== "test") {
      await client.query("ROLLBACK");
      return res.status(400).json({
        status: "error",
        message: "Seuls les liens de test peuvent être simulés.",
      });
    }

    if (isPaymentLinkExpired(link)) {
      await expirePaymentLinkIfDue(client, link.id);
      await client.query("COMMIT");
      return res.status(409).json({
        status: "error",
        message: "Ce lien est expiré, annulé ou déjà utilisé.",
      });
    }

    if (link.status !== "active") {
      const previous = await client.query(
        `SELECT id, reference, amount, currency, mode, type, status, provider, created_at
         FROM public.transactions
         WHERE provider = 'abvs_test' AND provider_ref = $1
         LIMIT 1`,
        [`payment-link:${token}`]
      );
      await client.query("COMMIT");

      if (previous.rows.length) {
        return res.json({
          status: "ok",
          duplicate: true,
          message: "Ce paiement de test a déjà été traité.",
          transaction: previous.rows[0],
          simulation_only: true,
        });
      }

      return res.status(409).json({
        status: "error",
        message: "Ce lien est expiré, annulé ou déjà utilisé.",
      });
    }

    const reference = "ABVSTEST-" + crypto.randomBytes(12).toString("hex").toUpperCase();
    const result = await client.query(
      `INSERT INTO public.transactions
         (merchant_id, mode, type, status, amount, fee, currency, method, provider, provider_ref, reference)
       VALUES ($1, 'test', 'payment', 'succeeded', $2, ROUND($2::bigint * 0.01)::bigint, $3, 'test', 'abvs_test', $4, $5)
       RETURNING id, reference, amount, currency, mode, type, status, provider, created_at`,
      [
        link.merchant_id,
        link.amount,
        link.currency,
        `payment-link:${token}`,
        reference,
      ]
    );

    transaction = result.rows[0];
    await client.query(
      "UPDATE public.payment_links SET status = 'paid' WHERE id = $1",
      [link.id]
    );
    await enqueueWebhookDeliveries({
      merchantId,
      eventType: "payment.succeeded",
      payload: {
        id: transaction.id,
        reference: transaction.reference,
        amount: transaction.amount,
        currency: transaction.currency,
        status: transaction.status,
        mode: "test",
        type: "payment",
        provider: "abvs_test",
        created_at: transaction.created_at,
      },
      database: client,
    });
    await client.query("COMMIT");

    return res.status(201).json({
      status: "ok",
      message: "Paiement simulé avec succès. Aucun argent réel n'a été transféré.",
      transaction,
      simulation_only: true,
    });
  } catch (error) {
    if (client) {
      await client.query("ROLLBACK").catch((rollbackError) => {
        console.error("Annulation de transaction impossible :", rollbackError.message);
      });
    }

    if (error.code === "23505") {
      const existing = await db.query(
        `SELECT id, reference, amount, currency, mode, type, status, provider, created_at
         FROM public.transactions
         WHERE provider = 'abvs_test' AND provider_ref = $1
         LIMIT 1`,
        [`payment-link:${token}`]
      );

      if (existing.rows.length) {
        return res.json({
          status: "ok",
          duplicate: true,
          message: "Ce paiement de test a déjà été traité.",
          transaction: existing.rows[0],
          simulation_only: true,
        });
      }
    }

    console.error("Erreur paiement de test par lien :", error.message);
    return res.status(500).json({
      status: "error",
      message: "Impossible de traiter le paiement de test.",
    });
  } finally {
    if (client) client.release();
  }
});

// ============================================
// CRÉER UNE DEMANDE DE PAIEMENT FICTIVE
// ============================================

app.post("/api/test-payments", async (req, res) => {
  let client;
  let transactionStarted = false;
  try {
    const auth = await authenticateMerchant(req, res);
    if (!auth) return;

    const { merchant } = auth;
    const idempotencyKey = typeof req.body?.idempotency_key === "string" ? req.body.idempotency_key.trim() : null;
    const amount = req.body?.amount;

    if (!Number.isSafeInteger(amount) || amount < 100) {
      return res.status(400).json({
        status: "error",
        message:
          "Le montant doit être un nombre entier d'au moins 100 FCFA.",
      });
    }

    if (idempotencyKey && (idempotencyKey.length < 8 || idempotencyKey.length > 255)) {
      return res.status(400).json({
        status: "error",
        message: "La clé d'idempotence doit contenir entre 8 et 255 caractères.",
      });
    }

    const merchantId = merchant.id;
    const reference = "ABVSTEST-" + crypto.randomBytes(12).toString("hex").toUpperCase();
    client = await db.connect();
    await client.query("BEGIN");
    transactionStarted = true;

    const duplicateCheck = await handleIdempotencyRequest({
      merchantId,
      idempotencyKey,
      requestBody: { amount },
      responseBody: null,
      transactionId: null,
      database: client,
    });

    if (duplicateCheck && duplicateCheck.duplicate) {
      await client.query("COMMIT");
      transactionStarted = false;
      return res.status(200).json({
        ...duplicateCheck.responseBody,
        duplicate: true,
      });
    }

    const result = await client.query(
      "INSERT INTO public.transactions " +
        "(merchant_id, mode, type, status, amount, fee, currency, method, provider, reference) " +
        "VALUES ($1, 'test', 'payment', 'created', $2, 0, 'XOF', 'mobile_money', 'abvs_test', $3) " +
        "RETURNING id, reference, amount, currency, mode, type, status, provider, created_at",
      [merchantId, amount, reference]
    );

    const response = {
      status: "ok",
      message: "Demande de paiement test enregistrée.",
      transaction: result.rows[0],
      note: "Aucun argent réel n'a été transféré.",
    };

    if (idempotencyKey) {
      await client.query(
        `UPDATE public.idempotency_keys
         SET response_body = $3::jsonb,
             transaction_id = $4
         WHERE merchant_id = $1 AND key = $2`,
        [merchantId, idempotencyKey, JSON.stringify(response), result.rows[0].id]
      );
    }

    await client.query("COMMIT");
    transactionStarted = false;
    return res.status(201).json(response);
  } catch (error) {
    if (transactionStarted) {
      await client.query("ROLLBACK").catch((rollbackError) => {
        console.error("Annulation de transaction impossible :", rollbackError.message);
      });
      transactionStarted = false;
    }

    if (error && error.statusCode === 409) {
      return res.status(409).json({
        status: "error",
        message: error.message,
      });
    }

    console.error("Erreur paiement test :", error.message);

    return res.status(500).json({
      status: "error",
      message: "Impossible de créer la demande de paiement test.",
    });
  } finally {
    if (client) client.release();
  }
});

// ============================================
// ERREURS
// ============================================

app.use((req, res) => {
  res.status(404).json({
    status: "error",
    message: "Route introuvable.",
  });
});

setInterval(() => {
  deliverPendingWebhooks().catch((error) => {
    console.error("Échec cycle webhook :", error.message);
  });
}, 15000);

app.listen(PORT, () => {
  console.log(`ABVSPAIE est actif sur http://localhost:${PORT}`);
});

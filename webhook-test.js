const http = require("http");
const crypto = require("crypto");
const db = require("./src/config/database");

const PORT = 4000;
const MAX_BODY_BYTES = 100_000;

function sendJson(res, status, payload) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

const server = http.createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/webhook") {
    return sendJson(res, 404, { error: "Route introuvable" });
  }

  const chunks = [];
  let size = 0;

  req.on("data", (chunk) => {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      sendJson(res, 413, { error: "Notification trop volumineuse" });
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });

  req.on("end", async () => {
    const rawBody = Buffer.concat(chunks);
    const endpointId = req.headers["x-abvs-endpoint-id"];
    const suppliedSignature = req.headers["x-abvs-signature"];

    if (
      typeof endpointId !== "string" ||
      typeof suppliedSignature !== "string" ||
      !/^[a-f0-9-]{36}$/i.test(endpointId) ||
      !/^[a-f0-9]{64}$/i.test(suppliedSignature)
    ) {
      return sendJson(res, 401, { error: "Signature ou endpoint manquant" });
    }

    try {
      const endpointResult = await db.query(
        `SELECT secret
         FROM public.webhook_endpoints
         WHERE id = $1
           AND active = TRUE
           AND url IN (
             'http://localhost:4000/webhook',
             'http://127.0.0.1:4000/webhook'
           )
         LIMIT 1`,
        [endpointId]
      );

      if (!endpointResult.rows.length) {
        return sendJson(res, 401, { error: "Endpoint de test non autorisé" });
      }

      const expectedSignature = crypto
        .createHmac("sha256", endpointResult.rows[0].secret)
        .update(rawBody)
        .digest();
      const actualSignature = Buffer.from(suppliedSignature, "hex");

      if (
        actualSignature.length !== expectedSignature.length ||
        !crypto.timingSafeEqual(actualSignature, expectedSignature)
      ) {
        return sendJson(res, 401, { error: "Signature invalide" });
      }

      let event;
      try {
        event = JSON.parse(rawBody.toString("utf8"));
      } catch {
        return sendJson(res, 400, { error: "JSON invalide" });
      }

      console.log(
        `Webhook reçu et signature vérifiée : ${event.event || "événement inconnu"}`
      );
      return sendJson(res, 200, { received: true, signature_valid: true });
    } catch (error) {
      console.error("Erreur de validation du webhook :", error.message);
      return sendJson(res, 500, { error: "Validation du webhook impossible" });
    }
  });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Récepteur webhook de test actif sur http://127.0.0.1:${PORT}/webhook`);
});

server.on("close", () => {
  db.end().catch((error) => {
    console.error("Fermeture PostgreSQL impossible :", error.message);
  });
});

process.on("SIGINT", () => server.close());
process.on("SIGTERM", () => server.close());

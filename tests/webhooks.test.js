"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { encryptSecret, decryptSecret, verifySignature, readRawBody, authUser } = require("../server/webhooks");
const receiveWebhook = require("../api/webhooks/receive");

test("encrypts and decrypts a webhook secret", () => {
  process.env.WEBHOOK_ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");
  const secret = crypto.randomBytes(32).toString("base64url");
  const encrypted = encryptSecret(secret);
  assert.equal(decryptSecret(encrypted), secret);
  assert.notEqual(encrypted.ciphertext, secret);
});

test("rejects a tampered encrypted secret", () => {
  process.env.WEBHOOK_ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");
  const encrypted = encryptSecret("test-secret");
  encrypted.tag = Buffer.alloc(16).toString("base64");
  assert.throws(() => decryptSecret(encrypted));
});

test("verifies only the exact timestamp and request body signature", () => {
  const secret = "test-secret";
  const timestamp = "1791720000";
  const body = Buffer.from('{"event":"test.webhook"}');
  const digest = crypto.createHmac("sha256", secret).update(timestamp).update(".").update(body).digest("hex");
  assert.equal(verifySignature(secret, timestamp, body, `sha256=${digest}`), true);
  assert.equal(verifySignature(secret, timestamp, Buffer.from("{}"), `sha256=${digest}`), false);
  assert.equal(verifySignature(secret, timestamp, body, "invalid"), false);
});

test("rejects request bodies above the configured limit", async () => {
  const request = (async function* () {
    yield Buffer.from("1234");
  })();
  await assert.rejects(readRawBody(request, 3), { status: 413 });
});

test("authenticates existing sessions without email-MFA token claims", async t => {
  const env = { ...process.env };
  const originalFetch = global.fetch;
  const userId = crypto.randomUUID();
  process.env.SUPABASE_URL = "https://supabase.example";
  process.env.SUPABASE_ANON_KEY = "test-anon";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service";
  process.env.EMAIL_MFA_TOKEN_HOOK_CONFIGURED = "true";
  global.fetch = async () => Response.json({ id: userId });
  t.after(() => {
    process.env = env;
    global.fetch = originalFetch;
  });

  const accessToken = `header.${Buffer.from(JSON.stringify({ sub: userId })).toString("base64url")}.signature`;
  const user = await authUser({ headers: { authorization: `Bearer ${accessToken}` } });
  assert.equal(user.id, userId);
});

test("accepts and stores a correctly signed JSON webhook", async t => {
  const env = { ...process.env };
  const originalFetch = global.fetch;
  const secret = crypto.randomBytes(32).toString("base64url");
  const encrypted = encryptSecretForTest(secret);
  const endpointId = crypto.randomUUID();
  const merchantId = crypto.randomUUID();
  const inserted = [];
  process.env.SUPABASE_URL = "https://supabase.example";
  process.env.SUPABASE_ANON_KEY = "test-anon";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service";

  t.after(() => {
    process.env = env;
    global.fetch = originalFetch;
  });

  global.fetch = async (url, options) => {
    const target = String(url);
    if (target.includes("/webhook_endpoints?")) {
      return Response.json([{ id: endpointId, merchant_id: merchantId }]);
    }
    if (target.includes("/webhook_endpoint_secrets?")) {
      return Response.json([{
        secret_ciphertext: encrypted.ciphertext,
        secret_iv: encrypted.iv,
        secret_tag: encrypted.tag
      }]);
    }
    if (target.includes("/webhook_events?") && options.method === "POST") {
      inserted.push(JSON.parse(options.body));
      return Response.json([inserted.at(-1)], { status: 201 });
    }
    throw new Error(`Unexpected Supabase request: ${target}`);
  };

  const body = JSON.stringify({ event: "test.webhook", data: { amount: 12500 } });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const digest = crypto.createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
  const req = {
    method: "POST",
    query: { endpoint: endpointId },
    headers: {
      "content-type": "application/json",
      "x-abvs-timestamp": timestamp,
      "x-abvs-signature": `sha256=${digest}`,
      "x-abvs-delivery": "test-delivery-1"
    },
    async *[Symbol.asyncIterator]() { yield Buffer.from(body); }
  };
  const res = createResponse();

  await receiveWebhook(req, res);

  assert.equal(res.statusCode, 202);
  assert.equal(JSON.parse(res.body).received, true);
  assert.equal(inserted.length, 1);
  assert.equal(inserted[0].merchant_id, merchantId);
  assert.deepEqual(inserted[0].payload, { event: "test.webhook", data: { amount: 12500 } });
});

test("does not store webhook data with an invalid signature", async t => {
  const env = { ...process.env };
  const originalFetch = global.fetch;
  const secret = crypto.randomBytes(32).toString("base64url");
  const encrypted = encryptSecretForTest(secret);
  let stored = false;
  process.env.SUPABASE_URL = "https://supabase.example";
  process.env.SUPABASE_ANON_KEY = "test-anon";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service";
  t.after(() => {
    process.env = env;
    global.fetch = originalFetch;
  });
  global.fetch = async url => {
    if (String(url).includes("/webhook_endpoints?")) return Response.json([{ id: "endpoint", merchant_id: "merchant" }]);
    if (String(url).includes("/webhook_endpoint_secrets?")) return Response.json([{
      secret_ciphertext: encrypted.ciphertext,
      secret_iv: encrypted.iv,
      secret_tag: encrypted.tag
    }]);
    stored = true;
    return Response.json([]);
  };
  const timestamp = String(Math.floor(Date.now() / 1000));
  const req = {
    method: "POST",
    query: { endpoint: crypto.randomUUID() },
    headers: { "content-type": "application/json", "x-abvs-timestamp": timestamp, "x-abvs-signature": "sha256=" + "0".repeat(64) },
    async *[Symbol.asyncIterator]() { yield Buffer.from('{"event":"not-authorized"}'); }
  };
  const res = createResponse();
  await receiveWebhook(req, res);
  assert.equal(res.statusCode, 401);
  assert.equal(stored, false);
});

function encryptSecretForTest(secret) {
  const key = crypto.randomBytes(32);
  process.env.WEBHOOK_ENCRYPTION_KEY = key.toString("base64");
  return encryptSecret(secret);
}

function createResponse() {
  return {
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    end(body) { this.body = body; }
  };
}

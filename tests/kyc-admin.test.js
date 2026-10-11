"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const handler = require("../api/kyc/admin");

function createResponse() {
  return {
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    end(body) { this.body = body; }
  };
}

function makeToken(userId, aal = "aal2") {
  return `header.${Buffer.from(JSON.stringify({ sub: userId, aal })).toString("base64url")}.signature`;
}

async function withMockAuth(t, user, fetchMock, token = makeToken(user.id)) {
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };
  process.env.SUPABASE_URL = "https://supabase.example";
  process.env.SUPABASE_ANON_KEY = "test-anon";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service";
  global.fetch = async (url, options) => {
    if (String(url).endsWith("/auth/v1/user")) return Response.json(user);
    return fetchMock(url, options);
  };
  t.after(() => {
    global.fetch = originalFetch;
    process.env = originalEnv;
  });
  return token;
}

test("blocks a non-admin before querying privileged KYC data", async t => {
  const userId = crypto.randomUUID();
  const token = await withMockAuth(t, { id: userId, app_metadata: {} }, async () => {
    throw new Error("Privileged API must not be called");
  });
  const res = createResponse();
  await handler({ method: "GET", headers: { authorization: `Bearer ${token}` }, query: {} }, res);
  assert.equal(res.statusCode, 403);
  assert.match(JSON.parse(res.body).error, /administrateur/i);
});

test("requires MFA for KYC administrators", async t => {
  const userId = crypto.randomUUID();
  const token = await withMockAuth(
    t,
    { id: userId, app_metadata: { kyc_admin: true } },
    async () => { throw new Error("Privileged API must not be called"); },
    makeToken(userId, "aal1")
  );
  const res = createResponse();
  await handler({ method: "GET", headers: { authorization: `Bearer ${token}` }, query: {} }, res);
  assert.equal(res.statusCode, 403);
  assert.match(JSON.parse(res.body).error, /MFA/i);
});

test("rejects an administrator's attempt to review their own KYC dossier", async t => {
  const userId = crypto.randomUUID();
  const token = await withMockAuth(t, { id: userId, app_metadata: { kyc_admin: true } }, async () => {
    throw new Error("Decision RPC must not be called");
  });
  const res = createResponse();
  await handler({
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
    body: { merchant_id: userId, decision: "verified" }
  }, res);
  assert.equal(res.statusCode, 403);
});

test("records a rejection through the privileged transactional RPC", async t => {
  const adminId = crypto.randomUUID();
  const merchantId = crypto.randomUUID();
  const calls = [];
  const token = await withMockAuth(t, { id: adminId, app_metadata: { kyc_admin: true } }, async (url, options) => {
    calls.push({ url: String(url), options });
    return new Response(null, { status: 204 });
  });
  const res = createResponse();
  await handler({
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
    body: { merchant_id: merchantId, decision: "rejected", reason: "Le document est illisible." }
  }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /\/rest\/v1\/rpc\/decide_kyc$/);
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    p_merchant_id: merchantId,
    p_decision: "rejected",
    p_reason: "Le document est illisible.",
    p_admin_id: adminId
  });
});

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const handler = require("../api/auth/email-mfa");
const { authUser } = require("../server/webhooks");

function response() {
  return {
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    end(body) { this.body = body; }
  };
}

function token(userId, sessionId, extra = {}) {
  const claims = {
    sub: userId,
    session_id: sessionId,
    email_mfa_required: false,
    email_mfa_verified: true,
    ...extra
  };
  return `header.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.signature`;
}

function req(userId, sessionId, action, code, claims) {
  return {
    method: "POST",
    headers: { authorization: `Bearer ${token(userId, sessionId, claims)}` },
    body: code ? { action, code } : { action }
  };
}

function withServices(t, mockFetch) {
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };
  Object.assign(process.env, {
    SUPABASE_URL: "https://supabase.example",
    SUPABASE_ANON_KEY: "test-anon",
    SUPABASE_SERVICE_ROLE_KEY: "test-service",
    EMAIL_MFA_TOKEN_HOOK_CONFIGURED: "true",
    EMAIL_MFA_SECRET: "test-secret-that-is-long-enough-to-be-safe",
    BREVO_API_KEY: "test-brevo-key",
    BREVO_SENDER_EMAIL: "security@example.test"
  });
  global.fetch = async (url, options) => {
    if (String(url).endsWith("/auth/v1/user")) {
      return Response.json({ id: mockFetch.userId, email: "merchant@example.test", email_confirmed_at: "2026-01-01T00:00:00Z" });
    }
    return mockFetch(url, options);
  };
  t.after(() => {
    global.fetch = originalFetch;
    process.env = originalEnv;
  });
}

test("reports account email-MFA state from the signed access-token claims", async t => {
  const userId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  withServices(t, Object.assign(async () => { throw new Error("No RPC or mail request expected"); }, { userId }));
  const res = response();
  await handler(req(userId, sessionId, "status", null, {
    email_mfa_required: true,
    email_mfa_verified: true
  }), res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), { enabled: true, verified: true, available: true });
});

test("sends a hashed login challenge through Brevo", async t => {
  const userId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const calls = [];
  withServices(t, Object.assign(async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith("/rpc/start_email_mfa_challenge")) return Response.json(null);
    if (String(url) === "https://api.brevo.com/v3/smtp/email") return Response.json({ messageId: "test-message" });
    throw new Error(`Unexpected request: ${url}`);
  }, { userId }));

  const res = response();
  await handler(req(userId, sessionId, "start_login", null, {
    email_mfa_required: true,
    email_mfa_verified: false
  }), res);

  assert.equal(res.statusCode, 200);
  assert.match(JSON.parse(res.body).message, /Code envoyé/);
  assert.equal(calls.length, 2);
  const rpcBody = JSON.parse(calls[0].options.body);
  const mailBody = JSON.parse(calls[1].options.body);
  assert.equal(rpcBody.p_user_id, userId);
  assert.equal(rpcBody.p_session_id, sessionId);
  assert.equal(rpcBody.p_action, "login");
  assert.match(rpcBody.p_code_hash, /^[0-9a-f]{64}$/);
  assert.equal(mailBody.to[0].email, "merchant@example.test");
  assert.match(mailBody.textContent, /\b\d{6}\b/);
  assert.doesNotMatch(res.body, /\d{6}/);
});

test("accepts a valid email challenge and returns success only after the database confirms it", async t => {
  const userId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const code = "483921";
  const codeHash = crypto.createHmac("sha256", "test-secret-that-is-long-enough-to-be-safe")
    .update(`${userId}.${sessionId}.login.${code}`).digest("hex");
  let rpcBody;
  withServices(t, Object.assign(async (url, options) => {
    if (String(url).endsWith("/rpc/verify_email_mfa_challenge")) {
      rpcBody = JSON.parse(options.body);
      return Response.json(true);
    }
    throw new Error(`Unexpected request: ${url}`);
  }, { userId }));
  const res = response();
  await handler(req(userId, sessionId, "verify_login", code, {
    email_mfa_required: true,
    email_mfa_verified: false
  }), res);
  assert.equal(res.statusCode, 200);
  assert.equal(JSON.parse(res.body).ok, true);
  assert.equal(rpcBody.p_code_hash, codeHash);
});

test("refuses to start email login verification until the access-token hook is configured", async t => {
  const userId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };
  process.env.SUPABASE_URL = "https://supabase.example";
  process.env.SUPABASE_ANON_KEY = "test-anon";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service";
  delete process.env.EMAIL_MFA_TOKEN_HOOK_CONFIGURED;
  global.fetch = async url => String(url).endsWith("/auth/v1/user")
    ? Response.json({ id: userId, email: "merchant@example.test", email_confirmed_at: "2026-01-01T00:00:00Z" })
    : new Response(null, { status: 500 });
  t.after(() => {
    global.fetch = originalFetch;
    process.env = originalEnv;
  });
  const res = response();
  await handler(req(userId, sessionId, "start_enroll"), res);
  assert.equal(res.statusCode, 503);
  assert.match(JSON.parse(res.body).error, /pas encore activée/);
});

test("server API authentication blocks JWTs whose enrolled email factor is unverified", async t => {
  const userId = crypto.randomUUID();
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };
  process.env.SUPABASE_URL = "https://supabase.example";
  process.env.SUPABASE_ANON_KEY = "test-anon";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service";
  process.env.EMAIL_MFA_TOKEN_HOOK_CONFIGURED = "true";
  global.fetch = async () => Response.json({ id: userId });
  t.after(() => {
    global.fetch = originalFetch;
    process.env = originalEnv;
  });

  assert.equal(await authUser({ headers: { authorization: `Bearer ${token(userId, crypto.randomUUID(), {
    email_mfa_required: true,
    email_mfa_verified: false
  })}` } }), null);
  const accepted = await authUser({ headers: { authorization: `Bearer ${token(userId, crypto.randomUUID(), {
    email_mfa_required: true,
    email_mfa_verified: true
  })}` } });
  assert.equal(accepted.id, userId);
});

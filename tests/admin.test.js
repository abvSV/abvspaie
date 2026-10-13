"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const handler = require("../api/admin");

function createResponse() {
  return {
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    end(body) { this.body = body; }
  };
}

function token(userId, aal = "aal2") {
  return `header.${Buffer.from(JSON.stringify({ sub: userId, aal })).toString("base64url")}.signature`;
}

async function withAdmin(t, fetchMock, options = {}) {
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };
  const adminId = crypto.randomUUID();
  process.env.SUPABASE_URL = "https://supabase.example";
  process.env.SUPABASE_ANON_KEY = "test-anon";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service";
  if (!options.noOwnerId) process.env.PLATFORM_ADMIN_USER_ID = options.ownerId || adminId;
  else delete process.env.PLATFORM_ADMIN_USER_ID;
  global.fetch = async (url, init) => {
    if (String(url).endsWith("/auth/v1/user")) {
      return Response.json({
        id: adminId,
        app_metadata: options.roles || { platform_admin: true }
      });
    }
    return fetchMock(url, init);
  };
  t.after(() => {
    global.fetch = originalFetch;
    process.env = originalEnv;
  });
  return { adminId, authorization: `Bearer ${token(adminId, options.aal || "aal2")}` };
}

test("denies requests without the server-authorized platform-admin role", async t => {
  const { adminId, authorization } = await withAdmin(t, async () => {
    throw new Error("Privileged API must not be called");
  }, { roles: { kyc_admin: true } });
  const res = createResponse();
  await handler({ method: "GET", headers: { authorization }, query: { resource: "users" } }, res);
  assert.equal(res.statusCode, 403);
  assert.match(JSON.parse(res.body).error, /compte administrateur unique/i);
  assert.ok(adminId);
});

test("allows the single authorized administrator without MFA", async t => {
  const { authorization } = await withAdmin(t, async () => {
    return Response.json({ users: [] });
  }, { aal: "aal1" });
  const res = createResponse();
  await handler({ method: "GET", headers: { authorization }, query: { resource: "users" } }, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body).data, []);
});

test("allows only the configured account with the platform-admin role", async t => {
  const allowedId = crypto.randomUUID();
  const { adminId, authorization } = await withAdmin(t, async () => {
    throw new Error("Invalid resources must be rejected before privileged queries");
  }, { ownerId: allowedId });
  const res = createResponse();
  await handler({ method: "GET", headers: { authorization }, query: { resource: "unknown" } }, res);
  assert.equal(res.statusCode, 403);
  assert.match(JSON.parse(res.body).error, /compte administrateur unique/i);
  assert.notEqual(adminId, allowedId);
});

test("requires the single administrator account to be configured", async t => {
  const { authorization } = await withAdmin(t, async () => {
    throw new Error("Privileged API must not be called");
  }, { noOwnerId: true });
  const res = createResponse();
  await handler({ method: "GET", headers: { authorization }, query: { resource: "users" } }, res);
  assert.equal(res.statusCode, 503);
  assert.match(JSON.parse(res.body).error, /PLATFORM_ADMIN_USER_ID/i);
});

test("lists only the whitelisted merchant fields with pagination", async t => {
  const { authorization } = await withAdmin(t, async (url, options) => {
    assert.match(String(url), /\/rest\/v1\/merchants\?/);
    assert.match(String(url), /select=id%2Cname%2Cemail%2Ccountry%2Ctest_mode%2Ckyc_status/);
    assert.match(String(url), /offset=50/);
    return Response.json([{ id: crypto.randomUUID(), name: "Marchand" }], {
      headers: { "content-range": "50-50/51" }
    });
  });
  const res = createResponse();
  await handler({ method: "GET", headers: { authorization }, query: { resource: "merchants", page: "2" } }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(JSON.parse(res.body).hasMore, false);
  assert.equal(JSON.parse(res.body).total, 51);
});

test("does not expose webhook secret records through the resource API", async t => {
  const { authorization } = await withAdmin(t, async () => {
    throw new Error("Unknown resources must not be queried");
  });
  const res = createResponse();
  await handler({ method: "GET", headers: { authorization }, query: { resource: "webhook_endpoint_secrets" } }, res);
  assert.equal(res.statusCode, 400);
});

test("allows changing the KYC reviewer role through the audited Auth Admin API", async t => {
  const targetId = crypto.randomUUID();
  const auditId = crypto.randomUUID();
  const calls = [];
  const { authorization } = await withAdmin(t, async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith(`/auth/v1/admin/users/${targetId}`) && !options.method) {
      return Response.json({ id: targetId, app_metadata: { platform_admin: false, kyc_admin: false } });
    }
    if (String(url).endsWith("/rest/v1/platform_admin_audit_logs") && options.method === "POST") {
      assert.deepEqual(JSON.parse(options.body).details.new_roles, { platform_admin: false, kyc_admin: true });
      return Response.json([{ id: auditId }], { status: 201 });
    }
    if (String(url).endsWith(`/auth/v1/admin/users/${targetId}`) && options.method === "PUT") {
      assert.deepEqual(JSON.parse(options.body).app_metadata, { platform_admin: false, kyc_admin: true });
      return Response.json({ id: targetId });
    }
    if (String(url).includes(`/rest/v1/platform_admin_audit_logs?id=eq.${auditId}`) && options.method === "PATCH") {
      assert.equal(JSON.parse(options.body).action, "role_change_succeeded");
      return new Response(null, { status: 204 });
    }
    throw new Error(`Unexpected request: ${url}`);
  });
  const res = createResponse();
  await handler({
    method: "POST",
    headers: { authorization },
    body: { user_id: targetId, platform_admin: false, kyc_admin: true }
  }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(calls.length, 4);
  assert.equal(calls[0].options.headers.apikey, "test-service");
});

test("does not allow the console to grant platform-admin access", async t => {
  const targetId = crypto.randomUUID();
  const { authorization } = await withAdmin(t, async url => {
    if (String(url).endsWith(`/auth/v1/admin/users/${targetId}`)) {
      return Response.json({ id: targetId, app_metadata: { platform_admin: false, kyc_admin: false } });
    }
    throw new Error("Role update must not be attempted");
  });
  const res = createResponse();
  await handler({
    method: "POST",
    headers: { authorization },
    body: { user_id: targetId, platform_admin: true, kyc_admin: false }
  }, res);
  assert.equal(res.statusCode, 403);
  assert.match(JSON.parse(res.body).error, /uniquement depuis.*Supabase/i);
});

test("suspends an account and records the action in the admin audit log", async t => {
  const targetId = crypto.randomUUID();
  const auditId = crypto.randomUUID();
  const calls = [];
  const { authorization } = await withAdmin(t, async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith(`/auth/v1/admin/users/${targetId}`) && !options.method) {
      return Response.json({ id: targetId, banned_until: null });
    }
    if (String(url).endsWith("/rest/v1/platform_admin_audit_logs") && options.method === "POST") {
      assert.equal(JSON.parse(options.body).details.operation, "suspend");
      return Response.json([{ id: auditId }], { status: 201 });
    }
    if (String(url).endsWith(`/auth/v1/admin/users/${targetId}`) && options.method === "PUT") {
      assert.equal(JSON.parse(options.body).ban_duration, "876000h");
      return Response.json({ id: targetId });
    }
    if (String(url).includes(`/rest/v1/platform_admin_audit_logs?id=eq.${auditId}`) && options.method === "PATCH") {
      assert.equal(JSON.parse(options.body).action, "account_change_succeeded");
      assert.equal(JSON.parse(options.body).details.operation, "suspend");
      return new Response(null, { status: 204 });
    }
    throw new Error(`Unexpected request: ${url}`);
  });
  const res = createResponse();
  await handler({ method: "POST", headers: { authorization }, body: { user_id: targetId, action: "suspend" } }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(calls.length, 4);
});

test("deletes an account only after creating an audit record", async t => {
  const targetId = crypto.randomUUID();
  const auditId = crypto.randomUUID();
  const calls = [];
  const { authorization } = await withAdmin(t, async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith(`/auth/v1/admin/users/${targetId}`) && !options.method) {
      return Response.json({ id: targetId, banned_until: null });
    }
    if (String(url).endsWith("/rest/v1/platform_admin_audit_logs") && options.method === "POST") {
      return Response.json([{ id: auditId }], { status: 201 });
    }
    if (String(url).endsWith(`/auth/v1/admin/users/${targetId}`) && options.method === "DELETE") {
      assert.equal(calls.length, 3);
      return new Response(null, { status: 204 });
    }
    if (String(url).includes(`/rest/v1/platform_admin_audit_logs?id=eq.${auditId}`) && options.method === "PATCH") {
      assert.equal(JSON.parse(options.body).details.operation, "delete");
      return new Response(null, { status: 204 });
    }
    throw new Error(`Unexpected request: ${url}`);
  });
  const res = createResponse();
  await handler({ method: "POST", headers: { authorization }, body: { user_id: targetId, action: "delete" } }, res);
  assert.equal(res.statusCode, 200);
});

test("protects the configured administrator account from deletion", async t => {
  const { adminId, authorization } = await withAdmin(t, async () => {
    throw new Error("Admin account must not be modified");
  });
  const res = createResponse();
  await handler({ method: "POST", headers: { authorization }, body: { user_id: adminId, action: "delete" } }, res);
  assert.equal(res.statusCode, 403);
  assert.match(JSON.parse(res.body).error, /principal ne peut pas être suspendu ni supprimé/i);
});

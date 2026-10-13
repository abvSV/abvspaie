"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const handler = require("../api/kyc/cases");

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

test("does not return verified when current KYC evidence is incomplete", async t => {
  const userId = crypto.randomUUID();
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };
  process.env.SUPABASE_URL = "https://supabase.example";
  process.env.SUPABASE_ANON_KEY = "test-anon";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service";
  const profile = {
    kyc_status: "verified",
    kyc_full_name: "Test User",
    kyc_country: "CI",
    kyc_document_type: "national_id",
    kyc_submitted_at: "2026-01-01T00:00:00.000Z",
    kyc_decided_at: "2026-01-02T00:00:00.000Z",
    kyc_decided_by: crypto.randomUUID(),
    verified_at: "2026-01-02T00:00:00.000Z"
  };
  let documentsQuery;
  global.fetch = async url => {
    const target = String(url);
    if (target.endsWith("/auth/v1/user")) return Response.json({ id: userId });
    if (target.includes("/rest/v1/merchant_profiles?")) return Response.json([profile]);
    if (target.includes("/rest/v1/merchant_kyc_documents?")) {
      documentsQuery = target;
      return Response.json([{
        id: crypto.randomUUID(),
        document_type: "identity",
        document_side: "front",
        storage_path: `${userId}/identity.png`,
        created_at: "2026-01-01T00:00:00.000Z"
      }]);
    }
    if (target.includes("/rest/v1/kyc_audit_logs?")) {
      return Response.json([
        { actor_id: userId, event_type: "submitted", created_at: "2026-01-01T00:00:00.000Z" },
        { actor_id: profile.kyc_decided_by, event_type: "approved", created_at: "2026-01-02T00:00:00.000Z" }
      ]);
    }
    if (target.includes("/storage/v1/object/sign/")) {
      return Response.json({ signedURL: "/object/sign/merchant-kyc-documents/identity?token=temp" });
    }
    throw new Error(`Unexpected request: ${target}`);
  };
  t.after(() => {
    global.fetch = originalFetch;
    process.env = originalEnv;
  });

  const res = createResponse();
  await handler({
    method: "GET",
    headers: { authorization: `Bearer ${makeToken(userId)}` }
  }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(JSON.parse(res.body).profile.kyc_status, "none");
  assert.match(documentsQuery, /is_current=eq\.true/);
});

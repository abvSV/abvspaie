"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const handler = require("../api/kyc/upload");

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

function request(userId, bytes, contentType = "image/png", token = makeToken(userId), documentType = "identity", documentSide = "front") {
  return {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": contentType,
      "x-kyc-document-type": documentType,
      "x-kyc-document-side": documentSide
    },
    async *[Symbol.asyncIterator]() { yield bytes; }
  };
}

async function withEnvironment(t, userId, fetchMock) {
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };
  process.env.SUPABASE_URL = "https://supabase.example";
  process.env.SUPABASE_ANON_KEY = "test-anon";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service";
  global.fetch = async (url, options) => {
    if (String(url).endsWith("/auth/v1/user")) return Response.json({ id: userId });
    return fetchMock(url, options);
  };
  t.after(() => {
    global.fetch = originalFetch;
    process.env = originalEnv;
  });
}

test("rejects a file whose bytes do not match its declared MIME type", async t => {
  const userId = crypto.randomUUID();
  await withEnvironment(t, userId, async () => {
    throw new Error("Storage must not be called for an invalid file");
  });
  const res = createResponse();
  await handler(request(userId, Buffer.from("<script>alert(1)</script>")), res);
  assert.equal(res.statusCode, 400);
  assert.match(JSON.parse(res.body).error, /contenu du fichier/i);
});

test("uploads validated bytes and stores metadata through the server key", async t => {
  const userId = crypto.randomUUID();
  const documentId = crypto.randomUUID();
  const calls = [];
  await withEnvironment(t, userId, async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).includes("/storage/v1/object/merchant-kyc-documents/")) {
      return new Response(null, { status: 200 });
    }
    if (String(url).endsWith("/rest/v1/merchant_kyc_documents")) {
      return Response.json([{ id: documentId }], { status: 201 });
    }
    throw new Error(`Unexpected request: ${url}`);
  });

  const bytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x01]);
  const res = createResponse();
  await handler(request(userId, bytes), res);

  assert.equal(res.statusCode, 201);
  assert.equal(JSON.parse(res.body).id, documentId);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.body.equals(bytes), true);
  assert.equal(calls[0].options.headers.apikey, "test-service");
  const metadata = JSON.parse(calls[1].options.body);
  assert.equal(metadata.merchant_id, userId);
  assert.equal(metadata.document_type, "identity");
  assert.equal(metadata.document_side, "front");
  assert.match(metadata.storage_path, new RegExp(`^${userId}/[0-9a-f-]+\\.png$`));
});

test("uploads a selfie as a supporting image", async t => {
  const userId = crypto.randomUUID();
  const documentId = crypto.randomUUID();
  let metadata;
  await withEnvironment(t, userId, async (url, options) => {
    if (String(url).includes("/storage/v1/object/merchant-kyc-documents/")) {
      assert.equal(options.body.equals(Buffer.from([0xff, 0xd8, 0xff])), true);
      return new Response(null, { status: 201 });
    }
    if (String(url).endsWith("/rest/v1/merchant_kyc_documents")) {
      metadata = JSON.parse(options.body);
      return Response.json([{ id: documentId }], { status: 201 });
    }
    throw new Error(`Unexpected request: ${url}`);
  });

  const res = createResponse();
  await handler(request(userId, Buffer.from([0xff, 0xd8, 0xff]), "image/jpeg", makeToken(userId), "selfie", "supporting"), res);
  assert.equal(res.statusCode, 201);
  assert.equal(JSON.parse(res.body).document_type, "selfie");
  assert.equal(metadata.document_type, "selfie");
  assert.equal(metadata.document_side, "supporting");
});

test("rejects a PDF as a selfie", async t => {
  const userId = crypto.randomUUID();
  await withEnvironment(t, userId, async () => {
    throw new Error("Storage must not be called for a PDF selfie");
  });
  const res = createResponse();
  await handler(request(userId, Buffer.from("%PDF-1.7 test"), "application/pdf", makeToken(userId), "selfie", "supporting"), res);
  assert.equal(res.statusCode, 415);
  assert.match(JSON.parse(res.body).error, /selfie.*JPG ou PNG/i);
});

test("rejects uploads without an AAL2 session", async t => {
  const userId = crypto.randomUUID();
  await withEnvironment(t, userId, async () => {
    throw new Error("Storage must not be called without MFA");
  });
  const res = createResponse();
  await handler(request(userId, Buffer.from("file"), "application/pdf", makeToken(userId, "aal1")), res);
  assert.equal(res.statusCode, 403);
});

test("rejects a payload above the four-megabyte limit before calling Supabase", async t => {
  const userId = crypto.randomUUID();
  await withEnvironment(t, userId, async () => {
    throw new Error("Supabase must not be called for an oversized payload");
  });
  const res = createResponse();
  await handler(request(userId, Buffer.alloc(4 * 1024 * 1024 + 1)), res);
  assert.equal(res.statusCode, 413);
});

test("removes the uploaded object when metadata registration fails", async t => {
  const userId = crypto.randomUUID();
  const calls = [];
  await withEnvironment(t, userId, async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).includes("/storage/v1/object/merchant-kyc-documents/")) {
      return new Response(null, { status: options.method === "DELETE" ? 200 : 201 });
    }
    if (String(url).endsWith("/rest/v1/merchant_kyc_documents")) {
      return new Response(null, { status: 400 });
    }
    throw new Error(`Unexpected request: ${url}`);
  });
  const bytes = Buffer.from("%PDF-1.7 test");
  const res = createResponse();
  await handler(request(userId, bytes, "application/pdf"), res);
  assert.equal(res.statusCode, 409);
  assert.equal(calls.length, 3);
  assert.equal(calls[2].options.method, "DELETE");
  assert.match(JSON.parse(res.body).error, /pas pu être enregistré/i);
});

test("cleans up the uploaded file when metadata returns a non-JSON response", async t => {
  const userId = crypto.randomUUID();
  const calls = [];
  await withEnvironment(t, userId, async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).includes("/storage/v1/object/merchant-kyc-documents/")) {
      return new Response(null, { status: options.method === "DELETE" ? 200 : 201 });
    }
    if (String(url).endsWith("/rest/v1/merchant_kyc_documents")) {
      return new Response("Interdit.", { status: 200, headers: { "content-type": "text/plain" } });
    }
    throw new Error(`Unexpected request: ${url}`);
  });
  const res = createResponse();
  await handler(request(userId, Buffer.from("%PDF-1.7 test"), "application/pdf"), res);
  assert.equal(res.statusCode, 502);
  assert.match(JSON.parse(res.body).error, /réponse invalide/i);
  assert.equal(calls.length, 3);
  assert.equal(calls[2].options.method, "DELETE");
});

test("returns an actionable error when KYC metadata registration is forbidden", async t => {
  const userId = crypto.randomUUID();
  const calls = [];
  await withEnvironment(t, userId, async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).includes("/storage/v1/object/merchant-kyc-documents/")) {
      return new Response(null, { status: options.method === "DELETE" ? 200 : 201 });
    }
    if (String(url).endsWith("/rest/v1/merchant_kyc_documents")) {
      return new Response("Interdit.", { status: 403, headers: { "content-type": "text/plain" } });
    }
    throw new Error(`Unexpected request: ${url}`);
  });
  const res = createResponse();
  await handler(request(userId, Buffer.from("%PDF-1.7 test"), "application/pdf"), res);
  assert.equal(res.statusCode, 502);
  assert.match(JSON.parse(res.body).error, /configuration Supabase/i);
  assert.equal(calls.length, 3);
  assert.equal(calls[2].options.method, "DELETE");
});

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync(require.resolve("../site/assets/abvs-auth.js"), "utf8");

function loadAuth(client) {
  const window = {
    ABVS_CONFIG: { url: "https://supabase.example", anonKey: "test-anon" },
    supabase: { createClient: () => client }
  };
  const storage = { setItem() {}, getItem() { return null; }, removeItem() {} };
  vm.runInNewContext(source, {
    window,
    document: { getElementById() { return null; } },
    sessionStorage: storage,
    localStorage: storage,
    location: { replace() {} },
    addEventListener() {},
    setInterval() {},
    URL,
    Date
  });
  return window.ABVS;
}

test("signs in without the removed email-MFA flow when no TOTP factor is required", async () => {
  const client = {
    auth: {
      signInWithPassword: async () => ({ data: { session: {} } }),
      mfa: { getAuthenticatorAssuranceLevel: async () => ({ data: { currentLevel: "aal1", nextLevel: "aal1" } }) }
    }
  };
  const auth = loadAuth(client);
  const result = await auth.signIn("user@example.test", "password");
  assert.equal(result.ok, true);
  assert.equal(result.error, undefined);
  assert.equal(auth.emailMfa, undefined);
});

test("requires a verified TOTP factor when the account requires AAL2", async () => {
  const client = {
    auth: {
      signInWithPassword: async () => ({ data: { session: {} } }),
      mfa: {
        getAuthenticatorAssuranceLevel: async () => ({ data: { currentLevel: "aal1", nextLevel: "aal2" } }),
        listFactors: async () => ({ data: { totp: [
          { id: "unverified", status: "unverified" },
          { id: "verified", status: "verified" }
        ] } })
      }
    }
  };
  const result = await loadAuth(client).signIn("user@example.test", "password");
  assert.equal(result.mfa, true);
  assert.equal(result.factorId, "verified");
});

test("does not allow sign-in when AAL2 is required but no verified factor exists", async () => {
  let signedOut = false;
  const client = {
    auth: {
      signInWithPassword: async () => ({ data: { session: {} } }),
      signOut: async () => { signedOut = true; },
      mfa: {
        getAuthenticatorAssuranceLevel: async () => ({ data: { currentLevel: "aal1", nextLevel: "aal2" } }),
        listFactors: async () => ({ data: { totp: [{ id: "unverified", status: "unverified" }] } })
      }
    }
  };
  const result = await loadAuth(client).signIn("user@example.test", "password");
  assert.equal(signedOut, true);
  assert.match(loadAuth(client).msg(result.error), /aucune application d'authentification confirmée/i);
});

test("reports successful MFA only after the session reaches AAL2", async () => {
  const client = {
    auth: {
      mfa: {
        challenge: async () => ({ data: { id: "challenge" } }),
        verify: async () => ({ data: { access_token: "verified" } }),
        getAuthenticatorAssuranceLevel: async () => ({ data: { currentLevel: "aal2", nextLevel: "aal2" } })
      }
    }
  };
  const result = await loadAuth(client).verifyMfa("factor", "123456");
  assert.equal(result.ok, true);
  assert.equal(result.error, undefined);
});

test("does not report successful MFA when the session remains at AAL1", async () => {
  const client = {
    auth: {
      mfa: {
        challenge: async () => ({ data: { id: "challenge" } }),
        verify: async () => ({ data: { access_token: "not-elevated" } }),
        getAuthenticatorAssuranceLevel: async () => ({ data: { currentLevel: "aal1", nextLevel: "aal2" } })
      }
    }
  };
  const result = await loadAuth(client).verifyMfa("factor", "123456");
  assert.ok(result.error);
  assert.match(loadAuth(client).msg(result.error), /niveau MFA requis/i);
});

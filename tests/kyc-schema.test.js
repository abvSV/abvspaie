"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("limits uploads by current documents and archives replaced identity evidence", () => {
  const schema = fs.readFileSync(path.join(__dirname, "..", "supabase", "schema_kyc.sql"), "utf8").replace(/\r\n/g, "\n");
  const replacement = schema.indexOf("update public.merchant_kyc_documents\n      set is_current = false");
  const count = schema.indexOf("select count(*) into v_count");
  const countLimit = schema.indexOf("if v_count >= 8 then");

  assert.notEqual(replacement, -1);
  assert.ok(replacement < count);
  assert.notEqual(countLimit, -1);
  assert.match(schema.slice(count, countLimit), /and d\.is_current;/);
  assert.match(schema.slice(countLimit, schema.indexOf("return new;", countLimit)), /Limite de huit justificatifs actifs atteinte/);
});

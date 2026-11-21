// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Plan 2026-11-17-scaas-sdk T24.soroban: the ledger keys and entries of smartcontracts/vectors/families/soroban.json, the
// generator's bytes, and the refusals beside their controls.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as sor from "../src/fam/soroban.js";
import { decodeStrkey } from "../src/soroban.js";

const FILE = fileURLToPath(new URL("../../../smartcontracts/vectors/families/soroban.json", import.meta.url));
const V = JSON.parse(readFileSync(FILE, "utf8"));
const b64 = (b) => Buffer.from(b).toString("base64");

test("the generator writes the committed bytes", () => {
  const d = mkdtempSync(join(tmpdir(), "fam-vectors-"));
  try {
    execFileSync(process.execPath, [fileURLToPath(new URL("../scripts/families-vectors.mjs", import.meta.url)), d]);
    assert.equal(readFileSync(join(d, "soroban.json"), "utf8"), readFileSync(FILE, "utf8"));
  } finally {
    rmSync(d, { recursive: true });
  }
});

test("every key from its holder and contract", () => {
  assert.equal(V.keys.length, 5);
  assert.equal(V.keys[0].key, b64(sor.accountKey(V.keys[0].holder)));
  for (const k of V.keys.slice(1)) assert.equal(k.key, b64(sor.balanceKey(k.contract, k.holder)), k.what);
  // the three holder forms give three keys
  assert.equal(new Set(V.keys.map((k) => k.key)).size, 5);
});

test("refusals, each beside its control", () => {
  for (const r of V.refusedStrkeys) assert.throws(() => decodeStrkey(r.text), r.why);
  assert.ok(decodeStrkey(V.holders.account).payload.length === 32);
  assert.throws(() => sor.accountKey(V.holders.contract));
  assert.throws(() => sor.balanceKey(V.holders.account, V.holders.contract), /no contract/);
  assert.ok(sor.balanceKey(V.token, V.holders.account).length > 0);
});

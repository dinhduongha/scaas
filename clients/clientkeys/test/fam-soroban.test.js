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

// ---- T27.soroban: the op envelope; T41.soroban: the native transaction
import { ed25519 } from "@noble/curves/ed25519.js";
import { fromHex, hex } from "../src/bytes.js";
const NFILE = fileURLToPath(new URL("../../../smartcontracts/vectors/native/soroban-tx.json", import.meta.url));
const N = JSON.parse(readFileSync(NFILE, "utf8"));
const pk = (g) => decodeStrkey(g).payload;

test("the native generator writes the committed bytes", () => {
  const d = mkdtempSync(join(tmpdir(), "native-vectors-"));
  try {
    execFileSync(process.execPath, [fileURLToPath(new URL("../scripts/native-tx-vectors.mjs", import.meta.url)), d]);
    assert.equal(readFileSync(join(d, "soroban-tx.json"), "utf8"), readFileSync(NFILE, "utf8"));
  } finally {
    rmSync(d, { recursive: true });
  }
});

test("each op row: checkTerms rebuilds its preimage and digest, the subject's signature verifies, the signed_op is named", () => {
  assert.deepEqual(
    V.ops.map((o) => o.kind),
    ["transfer", "pay", "burn"],
  );
  for (const o of V.ops) {
    const c = sor.checkTerms(o.terms, o.shown);
    assert.ok(Object.isFrozen(c));
    assert.equal(hex(Buffer.from(c.walletInput, "base64")), o.preimage);
    assert.equal(hex(c.signingBytes), o.digest);
    assert.ok(ed25519.verify(fromHex(o.signature), c.signingBytes, pk(o.shown.from)));
    assert.deepEqual(o.signed_op.payload, c.payload);
    assert.equal(o.signed_op.family, "soroban");
  }
});

test("a pay's nonce is NET-SOR-02's; the rows' nonces", () => {
  const p = V.ops.find((o) => o.kind === "pay");
  assert.equal(p.terms.nonce, String(sor.payNonce(p.terms.fields.pay_ref, p.terms.fields.valid_until)));
  for (const r of V.payNonces) assert.equal(String(sor.payNonce(r.pay_ref, r.valid_until)), r.nonce);
});

test("each refused op row is refused by name, its kind's row the control", () => {
  assert.ok(V.refusedOps.length >= 17);
  for (const r of V.refusedOps) {
    assert.throws(() => sor.checkTerms(r.terms, r.shown), sor.SorobanError, r.why);
    const control = V.ops.find((o) => o.kind === r.shown.kind) ?? V.ops[0];
    assert.doesNotThrow(() => sor.checkTerms(control.terms, control.shown));
  }
});

test("packSignature takes only a checkTerms result and 64 bytes", () => {
  const o = V.ops[0];
  const c = sor.checkTerms(o.terms, o.shown);
  const key = { address: o.shown.from };
  assert.equal(sor.packSignature(c, key, fromHex(o.signature)).signature, o.signature);
  assert.throws(() => sor.packSignature({ ...c }, key, fromHex(o.signature)), sor.SorobanError);
  assert.throws(() => sor.packSignature(c, key, fromHex(o.signature).slice(1)), sor.SorobanError);
});

test("each native row: the tx, its id, the payer's signature and the envelope", () => {
  for (const r of N.rows) {
    const tx = sor.nativeTx(r);
    assert.equal(hex(tx), r.tx, r.what);
    const id = sor.txHash(N.networkId, tx);
    assert.equal(hex(id), r.hash);
    assert.ok(ed25519.verify(fromHex(r.signature), id, pk(N.payer)));
    assert.equal(hex(sor.envelope(tx, N.payer, r.signature)), r.envelope);
  }
  // the self-relay carries T27's signed pay as its auth entry, unchanged
  const op = V.ops.find((o) => o.kind === "pay").signed_op;
  assert.deepEqual(N.rows[0].op.invoke.auth[0], { payload: op.payload, from: op.from, signature: op.signature });
});

test("each refused native row is refused, a row of its op the control", () => {
  for (const r of N.refused) {
    assert.throws(() => sor.nativeTx(r), sor.SorobanError, r.why);
    const control = N.rows.find((x) => Object.keys(x.op)[0] === Object.keys(r.op)[0]);
    assert.doesNotThrow(() => sor.nativeTx(control));
  }
});

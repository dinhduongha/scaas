// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Plan 2026-11-17-scaas-sdk T24.solana: the program address and the SCaaS Account rows of smartcontracts/vectors/families/
// solana.json, the generator's bytes, and the refusals beside their controls.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { base58 } from "@scure/base";
import * as sol from "../src/fam/solana.js";
import { fromHex, utf8ToBytes } from "../src/bytes.js";

const FILE = fileURLToPath(new URL("../../../smartcontracts/vectors/families/solana.json", import.meta.url));
const V = JSON.parse(readFileSync(FILE, "utf8"));

test("the generator writes the committed bytes", () => {
  const d = mkdtempSync(join(tmpdir(), "fam-vectors-"));
  try {
    execFileSync(process.execPath, [fileURLToPath(new URL("../scripts/families-vectors.mjs", import.meta.url)), d]);
    assert.equal(readFileSync(join(d, "solana.json"), "utf8"), readFileSync(FILE, "utf8"));
  } finally {
    rmSync(d, { recursive: true });
  }
});

test("find_program_address rows, a bump below 255 among them", () => {
  assert.ok(V.pda.some((r) => r.bump < 255));
  for (const r of V.pda) {
    const got = sol.findPda(r.seeds.map(fromHex), base58.decode(r.program));
    assert.deepEqual([base58.encode(got.address), got.bump], [r.address, r.bump]);
    assert.equal(sol.onCurve(got.address), false);
  }
});

test("the Account of an owner is the [acct, owner] address", () => {
  for (const r of V.account) {
    const p = base58.decode(r.program);
    const o = base58.decode(r.owner);
    assert.equal(base58.encode(sol.accountOf(p, o)), r.account);
    assert.equal(sol.findPda([utf8ToBytes("acct"), o], p).bump, r.bump);
  }
});

test("refusals, each beside its control", () => {
  const p = fromHex(V.refused[0].program);
  for (const r of V.refused)
    assert.throws(() => sol.findPda(r.seeds.map(fromHex), fromHex(r.program)), sol.SolanaError, r.why);
  // controls: 15 seeds, a 32-byte seed, a 32-byte program
  assert.ok(
    sol.findPda(
      Array.from({ length: 15 }, () => new Uint8Array(0)),
      p,
    ).address.length === 32,
  );
  assert.ok(sol.findPda([new Uint8Array(32)], p).address.length === 32);
  assert.throws(() => sol.accountOf(p, new Uint8Array(31)), sol.SolanaError);
  // the curve: the ed25519 base point is on it, the rows' addresses are not
  assert.equal(sol.onCurve(fromHex("0x5866666666666666666666666666666666666666666666666666666666666666")), true);
});

// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Plan 2026-11-17-scaas-sdk T24.sui: the derived `Account<T>` id rows of smartcontracts/vectors/families/sui.json, the
// generator's bytes, the Move test's own known answer, and the refusals beside their controls.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as sui from "../src/fam/sui.js";
import { hex, fromHex } from "../src/bytes.js";

const FILE = fileURLToPath(new URL("../../../smartcontracts/vectors/families/sui.json", import.meta.url));
const V = JSON.parse(readFileSync(FILE, "utf8"));

// smartcontracts/move/sui/tests/meta_tests.move: `meta::account_address(&r, v::alice()) == v::a_sui_account()` under the
// test scenario's `Registry<SUI>` (gen_vectors.py REG_SUI): the chain's own derive_address, not this module's
const MOVE = {
  registry: "0x7c9575082976f063e7bfa16aa86ca20e1675b50efa7d5a64d1fa66ce127f5fdf",
  owner: "0x6a749c33bda66662e3709eea404a27dbb2b27d7a58bc0a1248d12436fb2fae71",
  account: "0xd4793a1919a40ebfe5587a3a49fe89bb64c54bd49c75ab2a08ac0d5636706382",
};

test("the generator writes the committed bytes", () => {
  const d = mkdtempSync(join(tmpdir(), "fam-vectors-"));
  try {
    execFileSync(process.execPath, [fileURLToPath(new URL("../scripts/families-vectors.mjs", import.meta.url)), d]);
    assert.equal(readFileSync(join(d, "sui.json"), "utf8"), readFileSync(FILE, "utf8"));
  } finally {
    rmSync(d, { recursive: true });
  }
});

test("the Move test's Account<SUI> of alice is derived, and is a row", () => {
  assert.equal(hex(sui.deriveAccount(fromHex(MOVE.registry), fromHex(MOVE.owner))), MOVE.account);
  assert.ok(
    V.account.some((r) => r.registry === MOVE.registry && r.owner === MOVE.owner && r.account === MOVE.account),
  );
});

test("every Account<T> row is derive_address(registry, owner)", () => {
  assert.ok(V.account.length >= 4);
  for (const r of V.account) assert.equal(hex(sui.deriveAccount(fromHex(r.registry), fromHex(r.owner))), r.account);
  // the registry and the owner are not interchangeable
  const r = V.account[1];
  assert.notEqual(hex(sui.deriveAccount(fromHex(r.owner), fromHex(r.registry))), r.account);
});

test("refusals, each beside its control", () => {
  const k = fromHex(MOVE.registry);
  for (const r of V.refused)
    assert.throws(() => sui.deriveAccount(fromHex(r.registry), fromHex(r.owner)), sui.SuiError, r.why);
  assert.equal(sui.deriveAccount(k, k).length, 32, "control: 32 and 32 bytes");
});

// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// P6h (3): sealPqKey / openPqKey (CTR-PQZ-13 seed custody, CLI-SGN-10, CLI-SGN-52): the registry-class PQZ leaf seed32 sealed in
// vault v2 under label `pqz:registry:<account>:<index>:<version>`, opened alone (never the BIP-39 seed). Every refusal of
// openPqKey is one class, VaultOpen, each beside a positive control. Rows: smartcontracts/vectors/ua/pqz_leaf.json
// (scripts/pqz-leaf-vectors.mjs). UNAUDITED.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { sealPqKey, openPqKey, pqzLeafLabel, pqzKeySeed } from "../src/pq.js";
import { createVault, openVault, rewrapPin } from "../src/vault.js";
import { seedFromWords } from "../src/seed.js";
import { hex, fromHex, b64url, fromB64url } from "../src/bytes.js";
import { dir as uaDir } from "./ua-vectors-dir.js";

const PASS = "river-otter-7 ünï";
const seed = seedFromWords(`${"abandon ".repeat(23)}art`);
const code = async (p) => {
  try {
    await p();
    return null;
  } catch (e) {
    return e.code ?? e.message;
  }
};
const fast = (v) => rewrapPin(v, PASS, PASS, { N: 2 ** 15, r: 8, p: 1, dkLen: 32 }, { policy: false });

test("pqzLeafLabel: pqz:registry:<account>:<index>:<version>, decimal", () => {
  assert.equal(pqzLeafLabel({ account: 0, index: 0 }), "pqz:registry:0:0:0");
  assert.equal(
    pqzLeafLabel({ account: 3, index: 7, version: 2n ** 64n - 1n }),
    "pqz:registry:3:7:18446744073709551615",
  );
});

test("sealPqKey seals pqzKeySeed under the leaf label and the given vault id; openPqKey gives the 32 bytes back", async () => {
  const id = "bdc16c40-f62b-4160-bc75-c6c5fcab079c";
  for (const [account, index, version] of [
    [0, 0, 0],
    [1, 2, 0],
    [0, 0, 1],
  ]) {
    const vault = await sealPqKey({ seed, account, index, version, pin: PASS, id });
    assert.equal(vault.v, 2);
    assert.equal(vault.id, id);
    assert.equal(vault.label, pqzLeafLabel({ account, index, version }));
    assert.ok(!JSON.stringify(vault).includes(hex(pqzKeySeed(seed, account, index, version)).slice(2)));
    const leaf = await openPqKey(await fast(vault), { account, index, version, pin: PASS });
    assert.equal(hex(leaf), hex(pqzKeySeed(seed, account, index, version)));
  }
});

test("sealPqKey refuses an account or index of 2^31 or more (the hardened range), as ua-rs", async () => {
  await assert.rejects(sealPqKey({ seed, account: 2 ** 31, index: 0, pin: PASS }));
  await assert.rejects(sealPqKey({ seed, account: 0, index: 2 ** 31, pin: PASS }));
});

test("openPqKey: every refusal is VaultOpen, each beside its positive control", async () => {
  const at = { account: 0, index: 0, version: 0 };
  const good = await fast(await sealPqKey({ seed, ...at, pin: PASS }));
  const ok = (v, a = at, u = { pin: PASS }) => openPqKey(v, { ...a, ...u });
  assert.equal(hex(await ok(good)), hex(pqzKeySeed(seed, 0, 0, 0)), "positive control");
  const leafOf = async (label, secret) => fast(await createVault(secret, { label, pin: PASS, id: good.id }));
  const ct = fromB64url(good.data.ct);
  const cases = [
    ["wrong passphrase", () => ok(good, at, { pin: "river-otter-8 ünï" })],
    ["another account", () => ok(good, { ...at, account: 1 })],
    ["another index", () => ok(good, { ...at, index: 1 })],
    ["another key version", () => ok(good, { ...at, version: 1 })],
    [
      "relabelled (sealed at version 1)",
      async () => ok({ ...(await leafOf("pqz:registry:0:0:1", new Uint8Array(32))), label: good.label }),
    ],
    ["truncated ciphertext", () => ok({ ...good, data: { ...good.data, ct: b64url(ct.subarray(0, ct.length - 1)) } })],
    ["31-byte payload", async () => ok(await leafOf(good.label, new Uint8Array(31)))],
    ["33-byte payload", async () => ok(await leafOf(good.label, new Uint8Array(33)))],
    ["v 1", () => ok({ ...good, v: 1 })],
    ["tombstone", () => ok({ v: 2, moved: "browser-device-key" })],
    ["N = 2^31", () => ok({ ...good, pin: { ...good.pin, N: 2 ** 31 } })],
    ["an id not a UUID v4", () => ok({ ...good, id: good.id.toUpperCase() })],
    ["a seed vault", async () => ok(await leafOf("seed", new Uint8Array(32)))],
    ["no PRF envelope", () => ok(good, at, { pin: undefined, prfOutput: new Uint8Array(32) })],
    ["not a vault", () => ok(null)],
  ];
  for (const [name, f] of cases) assert.equal(await code(f), "VaultOpen", name);
  // the payload-length controls: a 32-byte payload under the same label opens
  assert.equal(hex(await ok(await leafOf(good.label, new Uint8Array(32)))), hex(new Uint8Array(32)), "32-byte control");
});

const PL = (() => {
  try {
    return JSON.parse(readFileSync(new URL("pqz_leaf.json", uaDir), "utf8"));
  } catch {
    return null;
  }
})();
const unlockOf = (u) => (u.prfOutput ? { prfOutput: fromHex(u.prfOutput) } : u);

test("pqz_leaf.json: every leaf opens to seed32, which is pqzKeySeed of the mnemonic at its account, index and version", async () => {
  assert.ok(PL, "pqz_leaf.json");
  const s = seedFromWords(PL.mnemonic);
  assert.ok(PL.leaves.length >= 4);
  for (const r of PL.leaves) {
    assert.equal(r.vault.label, pqzLeafLabel(r), r.id);
    assert.equal(r.vault.label, r.label, r.id);
    assert.equal(r.seed32, hex(pqzKeySeed(s, r.account, r.index, r.version)), r.id);
    assert.equal(hex(await openPqKey(r.vault, { ...r, ...unlockOf(r.unlock) })), r.seed32, r.id);
    // the leaf is an ordinary vault v2: openVault gives the same 32 bytes
    assert.equal(hex(await openVault(r.vault, unlockOf(r.unlock))), r.seed32, r.id);
  }
});

test("pqz_leaf.json refusals: each VaultOpen, and each row's control opens", async () => {
  for (const x of PL.refusals) {
    assert.equal(await code(() => openPqKey(x.vault, { ...x.open, ...unlockOf(x.unlock) })), "VaultOpen", x.id);
    assert.equal(x.error, "VaultOpen");
  }
  for (const x of PL.refusals) {
    const c = x.control;
    assert.equal(hex(await openPqKey(c.vault, { ...c.open, ...unlockOf(c.unlock) })), c.seed32, `control ${x.id}`);
  }
});

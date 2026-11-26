// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Generates smartcontracts/vectors/ua/pqz_leaf.json (P6h (3), CLI-SGN-55): the registry-class PQZ leaf seed32 that src/pq.js
// sealPqKey seals in vault v2 (label pqz:registry:<account>:<index>:<version>) and openPqKey opens, and openPqKey's refusals
// (one class, VaultOpen), each with its positive control. Randomness: the platform RNG replaced by a fixed SHAKE256 stream per
// vault while it is sealed, so the file does not move between runs. Pin envelopes at N = 2^15 (rewrapped) keep the readers fast.
// ua-rs (tests/pqz_leaf.rs), ua-c and every binding read the same rows.
//   node scripts/pqz-leaf-vectors.mjs [--check]
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { shake256 } from "@noble/hashes/sha3.js";
import { hex, utf8ToBytes, b64url, fromB64url } from "../src/bytes.js";
import { seedFromWords } from "../src/seed.js";
import { sealPqKey, openPqKey, pqzLeafLabel, pqzKeySeed } from "../src/pq.js";
import { createVault, rewrapPin } from "../src/vault.js";

const OUT = fileURLToPath(new URL("../../../smartcontracts/vectors/ua/pqz_leaf.json", import.meta.url));
const MNEMONIC =
  "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author " +
  "capable act festival slice deposit sauce coconut afford frown better"; // pq_kat.json's
const seed = seedFromWords(MNEMONIC);
const PIN = "river-otter-7 ünï";
const ID = "bdc16c40-f62b-4160-bc75-c6c5fcab079c"; // vault.json's seed vault id: the leaves are that seed's
const stream = (label, n) => shake256(utf8ToBytes(`scaas.p6h-sealpq.${label}`), { dkLen: n });
const must = (ok, what) => {
  if (!ok) throw new Error(`generator self-check: ${what}`);
};

const withStream = async (label, f) => {
  let n = 0;
  Object.defineProperty(globalThis.crypto, "getRandomValues", {
    configurable: true,
    writable: true,
    value: (a) => {
      new Uint8Array(a.buffer, a.byteOffset, a.byteLength).set(stream(`${label}.${n++}`, a.byteLength));
      return a;
    },
  });
  try {
    return await f();
  } finally {
    delete globalThis.crypto.getRandomValues;
  }
};
const fast = (v) => rewrapPin(v, PIN, PIN, { N: 2 ** 15, r: 8, p: 1, dkLen: 32 }, { policy: false });
const leafVault = (label, at, prf) =>
  withStream(label, async () => fast(await sealPqKey({ seed, ...at, pin: PIN, prf, id: ID })));
const rawVault = (label, vlabel, secret) =>
  withStream(label, async () => fast(await createVault(secret, { label: vlabel, pin: PIN, id: ID })));

const prf = { output: stream("prf.output", 32), credentialId: "Y3JlZGVudGlhbC0x", salt: stream("prf.salt", 32) };
const leaves = [];
for (const [id, at, p] of [
  ["account 0, index 0, version 0", { account: 0, index: 0, version: 0 }],
  ["account 1, index 2, version 0", { account: 1, index: 2, version: 0 }],
  ["account 0, index 0, version 1 (be64(1) in the HKDF info)", { account: 0, index: 0, version: 1 }],
  [
    "account 2^31 - 1, index 2^31 - 1, version 2^32 (past a u32)",
    { account: 2 ** 31 - 1, index: 2 ** 31 - 1, version: 2 ** 32 },
  ],
  ["PRF envelope (account 0, index 0, version 0)", { account: 0, index: 0, version: 0 }, prf],
]) {
  const vault = await leafVault(`leaf.${leaves.length}`, at, p);
  leaves.push({
    id,
    ...at,
    label: pqzLeafLabel(at),
    unlock: p ? { prfOutput: hex(prf.output) } : { pin: PIN },
    seed32: hex(pqzKeySeed(seed, at.account, at.index, at.version)),
    vault,
  });
}
const unlockOf = (u) => (u.prfOutput ? { prfOutput: Uint8Array.from(Buffer.from(u.prfOutput.slice(2), "hex")) } : u);
for (const r of leaves)
  must(hex(await openPqKey(r.vault, { ...r, ...unlockOf(r.unlock) })) === r.seed32, `leaf ${r.id}`);

const base = leaves[0];
const at0 = { account: 0, index: 0, version: 0 };
const control = { vault: base.vault, open: at0, unlock: { pin: PIN }, seed32: base.seed32 };
const ct = fromB64url(base.vault.data.ct);
const zero32 = hex(new Uint8Array(32));
const v1 = await leafVault("relabel", { account: 0, index: 0, version: 1 });
const refusals = [
  { id: "wrong passphrase", vault: base.vault, open: at0, unlock: { pin: "river-otter-8 ünï" }, control },
  { id: "another account", vault: base.vault, open: { ...at0, account: 1 }, unlock: { pin: PIN }, control },
  { id: "another index", vault: base.vault, open: { ...at0, index: 1 }, unlock: { pin: PIN }, control },
  { id: "another key version", vault: base.vault, open: { ...at0, version: 1 }, unlock: { pin: PIN }, control },
  {
    id: "relabelled: the version-1 leaf with the version-0 label (AAD)",
    vault: { ...v1, label: base.label },
    open: at0,
    unlock: { pin: PIN },
    control: { vault: v1, open: { ...at0, version: 1 }, unlock: { pin: PIN }, seed32: leaves[2].seed32 },
  },
  {
    id: "truncated ciphertext (one byte short)",
    vault: { ...base.vault, data: { ...base.vault.data, ct: b64url(ct.subarray(0, ct.length - 1)) } },
    open: at0,
    unlock: { pin: PIN },
    control,
  },
  {
    id: "altered ciphertext (last byte)",
    vault: {
      ...base.vault,
      data: { ...base.vault.data, ct: b64url(Uint8Array.from(ct, (b, i) => (i === ct.length - 1 ? b ^ 1 : b))) },
    },
    open: at0,
    unlock: { pin: PIN },
    control,
  },
  {
    id: "payload of 31 bytes under the leaf label",
    vault: await rawVault("p31", base.label, new Uint8Array(31)),
    open: at0,
    unlock: { pin: PIN },
    control: {
      vault: await rawVault("p32", base.label, new Uint8Array(32)),
      open: at0,
      unlock: { pin: PIN },
      seed32: zero32,
    },
  },
  {
    id: "payload of 33 bytes under the leaf label",
    vault: await rawVault("p33", base.label, new Uint8Array(33)),
    open: at0,
    unlock: { pin: PIN },
    control: {
      vault: await rawVault("p32", base.label, new Uint8Array(32)),
      open: at0,
      unlock: { pin: PIN },
      seed32: zero32,
    },
  },
  { id: "v: 1", vault: { ...structuredClone(base.vault), v: 1 }, open: at0, unlock: { pin: PIN }, control },
  { id: "v: 2 tombstone", vault: { v: 2, moved: "browser-device-key" }, open: at0, unlock: { pin: PIN }, control },
  {
    id: "N = 2^31 (refused before scrypt runs)",
    vault: { ...structuredClone(base.vault), pin: { ...base.vault.pin, N: 2 ** 31 } },
    open: at0,
    unlock: { pin: PIN },
    control,
  },
  {
    id: "an id not a lower-case UUID v4",
    vault: { ...structuredClone(base.vault), id: ID.toUpperCase() },
    open: at0,
    unlock: { pin: PIN },
    control,
  },
  {
    id: "altered AAD id (another seed's id)",
    vault: { ...structuredClone(base.vault), id: "0b9c2f0e-5d0e-4a51-9d3b-6a1f6f6f2a10" },
    open: at0,
    unlock: { pin: PIN },
    control,
  },
  {
    id: "a seed vault (label seed) opened as a leaf",
    vault: await rawVault("seedlabel", "seed", new Uint8Array(32)),
    open: at0,
    unlock: { pin: PIN },
    control,
  },
  {
    id: "a non-canonical label (version 00)",
    vault: await rawVault("noncanon", "pqz:registry:0:0:00", new Uint8Array(32)),
    open: at0,
    unlock: { pin: PIN },
    control,
  },
  {
    id: "a PRF output on a vault without a PRF envelope",
    vault: base.vault,
    open: at0,
    unlock: { prfOutput: hex(prf.output) },
    control,
  },
].map((x) => ({ ...x, error: "VaultOpen" }));
for (const x of refusals) {
  let e = null;
  try {
    await openPqKey(x.vault, { ...x.open, ...unlockOf(x.unlock) });
  } catch (err) {
    e = err;
  }
  must(e?.code === "VaultOpen", `refusal ${x.id}: ${e?.message}`);
  const c = x.control;
  must(hex(await openPqKey(c.vault, { ...c.open, ...unlockOf(c.unlock) })) === c.seed32, `control ${x.id}`);
}

const out = {
  note:
    "Generated by clients/clientkeys/scripts/pqz-leaf-vectors.mjs (P6h (3), CLI-SGN-55) from src/pq.js sealPqKey / openPqKey; " +
    'never edit by hand. The leaf is seed32 = HKDF-SHA256(BIP-39 seed, "scaas.ua.pq.v1", "scaas.ua.pqz-mlwe.v1" ‖ u32 account ‖ ' +
    "u32 index [‖ be64 version for version ≥ 1]) (CTR-PQZ-13, CLI-SGN-49), sealed as vault v2 (vault.json's rules) under label " +
    "pqz:registry:<account>:<index>:<version> (decimal) with the seed vault's id. openPqKey(vault, {account, index, version, " +
    "unlock}) takes the leaf whose label is exactly that and whose payload is 32 bytes; every refusal is VaultOpen (one class, " +
    "ARCH-POS-13). Each refusal's control changes the one thing back and opens. The DEK, IVs and salts come from a fixed stream.",
  mnemonic: MNEMONIC,
  leaves,
  refusals,
};
const text = JSON.stringify(out, null, 1) + "\n";
if (process.argv.includes("--check")) {
  if (readFileSync(OUT, "utf8") !== text) {
    console.error("pqz-leaf-vectors.mjs --check: smartcontracts/vectors/ua/pqz_leaf.json differs");
    process.exit(1);
  }
  console.log(`pqz-leaf-vectors.mjs --check: ok (${leaves.length} leaves, ${refusals.length} refusals)`);
} else {
  writeFileSync(OUT, text);
  console.log(`pqz_leaf.json: ${leaves.length} leaves, ${refusals.length} refusals`);
}

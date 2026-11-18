// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Generates smartcontracts/vectors/keystore/index_mac.json and reseal.json (scaas-sdk plan T2a; spec §6.1, §6.2, §6.10): the
// BIP-32 master fingerprint of the repository mnemonic, the index MAC of seed entries (a base entry, one row per field changed,
// another seed), and vaults re-sealed under their same DEK; keystore.json (T2b): valid containers of src/keystore.js and one
// refused file per rule with its error name. Randomness: the platform RNG replaced by a fixed SHAKE256 stream per
// vault while it is sealed, so the files do not move between runs (test/keystore-index.test.js regenerates them byte for byte).
// Read back by test/keystore-index.test.js, test/keystore.test.js, clients/ua-rs/tests/{index_mac,reseal}.rs and the scaas-sdk.
//   node scripts/keystore-vectors.mjs [outDir]
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { shake256 } from "@noble/hashes/sha3.js";
import { hex, utf8ToBytes, bytesToHex } from "../src/bytes.js";
import { wordsToEntropy, seedFromEntropy, masterFingerprint, deriveKey, importKey } from "../src/seed.js";
import { deriveUAKey } from "../src/uakey.js";
import { polkadotKey } from "../src/substrate.js";
import { parse, serialize } from "../src/keystore.js";
import { indexMac, indexCanonical } from "../src/keystore-mac.js";
import { createVault, openVault, resealData } from "../src/vault.js";

const OUT = process.argv[2] ?? fileURLToPath(new URL("../../../smartcontracts/vectors/keystore", import.meta.url));
const must = (ok, what) => {
  if (!ok) throw new Error(`keystore vectors: ${what}`);
};
const stream = (label, n) => shake256(utf8ToBytes(`scaas.scaas-sdk.t2a.${label}`), { dkLen: n });
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

const MNEMONIC =
  "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author " +
  "capable act festival slice deposit sauce coconut afford frown better";
const TWELVE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASS = "river-otter-7 ünï";
const ENTROPY = wordsToEntropy(MNEMONIC);
const ENTROPY12 = wordsToEntropy(TWELVE);

// --- fingerprints: the main set (empty BIP-39 passphrase) and a hidden set's, which differs
const fingerprints = [
  {
    id: "repository mnemonic, main set",
    entropy: hex(ENTROPY),
    bip39Passphrase: "",
    fingerprint: masterFingerprint(seedFromEntropy(ENTROPY)),
  },
  {
    id: "repository mnemonic, a BIP-39 passphrase",
    entropy: hex(ENTROPY),
    bip39Passphrase: "hidden ünï",
    fingerprint: masterFingerprint(seedFromEntropy(ENTROPY, "hidden ünï")),
  },
  {
    id: "twelve words, main set",
    entropy: hex(ENTROPY12),
    bip39Passphrase: "",
    fingerprint: masterFingerprint(seedFromEntropy(ENTROPY12)),
  },
];
must(fingerprints[0].fingerprint !== fingerprints[1].fingerprint, "a hidden set has another fingerprint");

// --- index MAC rows
const BASE = {
  id: "0b9c2f0e-5d0e-4a51-9d3b-6a1f6f6f2a10",
  label: "Ví chính",
  words: 24,
  fingerprint: fingerprints[0].fingerprint,
  origin: "generated",
  class: "full",
  warnings: [],
  backup: "verified",
  accounts: [
    {
      id: "6f1d1f4e-58b5-4d0c-8a6e-1a2b3c4d5e6f",
      name: "Daily",
      kind: 305,
      account: 0,
      index: 0,
      ua: "0x" + "11".repeat(32),
    },
    {
      id: "7a2e2a5f-69c6-4e1d-9b7f-2b3c4d5e6f70",
      name: "DOT",
      network: "polkadot",
      index: 0,
      path: "//polkadot",
      ss58Prefix: 0,
      address: "1xyz",
    },
  ],
  // the vault texts the MAC covers (T13b ruling 3): opaque strings to it, in any key order (the canonical form sorts them)
  vaults: { seed: '{"v":2,"label":"seed"}', manifest: '{"v":2,"label":"manifest"}' },
};
const changes = [
  ["id", "1c0d3f1f-6e1f-4b62-8e4c-7b2f7f7f3b21"],
  ["label", "Vi chinh"],
  ["words", 12],
  ["fingerprint", "00000000"],
  ["origin", "imported"],
  ["class", "classical-rooted"],
  ["warnings", ["short_seed"]],
  ["backup", "pending"],
  ["accounts", BASE.accounts.slice(0, 1)],
  ["vaults", { ...BASE.vaults, seed: '{"v":2,"label":"seed","x":1}' }],
];
const macRow = (id, entropy, fields) => ({
  id,
  entropy: hex(entropy),
  fields,
  canonical: indexCanonical(fields),
  mac: indexMac(entropy, fields),
});
const macs = [
  macRow("base entry", ENTROPY, BASE),
  ...changes.map(([k, v]) => macRow(`${k} changed`, ENTROPY, { ...BASE, [k]: v })),
  macRow("the same fields, another seed", ENTROPY12, BASE),
  macRow("an empty account list", ENTROPY, { ...BASE, accounts: [] }),
];
must(new Set(macs.map((r) => r.mac)).size === macs.length, "every row a different MAC");

// --- re-sealed vaults: the same DEK, a fresh IV, both envelopes kept
const prf = { output: stream("prf.output", 32), credentialId: "Y3JlZGVudGlhbC0x", salt: stream("prf.salt", 32) };
const resealRow = async (id, label, withPrf) => {
  // ua-rs's manifest form (Manifest::to_json), so a reader can open the vault into a wallet; the change: backupGeneration
  const manifest = (g) =>
    utf8ToBytes(
      `{"v":1,"entries":[],"natives":[],"kem":[],"imports":[],"importedUas":[],"pqzHeld":[],"backupGeneration":${g},"backupSenders":[]}`,
    );
  const [before, after] = withPrf ? [manifest(0), manifest(1)] : [manifest(2), manifest(3)];
  const vault = await withStream(`${id}.seal`, () =>
    createVault(before, {
      label,
      pin: PASS,
      prf: withPrf ? prf : undefined,
      id: "5a417c5d-ac5d-4fa6-8280-bf6dbdbd7f65",
    }),
  );
  const resealed = await withStream(`${id}.reseal`, () => resealData(vault, { pin: PASS }, after));
  must(JSON.stringify(resealed.pin) === JSON.stringify(vault.pin), `${id}: pin kept`);
  must(JSON.stringify(resealed.prf) === JSON.stringify(vault.prf), `${id}: prf kept`);
  must(bytesToHex(await openVault(resealed, { pin: PASS })) === bytesToHex(after), `${id}: opens by passphrase`);
  if (withPrf)
    must(bytesToHex(await openVault(resealed, { prfOutput: prf.output })) === bytesToHex(after), `${id}: opens by PRF`);
  return {
    id,
    vault,
    resealed,
    pin: PASS,
    prfOutput: withPrf ? hex(prf.output) : null,
    before: hex(before),
    plaintext: hex(after),
  };
};
const reseals = [
  await resealRow("manifest with a PRF envelope", "manifest", true),
  await resealRow("manifest, passphrase only", "manifest", false),
];

// --- keystore.json (T2b): containers. Every vault sealed under PASS by src/vault.js from a stream; every entry's MAC under its
// seed's entropy.
const vaultText = async (label, secret, id) =>
  JSON.stringify(await withStream(`ks.${id}.${label}`, () => createVault(secret, { label, pin: PASS, id })));
const emptyManifest = utf8ToBytes(
  '{"v":1,"entries":[],"natives":[],"kem":[],"imports":[],"importedUas":[],"pqzHeld":[],"backupGeneration":0,"backupSenders":[]}',
);
const macOf = (entropy, e) => ({ ...e, indexMac: indexMac(entropy, e) });
const entry = async ({ id, label, entropy, origin, warnings = [], backup, accounts = [], extraVaults = {} }) => {
  const vaults = {
    seed: await vaultText("seed", entropy, id),
    manifest: await vaultText("manifest", emptyManifest, id),
  };
  for (const [k, v] of Object.entries(extraVaults)) vaults[k] = await vaultText(k, v, id);
  const e = {
    id,
    label,
    words: (entropy.length * 3) / 4,
    fingerprint: masterFingerprint(seedFromEntropy(entropy)),
    origin,
    class: "full",
    warnings,
    backup,
    accounts,
    vaults,
  };
  return macOf(entropy, e);
};
const ordered = (e) => ({
  id: e.id,
  label: e.label,
  words: e.words,
  fingerprint: e.fingerprint,
  origin: e.origin,
  class: e.class,
  warnings: e.warnings,
  backup: e.backup,
  vaults: Object.fromEntries(
    Object.keys(e.vaults)
      .sort()
      .map((k) => [k, e.vaults[k]]),
  ),
  accounts: e.accounts,
  indexMac: e.indexMac,
});
const SEED24 = seedFromEntropy(ENTROPY);
const ua0101 = hex(deriveUAKey(SEED24, { kind: 0x0101, account: 0, index: 0 }).ua);
const dot = polkadotKey(ENTROPY, "", "//polkadot");
const imported = importKey("evm", stream("ks.import.secret", 32));
const main = ordered(
  await entry({
    id: "0b9c2f0e-5d0e-4a51-9d3b-6a1f6f6f2a10",
    label: "Main",
    entropy: ENTROPY,
    origin: "generated",
    backup: "verified",
    accounts: [
      { id: "6f1d1f4e-58b5-4d0c-8a6e-1a2b3c4d5e6f", name: "Daily", kind: 0x0101, account: 0, index: 0, ua: ua0101 },
      {
        id: "8b3f3b60-7ad7-4f2e-8c80-3c4d5e6f7081",
        name: "EVM",
        network: "evm",
        index: 0,
        address: deriveKey(SEED24, "evm", 0).address,
      },
    ],
  }),
);
const short = ordered(
  await entry({
    id: "2d1e4a2a-7f2a-4c73-9f5d-8c3a8a8a4c32",
    label: "Imported 12",
    entropy: ENTROPY12,
    origin: "imported",
    warnings: ["short_seed"],
    backup: "verified",
  }),
);
const withImport = ordered(
  await entry({
    id: "3e2f5b3b-8a3b-4d84-a06e-9d4b9b9b5d43",
    label: "With an import",
    entropy: ENTROPY,
    origin: "generated",
    warnings: ["imported_key"],
    backup: "pending",
    extraVaults: { "native-import:evm:0": imported.privateKey },
    accounts: [
      {
        id: "9c4a4c71-8be8-4a3f-9d91-4d5e6f708192",
        name: "Imported EVM",
        network: "evm",
        index: 0,
        address: imported.address,
      },
    ],
  }),
);
const polkadot = ordered(
  await entry({
    id: "4f306c4c-9b4c-4e95-b17f-ae5cacac6e54",
    label: "Polkadot",
    entropy: ENTROPY,
    origin: "generated",
    backup: "verified",
    accounts: [
      {
        id: "ad5b5d82-9cf9-4b40-ae02-5e6f708192a3",
        name: "DOT",
        network: "polkadot",
        index: 0,
        path: "//polkadot",
        ss58Prefix: 0,
        address: dot.address,
      },
    ],
  }),
);
const ks = (rev, seeds) => ({ format: "scaas.keystore", v: 2, rev, seeds });
const validRows = [
  { id: "an empty keystore", container: ks(0, []) },
  { id: "one 24-word seed with seed and manifest vaults", container: ks(1, [main]) },
  { id: "a 12-word import with short_seed", container: ks(2, [short]) },
  { id: "a seed with an import vault", container: ks(3, [withImport]) },
  { id: "a Polkadot row with path and ss58Prefix", container: ks(4, [polkadot]) },
  { id: "four seeds", container: ks(42, [main, short, withImport, polkadot]) },
].map((r) => ({ id: r.id, text: serialize(r.container) }));
for (const r of validRows) must(serialize(parse(r.text)) === r.text, `valid ${r.id}`);
const base = () => structuredClone(ks(7, [main, short]));
const mutate = (f) => {
  const c = base();
  f(c);
  return JSON.stringify(c);
};
const sixtyFive = () => {
  const c = base();
  c.seeds = Array.from({ length: 65 }, (_, i) => ({
    ...structuredClone(main),
    id: `${String(i).padStart(8, "0")}-0000-4000-8000-000000000000`,
    label: `S${i}`,
  }));
  return JSON.stringify(c);
};
const refusedRows = [
  [
    "another format",
    "VaultVersion",
    mutate((c) => {
      c.format = "scaas.keystore2";
    }),
  ],
  [
    "v: 1 (vault v1, no migration)",
    "VaultVersion",
    mutate((c) => {
      c.v = 1;
    }),
  ],
  [
    "a vault of another seed's id",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].vaults.manifest = c.seeds[1].vaults.manifest;
    }),
  ],
  [
    "a vault v 1 text",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].vaults.manifest = c.seeds[0].vaults.manifest.replace('"v":2', '"v":1');
    }),
  ],
  [
    "an unknown top-level field",
    "VaultFormat",
    mutate((c) => {
      c.extra = 1;
    }),
  ],
  [
    "an unknown seed field",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].parent = "x";
    }),
  ],
  [
    "an unknown account field",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].accounts[0].note = "x";
    }),
  ],
  [
    "a duplicate id",
    "VaultFormat",
    mutate((c) => {
      c.seeds[1].id = c.seeds[0].id;
    }),
  ],
  [
    "a duplicate label",
    "VaultFormat",
    mutate((c) => {
      c.seeds[1].label = c.seeds[0].label;
    }),
  ],
  [
    "a label of 0 scalar values",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].label = "";
    }),
  ],
  [
    "a label of 65 scalar values",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].label = "ư".repeat(65);
    }),
  ],
  [
    "a label with a control character",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].label = "Ma\u0007in";
    }),
  ],
  [
    "a label not NFC",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].label = "Mé";
    }),
  ],
  [
    "words 13",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].words = 13;
    }),
  ],
  [
    "backup lost",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].backup = "lost";
    }),
  ],
  [
    "a vaults key unequal to its vault's label",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].vaults.manifest = c.seeds[0].vaults.seed;
    }),
  ],
  [
    "no seed vault",
    "VaultFormat",
    mutate((c) => {
      delete c.seeds[0].vaults.seed;
    }),
  ],
  [
    "no rev",
    "VaultFormat",
    mutate((c) => {
      delete c.rev;
    }),
  ],
  [
    "no indexMac",
    "VaultFormat",
    mutate((c) => {
      delete c.seeds[0].indexMac;
    }),
  ],
  ["65 seeds", "VaultFormat", sixtyFive()],
  [
    "depth 6",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].accounts[0].name = "x";
      c.seeds[0].accounts[0].ua = ["deep"];
    }),
  ],
  [
    "an id not a lower-case UUID v4",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].id = c.seeds[0].id.toUpperCase();
    }),
  ],
  [
    "a fingerprint in upper case",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].fingerprint = c.seeds[0].fingerprint.toUpperCase().replace(/^[0-9]/, "A");
    }),
  ],
  [
    "an unknown origin",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].origin = "found";
    }),
  ],
  [
    "an unknown class",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].class = "pq";
    }),
  ],
  [
    "an unknown warning",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].warnings = ["old"];
    }),
  ],
  [
    "an indexMac of 63 digits",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].indexMac = c.seeds[0].indexMac.slice(1);
    }),
  ],
  ["white space (not the canonical form)", "VaultFormat", JSON.stringify(base(), null, 1)],
  [
    "fields in another order",
    "VaultFormat",
    mutate((c) => {
      const r = c.rev;
      delete c.rev;
      c.rev = r;
    }),
  ],
  ["a duplicate key", "VaultFormat", JSON.stringify(base()).replace('"rev":7,', '"rev":7,"rev":8,')],
  ["words as 24.0", "VaultFormat", JSON.stringify(base()).replace('"words":24,', '"words":24.0,')],
  [
    "a label with a lone surrogate",
    "VaultFormat",
    JSON.stringify(base()).replace('"label":"Main"', '"label":"Main\\ud800"'),
  ],
  ["a byte-order mark", "VaultFormat", "\ufeff" + JSON.stringify(base())],
  [
    "a vault key with a space",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].vaults = {
        "native import": c.seeds[0].vaults.manifest.replace('"label":"manifest"', '"label":"native import"'),
        ...c.seeds[0].vaults,
      };
    }),
  ],
  [
    "a vault text nested deeper than 2",
    "VaultFormat",
    mutate((c) => {
      c.seeds[0].vaults.manifest = JSON.stringify({ ...JSON.parse(c.seeds[0].vaults.manifest), extra: [[1]] });
    }),
  ],
  [
    "vaults not in key order",
    "VaultFormat",
    mutate((c) => {
      const { seed, ...rest } = c.seeds[0].vaults;
      c.seeds[0].vaults = { seed, ...rest };
    }),
  ],
].map(([id, error, text]) => ({ id, error, text }));
must(serialize(base()) === JSON.stringify(base()), "the refusals' base is canonical");
for (const r of refusedRows) {
  let code = null;
  try {
    parse(r.text);
  } catch (e) {
    code = e.code;
  }
  must(code === r.error, `refused ${r.id}: ${code}`);
}

const write = (name, obj) => {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, name), JSON.stringify(obj, null, 1) + "\n");
};
write("index_mac.json", {
  note:
    "Generated by clients/clientkeys/scripts/keystore-vectors.mjs (scaas-sdk plan T2a) from src/seed.js masterFingerprint and " +
    "src/keystore-mac.js indexMac; never edit by hand. fingerprint: the BIP-32 master key fingerprint of the seed of the entropy " +
    'and the BIP-39 passphrase (8 lower-case hex). mac: HMAC-SHA256(HKDF-SHA256(entropy, "", "scaas.keystore.index.v2", 32), ' +
    "canonical), canonical the JSON of exactly id, label, words, fingerprint, origin, class, warnings, backup, accounts, vaults " +
    "(the label → vault text object, keys sorted) in that order without white space (given here as well); every row a " +
    "different MAC (owner 2026-11-19, T13b ruling 3: the MAC covers the vault texts).",
  fingerprints,
  macs,
});
write("reseal.json", {
  note:
    "Generated by clients/clientkeys/scripts/keystore-vectors.mjs (scaas-sdk plan T2a) from src/vault.js resealData; never edit " +
    "by hand. resealed = vault with data re-encrypted under the same DEK and a fresh IV: pin and prf byte for byte the same, data " +
    "not; resealed opens to plaintext by the passphrase and (when prfOutput is set) by the PRF output, vault to before. DEK, IVs " +
    "and salts come from a fixed stream.",
  reseals,
});
write("keystore.json", {
  note:
    "Generated by clients/clientkeys/scripts/keystore-vectors.mjs (scaas-sdk plan T2b) from src/keystore.js; never edit by hand. " +
    "Container v 2 holding vault v2 texts, each of its seed's id (owner 2026-11-19, T13b ruling 3). " +
    "valid: canonical containers (serialize(parse(text)) === text); refused: the base container (rev 7, the first two seeds of " +
    '"four seeds") with one rule broken each, and the error a reader names. Vaults sealed by src/vault.js under the passphrase ' +
    "\"river-otter-7 ünï\" from a fixed stream; each entry's indexMac under its seed's entropy (the repository mnemonic, or the " +
    '12-word "abandon … about"). Only the canonical text is accepted.',
  passphrase: PASS,
  valid: validRows,
  refused: refusedRows,
});
console.log(
  `keystore vectors: ${fingerprints.length} fingerprints, ${macs.length} MACs, ${reseals.length} re-sealed vaults, ${validRows.length} containers, ${refusedRows.length} refused -> ${OUT}`,
);

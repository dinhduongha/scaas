// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Generates smartcontracts/vectors/keystore/index_mac.json and reseal.json (scaas-sdk plan T2a; spec §6.1, §6.2, §6.10): the
// BIP-32 master fingerprint of the repository mnemonic, the index MAC of seed entries (a base entry, one row per field changed,
// another seed), and vaults re-sealed under their same DEK. Randomness: the platform RNG replaced by a fixed SHAKE256 stream per
// vault while it is sealed, so the files do not move between runs (test/keystore-index.test.js regenerates them byte for byte).
// Read back by test/keystore-index.test.js and clients/ua-rs/tests/{index_mac,reseal}.rs.
//   node scripts/keystore-vectors.mjs [outDir]
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { shake256 } from '@noble/hashes/sha3.js';
import { hex, utf8ToBytes, bytesToHex } from '../src/bytes.js';
import { wordsToEntropy, seedFromEntropy, masterFingerprint } from '../src/seed.js';
import { indexMac, indexCanonical } from '../src/keystore-mac.js';
import { createVault, openVault, resealData } from '../src/vault.js';

const OUT = process.argv[2] ?? fileURLToPath(new URL('../../../smartcontracts/vectors/keystore', import.meta.url));
const must = (ok, what) => { if (!ok) throw new Error(`keystore vectors: ${what}`); };
const stream = (label, n) => shake256(utf8ToBytes(`scaas.scaas-sdk.t2a.${label}`), { dkLen: n });
const withStream = async (label, f) => {
  let n = 0;
  Object.defineProperty(globalThis.crypto, 'getRandomValues', { configurable: true, writable: true,
    value: (a) => { new Uint8Array(a.buffer, a.byteOffset, a.byteLength).set(stream(`${label}.${n++}`, a.byteLength)); return a; } });
  try { return await f(); } finally { delete globalThis.crypto.getRandomValues; }
};

const MNEMONIC = 'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author '
  + 'capable act festival slice deposit sauce coconut afford frown better';
const TWELVE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASS = 'river-otter-7 ünï';
const ENTROPY = wordsToEntropy(MNEMONIC);
const ENTROPY12 = wordsToEntropy(TWELVE);

// --- fingerprints: the main set (empty BIP-39 passphrase) and a hidden set's, which differs
const fingerprints = [
  { id: 'repository mnemonic, main set', entropy: hex(ENTROPY), bip39Passphrase: '', fingerprint: masterFingerprint(seedFromEntropy(ENTROPY)) },
  { id: 'repository mnemonic, a BIP-39 passphrase', entropy: hex(ENTROPY), bip39Passphrase: 'hidden ünï', fingerprint: masterFingerprint(seedFromEntropy(ENTROPY, 'hidden ünï')) },
  { id: 'twelve words, main set', entropy: hex(ENTROPY12), bip39Passphrase: '', fingerprint: masterFingerprint(seedFromEntropy(ENTROPY12)) },
];
must(fingerprints[0].fingerprint !== fingerprints[1].fingerprint, 'a hidden set has another fingerprint');

// --- index MAC rows
const BASE = {
  id: '0b9c2f0e-5d0e-4a51-9d3b-6a1f6f6f2a10',
  label: 'Ví chính',
  words: 24,
  fingerprint: fingerprints[0].fingerprint,
  origin: 'generated',
  class: 'full',
  warnings: [],
  backup: 'verified',
  accounts: [
    { id: '6f1d1f4e-58b5-4d0c-8a6e-1a2b3c4d5e6f', name: 'Daily', kind: 305, account: 0, index: 0, ua: '0x' + '11'.repeat(32) },
    { id: '7a2e2a5f-69c6-4e1d-9b7f-2b3c4d5e6f70', name: 'DOT', network: 'polkadot', index: 0, path: '//polkadot', ss58Prefix: 0, address: '1xyz' },
  ],
};
const changes = [
  ['id', '1c0d3f1f-6e1f-4b62-8e4c-7b2f7f7f3b21'],
  ['label', 'Vi chinh'],
  ['words', 12],
  ['fingerprint', '00000000'],
  ['origin', 'imported'],
  ['class', 'classical-rooted'],
  ['warnings', ['short_seed']],
  ['backup', 'pending'],
  ['accounts', BASE.accounts.slice(0, 1)],
];
const macRow = (id, entropy, fields) => ({ id, entropy: hex(entropy), fields, canonical: indexCanonical(fields), mac: indexMac(entropy, fields) });
const macs = [
  macRow('base entry', ENTROPY, BASE),
  ...changes.map(([k, v]) => macRow(`${k} changed`, ENTROPY, { ...BASE, [k]: v })),
  macRow('the same fields, another seed', ENTROPY12, BASE),
  macRow('an empty account list', ENTROPY, { ...BASE, accounts: [] }),
];
must(new Set(macs.map((r) => r.mac)).size === macs.length, 'every row a different MAC');

// --- re-sealed vaults: the same DEK, a fresh IV, both envelopes kept
const prf = { output: stream('prf.output', 32), credentialId: 'Y3JlZGVudGlhbC0x', salt: stream('prf.salt', 32) };
const resealRow = async (id, label, withPrf) => {
  // ua-rs's manifest form (Manifest::to_json), so a reader can open the vault into a wallet; the change: backupGeneration
  const manifest = (g) => utf8ToBytes(`{"v":1,"entries":[],"natives":[],"kem":[],"imports":[],"importedUas":[],"pqzHeld":[],"backupGeneration":${g},"backupSenders":[]}`);
  const [before, after] = withPrf ? [manifest(0), manifest(1)] : [manifest(2), manifest(3)];
  const vault = await withStream(`${id}.seal`, () => createVault(before, { label, pin: PASS, prf: withPrf ? prf : undefined }));
  const resealed = await withStream(`${id}.reseal`, () => resealData(vault, { pin: PASS }, after));
  must(JSON.stringify(resealed.pin) === JSON.stringify(vault.pin), `${id}: pin kept`);
  must(JSON.stringify(resealed.prf) === JSON.stringify(vault.prf), `${id}: prf kept`);
  must(bytesToHex(await openVault(resealed, { pin: PASS })) === bytesToHex(after), `${id}: opens by passphrase`);
  if (withPrf) must(bytesToHex(await openVault(resealed, { prfOutput: prf.output })) === bytesToHex(after), `${id}: opens by PRF`);
  return { id, vault, resealed, pin: PASS, prfOutput: withPrf ? hex(prf.output) : null, before: hex(before), plaintext: hex(after) };
};
const reseals = [
  await resealRow('manifest with a PRF envelope', 'manifest', true),
  await resealRow('manifest, passphrase only', 'manifest', false),
];

const write = (name, obj) => {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, name), JSON.stringify(obj, null, 1) + '\n');
};
write('index_mac.json', {
  note: 'Generated by clients/clientkeys/scripts/keystore-vectors.mjs (scaas-sdk plan T2a) from src/seed.js masterFingerprint and '
    + 'src/keystore-mac.js indexMac; never edit by hand. fingerprint: the BIP-32 master key fingerprint of the seed of the entropy '
    + 'and the BIP-39 passphrase (8 lower-case hex). mac: HMAC-SHA256(HKDF-SHA256(entropy, "", "scaas.keystore.index.v1", 32), '
    + 'canonical), canonical the JSON of exactly id, label, words, fingerprint, origin, class, warnings, backup, accounts in that '
    + 'order without white space (given here as well); every row a different MAC.',
  fingerprints,
  macs,
});
write('reseal.json', {
  note: 'Generated by clients/clientkeys/scripts/keystore-vectors.mjs (scaas-sdk plan T2a) from src/vault.js resealData; never edit '
    + 'by hand. resealed = vault with data re-encrypted under the same DEK and a fresh IV: pin and prf byte for byte the same, data '
    + 'not; resealed opens to plaintext by the passphrase and (when prfOutput is set) by the PRF output, vault to before. DEK, IVs '
    + 'and salts come from a fixed stream.',
  reseals,
});
console.log(`keystore vectors: ${fingerprints.length} fingerprints, ${macs.length} MACs, ${reseals.length} re-sealed vaults -> ${OUT}`);

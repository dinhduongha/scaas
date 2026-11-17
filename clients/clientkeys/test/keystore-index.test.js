// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T2a: masterFingerprint against BIP-32's published vectors (outside data), the index MAC and the same-DEK re-seal
// against smartcontracts/vectors/keystore/{index_mac,reseal}.json, which the generator reproduces byte for byte.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { HDKey } from '@scure/bip32';
import { masterFingerprint, seedFromEntropy } from '../src/seed.js';
import { indexMac, indexCanonical, INDEX_FIELDS } from '../src/keystore-mac.js';
import { createVault, openVault, resealData } from '../src/vault.js';
import { fromHex, bytesToHex, utf8ToBytes } from '../src/bytes.js';

const DIR = fileURLToPath(new URL('../../../smartcontracts/vectors/keystore/', import.meta.url));
const load = (n) => JSON.parse(readFileSync(join(DIR, n), 'utf8'));
const bip32 = JSON.parse(readFileSync(new URL('./vectors/bip32-fingerprint.json', import.meta.url), 'utf8'));

test('masterFingerprint: the parent fingerprint of BIP-32 test vectors 1-3 (published children)', () => {
  assert.equal(bip32.rows.length, 3);
  for (const r of bip32.rows) {
    const child = HDKey.fromExtendedKey(r.child);
    assert.equal(child.depth, 1);
    assert.equal(masterFingerprint(fromHex(r.seed)), child.parentFingerprint.toString(16).padStart(8, '0'), `vector ${r.vector}`);
  }
  // control: another seed, another fingerprint
  assert.notEqual(masterFingerprint(fromHex(bip32.rows[0].seed)), masterFingerprint(fromHex(bip32.rows[1].seed)));
});

test('index_mac.json: fingerprints and MACs reproduce; every field changes the MAC; a missing field is refused', () => {
  const v = load('index_mac.json');
  for (const r of v.fingerprints) assert.equal(masterFingerprint(seedFromEntropy(fromHex(r.entropy), r.bip39Passphrase)), r.fingerprint, r.id);
  for (const r of v.macs) {
    assert.equal(indexCanonical(r.fields), r.canonical, r.id);
    assert.equal(indexMac(fromHex(r.entropy), r.fields), r.mac, r.id);
  }
  assert.equal(new Set(v.macs.map((r) => r.mac)).size, v.macs.length);
  const changed = new Set(v.macs.filter((r) => r.id.endsWith(' changed')).map((r) => r.id.split(' ')[0]));
  assert.deepEqual([...changed].sort(), [...INDEX_FIELDS].sort(), 'one row per field');
  const base = v.macs[0];
  // the canonical order is fixed: the same fields in another order give the same MAC
  const reordered = Object.fromEntries(Object.entries(base.fields).reverse());
  assert.equal(indexMac(fromHex(base.entropy), reordered), base.mac);
  const { accounts, ...noAccounts } = base.fields;
  assert.ok(accounts);
  assert.throws(() => indexMac(fromHex(base.entropy), noAccounts), /index field missing: accounts/);
});

test('reseal.json: the re-sealed vault keeps both envelopes and opens by passphrase and by PRF', async () => {
  for (const r of load('reseal.json').reseals) {
    assert.deepEqual(r.resealed.pin, r.vault.pin, r.id);
    assert.deepEqual(r.resealed.prf, r.vault.prf, r.id);
    assert.notDeepEqual(r.resealed.data, r.vault.data, r.id);
    assert.equal(bytesToHex(await openVault(r.resealed, { pin: r.pin })), r.plaintext.slice(2), r.id);
    assert.equal(bytesToHex(await openVault(r.vault, { pin: r.pin })), r.before.slice(2), r.id);
    if (r.prfOutput) assert.equal(bytesToHex(await openVault(r.resealed, { prfOutput: fromHex(r.prfOutput) })), r.plaintext.slice(2), r.id);
  }
});

test('resealData: the same DEK (a new vault would drop the PRF envelope); a wrong passphrase reseals nothing', async () => {
  const prf = { output: new Uint8Array(32).fill(7), credentialId: 'Yw', salt: new Uint8Array(32).fill(9) };
  const v = await createVault(utf8ToBytes('one'), { label: 'manifest', pin: 'river-otter-7', prf });
  const r = await resealData(v, { prfOutput: prf.output }, utf8ToBytes('two'));
  assert.deepEqual([r.pin, r.prf, r.label, r.v], [v.pin, v.prf, v.label, v.v]);
  assert.equal(new TextDecoder().decode(await openVault(r, { pin: 'river-otter-7' })), 'two');
  // control: a fresh vault of the same secret has its own DEK, no PRF envelope unless given again
  const fresh = await createVault(utf8ToBytes('two'), { label: 'manifest', pin: 'river-otter-7' });
  assert.equal(fresh.prf, undefined);
  assert.notDeepEqual(fresh.pin, v.pin);
  await assert.rejects(resealData(v, { pin: 'river-otter-8' }, utf8ToBytes('x')), (e) => e.code === 'VaultOpen');
});

test('the generator reproduces index_mac.json and reseal.json byte for byte', () => {
  const out = mkdtempSync(join(tmpdir(), 'keystore-vectors-'));
  try {
    execFileSync(process.execPath, [fileURLToPath(new URL('../scripts/keystore-vectors.mjs', import.meta.url)), out]);
    for (const n of ['index_mac.json', 'reseal.json']) assert.equal(readFileSync(join(out, n), 'utf8'), readFileSync(join(DIR, n), 'utf8'), n);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

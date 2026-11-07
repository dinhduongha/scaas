// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Group 3g (spec 2026-11-06-pqz-key-versions §7.2, KV-1, KV-7, KV-8, C8, F-14): the client's rules for PQZ key versions, apart from
// the vector rows (test/ua8.test.js, test/typed-ops.test.js). UNAUDITED.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as ua from '../src/ua.js';
import * as evm from '../src/evm.js';
import { pqzKeySeed } from '../src/pq.js';
import { seedFromWords } from '../src/seed.js';
import { hex, fromHex, concatBytes, utf8ToBytes } from '../src/bytes.js';

const json = (p) => JSON.parse(readFileSync(new URL(`../../../smartcontracts/vectors/${p}`, import.meta.url), 'utf8'));
const KAT = json('ua/pq_kat.json');
const P = json('ua/portable.json');
const T = json('typed/typed_ops.json');
const refuses = (f, code) => assert.throws(f, { code }, code);
const be32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };

test('C8: version 0 keeps the info without a suffix, version v >= 1 appends be64(v); the rows by hand', () => {
  assert.deepEqual(KAT.pqzSeeds.map((r) => r.version), [0, 1, 2]);
  const seed = seedFromWords(KAT.mnemonic);
  const info = (a, i) => concatBytes(utf8ToBytes('scaas.ua.pqz-mlwe.v1'), be32(a), be32(i));
  const salt = utf8ToBytes('scaas.ua.pq.v1');
  for (const r of KAT.pqzSeeds) {
    const suffix = r.version === 0 ? new Uint8Array(0) : fromHex(`0x${BigInt(r.version).toString(16).padStart(16, '0')}`);
    assert.equal(hex(hkdf(sha256, seed, salt, concatBytes(info(r.account, r.index), suffix), 32)), r.seed32, `v${r.version}`);
    assert.equal(hex(pqzKeySeed(seed, r.account, r.index, r.version)), r.seed32, `v${r.version}`);
  }
  assert.equal(hex(pqzKeySeed(seed, 0, 0)), KAT.pqzSeeds[0].seed32, 'version 0 is the default');
  assert.throws(() => pqzKeySeed(seed, 0, 0, 2n ** 64n), /uint64/);
});

test('the builder refuses a version-0 replacement, a gap, no version 0, a repeated key; the control passes', () => {
  const k = P.pqzKeyVersions.find((r) => r.name.startsWith('fndsa512/v1/'));
  const zero = P.pqzKeyRecords.find((r) => r.name === `fndsa512/${k.set}`);
  const keyData = P.registrations.find((r) => r.ua === k.ua).keyData;
  const at = (over) => ua.pqzKeyVersionRecordMessage(k.kind, { ua: k.ua, keyData, version: 1, pqzKey: k.pqzKey, pqzPopHash: k.pqzPopHash,
    stored: [{ version: 0, pqzKeyHash: zero.pqzKeyHash }], ...over });
  assert.equal(hex(at({}).recordDigest), k.recordDigest, 'the control');
  refuses(() => at({ version: 0 }), 'UAPqzKeySet');
  refuses(() => at({ version: 2 }), 'UAPqzKeyVersion');
  refuses(() => at({ stored: [] }), 'UAPqzKeyVersion');
  refuses(() => at({ stored: undefined }), 'UAPqzKeyVersion');
  refuses(() => at({ stored: [{ version: 0, pqzKeyHash: k.pqzKeyHash }] }), 'UAKeyInUse');
});

test('KV-7: a pending version is the latest of this set\'s length, not eligible; the decoy filter drops only those', () => {
  const LEN = 16384;
  const c = (name, length, eligible, rotatedRecently = false) => ({ ua: name, latest: { length, eligible }, rotatedRecently });
  assert.equal(ua.pqzKeyPending({ length: LEN, eligible: false }, LEN), true);
  assert.equal(ua.pqzKeyPending({ length: LEN, eligible: true }, LEN), false);
  assert.equal(ua.pqzKeyPending({ length: 12288, eligible: false }, LEN), false, 'another set\'s length never becomes current here');
  const got = ua.pqzDecoyCandidates([c('rotated', LEN, true, true), c('pending', LEN, false), c('other-set', 12288, false), c('plain', LEN, true)], LEN);
  assert.deepEqual(got.map((x) => x.ua), ['other-set', 'plain', 'rotated'], 'no pending; a recent rotation last');
});

test('F-14: a vault or backup key names (ua, version, pqzKeyHash): two keys at one number stay apart', () => {
  const [a, b] = [P.pqzKeyVersions[0], P.pqzKeyVersions[1]];
  const key = (version, pqzKeyHash) => ua.pqzVaultKey({ ua: a.ua, version, pqzKeyHash });
  assert.equal(key(1, a.pqzKeyHash), key(1, a.pqzKeyHash));
  assert.notEqual(key(1, a.pqzKeyHash), key(1, b.pqzKeyHash), 'one number, two keys');
  assert.notEqual(key(1, a.pqzKeyHash), key(2, a.pqzKeyHash), 'one key, two numbers');
});

// KV-8, KV-9, on the typed_ops.json rows with one field changed at a time
const domain = (name) => { const d = Object.values(T.ops[name].domains)[0].domain; return { name: d.name, contract: d.verifyingContract, chainId: d.chainId, chainUid: d.salt }; };
const debit = (name, over = {}, args = {}) => {
  const builder = evm.TYPED_OPS[name].builder;
  const m = T.ops[name].message;
  return evm.OP_BUILDERS[`${builder}TypedData`]({ ...domain(name), message: { ...m, ...over, args: { ...m.args, ...args } } });
};
const OTHER = `0x${'77'.repeat(32)}`;
const refusesMsg = (f, re) => assert.throws(f, re);

test('KV-8: at the current version every debit; a stale one only migrates or refreshes; above current none', () => {
  for (const name of ['UAPqzTransferSingle', 'UAPqzTransferSingleCompact', 'UAPqzTransfer', 'UAPqzTransferCompact', 'UAPqzUnshield', 'UAPqzUnshieldUnwrap']) {
    const td = debit(name, {}, { keyVersion: '3' });
    assert.equal(evm.checkPqzDebit(td, { current: 3 }).kind, 'debit', name);
    refusesMsg(() => evm.checkPqzDebit(td, { current: 4 }), /StaleKeyVersion/);
    refusesMsg(() => evm.checkPqzDebit(td, { current: 2 }), /KeyVersionUnknown/);
  }
  refusesMsg(() => evm.checkPqzDebit({ primaryType: 'UAShield', message: {} }, { current: 0 }), /not a PQZ debit/);
});

test('KV-9: op 1 to itself is the migration from a stale version, SelfTransfer at the current one', () => {
  for (const name of ['UAPqzTransferSingle', 'UAPqzTransferSingleCompact']) {
    const from = T.ops[name].message.args.fromUA;
    const td = debit(name, {}, { keyVersion: '1', toUA: from });
    const r = evm.checkPqzDebit(td, { current: 3 });
    assert.deepEqual([r.kind, r.show], ['migration', 'moves the balance of version 1 to version 3'], name);
    refusesMsg(() => evm.checkPqzDebit(td, { current: 1 }), /SelfTransfer/);
    refusesMsg(() => evm.checkPqzDebit(debit(name, {}, { keyVersion: '1', toUA: OTHER }), { current: 3 }), /StaleKeyVersion/);
  }
});

test('KV-8: the refresh is a burn of 0 with no recipient, the unwrap form never', () => {
  const Z = `0x${'00'.repeat(32)}`;
  const check = (over) => () => evm.checkPqzDebit(debit('UAPqzUnshield', over, { keyVersion: '1' }), { current: 2 });
  assert.equal(check({ amount: '0', recipient: Z })().kind, 'refresh');
  refusesMsg(check({ amount: '1', recipient: Z }), /StaleKeyVersion/);
  refusesMsg(check({ amount: '0', recipient: OTHER }), /StaleKeyVersion/);
  const m = T.ops.UAPqzUnshieldUnwrap.message;
  const unwrap = debit('UAPqzUnshieldUnwrap', { unwrap: { ...m.unwrap, amount: '0' } }, { keyVersion: '1' });
  refusesMsg(() => evm.checkPqzDebit(unwrap, { current: 2 }), /StaleKeyVersion/);
});

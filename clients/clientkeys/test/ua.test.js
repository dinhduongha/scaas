// The UA identity layer (src/ua.js) against smartcontracts/vectors/ua/: the generator reproduces both files byte for byte,
// the valid, invalid, pop, uaAuth and member rows hold through the public API (the other tables are covered by the regeneration), and pq.js (P6a) agrees on the PQ kinds.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import * as ua from '../src/ua.js';
import { PQ_KINDS, uaId, kindTag } from '../src/pq.js';
import { hex, fromHex } from '../src/bytes.js';

import { dir } from './ua-vectors-dir.js';
const K = JSON.parse(readFileSync(new URL('kinds.json', dir)));
const S = JSON.parse(readFileSync(new URL('structures.json', dir)));

test('the generator reproduces kinds.json and structures.json byte for byte', () => {
  const out = mkdtempSync(join(tmpdir(), 'ua-vectors-'));
  try {
    const r = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/ua-vectors.mjs', import.meta.url)), out], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    for (const f of ['kinds.json', 'structures.json']) {
      assert.equal(readFileSync(join(out, f), 'utf8'), readFileSync(new URL(f, dir), 'utf8'), f);
    }
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('valid rows derive, invalid rows fail with their code', () => {
  for (const r of K.valid) {
    assert.equal(hex(ua.deriveUA(r.kind, fromHex(r.keyData), { hederaNative: r.hederaNative })), r.ua, r.name);
    const h = ua.keyHashOf(r.kind, fromHex(r.keyData));
    assert.equal(h && hex(h), r.keyHash, r.name);
  }
  for (const r of K.invalid) {
    assert.throws(() => ua.validateKeyData(r.kind, fromHex(r.keyData), { hederaNative: r.hederaNative }),
      (e) => e instanceof ua.UAError && e.code === r.error, `${r.kind} ${r.reason}`);
  }
});

test('digests: popDigest, UAAuth, member', () => {
  for (const p of S.pop) {
    const c = S.contexts[p.context];
    assert.equal(hex(ua.popDigest({ ...c, ua: p.ua, pqzKeyHash: p.pqzKeyHash })), p.popDigest);
  }
  for (const a of S.uaAuth) {
    const domain = { generation: a.generation, ...S.contexts[a.context] };
    assert.equal(hex(ua.uaAuthDigest(domain, a.ua, a.purposeTag, a.digest)), a.uaAuthDigest);
  }
  for (const m of S.member) assert.equal(hex(ua.memberDigest(m.structureUa, m.uaMsg)), m.memberDigest);
});

test('pq.js and ua.js agree on the PQ kinds', () => {
  for (const [name, { kind }] of Object.entries(PQ_KINDS)) {
    assert.equal(hex(kindTag(name)), hex(ua.TAG(kind)), name);
    const r = K.valid.find((v) => v.kind === kind);
    assert.equal(hex(uaId(name, fromHex(r.keyData))), r.ua, name);
  }
});

test('key data that is neither bytes nor a hex string is UAKeyData type', () => {
  for (const v of [5, 5n, null, undefined, [1, 2], {}]) {
    for (const f of [() => ua.validateKeyData(0x0101, v), () => ua.deriveUA(0x0101, v), () => ua.uaOf(0x0101, v),
      () => ua.keyHashOf(0x0101, v), () => ua.nativeId(0x0001, v)]) {
      assert.throws(f, (e) => e instanceof ua.UAError && e.code === 'UAKeyData' && e.reason === 'type');
    }
  }
});

test('UA-6: 0x0142 is a scheme, not a kind; 0x0140 is gone; Zether is 0x0141 alone and signs', () => {
  assert.equal(ua.KINDS.some((k) => k.kind === 0x0140 || k.kind === 0x0142), false);
  assert.deepEqual(ua.SCHEMES.map((s) => [s.kind, s.name, s.group]), [[0x0142, 'pqz-mlwe', 'pqz-mlwe']]);
  assert.equal(ua.kindTagString(0x0142), 'scaas.ua.pqz-mlwe.v1'); // the tag and the keyHash group survive
  assert.ok(ua.GROUPS.includes('pqz-mlwe'));
  const key = new Uint8Array(16384);
  assert.equal(hex(ua.keyHashOf(0x0142, key)).length, 66);
  assert.equal(hex(ua.uaMessage(0x0142, ua.POP_TAG, new Uint8Array(32))).length, 66);
  for (const f of [() => ua.uaOf(0x0142, key), () => ua.deriveUA(0x0142, key), () => ua.validateKeyData(0x0142, key)]) {
    assert.throws(f, (e) => e instanceof ua.UAError && e.code === 'UAKindNotDerived');
  }
  assert.throws(() => ua.kindInfo(0x0140), (e) => e.code === 'UAKindUnknown');
  assert.throws(() => ua.uaOf(0x0140, new Uint8Array(64)), (e) => e.code === 'UAKindUnknown');
  assert.deepEqual([0x0140, 0x0141, 0x0142].map(ua.isZetherKind), [false, true, false]);
  assert.deepEqual([0x0141, 0x0120, 0x0130, 0x0142].map(ua.isSigningKind), [true, true, true, false]);
  assert.equal(ua.isMemberKind(0x0141), false);
  assert.equal(ua.PURPOSES.includes('authref'), false);
  assert.throws(() => ua.purposeTag('authref'), (e) => e.code === 'UAPurposeUnknown');
});

test('UA-6: PQZ holders, msig eligibility, pop digest and R_REG message', () => {
  assert.deepEqual([0x012f, 0x0130, 0x0131, 0x0132, 0x0133].map(ua.isPqzHolder), [false, true, true, true, false]);
  const m = (t, ...ms) => ua.encodeMsig(t, ms.map(([kind, weight], i) => ({ kind, id: new Uint8Array(32).fill(i + 1), weight })));
  assert.equal(ua.msigPqzEligible(m(2, [0x0101, 1], [0x0130, 1])), true);
  assert.equal(ua.msigPqzEligible(m(1, [0x0101, 1], [0x0130, 1])), false); // classical weight = threshold
  assert.equal(ua.msigPqzEligible(m(2, [0x0130, 1], [0x0133, 1])), true); // slhdsa128s counts as PQ
  assert.equal(ua.msigPqzEligible(m(3, [0x0101, 2], [0x0131, 2])), true);
  assert.throws(() => ua.msigPqzEligible(new Uint8Array(5)), (e) => e.code === 'UAKeyData');
  const c = { chainId: 31337, chainUid: '0x' + '24'.repeat(32), registry: '0x' + 'aa'.repeat(20), ua: '0x' + '11'.repeat(32) };
  const h = ua.keyHashOf(0x0142, new Uint8Array(16384));
  assert.equal(hex(ua.popDigest(c)), hex(ua.popDigest({ ...c, pqzKeyHash: new Uint8Array(32) })), 'no key: the bytes of the former authRef = 0');
  assert.notEqual(hex(ua.popDigest({ ...c, pqzKeyHash: h })), hex(ua.popDigest(c)));
  const hp = ua.holderPopMessage(0x0130, { ...c, pqzKey: new Uint8Array(16384) });
  assert.equal(hex(hp.pqzKeyHash), hex(h));
  assert.equal(hex(hp.message), hex(ua.uaMessage(0x0130, ua.POP_TAG, ua.popDigest({ ...c, pqzKeyHash: h }))));
  assert.equal(hex(ua.holderPopMessage(0x0130, c).popDigest), hex(ua.popDigest(c)), 'no key: the plain pop');
  assert.equal(hex(ua.pqzRegMessage({ ...c, pqzKey: new Uint8Array(16384) })),
    hex(ua.uaMessage(0x0142, ua.POP_TAG, ua.popDigest({ ...c, pqzKeyHash: h }))));
});

test('UA-6 vectors: schemes, holder flags, pqz_reg_message and msig eligibility rows', () => {
  assert.deepEqual(K.schemes.map((s) => [s.kind, s.name, s.group, s.TAG]), [[0x0142, 'pqz-mlwe', 'pqz-mlwe', hex(ua.TAG(0x0142))]]);
  for (const k of K.kinds) assert.equal(k.pqzHolder, ua.isPqzHolder(k.kind), k.name);
  assert.equal(K.kinds.some((k) => k.kind === 0x0140 || k.kind === 0x0142), false);
  assert.equal(K.valid.some((r) => r.kind === 0x0140 || r.kind === 0x0142), false);
  assert.equal(K.purposes.some((p) => p.purpose === 'authref'), false);
  assert.equal(K.pqzKeyHash, hex(ua.keyHashOf(0x0142, fromHex(K.pqzKey))));
  for (const r of K.invalid.filter((x) => x.kind === 0x0142)) assert.equal(r.error, 'UAKindNotDerived');
  for (const p of S.pop) assert.equal('authRef' in p, false);
  for (const r of S.pqzReg) {
    const c = S.contexts[r.context];
    assert.equal(hex(ua.pqzRegMessage({ ...c, ua: r.ua, pqzKey: K.pqzKey })), r.pqzRegMessage);
    assert.equal(hex(ua.popDigest({ ...c, ua: r.ua, pqzKeyHash: r.pqzKeyHash })), r.popDigest);
  }
  for (const r of S.pqzMsig) assert.equal(ua.msigPqzEligible(r.keyData), r.eligible, r.reason);
  assert.ok(S.pqzMsig.some((r) => r.eligible) && S.pqzMsig.some((r) => !r.eligible));
});

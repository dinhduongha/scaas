// The UA identity layer (src/ua.js) against smartcontracts/vectors/ua/: the generator reproduces both files byte for byte,
// the valid, invalid, portable pop (UA-8), uaAuth and member rows hold through the public API (the other tables are covered by the regeneration), and pq.js (P6a) agrees on the PQ kinds.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import * as ua from '../src/ua.js';
import { PQ_KINDS, uaId, kindTag } from '../src/pq.js';
import { hex, fromHex, keccak_256 } from '../src/bytes.js';

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

test('digests: portable pop (UA-8, no chain context; typed records), UAAuth, member', () => {
  assert.equal(S.version, 3);
  for (const p of S.pop) {
    assert.equal('context' in p, false);
    const w = { ua: p.ua, kind: p.kind, pqzKeyHash: p.pqzKeyHash, kemRecordHash: p.kemRecordHash };
    assert.equal(hex(ua.portableRecordDigest(w)), p.portableRecordDigest);
    assert.equal(hex(ua.registrationDigest({ ...w, pqzPopHash: p.pqzPopHash })), p.registrationDigest);
  }
  assert.ok(S.pop.some((p) => p.kind === 0x0141), 'the Zether row');
  for (const a of S.uaAuth) {
    const domain = { generation: a.generation, ...S.contexts[a.context] };
    assert.equal(hex(ua.uaAuthDigest(domain, a.ua, a.purposeTag, a.digest)), a.uaAuthDigest);
  }
  for (const m of S.member) assert.equal(hex(ua.memberDigest(m.structureUa, m.uaMsg)), m.memberDigest);
});

test('purposes: every purpose at v1, pop also at v2 (UA-8), kem', () => {
  assert.deepEqual(K.purposes.map((p) => `${p.purpose}.v${p.version}`).filter((x) => x.startsWith('pop') || x.startsWith('kem')),
    ['pop.v1', 'kem.v1', 'pop.v2']);
  for (const p of K.purposes) {
    assert.equal(p.tag, `scaas.ua.purpose.${p.purpose}.v${p.version}`);
    assert.equal(hex(ua.purposeTag(p.purpose, p.version)), p.purposeTag, p.tag);
  }
  assert.equal(hex(ua.POP_V2_TAG), K.purposes.find((p) => p.purpose === 'pop' && p.version === 2).purposeTag);
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
  assert.equal(ua.msigPqzEligible(m(2, [0x0101, 1], [0x0133, 2])), true); // decides: only if 0x0133 counts as PQ weight
  assert.equal(ua.msigPqzEligible(m(2, [0x0101, 1], [0x0141, 2])), false); // a non-PQ member of the same weight does not
  assert.throws(() => ua.msigPqzEligible(new Uint8Array(5)), (e) => e.code === 'UAKeyData');
  const u = '0x' + '11'.repeat(32);
  const key = new Uint8Array(16384);
  const proof = Uint8Array.of(0xaa);
  const h = ua.keyHashOf(0x0142, key);
  const z = new Uint8Array(32);
  const none = ua.kemRecordHash({ ua: u }); // no KEM record = the zero record UAKemRecord{u, 0, 0, 0} (TS-D2)
  assert.equal(hex(ua.portableRecordDigest({ ua: u, kind: 0x0130 })),
    hex(ua.portableRecordDigest({ ua: u, kind: 0x0130, pqzKeyHash: z, kemRecordHash: none })), 'absent = 0 / the zero record');
  assert.notEqual(hex(ua.portableRecordDigest({ ua: u, kind: 0x0130, kemRecordHash: z })), hex(ua.portableRecordDigest({ ua: u, kind: 0x0130 })));
  assert.notEqual(hex(ua.portableRecordDigest({ ua: u, kind: 0x0130, pqzKeyHash: h })), hex(ua.portableRecordDigest({ ua: u, kind: 0x0130 })));
  const hp = ua.holderPopMessage(0x0130, { ua: u, pqzKey: key, pqzPop: proof });
  assert.equal(hex(hp.pqzKeyHash), hex(h));
  assert.equal(hex(hp.pqzPopHash), hex(keccak_256(proof)));
  assert.equal(hex(hp.message), hex(ua.uaMessage(0x0130, ua.POP_V2_TAG,
    ua.registrationDigest({ ua: u, kind: 0x0130, pqzKeyHash: h, pqzPopHash: keccak_256(proof) }))));
  assert.throws(() => ua.holderPopMessage(0x0101, { ua: u, pqzKey: key, pqzPop: proof }), (e) => e.code === 'UAPqzHolder');
  assert.throws(() => ua.holderPopMessage(0x0133, { ua: u, pqzKey: key, pqzPop: proof }), (e) => e.code === 'UAPqzHolder');
  assert.equal(hex(ua.holderPopMessage(0x0130, { ua: u }).registrationDigest),
    hex(ua.registrationDigest({ ua: u, kind: 0x0130 })), 'no key: the plain pop');
  assert.equal(hex(ua.pqzRegMessage({ ua: u, kind: 0x0130, pqzKey: key })),
    hex(ua.uaMessage(0x0142, ua.POP_V2_TAG, ua.portableRecordDigest({ ua: u, kind: 0x0130, pqzKeyHash: h }))));
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
    assert.equal(r.pqzKeyHash, K.pqzKeyHash);
    assert.equal(hex(ua.portableRecordDigest({ ua: r.ua, kind: r.kind, pqzKeyHash: r.pqzKeyHash, kemRecordHash: r.kemRecordHash })),
      r.portableRecordDigest);
    assert.equal(hex(ua.uaMessage(0x0142, ua.POP_V2_TAG, fromHex(r.portableRecordDigest))), r.pqzRegMessage);
  }
  assert.equal(new Set(S.pqzReg.map((r) => r.pqzRegMessage)).size, S.pqzReg.length);
  for (const r of S.pqzMsig) {
    const pqzKeyHash = r.eligible ? fromHex(K.pqzKeyHash) : new Uint8Array(32);
    assert.equal(hex(ua.portableRecordDigest({ ua: r.ua, kind: 0x0120, pqzKeyHash })), r.portableRecordDigest, r.reason);
  }
  for (const r of S.pqzMsig) assert.equal(ua.msigPqzEligible(r.keyData), r.eligible, r.reason);
  assert.ok(S.pqzMsig.some((r) => r.eligible) && S.pqzMsig.some((r) => !r.eligible));
});

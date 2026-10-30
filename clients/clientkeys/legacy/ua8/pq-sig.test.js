// smartcontracts/vectors/ua/pq_signatures.json (P6c): the PQ kinds on context A. Keys = pq_kat.json's (same seed path),
// ids and PoP digests rebuilt from src/ua.js, every signature re-verified with noble, every negative refused, the msig
// structures re-encoded, the metatx3 rows' typed data hashed to their digests. On chain: test/ua/UARegistryPq.t.sol and
// test/ua/UAMetaTx3Pq.t.sol with the real verifiers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { seedFromWords } from '../src/seed.js';
import { PQ_KINDS, pqKeygen, pqMessage } from '../src/pq.js';
import * as ua from '../src/ua.js';
import { hex, fromHex, abiEncode } from '../src/bytes.js';
import { hashTypedData } from '../src/evm.js';

import { dir } from './ua-vectors-dir.js';
const V = JSON.parse(readFileSync(new URL('pq_signatures.json', dir)));
const K = JSON.parse(readFileSync(new URL('pq_kat.json', dir)));
const seed = seedFromWords(V.mnemonic);
const tag = (p) => ua.purposeTag(p);
const nameOf = (kind) => Object.keys(PQ_KINDS).find((n) => PQ_KINDS[n].kind === kind);
const ok = (kind, pk, uaMsg, sig) => {
  const n = nameOf(kind);
  const m = PQ_KINDS[n].pq ? pqMessage(n, fromHex(uaMsg)) : fromHex(uaMsg);
  try { return PQ_KINDS[n].alg.verify(fromHex(sig), m, fromHex(pk)); } catch { return false; }
};

test('keys and ids: pq_kat.json\'s keys, ids from the kind table, PoP digests of contexts A and B', () => {
  assert.equal(V.mnemonic, K.mnemonic);
  assert.deepEqual(V.kinds.map((r) => r.name), Object.keys(PQ_KINDS));
  for (const r of V.kinds) {
    assert.equal(r.keyData, K.kinds[r.name].pk, r.name);
    assert.equal(hex(ua.deriveUA(r.kind, fromHex(r.keyData))), r.ua, r.name);
    for (const p of [r.pop, r.popOther]) {
      const d = ua.popDigest({ ...V.contexts[p.context], ua: fromHex(r.ua) });
      assert.equal(hex(d), p.popDigest);
      assert.equal(hex(ua.uaMessage(r.kind, ua.POP_TAG, d)), p.message);
    }
  }
  for (const x of V.extraKeys) {
    const kp = pqKeygen(seed, x.name, 0, x.index);
    assert.equal(hex(kp.publicKey), x.keyData);
    assert.equal(hex(kp.ua), x.ua);
  }
});

test('every PoP and signature verifies with noble; every negative is refused', () => {
  let negs = 0;
  for (const r of V.kinds) {
    assert.ok(ok(r.kind, r.keyData, r.pop.message, r.pop.sig), `${r.name} pop A`);
    assert.ok(ok(r.kind, r.keyData, r.popOther.message, r.popOther.sig), `${r.name} pop B`);
    for (const s of r.sigs) {
      assert.equal(hex(ua.uaMessage(r.kind, tag(s.purpose), fromHex(s.digest))), s.message);
      assert.ok(ok(r.kind, r.keyData, s.message, s.sig), `${r.name} ${s.purpose}`);
    }
    for (const n of r.negatives) {
      assert.equal(ok(r.kind, r.keyData, n.message, n.sig), false, `${r.name} ${n.name}`);
      negs++;
    }
  }
  assert.equal(negs, 33);
  for (const x of V.extraKeys) assert.ok(ok(x.kind, x.keyData, x.pop.message, x.pop.sig), `extra ${x.index}`);
});

test('UA-6: a holder registers its PQZ key in the same call: pop over popDigest(ua, h), h = keyHash(0x0142, pqzKey) != 0', () => {
  const h = hex(ua.keyHashOf(0x0142, fromHex(V.kinds[0].pqzKey)));
  assert.notEqual(h, '0x' + '00'.repeat(32));
  const holders = V.kinds.filter((r) => r.popPqz);
  assert.deepEqual(holders.map((r) => r.name), ['mldsa44', 'mldsa65', 'fndsa512']); // slhdsa128s holds none
  for (const r of holders) {
    const p = r.popPqz;
    assert.equal(p.pqzKeyHash, h);
    const d = ua.popDigest({ ...V.contexts[p.context], ua: fromHex(r.ua), pqzKeyHash: h });
    assert.equal(hex(d), p.popDigest);
    assert.notEqual(p.popDigest, r.pop.popDigest, 'h moves the digest');
    assert.equal(hex(ua.uaMessage(r.kind, ua.POP_TAG, d)), p.message);
    assert.ok(ok(r.kind, r.keyData, p.message, p.sig), `${r.name} pop with the key`);
    assert.ok(!ok(r.kind, r.keyData, p.message, r.pop.sig), `${r.name}: the plain pop is not the holder's pop`);
    assert.equal(hex(ua.pqzRegMessage({ ...V.contexts[p.context], ua: fromHex(r.ua), pqzKey: fromHex(r.pqzKey) })),
      hex(ua.uaMessage(0x0142, ua.POP_TAG, d)), 'R_REG message');
  }
});

test('msig structures: key data, id, member digest; every member signature verifies; auth = abi.encode(keyData, sig)', () => {
  const keyOf = Object.fromEntries([...V.kinds, ...V.extraKeys].map((r) => [r.ua, r.keyData]));
  let pqSigs = 0;
  for (const m of [V.msig.treasury, V.msig.hybrid]) {
    const kd = ua.encodeMsig(m.threshold, m.members.map((x) => ({ kind: x.kind, id: fromHex(x.id), weight: x.weight })));
    assert.equal(hex(kd), m.keyData, m.name);
    assert.equal(hex(ua.deriveUA(0x0120, kd)), m.ua, m.name);
    const md = ua.memberDigest(fromHex(m.ua), ua.uaMessage(0x0120, tag(m.purpose), fromHex(m.digest)));
    assert.equal(hex(md), m.memberDigest, m.name);
    for (const s of m.sets) {
      assert.equal(s.auth, hex(abiEncode(['bytes', 'bytes'], [kd, fromHex(s.sig)])), s.name);
      assert.deepEqual(s.memberSigs.map((x) => x.index), s.indices);
      for (const x of s.memberSigs) {
        const mem = m.members[x.index];
        if (mem.kind !== 0x0131) continue; // the p256 member is signatures.json's key (re-verified in ua-sig.test.js)
        assert.equal(x.keyData, '0x', 'stored kind: no key data');
        assert.ok(ok(0x0131, keyOf[mem.id], hex(ua.uaMessage(0x0131, tag('member'), md)), x.sig), `${m.name} ${s.name} ${x.index}`);
        pqSigs++;
      }
    }
  }
  assert.equal(pqSigs, 6);
  // UA-6 U5: a PQ-eligible msig registers with an m-of-n pop over popDigest(ua, h) (purpose pop, members under member)
  for (const m of [V.msig.treasury, V.msig.hybrid]) {
    assert.equal(m.pqzEligible, true, m.name);
    assert.equal(ua.msigPqzEligible(fromHex(m.keyData)), true, m.name);
    const pd = ua.popDigest({ ...V.contexts[m.popPqz.context], ua: fromHex(m.ua), pqzKeyHash: fromHex(m.popPqz.pqzKeyHash) });
    assert.equal(hex(pd), m.popPqz.popDigest);
    assert.equal(hex(ua.memberDigest(fromHex(m.ua), ua.uaMessage(0x0120, ua.POP_TAG, pd))), m.popPqz.memberDigest);
  }
});

test('metatx3 rows: typed data → digest, one call and one transfer per PQ kind, auth with empty key data', () => {
  for (const rows of [V.metatx3.call, V.metatx3.transfer]) {
    assert.deepEqual(rows.map((r) => r.from), V.kinds.map((k) => k.ua));
    for (const r of rows) {
      assert.equal(hex(hashTypedData(r.typedData)), r.digest, r.name);
      assert.equal(r.typedData.domain.verifyingContract.toLowerCase(), V.metatx3.token);
      assert.ok(r.auth.startsWith(`0x${'0'.repeat(62)}40`), 'abi.encode(bytes(""), sig)');
    }
  }
});

test('metatx3 receiverFee (UA-5a): an mldsa65 payer and an mldsa65 payee, both signatures verify with noble', () => {
  const [r] = V.metatx3.receiverFee;
  assert.equal(V.metatx3.receiverFee.length, 1);
  const payer = V.kinds.find((k) => k.name === 'mldsa65');
  const payee = V.extraKeys.find((x) => x.name === 'mldsa65' && x.index === 1);
  assert.deepEqual([r.transfer.message.from, r.transfer.message.to], [payer.ua, payee.ua]);
  assert.equal(hex(hashTypedData(r.transfer)), r.paymentDigest);
  assert.equal(r.receiverFee.message.paymentDigest, r.paymentDigest);
  assert.equal(hex(hashTypedData(r.receiverFee)), r.receiverFeeDigest);
  // abi.encode(bytes(""), sig): heads 0x40, 0x60; keyData length 0; sig length; sig
  const sigOf = (auth) => { const b = fromHex(auth); return hex(b.subarray(128, 128 + Number(BigInt(hex(b.subarray(96, 128)))))); };
  for (const [auth, purpose, digest, k] of [[r.payerAuth, 'metatx', r.paymentDigest, payer],
    [r.payeeAuth, 'receiver-fee', r.receiverFeeDigest, payee]]) {
    assert.ok(auth.startsWith(`0x${'0'.repeat(62)}40`), 'abi.encode(bytes(""), sig)');
    const m = hex(ua.uaMessage(0x0131, tag(purpose), fromHex(digest)));
    assert.ok(ok(0x0131, k.keyData, m, sigOf(auth)), purpose);
    assert.ok(!ok(0x0131, k.keyData, hex(ua.uaMessage(0x0131, tag(purpose === 'metatx' ? 'receiver-fee' : 'metatx'),
      fromHex(digest))), sigOf(auth)), `${purpose}: the other purpose fails`);
  }
});

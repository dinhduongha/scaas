// smartcontracts/vectors/ua/uatrade_kat.json (UA-5b, dex.md CTR-DEX-25/26): a UA's order, its cancel and the lane
// invalidation under the purpose trade. Each row's typed data hashes to its digest and the builders rebuild it; the native
// rows recover the native key; p256, bip340 and ed25519 auths verify with noble under trade and fail under metatx; the
// mldsa65 rows verify with @noble/post-quantum (the other derived kinds: on chain, test/ua/UATradeVectors.t.sol).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as ua from '../src/ua.js';
import { schnorrVerify as zetherVerify } from '../src/zether.js';
import { hex, fromHex, keccak_256, concatBytes } from '../src/bytes.js';
import { PQ_KINDS, pqMessage } from '../src/pq.js';
import { hashTypedData, hashStruct, padId, uaTradeOrderTypedData, uaInvalidateNoncesTypedData, orderCancelTypedData,
  checkTradeOrder, checkCancel } from '../src/evm.js';

import { dir } from './ua-vectors-dir.js';
const V = JSON.parse(readFileSync(new URL('uatrade_kat.json', dir)));
const S = JSON.parse(readFileSync(new URL('signatures.json', dir)));
const P = JSON.parse(readFileSync(new URL('pq_signatures.json', dir)));
const at = { chainId: V.chainId, chainUid: V.chainUid };

const recover = (sig, digest) => {
  const s = fromHex(sig);
  const rec = secp256k1.Signature.fromBytes(s.subarray(0, 64), 'compact').addRecoveryBit(s[64] - 27);
  return hex(keccak_256(rec.recoverPublicKey(fromHex(digest)).toBytes(false).subarray(1)).subarray(12));
};
const split = (auth) => {
  const b = fromHex(auth);
  const word = (o) => Number(BigInt(hex(b.subarray(o, o + 32))));
  const bytesAt = (head) => { const o = word(head); return b.subarray(o + 32, o + 32 + word(o)); };
  return [bytesAt(0), bytesAt(32)];
};
const NOBLE = {
  0x0101: (kd, m, sig) => p256.verify(sig, sha256(m), concatBytes(Uint8Array.of(4), kd), { prehash: false, lowS: true }),
  0x0103: (kd, m, sig) => schnorr.verify(sig, m, kd),
  0x0102: (kd, m, sig) => ed25519.verify(sig, m, kd, { zip215: false }),
  0x0141: (kd, m, sig) => zetherVerify('bls12381', kd, m, sig), // UA-6: the Zether UA signs every write
};
/** true / false where noble can tell; null for a kind verified on chain only. */
const authOk = (from, purpose, digest, auth) => {
  if (from === S.native.ua) return recover(auth, digest) === S.native.address;
  const d = S.derived.find((x) => x.ua === from);
  const [kd, sig] = split(auth);
  assert.equal(hex(kd), d.stored ? '0x' : d.keyData, 'a stored kind (Zether) sends no key data');
  return NOBLE[d.kind] ? NOBLE[d.kind](d.stored ? fromHex(d.keyData) : kd, ua.uaMessage(d.kind, ua.purposeTag(purpose), fromHex(digest)), sig) : null;
};

test('typehashes, the purpose tag and the signer set', () => {
  const th = (td) => hex(keccak_256(new TextEncoder().encode(
    `${td.primaryType}(${td.types[td.primaryType].map((f) => `${f.type} ${f.name}`).join(',')})`)));
  assert.equal(th(V.rows[0].order), V.typeHashes.UATradeOrder);
  assert.equal(th(V.rows[0].invalidate), V.typeHashes.UAInvalidateNonces);
  assert.equal(V.purposeTag, hex(ua.purposeTag('trade')));
  assert.deepEqual(V.rows.map((r) => r.from), [S.native.ua, ...S.derived.map((d) => d.ua)]);
  assert.equal(V.rows[0].from, padId(S.native.address));
  assert.equal(hex(hashStruct(V.rows[0].order.types, 'EIP712Domain', { ...V.rows[0].order.domain })), V.domainSeparatorA);
});

test('every row: order, cancel and invalidate digests; the builders rebuild the typed data', () => {
  let nobled = 0;
  for (const r of V.rows) {
    const m = r.order.message;
    assert.deepEqual(uaTradeOrderTypedData({ ...at, token: V.tokenA, order: m }), r.order, r.name);
    assert.equal(hex(hashStruct(r.order.types, 'UATradeOrder', m)), r.structHash);
    assert.equal(hex(hashTypedData(r.order)), r.orderHash, r.name);
    assert.equal(hex(hashTypedData(orderCancelTypedData({ ...at, contract: V.tokenA, orderHash: r.orderHash }))), r.cancelDigest);
    assert.deepEqual(uaInvalidateNoncesTypedData({ ...at, contract: V.tokenA, from: r.from, batch: 1, minNonce: 5 }), r.invalidate);
    assert.equal(hex(hashTypedData(r.invalidate)), r.invalidateDigest);
    for (const [d, auth] of [[r.orderHash, r.auth], [r.cancelDigest, r.cancelAuth], [r.invalidateDigest, r.invalidateAuth]]) {
      const v = authOk(r.from, 'trade', d, auth);
      assert.notEqual(v, false, r.name);
      if (v === true) nobled++;
      if (v === true && r.from !== S.native.ua) assert.equal(authOk(r.from, 'metatx', d, auth), false, 'the purpose binds');
    }
  }
  assert.equal(nobled, 3 * 5, 'native ECDSA, p256, bip340, ed25519, zether x order / cancel / invalidate');
  const n = V.nativeMaker;
  assert.equal(hex(hashTypedData(n.order)), n.orderHash);
  assert.equal(recover(n.auth, n.orderHash), S.native.address);
});

test('mldsa65 orders for the caps verify with noble under trade', () => {
  const keys = [P.kinds.find((k) => k.name === 'mldsa65'), ...P.extraKeys];
  assert.deepEqual(V.pq.map((r) => r.from), keys.map((k) => k.ua));
  for (const r of V.pq) {
    assert.equal(hex(hashTypedData(r.order)), r.orderHash);
    const [kd, sig] = split(r.auth);
    assert.equal(kd.length, 0, 'stored kind: empty keyData');
    const msg = ua.uaMessage(0x0131, ua.purposeTag('trade'), fromHex(r.orderHash));
    assert.ok(PQ_KINDS.mldsa65.alg.verify(sig, pqMessage('mldsa65', msg), fromHex(keys[r.index].keyData)), r.name);
    const other = ua.uaMessage(0x0131, ua.purposeTag('metatx'), fromHex(r.orderHash));
    assert.equal(PQ_KINDS.mldsa65.alg.verify(sig, pqMessage('mldsa65', other), fromHex(keys[r.index].keyData)), false);
  }
});

test('checkTradeOrder({ ua }) accepts the order built from the input and refuses any other; checkCancel UA invalidate', () => {
  const r = V.rows[1];
  const m = r.order.message;
  const input = { receiveToken: m.receiveToken, amount: m.amount, receiveAmount: m.receiveAmount, fee: m.fee,
    relayer: m.relayer, dex: m.dex, batch: m.batch, validUntil: m.validUntil };
  const opts = { account: r.from, ...at, order: input, sellToken: V.tokenA, dexes: [V.dex], ua: true, now: 1800000000 };
  const ok = checkTradeOrder(r.order, opts);
  assert.equal(hex(ok.digest), r.orderHash);
  assert.deepEqual(ok.warnings, []);
  assert.throws(() => checkTradeOrder({ ...r.order, message: { ...m, amount: '1001' } }, opts), /Refusing/);
  assert.throws(() => checkTradeOrder(r.order, { ...opts, ua: false }), /Refusing/);
  assert.throws(() => checkTradeOrder(r.order, { ...opts, outside: true }), /Refusing/);
  const away = uaTradeOrderTypedData({ ...at, token: V.tokenA, order: { ...m, destination: V.rows[2].from } });
  assert.deepEqual(checkTradeOrder(away, { ...opts, order: { ...input, destination: V.rows[2].from } }).warnings,
    ['someone else receives the proceeds']);
  assert.equal(hex(checkCancel(r.invalidate, { account: r.from, ...at, contract: V.tokenA, ua: true,
    invalidate: { batch: 1, minNonce: 5 } })), r.invalidateDigest);
  assert.throws(() => checkCancel(r.invalidate, { account: V.rows[2].from, ...at, contract: V.tokenA, ua: true,
    invalidate: { batch: 1, minNonce: 5 } }), /Refusing/);
});

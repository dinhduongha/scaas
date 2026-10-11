// PQ UA kinds (src/pq.js) against smartcontracts/vectors/ua/pq_kat.json, the vectors the forge suite verifies on chain
// (test/ua/PqVerifiers.t.sol): same keys from the seed, same ids and messages, the same deterministic signatures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { seedFromWords } from '../src/seed.js';
import {
  PQ_KINDS, pqSeed, pqKeygen, kindTag, uaId, uaMessage, pqMessage, signedMessage, signUA, verifyUA, purposeTag, mldsaExpandedKey,
} from '../src/pq.js';
import { hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';
import { shake256 } from '@noble/hashes/sha3.js';

const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/ua/pq_kat.json', import.meta.url)));
const seed = seedFromWords(V.mnemonic);
const purpose = fromHex(V.purpose_tag);
const digest = fromHex(V.digest);

test('purpose tag and digest of the vectors', () => {
  assert.equal(hex(purposeTag('pop')), V.purpose_tag);
  assert.equal(hex(digest), hex(keccak_256(utf8ToBytes('scaas p6a pq vector digest'))));
});

for (const name of Object.keys(PQ_KINDS)) {
  const v = V.kinds[name];
  test(`${name}: seed → key, UA id, ua_msg, signed message = vectors`, () => {
    const kp = pqKeygen(seed, name, V.account, V.index);
    assert.equal(hex(kp.publicKey), v.pk);
    assert.equal(hex(kp.ua), v.ua);
    assert.equal(hex(uaId(name, kp.publicKey)), v.ua);
    assert.equal(hex(kindTag(name)), v.tag_hash);
    assert.equal(hex(uaMessage(name, purpose, digest)), v.ua_msg);
    const signed = signedMessage(name, purpose, digest);
    assert.equal(hex(signed), v.signed_message);
    // ML-DSA and SLH-DSA sign pq_msg; Falcon signs ua_msg itself
    assert.equal(hex(signed), PQ_KINDS[name].pq ? hex(pqMessage(name, fromHex(v.ua_msg))) : v.ua_msg);
  });

  test(`${name}: deterministic signature = vector; verifies; tampering fails`, () => {
    const kp = pqKeygen(seed, name, V.account, V.index);
    const opts = name === 'fndsa512'
      ? { random: (n) => shake256(utf8ToBytes('scaas p6a falcon randomness'), { dkLen: n }) }
      : { extraEntropy: false };
    const sig = signUA(name, kp.secretKey, purpose, digest, opts);
    assert.equal(hex(sig), v.sig);
    assert.ok(verifyUA(name, kp.publicKey, purpose, digest, sig));
    assert.ok(!verifyUA(name, kp.publicKey, purposeTag('metatx'), digest, sig), 'another purpose');
    const other = name === 'mldsa44' ? 'mldsa65' : 'mldsa44';
    assert.notEqual(hex(signedMessage(other, purpose, digest)), hex(signedMessage(name, purpose, digest)), 'kind-tagged');
    // hedged signing (the default) still verifies
    assert.ok(verifyUA(name, kp.publicKey, purpose, digest, signUA(name, kp.secretKey, purpose, digest)));
  });
}

test('PQ seeds: HKDF per kind, account and index; lengths per scheme', () => {
  assert.equal(pqSeed(seed, 'mldsa44', 0, 0).length, 32);
  assert.equal(pqSeed(seed, 'slhdsa128s', 0, 0).length, 48);
  assert.equal(pqSeed(seed, 'fndsa512', 0, 0).length, 48);
  assert.notEqual(hex(pqSeed(seed, 'mldsa44', 0, 0)), hex(pqSeed(seed, 'mldsa44', 0, 1)));
  assert.notEqual(hex(pqSeed(seed, 'mldsa44', 0, 0)), hex(pqSeed(seed, 'mldsa44', 1, 0)));
  assert.notEqual(hex(pqSeed(seed, 'mldsa44', 0, 0)), hex(pqSeed(seed, 'mldsa65', 0, 0)));
});

test('EIP-8051 expanded key = vectors (the forge suite derives the same bytes on chain)', () => {
  for (const name of ['mldsa44', 'mldsa65']) {
    assert.equal(hex(mldsaExpandedKey(name, fromHex(V.kinds[name].pk))), V.kinds[name].expanded_key);
  }
  assert.throws(() => mldsaExpandedKey('fndsa512', fromHex(V.kinds.fndsa512.pk)));
});

test('no raw-digest signing: purpose and digest must be 32 bytes', () => {
  const kp = pqKeygen(seed, 'mldsa44', 0, 0);
  assert.throws(() => signUA('mldsa44', kp.secretKey, purpose, new Uint8Array(31)), /32 bytes/);
  assert.throws(() => signUA('mldsa44', kp.secretKey, new Uint8Array(5), digest), /32 bytes/);
  assert.throws(() => signUA('rsa', kp.secretKey, purpose, digest), /unknown PQ kind/);
});

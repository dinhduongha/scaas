// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The PQZ three-key model on the client (spec 2026-11-13 pqz-three-keys; CLI-SGN-50, -51, CTR-PQZ-40): the scoped key seeds, the
// opening KEM seed and key against pqz-ffi's KAT (smartcontracts/vectors/pqz/opening.json), the leg seed, the sealed opening's
// round trip and every one-change refusal giving the one outcome `null`. UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { hex, fromHex } from '../src/bytes.js';
import { pqzKeySeed } from '../src/pq.js';
import { pqzScopedKeySeed, openKemSeed, openKemKey, legSeedOfKeyHash, openingCoins, sealOpening, openOpening, pqzOpeningMemoHash }
  from '../src/pqzopen.js';

const ROOT = new URL('../../../', import.meta.url);
const K = JSON.parse(readFileSync(new URL('smartcontracts/vectors/pqz/opening.json', ROOT), 'utf8'));
const h0 = (x) => (x.startsWith('0x') ? x : `0x${x}`);
const SEED = fromHex(h0(K.bip39_seed));
const CU = ['0x' + 'c1'.repeat(32), '0x' + 'c2'.repeat(32)];
const TOK = ['0x' + 'a1'.repeat(20), '0x' + 'a2'.repeat(20)];

test('opening KEM seed and key (K3-6b) = pqz-ffi, both classes, every KAT row', () => {
  assert.ok(K.openKemSeeds.length >= 8);
  for (const r of K.openKemSeeds) {
    const s = openKemSeed(SEED, { ua: h0(r.ua), chainUid: h0(r.chainUid), token: r.token ? h0(r.token) : undefined, version: r.version });
    assert.equal(hex(s), h0(r.openKemSeed), JSON.stringify([r.chainUid, r.token, r.version]));
    assert.equal(hex(keccak_256(openKemKey(s).kemPk)), h0(r.kemPk_keccak));
  }
});

test('leg seed (K3-4) = pqz-ffi; recipient and key inside', () => {
  for (const r of K.rows) assert.equal(hex(legSeedOfKeyHash(h0(r.seed_enc), h0(r.toUA), h0(r.pk_t_keccak))), h0(r.seed_leg));
  const r = K.rows[0];
  const other = '0x' + '22'.repeat(32);
  assert.notEqual(hex(legSeedOfKeyHash(h0(r.seed_enc), other, h0(r.pk_t_keccak))), h0(r.seed_leg), 'another recipient');
  assert.notEqual(hex(legSeedOfKeyHash(h0(r.seed_enc), h0(r.toUA), '0x' + '00'.repeat(32))), h0(r.seed_leg), 'another key');
});

test('scoped PQZ seeds (K3-2): three classes, two chains, two tokens, versions 0 and 1 pairwise distinct; registry unchanged', () => {
  const at = { account: 0, index: 0 };
  const all = [hex(pqzKeySeed(SEED, 0, 0, 0)), hex(pqzKeySeed(SEED, 0, 0, 1))];
  for (const chainUid of CU) {
    for (const version of [0, 1]) {
      all.push(hex(pqzScopedKeySeed(SEED, { ...at, chainUid, version })));
      for (const token of TOK) all.push(hex(pqzScopedKeySeed(SEED, { ...at, chainUid, token, version })));
    }
  }
  assert.equal(new Set(all).size, all.length);
  // the class-2 version 0 carries be64(0) (unlike class 1's version 0)
  assert.notEqual(hex(pqzScopedKeySeed(SEED, { ...at, chainUid: CU[0], version: 0 })), hex(pqzKeySeed(SEED, 0, 0, 0)));
});

const fixture = () => {
  const ok = openKemSeed(SEED, { ua: '0x' + '11'.repeat(32), chainUid: CU[0], version: 0 });
  const key = openKemKey(ok);
  const seedLeg = fromHex('0x' + '5e'.repeat(32));
  const aad = fromHex('0x' + 'aa'.repeat(32 + 20 + 32 + 8 + 32));
  return { key, seedLeg, aad, o: sealOpening({ seedLeg, role: 0, kemPk: key.kemPk, aad }) };
};

test('the sealed opening (K3-6): deterministic, 1,648 bytes, opens to seed_leg; roles and keys give other coins', () => {
  const { key, seedLeg, aad, o } = fixture();
  assert.equal(o.bytes.length, 1648);
  assert.equal(hex(sealOpening({ seedLeg, role: 0, kemPk: key.kemPk, aad }).bytes), hex(o.bytes), 'deterministic');
  assert.equal(hex(openOpening({ opening: o.bytes, kemPk: key.kemPk, dk: key.dk, x25519Secret: key.x25519Secret, aad })), hex(seedLeg));
  assert.notEqual(hex(openingCoins(seedLeg, 0, key.kemPk)), hex(openingCoins(seedLeg, 1, key.kemPk)), 'role');
  const k2 = openKemKey(openKemSeed(SEED, { ua: '0x' + '11'.repeat(32), chainUid: CU[0], version: 1 }));
  assert.notEqual(hex(openingCoins(seedLeg, 0, key.kemPk)), hex(openingCoins(seedLeg, 0, k2.kemPk)), 'key');
});

test('every one-change refusal is the one outcome null (CLI-SGN-51)', () => {
  const { key, aad, o } = fixture();
  const open = (opening, x = {}) => openOpening({ opening, kemPk: key.kemPk, dk: key.dk, x25519Secret: key.x25519Secret, aad, ...x });
  const flip = (i) => { const b = o.bytes.slice(); b[i] ^= 1; return b; };
  assert.equal(open(flip(10)), null, 'mlkemCt bit');
  assert.equal(open(flip(1568 + 3)), null, 'x25519Eph bit');
  assert.equal(open(flip(1600 + 47)), null, 'tag bit');
  assert.equal(open(flip(1600)), null, 'sealedSeed bit');
  const aad2 = aad.slice(); aad2[0] ^= 1;
  assert.equal(open(o.bytes, { aad: aad2 }), null, 'another aad (token, ua, version or ciphertext)');
  const k2 = openKemKey(openKemSeed(SEED, { ua: '0x' + '11'.repeat(32), chainUid: CU[1], version: 0 }));
  assert.equal(open(o.bytes, { dk: k2.dk, x25519Secret: k2.x25519Secret, kemPk: k2.kemPk }), null, 'another chain\'s key');
  const low = o.bytes.slice(); low.fill(0, 1568, 1600);
  assert.equal(open(low), null, 'low-order X25519 point');
  assert.equal(open(o.bytes.subarray(0, 1647)), null, 'short');
  assert.ok(open(o.bytes) !== null, 'control');
});

test('memoHash covers the openings (CTR-PQZ-40): keccak256(memo ‖ ownTag ‖ keccak256(O_t ‖ [O_a]))', () => {
  const { o } = fixture();
  const tag = '0x' + '7a'.repeat(32);
  const a = hex(pqzOpeningMemoHash('0x', tag, [o.bytes]));
  assert.equal(a, hex(keccak_256(new Uint8Array([...fromHex(tag), ...keccak_256(o.bytes)]))));
  const b = o.bytes.slice(); b[0] ^= 1;
  assert.notEqual(hex(pqzOpeningMemoHash('0x', tag, [b])), a, 'a swapped opening moves the word');
});

// Owner ruling 2026-11-14 (CLI-SGN-51's Change; spec §13, §14.18): the key handle opens and checks, never decrypts; a credit of
// another class, scope or version is refused before anything of it is read.
test('pqzKeyHandle: no decrypt and no secret on its surface; the opening path works; another class or scope refused first', async () => {
  const { pqzKeyHandle } = await import('../src/pqzopen.js');
  const at = { chainUid: CU[0], ua: '0x' + '11'.repeat(32), version: 0 };
  const h2 = pqzKeyHandle(SEED, { kind: 'offchain-shared', ...at });
  const h3 = pqzKeyHandle(SEED, { kind: 'offchain-token', token: TOK[0], opening: true, ...at });
  const h3off = pqzKeyHandle(SEED, { kind: 'offchain-token', token: TOK[0], opening: false, ...at });
  const h1 = pqzKeyHandle(SEED, { kind: 'registry', ...at });
  for (const h of [h1, h2, h3, h3off]) {
    assert.deepEqual(Object.keys(h).sort(), ['check', 'kind', 'open', 'openKem', 'scope', 'version'], h.kind);
    assert.ok(Object.isFrozen(h));
    assert.ok(!('decrypt' in h) && !('seed' in h) && !('dk' in h), 'no decrypt, no secret');
  }
  // the opening path (positive control): sealed to the handle's key, opened, handed to the binding's check
  const seedLeg = fromHex('0x' + '5e'.repeat(32));
  const aad = fromHex('0x' + '0a'.repeat(40));
  const credit = (h, kind, scope, extra = {}) => {
    const o = sealOpening({ seedLeg, role: 0, kemPk: h.openKem, aad });
    return { kind, scope, version: 0, opening: o.bytes, aad, ...extra };
  };
  const c2 = credit(h2, 'offchain-shared', '0x' + '00'.repeat(20));
  assert.equal(hex(h2.open(c2)), hex(seedLeg));
  let seen = null;
  assert.equal(h2.check(c2, (s) => { seen = s; return 42n; }), 42n);
  assert.equal(hex(seen), hex(seedLeg), 'the check gets seed_leg');
  assert.equal(h2.check({ ...c2, aad: fromHex('0x0b') }, () => { throw new Error('not reached'); }), null, 'a failing tag: skip');
  const c3 = credit(h3, 'offchain-token', TOK[0]);
  assert.equal(hex(h3.open(c3)), hex(seedLeg), 'class 3 with the opening');
  // refused before anything of the credit is read: a getter counts the reads of `opening`
  const watched = (c) => {
    let reads = 0;
    const w = { ...c };
    Object.defineProperty(w, 'opening', { get() { reads += 1; return c.opening; }, enumerable: true });
    return { w, reads: () => reads };
  };
  const cases = [
    [h2, { ...c3 }, 'a class-2 handle given a class-3 credit'],
    [h3, { ...c2 }, 'a class-3 handle given a class-2 credit'],
    [h1, { ...c3 }, 'a class-1 handle given a class-3 credit'],
    [h1, { ...c2 }, 'a class-1 handle given a class-2 credit'],
    [h3, { ...c3, scope: TOK[1] }, 'a class-3 handle given another token\'s credit'],
    [h2, { ...c2, version: 1 }, 'another key version'],
    [h3off, { ...c3 }, 'class 3 without the opening'],
  ];
  for (const [h, c, what] of cases) {
    const { w, reads } = watched(c);
    assert.throws(() => h.open(w), /Refusing/, what);
    assert.throws(() => h.check(w, () => 1n), /Refusing/, what);
    assert.equal(reads(), 0, `${what}: nothing read`);
  }
  const { w, reads } = watched(c2);
  assert.equal(hex(h2.open(w)), hex(seedLeg));
  assert.equal(reads(), 1, 'the control reads it');
  assert.throws(() => pqzKeyHandle(SEED, { kind: 'offchain-shared', opening: false, ...at }), /always carries the opening/);
});

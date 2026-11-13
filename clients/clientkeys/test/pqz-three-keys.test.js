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

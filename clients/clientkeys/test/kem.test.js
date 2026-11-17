// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-rs-sign T1b: the UA KEM key per (UA, version), its refusals (non-holder, msig, version range), encapsulation with fixed
// m and e and its refusals (modulus, length, scheme 2, all-zero ss_X), decapsulation rows (lengths, implicit rejection, small-order
// E), read back from smartcontracts/vectors/ua/kem.json (scripts/ua-wallet-vectors.mjs). UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { dir } from './ua-vectors-dir.js';
import { hex, fromHex, keccak_256 } from '../src/bytes.js';
import * as ua from '../src/ua.js';

const KEM = await import('../src/kem.js').catch(() => ({}));
const U = await import('../src/uakey.js').catch(() => ({}));
const json = (f) => { try { return JSON.parse(readFileSync(new URL(f, dir), 'utf8')); } catch { return null; } };
const K = json('keys.json');
const V = json('kem.json');
const B = (h) => fromHex(h);
const seeds = () => Object.fromEntries(K.mnemonics.map((m) => [m.id, B(m.seed)]));
const ver = (v) => (typeof v === 'string' ? BigInt(v) : v);
const keyOf = (r) => U.deriveUAKey(seeds()[r.mnemonic], { kind: r.kind, account: r.account, index: r.index });
const kemOf = (r) => KEM.kemKeyOf(keyOf(r), ver(r.version));
const code = (f) => { try { f(); return null; } catch (e) { return e.code ?? e.message; } };

test('kem.json keys: the KEM key of every holder × version {0, 1}, other account / index / version, the 12-word wallet', () => {
  assert.ok(V, 'kem.json');
  assert.equal(V.keys.length, 14);
  for (const r of V.keys) {
    const k = kemOf(r);
    assert.equal(hex(k.kemPk), r.kemPk, `${r.kind} v${r.version}`);
    assert.equal(k.kemPk.length, 1601);
    assert.equal(k.kemPk[0], 1);
    assert.equal(hex(k.kemPkHash), r.kemPkHash);
    assert.equal(hex(keccak_256(k.kemPk)), r.kemPkHash);
    assert.equal(hex(k.ua), r.ua);
    // the registry's record of this key: scheme 1, the hash over the whole key
    assert.equal(ua.kemRecordStruct({ ua: r.ua, version: ver(r.version), kemPk: k.kemPk }).kemPkHash, r.kemPkHash);
  }
  assert.equal(new Set(V.keys.map((r) => r.kemPk)).size, V.keys.length, 'one key per (ua, version)');
});

test('kem.json refusals: a non-holder kind and an msig have no KEM key (KemHolder), version ≥ 2^64 (Argument)', () => {
  assert.equal(V.refusals.length, 11);
  for (const x of V.refusals) {
    const got = x.kind === 0x0120 ? code(() => KEM.kemKeyOf({ kind: 0x0120, ua: B(x.ua) }, 0))
      : code(() => KEM.kemKeyOf(keyOf(x), BigInt(x.version)));
    assert.equal(got, x.error, `${x.kind}: ${x.reason}`);
  }
  // positive control: the same derivation for a holder
  assert.ok(kemOf({ mnemonic: 'pq_kat', kind: 0x0130, account: 0, index: 0, version: 0 }).kemPk);
  assert.ok(V.refusals.some((x) => x.kind === 0x0120));
});

test('kem.json encaps: fixed m and e give mlkemCt, E and ss; the holder decapsulates the same ss', () => {
  for (const r of V.encaps) {
    const out = KEM.kemEncapsVector(B(r.kemPk), B(r.m), B(r.e));
    assert.equal(hex(out.mlkemCt), r.mlkemCt, r.id);
    assert.equal(hex(out.x25519Eph), r.x25519Eph);
    assert.equal(hex(out.ss), r.ss);
    const key = r.recipient.ephemeralSeed ? KEM.ephemeralVector(B(r.recipient.ephemeralSeed)) : kemOf(r.recipient);
    assert.equal(hex(key.kemPk), r.kemPk);
    assert.equal(hex(key.decaps(out.mlkemCt, out.x25519Eph)), r.ss);
    // the combiner: SHA3-256(ss_M ‖ ss_X ‖ E ‖ pk_X ‖ "scaas.kem.1"); ML-KEM alone gives ss_M ≠ ss
    const ssM = ml_kem1024.encapsulate(B(r.kemPk).subarray(1, 1569), B(r.m)).sharedSecret;
    assert.notEqual(hex(ssM), r.ss);
  }
  const e = V.encaps.find((r) => r.id === 'ephemeral');
  assert.deepEqual(KEM.ephemeralVector(B(e.recipient.ephemeralSeed)).recipient, { kemPkHash: keccak_256(B(e.kemPk)) });
});

test('kem.json encaps refusals: modulus, length, scheme 2, all-zero ss_X (KemCheck)', () => {
  assert.deepEqual(V.encapsRefusals.map((x) => x.id), ['modulus', 'length', 'scheme 2', 'all-zero ss_X']);
  for (const x of V.encapsRefusals) assert.equal(code(() => KEM.kemEncapsVector(B(x.kemPk), B(x.m), B(x.e))), x.error, x.id);
  // positive control: the unaltered key encapsulates with the same m and e
  const x = V.encapsRefusals[0];
  assert.ok(KEM.kemEncapsVector(B(V.keys[0].kemPk), B(x.m), B(x.e)).ss);
});

test('kem.json decaps: lengths and small-order E refused, a flipped mlkemCt byte gives another ss (implicit rejection)', () => {
  const key = kemOf(V.decaps[0].key);
  for (const r of V.decaps) {
    if (r.error) assert.equal(code(() => key.decaps(B(r.mlkemCt), B(r.x25519Eph))), r.error, r.id);
    else assert.equal(hex(key.decaps(B(r.mlkemCt), B(r.x25519Eph))), r.ss, r.id);
  }
  const [valid, flipped] = V.decaps;
  assert.notEqual(valid.ss, flipped.ss);
  assert.equal(V.decaps.filter((r) => r.error).length, 5);
});

test('KEM key only through the UA key: kemKey of the UA key equals kemKeyOf; another seed gives another key', () => {
  const r = V.keys[0];
  const k = keyOf(r);
  assert.equal(hex(k.kemKey(0).kemPk), r.kemPk);
  const twelve = V.keys.find((x) => x.mnemonic === 'twelve_words');
  assert.notEqual(twelve.kemPk, r.kemPk);
  assert.equal(code(() => keyOf({ mnemonic: 'pq_kat', kind: 0x0102, account: 0, index: 0 }).kemKey(0)), 'KemHolder');
});

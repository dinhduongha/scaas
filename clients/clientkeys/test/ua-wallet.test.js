// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-rs-sign T1a: the UA tree, the EIP-2333 UA paths, `solana`, the UA signers, the scaas Schnorr nonce, typed and policy
// rows, transactions and WebAuthn assertions, read back from smartcontracts/vectors/ua/{keys,sign}.json (written by
// scripts/ua-wallet-vectors.mjs). Every row is recomputed here; randomized rows are verified, never reproduced. UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { dir } from './ua-vectors-dir.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, abiEncode } from '../src/bytes.js';
import * as ua from '../src/ua.js';
import { verify as kindVerify, clientDataOk } from '../src/ua-verify.js';
import { PQ_KINDS } from '../src/pq.js';
import * as seedjs from '../src/seed.js';
import * as evm from '../src/evm.js';

// Loaded so that every named test fails on its own before the code exists (red first), not the whole file at import.
const U = await import('../src/uakey.js').catch(() => ({}));
const json = (f) => { try { return JSON.parse(readFileSync(new URL(f, dir), 'utf8')); } catch { return null; } };
const K = json('keys.json');
const S = json('sign.json');
const B = (h) => fromHex(h);
const PQ_BY_KIND = Object.fromEntries(Object.entries(PQ_KINDS).map(([name, s]) => [s.kind, name]));
const seeds = () => Object.fromEntries(K.mnemonics.map((m) => [m.id, B(m.seed)]));
const keyOf = (row) => U.deriveUAKey(seeds()[row.mnemonic], { kind: row.kind, account: row.account, index: row.index });
const EIP2333 = [0x0104, 0x0105, 0x0106, 0x0107, 0x0112];

test('mnemonics: entropy, seed, the 12-word row (16-byte entropy) and the non-ASCII BIP-39 passphrase row', () => {
  assert.ok(K, 'keys.json');
  for (const m of K.mnemonics) {
    const e = seedjs.wordsToEntropy(m.words);
    assert.equal(hex(e), m.entropy, m.id);
    assert.equal(hex(seedjs.seedFromEntropy(e, m.passphrase)), m.seed, m.id);
  }
  const twelve = K.mnemonics.find((m) => m.id === 'twelve_words');
  assert.equal(twelve.words.split(' ').length, 12);
  assert.equal(B(twelve.entropy).length, 16);
  const nonAscii = K.mnemonics.find((m) => m.id === 'non_ascii_passphrase');
  assert.ok(/[^\x00-\x7f]/.test(nonAscii.passphrase));
  assert.notEqual(nonAscii.passphrase, nonAscii.passphrase.normalize('NFKD'), 'the row passes a passphrase NFKD changes');
  // positive control: the same words without the passphrase give another seed
  assert.notEqual(hex(seedjs.seedFromWords(nonAscii.words)), nonAscii.seed);
});

test('normalization rows: NFKD of the words and of the passphrase', () => {
  for (const n of K.normalization) {
    assert.equal(hex(seedjs.seedFromWords(n.words, n.passphrase)), n.seed, n.id);
    assert.equal(n.seed, K.mnemonics.find((m) => m.id === n.sameAs).seed, n.id);
  }
  // our own normalization (scure normalizes again inside, which would hide a missing NFKD here)
  const fw = K.normalization.find((n) => n.id === 'words-fullwidth');
  assert.equal(seedjs.normalizeMnemonic(fw.words), K.mnemonics.find((m) => m.id === fw.sameAs).words);
});

test('keys.json rows equal deriveUAKey for every kind × account {0,1} × index {0,1}', () => {
  assert.equal(typeof U.deriveUAKey, 'function');
  const seen = new Set();
  for (const r of K.ua) {
    const k = keyOf(r);
    assert.equal(k.path, r.path, `${r.mnemonic} ${r.name} ${r.account}/${r.index}`);
    assert.equal(hex(k.keyData), r.keyData, `${r.mnemonic} ${r.name} ${r.account}/${r.index}`);
    assert.equal(k.ua === null ? null : hex(k.ua), r.ua);
    if (r.ua !== null) assert.equal(hex(ua.deriveUA(r.kind, B(r.keyData))), r.ua);
    seen.add(`${r.mnemonic}:${r.kind}:${r.account}:${r.index}`);
  }
  const kinds = [0x0101, 0x0102, 0x0103, 0x0108, 0x0110, ...Object.values(PQ_KINDS).map((s) => s.kind)];
  for (const m of K.mnemonics) {
    for (const kind of [...kinds, ...EIP2333]) {
      for (const account of [0, 1]) {
        for (const index of EIP2333.includes(kind) ? [0] : [0, 1]) assert.ok(seen.has(`${m.id}:${kind}:${account}:${index}`), `${m.id} ${kind} ${account}/${index}`);
      }
    }
  }
});

test('UA tree paths: m/22776\'/0\'/<account>\'/<kindNo>\'/<i>\', the EIP-2333 UA paths, never a native path', () => {
  const r = (kind, account, index) => K.ua.find((x) => x.mnemonic === 'pq_kat' && x.kind === kind && x.account === account && x.index === index);
  assert.equal(r(0x0101, 1, 1).path, "m/22776'/0'/1'/257'/1'");
  assert.equal(r(0x0108, 0, 1).path, "m/22776'/0'/0'/264'/1'");
  assert.equal(r(0x0110, 1, 0).path, "m/22776'/0'/1'/272'/0'");
  assert.equal(r(0x0104, 1, 0).path, 'm/254/0/1/260');
  assert.equal(r(0x0106, 0, 0).path, 'm/12381/0/0/262');
  const natives = new Set(K.native.map((n) => n.path));
  for (const x of K.ua) assert.ok(!natives.has(x.path), x.path);
  // a UA key never equals a native key of the same seed and curve
  const evmKeys = new Set(K.native.filter((n) => n.network === 'evm').map((n) => n.publicKey.slice(4)));
  for (const x of K.ua.filter((y) => y.kind === 0x0108)) assert.ok(!evmKeys.has(x.keyData.slice(2, 66)));
});

test('index 1 refused for every EIP-2333 kind and musig2-bn254 at m/254/0/<account>/274', () => {
  const seed = seeds().pq_kat;
  for (const kind of EIP2333) {
    U.deriveUAKey(seed, { kind, account: 1, index: 0 }); // positive control
    assert.throws(() => U.deriveUAKey(seed, { kind, account: 1, index: 1 }), (e) => e.code === 'Argument', `kind ${kind}`);
    assert.ok(K.refusals.some((x) => x.kind === kind && x.index === 1 && x.error === 'Argument'), `row for ${kind}`);
  }
  for (const account of [0, 1]) {
    const row = K.ua.find((x) => x.mnemonic === 'pq_kat' && x.kind === 0x0112 && x.account === account);
    assert.equal(row.path, `m/254/0/${account}/274`);
    assert.equal(row.derivation, 'eip2333-bn254');
  }
  // the 0x0112 participant key is the bn254 key at kindNo 274, not the secp256k1 musig2 tree
  const m = K.ua.find((x) => x.mnemonic === 'pq_kat' && x.kind === 0x0112 && x.account === 0);
  assert.equal(B(m.keyData).length, 64);
});

test('account 2^31 refused (and every keys.json refusal row)', () => {
  const seed = seeds().pq_kat;
  U.deriveUAKey(seed, { kind: 0x0101, account: 2 ** 31 - 1, index: 2 ** 31 - 1 }); // positive control: the largest in range
  assert.throws(() => U.deriveUAKey(seed, { kind: 0x0101, account: 2 ** 31, index: 0 }), (e) => e.code === 'Argument');
  assert.ok(K.refusals.length >= 10);
  for (const x of K.refusals) {
    if (x.what === 'ua') {
      assert.throws(() => U.deriveUAKey(seeds()[x.mnemonic], { kind: x.kind, account: x.account, index: x.index }),
        (e) => e.code === x.error, JSON.stringify(x));
    } else {
      assert.throws(() => seedjs.deriveKey(seeds()[x.mnemonic], x.network, x.index, { coinType: x.coinType }), JSON.stringify(x));
    }
  }
});

test('native keys per NETWORKS, solana at m/44\'/501\'/i\'/0\'', () => {
  for (const n of K.native) {
    const k = seedjs.deriveKey(seeds()[n.mnemonic], n.network, n.index, { coinType: n.coinType });
    assert.equal(k.path, n.path);
    assert.equal(k.publicKey, n.publicKey);
    assert.equal(k.address ?? null, n.address);
  }
  assert.equal(seedjs.NETWORKS.solana.path(3), "m/44'/501'/3'/0'");
  for (const net of Object.keys(seedjs.NETWORKS)) assert.ok(K.native.some((n) => n.network === net), net);
});

const rowsOf = (kind) => S.ua.filter((r) => r.kind === kind);

test('0x0101 and 0x0108 sign ua_msg (no prehash for 0x0108, sha256 for 0x0101)', () => {
  for (const kind of [0x0101, 0x0108]) {
    const rows = rowsOf(kind);
    assert.ok(rows.length >= 4, `rows of ${kind}`);
    for (const r of rows) {
      const k = keyOf(r);
      const msg = ua.uaMessage(kind, B(r.purposeTag), B(r.digest));
      assert.equal(hex(msg), r.uaMsg);
      assert.equal(hex(k.signUA(B(r.purposeTag), B(r.digest))), r.signature, 'deterministic: RFC 6979, no extra entropy');
      assert.ok(kindVerify(kind, r.keyData, r.uaMsg, r.signature));
    }
    const r = rows[0];
    const s = B(r.signature);
    if (kind === 0x0101) {
      assert.equal(r.signed, hex(sha256(B(r.uaMsg))));
      assert.ok(p256.verify(s, B(r.signed), concatBytes(Uint8Array.of(4), B(r.keyData)), { prehash: false }));
      assert.ok(!p256.verify(s, B(r.uaMsg), concatBytes(Uint8Array.of(4), B(r.keyData)), { prehash: false }));
    } else {
      assert.equal(r.signed, r.uaMsg);
      const pub = secp256k1.recoverPublicKey(concatBytes(Uint8Array.of(s[64] - 27), s.subarray(0, 64)), B(r.uaMsg), { prehash: false });
      assert.equal(hex(secp256k1.Point.fromBytes(pub).toBytes(false).subarray(1)), r.keyData);
    }
  }
});

test('sign.json ua rows: deterministic rows byte-equal, randomized rows verify, the role follows the purpose', () => {
  assert.ok(S.note.includes('extraEntropy: false'));
  const kinds = new Set(S.ua.map((r) => r.kind));
  for (const k of [0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, ...Object.values(PQ_KINDS).map((s) => s.kind)]) {
    assert.ok(kinds.has(k), `kind ${k}`);
  }
  for (const r of S.ua) {
    const k = keyOf(r);
    assert.equal(hex(k.keyData), r.keyData);
    assert.equal(hex(ua.uaMessage(r.kind, B(r.purposeTag), B(r.digest))), r.uaMsg);
    assert.equal(r.role, U.sigRole(B(r.purposeTag)));
    const pop = r.role === 'pop';
    assert.ok(kindVerifyAny(r.kind, r.keyData, r.uaMsg, r.signature, pop), `${r.name} ${r.purpose}`);
    if (r.compare === 'bytes') {
      const sig = r.fixed ? U.signUAVector(k, B(r.purposeTag), B(r.digest), fixedOf(r.fixed)) : k.signUA(B(r.purposeTag), B(r.digest));
      assert.equal(hex(sig), r.signature, `${r.name} ${r.purpose}`);
    }
  }
});

const fixedOf = (f) => Object.fromEntries(Object.entries(f).map(([n, v]) => [n, v === null ? null : B(v)]));
function kindVerifyAny(kind, kd, msg, sig, pop) {
  const name = PQ_BY_KIND[kind];
  if (name) return PQ_KINDS[name].alg.verify(B(sig), PQ_KINDS[name].pq ? keccak_256(concatBytes(ua.TAG(kind), B(msg))) : B(msg), B(kd));
  return kindVerify(kind, kd, msg, sig, pop);
}

test('two release signatures differ for every randomized kind; deterministic kinds repeat', () => {
  const seed = seeds().pq_kat;
  const p = ua.purposeTag('metatx');
  const d = keccak_256(utf8ToBytes('two release signatures'));
  for (const kind of [0x0103, 0x0104, 0x0105, 0x0130, 0x0131, 0x0132, 0x0133]) {
    const k = U.deriveUAKey(seed, { kind });
    const a = k.signUA(p, d);
    const b = k.signUA(p, d);
    assert.notEqual(hex(a), hex(b), `kind ${kind}`);
    assert.ok(kindVerifyAny(kind, hex(k.keyData), hex(ua.uaMessage(kind, p, d)), hex(a), false));
  }
  for (const kind of [0x0101, 0x0102, 0x0106, 0x0107, 0x0108]) {
    const k = U.deriveUAKey(seed, { kind });
    assert.equal(hex(k.signUA(p, d)), hex(k.signUA(p, d)), `kind ${kind}`);
  }
});

test('a purpose not in PURPOSES is refused; a UA key has no raw-digest call', () => {
  const k = U.deriveUAKey(seeds().pq_kat, { kind: 0x0108 });
  k.signUA(ua.purposeTag('metatx'), new Uint8Array(32)); // positive control
  assert.throws(() => k.signUA(keccak_256(utf8ToBytes('scaas.ua.purpose.drain.v1')), new Uint8Array(32)), (e) => e.code === 'UAPurposeUnknown');
  assert.equal(k.signDigest, undefined);
  assert.equal(k.privateKey, undefined);
});

test('member rows: sign_member signs uaMessage(kind, member, memberDigest(structure, structure ua_msg))', () => {
  assert.ok(S.member.length >= 3);
  for (const r of S.member) {
    const k = keyOf(r);
    const md = ua.memberDigest(B(r.structureUa), B(r.structureUaMsg));
    assert.equal(hex(md), r.memberDigest);
    assert.equal(hex(ua.uaMessage(r.kind, ua.purposeTag('member'), md)), r.uaMsg);
    assert.equal(hex(k.signMember(B(r.structureUa), B(r.structureUaMsg))), r.signature);
    assert.ok(kindVerify(r.kind, r.keyData, r.uaMsg, r.signature, false));
  }
});

test('BLS ordinary and PoP rows, right message under the wrong DST refused', () => {
  for (const kind of [0x0106, 0x0107]) {
    const rows = rowsOf(kind);
    assert.ok(rows.some((r) => r.role === 'pop') && rows.some((r) => r.role === 'authorization'), `kind ${kind}`);
    for (const r of rows) {
      assert.ok(kindVerify(kind, r.keyData, r.uaMsg, r.signature, r.role === 'pop'));
      assert.ok(!kindVerify(kind, r.keyData, r.uaMsg, r.signature, r.role !== 'pop'), 'the other domain refuses it');
    }
  }
  const refusals = S.refusals.filter((x) => x.case === 'bls-wrong-dst');
  assert.equal(refusals.length, 4);
  for (const x of refusals) assert.equal(kindVerify(x.kind, x.keyData, x.uaMsg, x.signature, x.pop), false, JSON.stringify(x.kind));
});

test('nonce map is the 512-bit map', () => {
  assert.equal(S.nonceMap.length, 2);
  for (const m of S.nonceMap) {
    const r = BigInt(m.r);
    const seed = keccak_256(B(m.input));
    assert.equal(hex(seed), m.seed);
    const wide = (BigInt(hex(keccak_256(concatBytes(seed, Uint8Array.of(2))))) << 256n) + BigInt(hex(keccak_256(concatBytes(seed, Uint8Array.of(3)))));
    assert.equal((wide % r).toString(), m.k);
    assert.notEqual(m.k, m.k256, 'the 256-bit map gives another nonce on this row');
    // the signer's nonce is this k: its R is k·G
    assert.equal(U.schnorrNonce(m.kind, BigInt(m.sk), B(m.keyData), B(m.uaMsg), B(m.aux)).toString(), m.k);
    const G = m.kind === 0x0104 ? bn254.G1.Point : bls12_381.G1.Point;
    const R = G.BASE.multiply(BigInt(m.k)).toAffine();
    const size = m.kind === 0x0104 ? 32 : 64;
    assert.equal(hex(B(m.signature).subarray(0, size)), '0x' + R.x.toString(16).padStart(2 * size, '0'));
    assert.equal(m.input, hex(concatBytes(utf8ToBytes('scaas.ua.schnorr.nonce.v1'), B(m.skBytes), B(m.keyData), B(m.uaMsg), B(m.aux))));
  }
});

test('unbound relayer / feeRecipient hashed as zero in every mode struct', () => {
  // ua-mtx-merge (CTR-MTX-30, R46): the token's address `MetaTransfer` and `ReceiverFee` left; `UABurn` is the op struct
  const want = new Set(['MetaTransaction', 'UAMetaTransaction', 'UAMetaTransfer', 'UABurn', 'UAReceiverFee']);
  const have = new Set();
  for (const r of S.typed.canon) {
    const td = (evm.OP_BUILDERS[r.builder] ?? evm[r.builder])(r.input);
    assert.deepEqual(JSON.parse(JSON.stringify(td)), r.td, r.id);
    assert.equal(hex(evm.hashTypedData(td)), r.digest, r.id);
    assert.equal(hex(evm.hashTypedData(r.zeroed)), r.digest, `${r.id}: the digest is the zeroed one`);
    assert.notEqual(hex(evm.hashTypedData({ ...td, message: r.input.message })), r.digest, `${r.id}: the supplied values hash otherwise`);
    have.add(td.primaryType);
  }
  for (const t of want) assert.ok(have.has(t), t);
  assert.ok(S.typed.canon.some((r) => r.nested), 'a nested UAMetaTransfer row');
});

test('unrelated Order(mode, relayer, feeRecipient, amount) through Any equals hashTypedData of the supplied values', () => {
  const r = S.typed.generic.find((x) => x.id === 'unrelated-order-any');
  assert.equal(r.td.message.mode, 0);
  assert.notEqual(r.td.message.relayer, '0x' + '00'.repeat(20));
  assert.equal(hex(evm.hashTypedData(r.td)), r.digest);
  assert.equal(hex(evm.expectDigest(r.td, { check: 'Any', allowAnyTypedData: true })), r.digest);
  assert.notEqual(r.canonicalDigest, r.digest, 'canon would have changed it');
  assert.throws(() => evm.expectDigest(r.td, { check: 'Any' }), /Refusing to sign/);
  const sig = seedjs.signTyped(seedjs.deriveKey(seeds()[r.signer.mnemonic], 'evm', r.signer.index), r.td);
  assert.equal(hex(sig), r.signature);
});

test('typed rows with arrays and a negative int; missing field is zero, unknown field refused', () => {
  for (const r of S.typed.generic) assert.equal(hex(evm.hashTypedData(r.td)), r.digest, r.id);
  const neg = S.typed.generic.find((x) => x.id === 'arrays-negative-int');
  assert.ok(JSON.stringify(neg.td.types).includes('int64'));
  assert.ok(JSON.stringify(neg.td.types).includes('[2]'));
  assert.ok(S.typed.refusals.length >= 3);
  for (const x of S.typed.refusals) assert.throws(() => evm.hashTypedData(x.td), x.id);
});

test('policy rows: accepted and refused, from the check* functions', () => {
  const checks = new Set(S.policy.map((p) => p.expect.check));
  for (const c of ['Payment', 'ReceiverFee', 'PayMeta', 'Op', 'Call', 'OwnerCall', 'Cancel', 'TradeOrder', 'WrapOrder', 'Any']) {
    assert.ok(checks.has(c), c);
    assert.ok(S.policy.some((p) => p.expect.check === c && p.digest), `${c} accepted`);
    if (c !== 'Any') assert.ok(S.policy.some((p) => p.expect.check === c && p.refused), `${c} refused`);
  }
  for (const p of S.policy) {
    if (p.digest) assert.equal(hex(evm.expectDigest(p.td, p.expect)), p.digest, p.id);
    else assert.throws(() => evm.expectDigest(p.td, p.expect), /Refusing to sign/, p.id);
  }
});

test('tx type 4 cannot be built', () => {
  const ok = S.tx.rows.find((r) => r.tx.type === 2).tx;
  evm.evmTransaction(ok); // positive control
  assert.throws(() => evm.evmTransaction({ ...ok, type: 4 }), /Refusing to sign/);
  assert.throws(() => evm.evmTransaction({ ...ok, type: 4, authorizationList: [] }), /Refusing to sign/);
  for (const x of S.tx.refusals) assert.throws(() => evm.evmTransaction(x.tx), /Refusing to sign/, x.id);
});

test('tx chainId < 2^64 (ua-rs ChainId, EIP-2294): 2^64 and 2^64 + 1 refused, 2^64 - 1 signed', () => {
  const ids = new Set(S.tx.refusals.map((x) => x.id));
  for (const id of ['chainId 2^64', 'legacy chainId 2^64', 'chainId 2^64 + 1']) assert.ok(ids.has(id), id);
  const max = S.tx.rows.find((r) => r.tx.chainId === '18446744073709551615');
  assert.ok(max, 'a row at chainId 2^64 - 1');
  evm.evmTransaction(max.tx); // positive control
  for (const type of [0, 2]) {
    const ok = S.tx.rows.find((r) => r.tx.type === type).tx;
    assert.throws(() => evm.evmTransaction({ ...ok, chainId: (1n << 64n).toString() }), /chainId is out of range/, `type ${type}`);
    assert.throws(() => evm.evmTransaction({ ...ok, chainId: ((1n << 256n) - 1n).toString() }), /chainId is out of range/, `type ${type}`);
  }
});

test('EIP-155 published row', () => {
  const p = S.tx.published[0];
  assert.match(p.source, /eip-155\.md$/);
  assert.equal(p.sha256.length, 66);
  const t = evm.evmTransaction(p.tx);
  assert.equal(hex(t.unsigned), p.signingData);
  assert.equal(hex(t.sighash), p.signingHash);
  const s = seedjs.signTransaction({ curve: 'secp256k1', privateKey: B(p.privateKey) }, p.tx);
  assert.equal(s.v, p.v);
  assert.equal(BigInt(hex(s.r)).toString(), p.r);
  assert.equal(BigInt(hex(s.s)).toString(), p.s);
  assert.equal(hex(s.raw), p.signedTx);
});

test('tx rows per type 0-3 from the seed\'s EVM key: unsigned, sighash, signature, raw', () => {
  assert.deepEqual([...new Set(S.tx.rows.map((r) => r.tx.type))].sort(), [0, 1, 2, 3]);
  for (const r of S.tx.rows) {
    const key = seedjs.deriveKey(seeds()[r.signer.mnemonic], 'evm', r.signer.index);
    assert.equal(key.address, r.signer.address);
    const t = evm.evmTransaction(r.tx);
    assert.equal(hex(t.unsigned), r.unsigned);
    assert.equal(hex(t.sighash), r.sighash);
    const s = seedjs.signTransaction(key, r.tx);
    assert.equal(hex(s.raw), r.raw);
    assert.equal(s.yParity, r.yParity);
    const pub = secp256k1.recoverPublicKey(concatBytes(Uint8Array.of(s.yParity), s.r, s.s), t.sighash, { prehash: false });
    assert.equal(evm.evmAddress(secp256k1.Point.fromBytes(pub).toBytes(false)), r.signer.address);
    assert.ok(BigInt(hex(s.s)) <= secp256k1.Point.Fn.ORDER / 2n, 'low-s');
  }
});

test('WebAuthn assertion: accepted rows, refusals (wrong challenge, reordered JSON, crossOrigin: true, r = 0, s = n)', () => {
  const a = S.webauthn.accepted;
  assert.ok(a.length >= 2 && a.some((x) => x.highS));
  for (const x of a) {
    assert.equal(hex(U.webauthnChallenge(B(x.purposeTag), B(x.digest))), x.expectedChallenge);
    const blob = U.webauthnAssertion({ keyData: B(x.keyData), expectedChallenge: B(x.expectedChallenge), authData: B(x.authData),
      clientDataJSON: B(x.clientDataJSON), r: B(x.r), s: B(x.s) });
    assert.equal(hex(blob), x.assertion);
    assert.ok(kindVerify(0x0100, x.keyData, x.expectedChallenge, x.assertion));
  }
  const cases = new Set(S.webauthn.refusals.map((x) => x.case));
  for (const c of ['wrong-challenge', 'reordered-json', 'cross-origin-true', 'r-zero', 's-n', 'client-data-not-utf8']) assert.ok(cases.has(c), c);
  for (const x of S.webauthn.refusals) {
    assert.throws(() => U.webauthnAssertion({ keyData: B(x.keyData), expectedChallenge: B(x.expectedChallenge), authData: B(x.authData),
      clientDataJSON: B(x.clientDataJSON), r: B(x.r), s: B(x.s) }), (e) => e.code === 'WebAuthnAssertion', x.case);
  }
});

test('WebAuthn clientDataJSON that is not UTF-8 is refused by the builder, accepted by the chains\' byte rule (ua-rs parity)', () => {
  const x = S.webauthn.refusals.find((r) => r.case === 'client-data-not-utf8');
  const cd = B(x.clientDataJSON);
  assert.throws(() => new TextDecoder('utf-8', { fatal: true }).decode(cd));
  // control: the same bytes pass the chains' rule (the verifier is not changed) and are validly signed
  assert.ok(clientDataOk(cd, B(x.expectedChallenge)));
  const [n, s] = [p256.Point.Fn.ORDER, BigInt(x.s)];
  const blob = abiEncode(['bytes', 'bytes', 'bytes32', 'bytes32'], [B(x.authData), cd, B(x.r), fromHex((s > n / 2n ? n - s : s).toString(16).padStart(64, '0'))]);
  assert.ok(kindVerify(0x0100, x.keyData, x.expectedChallenge, hex(blob)));
  assert.throws(() => U.webauthnAssertion({ keyData: B(x.keyData), expectedChallenge: B(x.expectedChallenge), authData: B(x.authData),
    clientDataJSON: cd, r: B(x.r), s: B(x.s) }), (e) => e.code === 'WebAuthnAssertion' && /UTF-8/.test(e.message));
});

test('msig rows: minimal sets signed at both levels, non-minimal and unsorted sets refused', () => {
  assert.ok(S.msig.some((m) => m.memberSigs) && S.msig.some((m) => m.refused));
  assert.ok(S.msig.some((m) => m.refused && m.case.includes('level-2')));
  for (const m of S.msig) {
    const slots = m.slots.map((s) => ({ index: s.index, key: s.key && keyOf(s.key),
      members: s.members?.map((i) => ({ index: i.index, key: keyOf(i.key) })) }));
    const inner = (id) => m.inner?.[id];
    const call = () => U.msigMemberSigs({ ua: B(m.ua), keyData: B(m.keyData), purposeTag: B(m.purposeTag), digest: B(m.digest), slots, inner });
    if (m.refused) assert.throws(call, (e) => e.code === m.refused, m.case);
    else assert.equal(hex(call()), m.memberSigs, m.case);
  }
});

test('chain separation (owner 2026-11-05): one message and one key on 7622 and 22776, other digests and signatures, no cross-chain verify', () => {
  const C = S.chainSeparation;
  assert.ok(C, 'sign.json chainSeparation');
  const key = U.deriveUAKey(seeds()[C.key.mnemonic], { kind: C.key.kind, account: C.key.account, index: C.key.index });
  const metatx = ua.purposeTag('metatx');
  assert.deepEqual(C.typed.map((r) => r.chainId), [7622, 22776]);
  for (const r of C.typed) {
    assert.equal(Number(r.td.domain.chainId), r.chainId);
    const digest = evm.hashTypedData(r.td);
    assert.equal(hex(digest), r.digest);
    assert.equal(hex(ua.uaMessage(key.kind, metatx, digest)), r.uaMsg);
    assert.equal(hex(key.signUA(metatx, digest)), r.signature, 'deterministic 0x0108');
    assert.ok(kindVerify(key.kind, hex(key.keyData), r.uaMsg, r.signature));
  }
  const [t1, t2] = C.typed;
  assert.notEqual(t1.digest, t2.digest);
  assert.notEqual(t1.signature, t2.signature);
  // the two typed data differ in chainId alone
  assert.deepEqual({ ...t1.td, domain: { ...t1.td.domain, chainId: 0 } }, { ...t2.td, domain: { ...t2.td.domain, chainId: 0 } });
  const evmKey = seedjs.deriveKey(seeds()[C.key.mnemonic], 'evm', C.key.evm.index);
  assert.equal(evmKey.address, C.key.evm.address);
  const pub = B(evmKey.publicKey);
  const txOk = (r, h) => secp256k1.verify(concatBytes(B(r.r), B(r.s)), B(h), pub, { prehash: false, lowS: true });
  assert.deepEqual(C.tx.map((r) => [r.type, r.chainId]), [[0, 7622], [0, 22776], [2, 7622], [2, 22776]]);
  for (const r of C.tx) {
    assert.equal(r.tx.chainId, String(r.chainId));
    assert.equal(hex(evm.evmTransaction(r.tx).sighash), r.sighash);
    assert.equal(hex(seedjs.signTransaction(evmKey, r.tx).raw), r.raw);
    assert.ok(txOk(r, r.sighash));
  }
  for (const type of [0, 2]) {
    const [a, b] = C.tx.filter((r) => r.type === type);
    assert.notEqual(a.sighash, b.sighash);
    assert.notEqual(a.r + a.s, b.r + b.s);
  }
  assert.equal(C.refusals.length, 6);
  for (const x of C.refusals) {
    if (x.what === 'typed') {
      const [p, q] = [C.typed.find((r) => r.chainId === x.signedFor), C.typed.find((r) => r.chainId === x.checkedAgainst)];
      assert.ok(!kindVerify(key.kind, hex(key.keyData), q.uaMsg, p.signature), JSON.stringify(x));
    } else {
      const of = (c) => C.tx.find((r) => r.type === x.type && r.chainId === c);
      assert.ok(!txOk(of(x.signedFor), of(x.checkedAgainst).sighash), JSON.stringify(x));
    }
  }
  const [p] = C.portable;
  assert.deepEqual(p.chains, [7622, 22776]);
  assert.ok(!('chainId' in p.td.domain) && !('verifyingContract' in p.td.domain));
  assert.deepEqual(p.td.domain, ua.PORTABLE_DOMAIN);
  assert.equal(hex(evm.hashTypedData(p.td)), p.digest);
  const m = ua.membershipMessage({ ua: B(p.td.message.ua), member: key.ua });
  assert.equal(hex(m.digest), p.digest, 'the builder takes no chain: one digest for every chain');
  assert.equal(hex(m.message), p.uaMsg);
  assert.equal(hex(key.signMember(B(p.td.message.ua), m.message)), p.signature);
});

test('sign.json external (T1c): RFC 6979 A.2.5 P-256 / SHA-256 and the named secp256k1 RFC 6979 set, with source and sha256', () => {
  const X = S.external;
  assert.ok(X, 'sign.json external');
  for (const s of [X.rfc6979, X.secp256k1]) {
    assert.match(s.sha256, /^0x[0-9a-f]{64}$/);
    assert.ok(s.source.startsWith('https://'));
  }
  const x = B(X.rfc6979.x);
  assert.equal(hex(p256.getPublicKey(x, false)), '0x04' + X.rfc6979.Ux.slice(2) + X.rfc6979.Uy.slice(2));
  assert.deepEqual(X.rfc6979.rows.map((r) => r.message), ['sample', 'test']);
  const n = p256.Point.Fn.ORDER;
  for (const r of X.rfc6979.rows) {
    const sig = p256.sign(sha256(utf8ToBytes(r.message)), x, { prehash: false, lowS: false, extraEntropy: false, format: 'compact' });
    assert.equal(hex(sig), r.r + r.s.slice(2), r.message);
    // the UA form (0x0101) is the low-s one of the same signature
    const low = p256.sign(sha256(utf8ToBytes(r.message)), x, { prehash: false, lowS: true, extraEntropy: false, format: 'compact' });
    const s = BigInt(r.s);
    assert.equal(hex(low), r.r + (s > n / 2n ? n - s : s).toString(16).padStart(64, '0'));
  }
  assert.equal(X.secp256k1.rows.length, 20);
  for (const r of X.secp256k1.rows) {
    const rec = secp256k1.sign(B('0x' + r.m), B('0x' + r.d), { prehash: false, lowS: true, extraEntropy: false, format: 'recovered' });
    assert.equal(hex(rec.subarray(1)), '0x' + r.signature, r.description);
    assert.equal(rec[0], r.recoveryId);
  }
  // the named messages hash to m: the rows sign SHA-256 of the text
  assert.ok(X.secp256k1.rows.filter((r) => hex(sha256(utf8ToBytes(r.description))) === '0x' + r.m).length >= 14);
});

// ua-rs-sign T3b, T3c (spec §11, MD-7): the both-ways fixture, written by ua-rs (tests/wallet_pq.rs, `--ignored regenerate`):
// ua-rs's release signatures of the randomized kinds over the sign.json `verify` requests, verified here by noble, so a bug
// shared by one crate's signer and verifier cannot pass.
test('rs_signatures.json: ua-rs signatures (Falcon, hedged ML-DSA, randomized SLH-DSA, OS-aux BIP-340 and scaas Schnorr) verify here', () => {
  const RS = json('rs_signatures.json');
  assert.ok(RS, 'rs_signatures.json');
  assert.ok(RS.note.includes('never edit by hand'));
  const kinds = new Set();
  for (const r of RS.rows) {
    const k = keyOf(r);
    assert.equal(hex(k.keyData), r.keyData);
    assert.equal(hex(ua.uaMessage(r.kind, B(r.purposeTag), B(r.digest))), r.uaMsg);
    assert.equal(r.role, U.sigRole(B(r.purposeTag)));
    const pop = r.role === 'pop';
    assert.ok(kindVerifyAny(r.kind, r.keyData, r.uaMsg, r.signature, pop), `${r.name} ${r.purpose}`);
    const bad = B(r.signature);
    bad[1] ^= 1; // negative control: one flipped byte
    assert.ok(!kindVerifyAny(r.kind, r.keyData, r.uaMsg, hex(bad), pop), `${r.name} ${r.purpose} flipped`);
    kinds.add(r.kind);
  }
  assert.deepEqual([...kinds].sort((a, b) => a - b), [0x0103, 0x0104, 0x0105, 0x0130, 0x0131, 0x0132, 0x0133, 0x0134, 0x0135]);
  assert.equal(RS.rows.length, 18);
  const own = new Set(S.ua.map((r) => r.signature)); // signed by ua-rs, not copied from sign.json
  assert.ok(RS.rows.every((r) => !own.has(r.signature)));
});

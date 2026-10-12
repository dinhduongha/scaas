// Generates smartcontracts/vectors/ua/kinds.json and structures.json: the UA identity layer of src/ua.js on deterministic
// keys — the kind table, every derived kind's valid key data with its id and keyHash, invalid key data with the error
// every implementation must give, native ids, canonical ids, ua_msg, popDigest, UAAuth and member digests. Every valid row
// is accepted and every invalid row refused by src/ua.js before it is written; clients/scaas-ua recomputes all of it with
// independent curve code (k256, p256, curve25519-dalek, arkworks). MuSig2 / FROST rows are valid layouts of valid points,
// not real groups (KeyAgg and the DKG check are UA-2).
//   node scripts/ua-vectors.mjs [outDir]
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519, ED25519_TORSION_SUBGROUP } from '@noble/curves/ed25519.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { seedFromWords } from '../src/seed.js';
import { pqKeygen } from '../src/pq.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes } from '../src/bytes.js';
import * as ua from '../src/ua.js';

const OUT = process.argv[2] ?? fileURLToPath(new URL('../../../smartcontracts/vectors/ua/', import.meta.url));
const label = (s) => keccak_256(utf8ToBytes(`scaas ua-1 vector ${s}`));
const scalar = (s, n) => (BigInt(hex(label(s))) % (n - 1n)) + 1n;
const be = (v, len) => fromHex(v.toString(16).padStart(2 * len, '0'));
const int = (b) => BigInt(hex(b));
const u16 = (v) => Uint8Array.of((v >> 8) & 0xff, v & 0xff);
const cmp = (a, b) => {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
};
const put = (b, o, chunk) => {
  const c = Uint8Array.from(b);
  c.set(chunk, o);
  return c;
};
const swap = (b, o1, o2, n) => put(put(b, o1, b.subarray(o2, o2 + n)), o2, b.subarray(o1, o1 + n));
const assert = (ok, what) => { if (!ok) throw new Error(what); };

const SECP_P = secp256k1.Point.Fp.ORDER;
const SECP_N = secp256k1.Point.Fn.ORDER;
const P256_P = p256.Point.Fp.ORDER;
const ED_P = 2n ** 255n - 19n;
const BN = bn254.fields;
const BLS = bls12_381.fields;

// deterministic points in their key-data encodings
const secpC = (s) => secp256k1.Point.BASE.multiply(scalar(s, SECP_N)).toBytes(true);
const p256xy = (s) => p256.Point.BASE.multiply(scalar(s, p256.Point.Fn.ORDER)).toBytes(false).subarray(1);
const bnG1enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, 32), be(y, 32)); };
const bnG1 = (s) => bnG1enc(bn254.G1.Point.BASE.multiply(scalar(s, BN.Fr.ORDER)));
const bnG2enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c1, 32), be(x.c0, 32), be(y.c1, 32), be(y.c0, 32)); };
const bnG2 = (s) => bnG2enc(bn254.G2.Point.BASE.multiply(scalar(s, BN.Fr.ORDER)));
const blsG1enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, 64), be(y, 64)); };
const blsG1 = (s) => blsG1enc(bls12_381.G1.Point.BASE.multiply(scalar(s, BLS.Fr.ORDER)));
const blsG2enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c0, 64), be(x.c1, 64), be(y.c0, 64), be(y.c1, 64)); };
const blsG2 = (s) => blsG2enc(bls12_381.G2.Point.BASE.multiply(scalar(s, BLS.Fr.ORDER)));

/** First point on `y² = x³ + b` (x = x0(0), x0(1), …) outside the prime-order subgroup, encoded. */
function offSubgroup(F, b, Point, x0, enc) {
  for (let i = 0n; ; i++) {
    const x = x0(i);
    let y;
    try { y = F.sqrt(F.add(F.mul(F.sqr(x), x), b)); } catch { continue; }
    if (y === undefined) continue;
    const P = Point.fromAffine({ x, y });
    try { P.assertValidity(); } catch { return enc(P); } // on the curve by construction, so the throw is the subgroup
  }
}
/** First encoding make(2), make(3), … that `ok` refuses. */
function firstRefused(make, ok) {
  for (let i = 2n; ; i++) {
    const b = make(i);
    try { ok(b); } catch { return b; }
  }
}

const musig2 = (pt, s) => {
  const pks = [1, 2, 3].map((i) => pt(`${s} pk ${i}`)).sort(cmp);
  return concatBytes(pt(`${s} Q`), u16(3), ...pks);
};
const frost = (pt, s, order, t = 2, n = 3) => {
  const parts = [];
  for (let i = 1; i <= n; i++) {
    for (let j = 0; j < t; j++) parts.push(pt(`${s} C ${i} ${j}`));
    parts.push(pt(`${s} R ${i}`), be(scalar(`${s} mu ${i}`, order), 32));
  }
  return concatBytes(pt(`${s} Y`), u16(t), u16(n), ...parts);
};

const MNEMONIC = 'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author '
  + 'capable act festival slice deposit sauce coconut afford frown better';
const seed = seedFromWords(MNEMONIC);
const pq = (name) => pqKeygen(seed, name, 0, 0).publicKey;

const key = new Map([
  [0x0100, concatBytes(p256xy('webauthn-p256'), sha256(utf8ToBytes('scaas.example')))],
  [0x0101, p256xy('p256')],
  [0x0102, ed25519.getPublicKey(label('ed25519'))],
  [0x0103, schnorr.getPublicKey(label('bip340'))],
  [0x0104, bnG1('schnorr-bn254')],
  [0x0105, blsG1('schnorr-bls12381')],
  [0x0106, blsG2('bls12381-minsig')],
  [0x0107, bnG2('bls-bn254-minsig')],
  [0x0110, musig2(secpC, 'musig2-secp256k1')],
  [0x0111, frost(secpC, 'frost-secp256k1', SECP_N)],
  [0x0112, musig2(bnG1, 'musig2-bn254')],
  [0x0113, frost(bnG1, 'frost-bn254', BN.Fr.ORDER)],
  [0x0130, pq('mldsa44')],
  [0x0131, pq('mldsa65')],
  [0x0132, pq('fndsa512')],
  [0x0133, pq('slhdsa128s')],
  [0x0140, bnG1('zether-bn254')],
  [0x0141, blsG1('zether-bls12381')],
  [0x0142, shake256(utf8ToBytes('scaas ua-1 vector pqz-mlwe key'), { dkLen: 16384 })],
]);
const id = (kind) => ua.deriveUA(kind, key.get(kind));
const eoa = ua.nativeId(0x0001, label('evm-eoa').subarray(12));
const hedera = ua.nativeId(0x0003, concatBytes(new Uint8Array(12), be(1234n, 8)));
const mem = (kind, mid, weight = 1) => ({ kind, id: mid, weight });
const sortM = (ms) => [...ms].sort((a, b) => cmp(a.id, b.id));
const msigMembers = sortM([mem(0x0001, eoa), mem(0x0101, id(0x0101)), mem(0x0103, id(0x0103)), mem(0x0130, id(0x0130))]);
const msigKey = ua.encodeMsig(2, msigMembers);
const msigHedera = ua.encodeMsig(1, sortM([mem(0x0003, hedera), mem(0x0101, id(0x0101))]));
const msigUa = ua.deriveUA(0x0120, msigKey);

// --- valid rows ---
const row = (kind, keyData, hederaNative = false) => {
  const h = ua.keyHashOf(kind, keyData);
  return {
    kind, name: ua.kindInfo(kind).name, hederaNative, keyData: hex(keyData),
    ua: hex(ua.deriveUA(kind, keyData, { hederaNative })), keyHash: h && hex(h),
  };
};
const valid = [...[...key].map(([k, d]) => row(k, d)), row(0x0120, msigKey), row(0x0120, msigHedera, true)];
// the same key under two kinds of one group: two ids, one keyHash (the registry's UAKeyInUse, CTR-UA-11)
valid.push(row(0x0140, key.get(0x0104)), row(0x0100, concatBytes(key.get(0x0101), sha256(utf8ToBytes('scaas.example')))));
for (const [a, b] of [[0x0104, 0x0140], [0x0101, 0x0100]]) {
  const [ra, rb] = [valid.find((r) => r.kind === a), valid.at(b === 0x0140 ? -2 : -1)];
  assert(ra.keyHash === rb.keyHash && ra.ua !== rb.ua, `shared key 0x${a.toString(16)} / 0x${b.toString(16)}`);
}

// ed25519 key with a torsion component (not small order, not in the prime-order subgroup): section 1.6 accepts it
const edY = (y) => be(y, 32).reverse();
const edPoint = (y) => { try { return ed25519.Point.fromBytes(edY(y), false); } catch { return null; } };
const edMixedY = (() => { for (let y = 2n; y < 19n; y++) { const P = edPoint(y); if (P && !P.isSmallOrder() && !P.isTorsionFree()) return y; } throw new Error('no mixed-order y < 19'); })();
valid.push(row(0x0102, edY(edMixedY)));
const heavy = 65535;
const msigMembers2 = sortM([mem(0x0002, ua.nativeId(0x0002, label('evm-contract').subarray(12))), mem(0x0133, id(0x0133)),
  mem(0x0110, id(0x0110)), mem(0x0111, id(0x0111)), mem(0x0100, id(0x0100))]);
valid.push(row(0x0120, ua.encodeMsig(3, msigMembers2)));
// weights above 255 and a threshold above the member count; a u16 weight sum that overflows
valid.push(row(0x0120, ua.encodeMsig(301, sortM([mem(0x0001, eoa, 300), mem(0x0101, id(0x0101), 1)]))));
valid.push(row(0x0120, ua.encodeMsig(heavy, sortM([mem(0x0001, eoa, heavy), mem(0x0101, id(0x0101), heavy)]))));

// --- invalid rows: each refused by src/ua.js with the stated error before it is written ---
const invalid = [];
function bad(kind, keyData, reason, { error = 'UAKeyData', hederaNative = false, why } = {}) {
  try {
    ua.validateKeyData(kind, keyData, { hederaNative });
  } catch (e) {
    assert(e instanceof ua.UAError && e.code === error, `0x${kind.toString(16)} ${reason}: ${e.message}`);
    assert(why === undefined || e.reason === why, `0x${kind.toString(16)} ${reason}: refused by '${e.reason}', not '${why}'`);
    invalid.push({ kind, hederaNative, keyData: hex(keyData), error, reason });
    return;
  }
  throw new Error(`0x${kind.toString(16)} ${reason}: accepted`);
}

for (const [kind, d] of [...key, [0x0120, msigKey]]) {
  bad(kind, new Uint8Array(0), 'empty');
  if (ua.kindInfo(kind).lengths.length) {
    bad(kind, d.subarray(0, d.length - 1), 'one byte short');
    bad(kind, concatBytes(d, Uint8Array.of(0)), 'one byte long');
  } else {
    bad(kind, concatBytes(d, Uint8Array.of(0)), 'trailing byte');
  }
}
for (const kind of [0x0100, 0x0101]) {
  const d = key.get(kind);
  bad(kind, put(d, 0, be(P256_P, 32)), 'x = p');
  bad(kind, put(d, 32, be((int(d.subarray(32, 64)) + 1n) % P256_P, 32)), 'off the curve');
}
for (const t of ED25519_TORSION_SUBGROUP) bad(0x0102, fromHex(t), `small order ${t.slice(0, 8)}`);
bad(0x0102, be(ED_P, 32).reverse(), 'y = p');
bad(0x0102, be(ED_P + 1n, 32).reverse(), 'y = p + 1 (non-canonical identity)');
bad(0x0102, put(put(new Uint8Array(32), 0, Uint8Array.of(1)), 31, Uint8Array.of(0x80)), 'x = 0 with the sign bit');
bad(0x0102, firstRefused((y) => be(y, 32).reverse(), (b) => ed25519.Point.fromBytes(b, false)), 'not a point');
bad(0x0103, be(SECP_P, 32), 'x = p');
bad(0x0103, firstRefused((x) => be(x, 32), (b) => secp256k1.Point.fromBytes(concatBytes(Uint8Array.of(2), b))), 'x does not lift');
for (const kind of [0x0104, 0x0140]) {
  const d = key.get(kind);
  bad(kind, new Uint8Array(64), 'identity');
  bad(kind, put(d, 0, be(BN.Fp.ORDER, 32)), 'x = p');
  bad(kind, put(d, 32, be((int(d.subarray(32, 64)) + 1n) % BN.Fp.ORDER, 32)), 'off the curve');
}
const blsG1Off = offSubgroup(BLS.Fp, 4n, bls12_381.G1.Point, (i) => i + 1n, blsG1enc);
for (const kind of [0x0105, 0x0141]) {
  const d = key.get(kind);
  bad(kind, new Uint8Array(128), 'identity');
  bad(kind, put(d, 0, Uint8Array.of(1)), 'non-zero padding');
  bad(kind, put(d, 16, be(BLS.Fp.ORDER, 48)), 'x = p');
  bad(kind, put(d, 64, be((int(d.subarray(64, 128)) + 1n) % BLS.Fp.ORDER, 64)), 'off the curve');
  bad(kind, blsG1Off, 'outside the subgroup');
}
{
  const d = key.get(0x0106);
  const b2 = BLS.Fp2.fromBigTuple([4n, 4n]);
  bad(0x0106, new Uint8Array(256), 'identity');
  bad(0x0106, put(d, 0, Uint8Array.of(1)), 'non-zero padding');
  bad(0x0106, put(d, 16, be(BLS.Fp.ORDER, 48)), 'x.c0 = p');
  bad(0x0106, put(d, 128, be((int(d.subarray(128, 192)) + 1n) % BLS.Fp.ORDER, 64)), 'off the curve');
  bad(0x0106, swap(d, 0, 64, 64), 'x.c0 and x.c1 swapped');
  bad(0x0106, offSubgroup(BLS.Fp2, b2, bls12_381.G2.Point, (i) => BLS.Fp2.fromBigTuple([i + 1n, 0n]), blsG2enc), 'outside the subgroup');
}
{
  const d = key.get(0x0107);
  const b2 = BN.Fp2.div(BN.Fp2.fromBigTuple([3n, 0n]), BN.Fp2.fromBigTuple([9n, 1n]));
  bad(0x0107, new Uint8Array(128), 'identity');
  bad(0x0107, put(d, 0, be(BN.Fp.ORDER, 32)), 'x_im = p');
  bad(0x0107, put(d, 96, be((int(d.subarray(96, 128)) + 1n) % BN.Fp.ORDER, 32)), 'off the twist');
  bad(0x0107, swap(d, 0, 32, 32), 'x_im and x_re swapped');
  bad(0x0107, offSubgroup(BN.Fp2, b2, bn254.G2.Point, (i) => BN.Fp2.fromBigTuple([i + 1n, 0n]), bnG2enc), 'outside the subgroup');
}
{
  const d = key.get(0x0110);
  const Q = d.subarray(0, 33);
  const pks = [0, 1, 2].map((i) => d.subarray(35 + 33 * i, 68 + 33 * i));
  const more = Array.from({ length: 17 }, (_, i) => secpC(`musig2-secp256k1 extra ${i}`)).sort(cmp);
  bad(0x0110, concatBytes(Q, u16(1), pks[0]), 'n = 1');
  bad(0x0110, concatBytes(Q, u16(17), ...more), 'n = 17');
  bad(0x0110, concatBytes(Q, u16(65535)), 'n = 65535 and no members');
  bad(0x0110, concatBytes(Q, u16(3), pks[1], pks[0], pks[2]), 'unsorted members');
  bad(0x0110, concatBytes(Q, u16(3), pks[0], pks[0], pks[2]), 'duplicate member');
  bad(0x0110, put(d, 35, Uint8Array.of(4)), 'member prefix 04');
  bad(0x0110, put(d, 0, Uint8Array.of(5)), 'Q prefix 05');
}
{
  const d = key.get(0x0111);
  bad(0x0111, frost(secpC, 'frost-secp256k1', SECP_N, 1, 3), 't = 1');
  bad(0x0111, put(d, 33, u16(4)), 't > n');
  bad(0x0111, concatBytes(d.subarray(0, 33), u16(65535), u16(65535)), 't = n = 65535 and no body');
  bad(0x0111, frost(secpC, 'frost-secp256k1', SECP_N, 2, 17), 'n = 17');
  bad(0x0111, put(d, 37 + 3 * 33, be(SECP_N, 32)), 'mu = N');
  bad(0x0111, put(d, 37, Uint8Array.of(4)), 'commitment prefix 04');
}
{
  const d = key.get(0x0112);
  bad(0x0112, concatBytes(d.subarray(0, 64), u16(1), d.subarray(66, 130)), 'n = 1');
  bad(0x0112, swap(d, 66, 130, 64), 'unsorted members');
  bad(0x0112, put(d, 66, new Uint8Array(64)), 'identity member');
  bad(0x0112, put(d, 32, be((int(d.subarray(32, 64)) + 1n) % BN.Fp.ORDER, 32)), 'Q off the curve');
}
{
  const d = key.get(0x0113);
  bad(0x0113, frost(bnG1, 'frost-bn254', BN.Fr.ORDER, 1, 3), 't = 1');
  bad(0x0113, put(d, 68 + 3 * 64, be(BN.Fr.ORDER, 32)), 'mu = r');
  bad(0x0113, put(d, 68, new Uint8Array(64)), 'identity commitment');
}
{
  const m = msigMembers;
  const fake = sortM(Array.from({ length: 17 }, (_, i) => mem(0x0101, label(`msig member ${i}`))));
  bad(0x0120, ua.encodeMsig(2, [m[1], m[0], m[2], m[3]]), 'unsorted members');
  bad(0x0120, ua.encodeMsig(2, [m[0], m[0], m[2], m[3]]), 'duplicate member');
  bad(0x0120, ua.encodeMsig(1, []), 'count = 0');
  bad(0x0120, ua.encodeMsig(2, fake), 'count = 17');
  bad(0x0120, concatBytes(u16(1), u16(65535)), 'count = 65535 and no members');
  bad(0x0120, ua.encodeMsig(0, m), 'threshold = 0');
  bad(0x0120, ua.encodeMsig(5, m), 'threshold > total weight');
  bad(0x0120, ua.encodeMsig(2, m.map((x, i) => (i === 0 ? { ...x, weight: 0 } : x))), 'weight = 0');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0140, id(0x0140)), mem(0x0101, id(0x0101))])), 'Zether member');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0120, msigUa), mem(0x0101, id(0x0101))])), 'structure member');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0108, label('unknown member')), mem(0x0101, id(0x0101))])), 'unknown member kind');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0010, label('solana member')), mem(0x0101, id(0x0101))])), 'foreign native member');
  bad(0x0120, msigHedera, 'hedera-native outside a Hedera profile');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0001, id(0x0101)), mem(0x0103, id(0x0103))])), 'native member, derived-space id');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0101, eoa), mem(0x0103, id(0x0103))])), 'derived member, native-space id');
}
{
  const d = key.get(0x0132);
  bad(0x0132, put(d, 0, Uint8Array.of(0x0a)), 'header 0x0a');
  const q0 = Uint8Array.from(d);
  q0[1] = 12289 >> 6;
  q0[2] = ((12289 & 0x3f) << 2) | (q0[2] & 0x03);
  bad(0x0132, q0, 'h_0 = q');
}
// --- non-canonical coordinates (value >= p that reduces to a valid point), bad FROST points, t > n, truncated bodies ---
const addP = (d, off, len, P) => {
  const v = int(d.subarray(off, off + len)) + P;
  assert(v < 1n << BigInt(8 * len), 'value + p overflows the field width');
  return put(d, off, be(v, len));
};
const accepts = (kind, d) => { ua.validateKeyData(kind, d); return d; };
const rng = (kind, d, reason) => bad(kind, d, reason, { why: 'range' });
{
  // ed25519: y = k + p < 2^255 only for k < 19; every valid point there has a torsion component, so one row
  rng(0x0102, edY(edMixedY + ED_P), `y = ${edMixedY} + p (non-canonical, reduces to a valid point)`);
  // P-256: x = 5 is on the curve (y + p does not fit for that point; the y = 1 point below pins y < p)
  const x5 = 5n;
  const y5 = p256.Point.fromBytes(concatBytes(Uint8Array.of(2), be(x5, 32))).toAffine().y;
  const xy5 = concatBytes(be(x5, 32), be(y5, 32));
  for (const [kind, d] of [[0x0101, xy5], [0x0100, concatBytes(xy5, sha256(utf8ToBytes('scaas.example')))]]) {
    accepts(kind, d);
    rng(kind, put(d, 0, be(x5 + P256_P, 32)), 'x = 5 + p (non-canonical)');
  }
  // the P-256 point with y = 1: (x, 1 + p) fits in 256 bits
  const xy1 = concatBytes(be(0x6916fac45e568b6b9e2e2ecd611b282e5fcc40a3067d601057f879ce5a8a73ccn, 32), be(1n, 32));
  for (const [kind, d] of [[0x0101, xy1], [0x0100, concatBytes(xy1, sha256(utf8ToBytes('scaas.example')))]]) {
    accepts(kind, d);
    rng(kind, addP(d, 32, 32, P256_P), 'y = 1 + p (non-canonical)');
  }
  // secp256k1: x = 1 lifts; x + p < 2^256 only for x < 2^32 + 977
  const sx1 = concatBytes(Uint8Array.of(2), be(1n, 32));
  secp256k1.Point.fromBytes(sx1);
  const sx1p = concatBytes(Uint8Array.of(2), be(1n + SECP_P, 32));
  accepts(0x0103, be(1n, 32));
  rng(0x0103, be(1n + SECP_P, 32), 'x = 1 + p (non-canonical)');
  const mu = key.get(0x0110);
  rng(0x0110, put(mu, 0, sx1p), 'Q: x = 1 + p (non-canonical)');
  rng(0x0110, put(mu, 35 + 66, sx1p), 'member: x = 1 + p (non-canonical)');
  const fr = key.get(0x0111);
  rng(0x0111, put(fr, 0, sx1p), 'Y: x = 1 + p (non-canonical)');
  // bn254 G1 (1, 2)
  const g1 = concatBytes(be(1n, 32), be(2n, 32));
  for (const kind of [0x0104, 0x0140]) {
    accepts(kind, g1);
    rng(kind, addP(g1, 0, 32, BN.Fp.ORDER), '(1 + p, 2) (non-canonical x)');
    rng(kind, addP(g1, 32, 32, BN.Fp.ORDER), '(1, 2 + p) (non-canonical y)');
  }
  rng(0x0112, addP(key.get(0x0112), 66 + 128, 32, BN.Fp.ORDER), 'member: x + p (non-canonical)');
  rng(0x0113, addP(key.get(0x0113), 68 + 128, 32, BN.Fp.ORDER), 'R_1: x + p (non-canonical)');
  for (const [i, w] of ['x_im', 'x_re', 'y_im', 'y_re'].entries()) rng(0x0107, addP(key.get(0x0107), 32 * i, 32, BN.Fp.ORDER), `${w} = valid + p (non-canonical)`);
  // BLS12-381: 48-byte field words, value + p < 2^384 for any coordinate
  for (const kind of [0x0105, 0x0141]) {
    rng(kind, addP(key.get(kind), 16, 48, BLS.Fp.ORDER), 'x = valid + p (non-canonical)');
    rng(kind, addP(key.get(kind), 80, 48, BLS.Fp.ORDER), 'y = valid + p (non-canonical)');
    bad(kind, put(key.get(kind), 64, Uint8Array.of(1)), 'non-zero padding on y', { why: 'padding' });
  }
  for (const [i, w] of ['x.c0', 'x.c1', 'y.c0', 'y.c1'].entries()) {
    rng(0x0106, addP(key.get(0x0106), 64 * i + 16, 48, BLS.Fp.ORDER), `${w} = valid + p (non-canonical)`);
    if (i) bad(0x0106, put(key.get(0x0106), 64 * i, Uint8Array.of(1)), `non-zero padding on ${w}`, { why: 'padding' });
  }
}
{
  const nonLift = firstRefused((x) => be(x, 32), (b) => secp256k1.Point.fromBytes(concatBytes(Uint8Array.of(2), b)));
  const d = key.get(0x0111);
  const per = 3 * 33 + 32;
  const lastR = 37 + 2 * per + 2 * 33;
  bad(0x0111, put(d, 0, Uint8Array.of(4)), 'Y prefix 04', { why: 'prefix' });
  bad(0x0111, put(d, 37 + 2 * 33, concatBytes(Uint8Array.of(2), nonLift)), 'R_1 does not lift', { why: 'curve' });
  bad(0x0111, put(d, 37 + 33, Uint8Array.of(4)), 'C_11 prefix 04', { why: 'prefix' });
  bad(0x0111, put(d, lastR, Uint8Array.of(4)), 'R_3 prefix 04', { why: 'prefix' });
  const b = key.get(0x0113);
  const bper = 3 * 64 + 32;
  const bump = (o) => put(b, o + 32, be((int(b.subarray(o + 32, o + 64)) + 1n) % BN.Fp.ORDER, 32));
  bad(0x0113, bump(0), 'Y off the curve', { why: 'curve' });
  bad(0x0113, put(b, 68 + 2 * 64, new Uint8Array(64)), 'R_1 identity', { why: 'identity' });
  bad(0x0113, put(b, 68 + 64, new Uint8Array(64)), 'C_11 identity', { why: 'identity' });
  bad(0x0113, bump(68 + 2 * bper + 2 * 64), 'R_3 off the curve', { why: 'curve' });
  // t > n on a well-formed transcript of the right length
  bad(0x0111, frost(secpC, 'frost-secp256k1', SECP_N, 4, 3), 't = 4 > n = 3', { why: 'threshold' });
  bad(0x0113, frost(bnG1, 'frost-bn254', BN.Fr.ORDER, 4, 3), 't = 4 > n = 3', { why: 'threshold' });
  // valid header, short body
  const mu = key.get(0x0110);
  bad(0x0110, mu.subarray(0, mu.length - 33), 'MuSig2 n = 3 with two members', { why: 'length' });
  bad(0x0110, mu.subarray(0, 35), 'MuSig2 header alone', { why: 'length' });
  bad(0x0110, mu.subarray(0, mu.length - 1), 'MuSig2 body one byte short', { why: 'length' });
  const mb = key.get(0x0112);
  bad(0x0112, mb.subarray(0, mb.length - 64), 'MuSig2 n = 3 with two members', { why: 'length' });
  bad(0x0112, mb.subarray(0, 66), 'MuSig2 header alone', { why: 'length' });
  bad(0x0112, mb.subarray(0, mb.length - 1), 'MuSig2 body one byte short', { why: 'length' });
  bad(0x0111, put(d, 37 + 2 * per + 3 * 33, be(SECP_N, 32)), 'mu_3 = N', { why: 'scalar' });
  bad(0x0113, put(b, 68 + 2 * bper + 3 * 64, be(BN.Fr.ORDER, 32)), 'mu_3 = r', { why: 'scalar' });
  bad(0x0111, d.subarray(0, d.length - per), 'FROST with one participant missing', { why: 'length' });
  bad(0x0111, d.subarray(0, 37), 'FROST header alone', { why: 'length' });
  bad(0x0111, d.subarray(0, d.length - 1), 'FROST body one byte short', { why: 'length' });
  bad(0x0113, b.subarray(0, b.length - bper), 'FROST with one participant missing', { why: 'length' });
  bad(0x0113, b.subarray(0, 68), 'FROST header alone', { why: 'length' });
  bad(0x0113, b.subarray(0, b.length - 1), 'FROST body one byte short', { why: 'length' });
  bad(0x0120, msigKey.subarray(0, msigKey.length - 36), 'msig count = 4 with three members', { why: 'length' });
  bad(0x0120, msigKey.subarray(0, 4), 'msig header alone', { why: 'length' });
  bad(0x0120, msigKey.subarray(0, msigKey.length - 1), 'msig body one byte short', { why: 'length' });
  // threshold = sum of weights + 1 where the sum is not the count
  bad(0x0120, ua.encodeMsig(302, sortM([mem(0x0001, eoa, 300), mem(0x0101, id(0x0101), 1)])), 'threshold = total weight + 1 (weights > 255)', { why: 'threshold' });
  // FN-DSA: a later coefficient
  const f = Uint8Array.from(key.get(0x0132));
  for (let j = 0; j < 14; j++) {
    const k = 511 * 14 + j;
    const bit = (12289 >> (13 - j)) & 1;
    f[1 + (k >> 3)] = (f[1 + (k >> 3)] & ~(1 << (7 - (k & 7)))) | (bit << (7 - (k & 7)));
  }
  bad(0x0132, f, 'h_511 = q', { why: 'coefficient' });
}

bad(0x0000, new Uint8Array(32), 'kind 0', { error: 'UAKindUnknown' });
bad(0x0108, new Uint8Array(32), 'unassigned kind', { error: 'UAKindUnknown' });
bad(0x0001, new Uint8Array(20), 'native kind', { error: 'UAKindNotDerived' });

// --- natives, native space, canonical ids ---
const natives = ua.KINDS.filter((k) => k.native).flatMap((k) => k.lengths.map((n) => {
  const raw = label(`native ${k.name} ${n}`).subarray(0, n);
  const nid = ua.nativeId(k.kind, raw);
  return { kind: k.kind, raw: hex(raw), id: hex(nid), canonical: ua.canonicalId(hex(nid)) };
}));
const nativeInvalid = [[0x0001, new Uint8Array(19), 'UAKeyData'], [0x0010, new Uint8Array(31), 'UAKeyData'],
  [0x0101, new Uint8Array(32), 'UAKindNotNative'], [0x0108, new Uint8Array(32), 'UAKindUnknown']].map(([kind, raw, error]) => {
  try { ua.nativeId(kind, raw); } catch (e) { assert(e.code === error, `nativeId 0x${kind.toString(16)}: ${e.message}`); return { kind, raw: hex(raw), error }; }
  throw new Error(`nativeId 0x${kind.toString(16)} accepted`);
});
const z32 = new Uint8Array(32);
const nativeSpace = [[z32, true], [put(z32, 12, Uint8Array.of(1)), true], [put(z32, 11, Uint8Array.of(1)), false], [label('derived'), false]]
  .map(([nid, v]) => { assert(ua.inNativeSpace(nid) === v, 'inNativeSpace'); return { id: hex(nid), inNativeSpace: v }; });
const eoa40 = hex(eoa.subarray(12));
const derivedId = hex(id(0x0101));
const okId = (input) => ({ input, canonical: ua.canonicalId(input) });
const badId = (input) => {
  try { ua.canonicalId(input); } catch (e) { assert(e.code === 'UAIdFormat', e.message); return { input, error: 'UAIdFormat' }; }
  throw new Error(`canonical id accepted: ${input}`);
};
const canonicalIds = [
  okId(`0x${'0'.repeat(24)}${eoa40.slice(2).toUpperCase()}`), okId(`0x${eoa40.slice(2).toUpperCase()}`), okId(eoa40),
  okId(`0x${derivedId.slice(2).toUpperCase()}`), okId(derivedId),
  okId(`0x${'0'.repeat(23)}1${'ab'.repeat(20)}`), okId(`0x${'0'.repeat(24)}${'0'.repeat(38)}ab`), okId(`0x${'0'.repeat(38)}ab`),
  badId(eoa40.slice(0, 41)), badId(`0X${eoa40.slice(2)}`), badId(`${derivedId}0`), badId(eoa40.slice(2)),
  badId(`0x${'g'.repeat(40)}`), badId(''), badId(`${eoa40}\n`),
];

// --- messages ---
const digest = label('digest');
const messages = [...[...key.keys(), 0x0120].map((kind) => [kind, 'pop']), ...ua.PURPOSES.map((p) => [0x0100, p])]
  .map(([kind, purpose]) => ({ kind, purpose, purposeTag: hex(ua.purposeTag(purpose)), digest: hex(digest),
    uaMsg: hex(ua.uaMessage(kind, ua.purposeTag(purpose), digest)) }));

// --- structures.json: pop, UAAuth, member ---
const registry = '0x5ca0000000000000000000000000000000000001';
const contexts = {
  A: { chainId: 31337, chainUid: hex(label('chain uid A')), registry },
  B: { chainId: 7622, chainUid: hex(label('chain uid B')), registry },
  C: { chainId: 7622, chainUid: hex(label('chain uid C')), registry },
  D: { chainId: 31337, chainUid: hex(label('chain uid A')), registry: '0x5ca0000000000000000000000000000000000002' },
  E: { chainId: 2 ** 40 + 7, chainUid: hex(label('chain uid E')), registry },
};
const zero = hex(z32);
const pop = [...Object.keys(contexts).map((c) => ({ context: c, ua: derivedId, authRef: zero })),
  { context: 'A', ua: hex(id(0x0140)), authRef: derivedId }]
  .map((p) => {
    const c = contexts[p.context];
    return { ...p, chainKeyHash: hex(ua.chainKeyHash(c.chainId)), popDigest: hex(ua.popDigest({ ...c, ua: p.ua, authRef: p.authRef })) };
  });
assert(new Set(pop.map((p) => p.popDigest)).size === pop.length, 'popDigest must separate chain id, chain uid, registry, ua and authRef');
const memberTag = ua.purposeTag('member');
const uaAuth = [['A', 1], ['A', 2], ['B', 1], ['C', 1], ['E', 1]].map(([context, generation]) => {
  const domain = { generation, ...contexts[context] };
  return { context, generation, domainSeparator: hex(ua.uaAuthDomainSeparator(domain)), ua: hex(eoa), purpose: 'member',
    purposeTag: hex(memberTag), digest: hex(digest), uaAuthDigest: hex(ua.uaAuthDigest(domain, eoa, memberTag, digest)) };
});
assert(new Set(uaAuth.map((a) => a.uaAuthDigest)).size === uaAuth.length, 'UAAuth must separate generation and chain uid');
const msigMsg = ua.uaMessage(0x0120, memberTag, digest);
const member = [{ structureUa: hex(msigUa), uaMsg: hex(msigMsg), memberDigest: hex(ua.memberDigest(msigUa, msigMsg)) }];

// --- write ---
const kinds = ua.KINDS.map((k) => ({
  kind: k.kind, name: k.name, native: k.native, lengths: k.lengths,
  tag: k.native ? null : ua.kindTagString(k.kind), TAG: k.native ? null : hex(ua.TAG(k.kind)), group: k.group,
  signing: ua.isSigningKind(k.kind), zether: ua.isZetherKind(k.kind),
  member: ua.isMemberKind(k.kind, false), memberHedera: ua.isMemberKind(k.kind, true),
}));
const constants = { MSG_TAG: hex(ua.MSG_TAG), POP_TAG: hex(ua.POP_TAG), DOMAIN_TYPEHASH: hex(ua.DOMAIN_TYPEHASH),
  UAAUTH_TYPEHASH: hex(ua.UAAUTH_TYPEHASH), NAME_HASH: hex(ua.NAME_HASH) };
const groups = ua.GROUPS.map((g) => ({ group: g, tag: ua.groupTagString(g), GROUP: hex(ua.GROUP(g)) }));
const purposes = ua.PURPOSES.map((p) => ({ purpose: p, tag: `scaas.ua.purpose.${p}.v1`, purposeTag: hex(ua.purposeTag(p)) }));
const note = 'Generated by clients/clientkeys/scripts/ua-vectors.mjs (src/ua.js on @noble/curves 2.4.0); never edit by hand. '
  + 'Solidity UAKinds, clientkeys ua.js, clients/scaas-ua, clients/ua-py, clients/ua-go and clients/ua-cs must reproduce every '
  + 'field and refuse every invalid row with its error (the reason is a label). MuSig2 / FROST rows are valid layouts of valid '
  + 'points, not real groups.';
mkdirSync(OUT, { recursive: true });
const write = (name, obj) => writeFileSync(join(OUT, name), `${JSON.stringify(obj, null, 2)}\n`);
write('kinds.json', { note, version: 1, constants, kinds, groups, purposes, valid, invalid, natives, nativeInvalid, nativeSpace,
  messages, canonicalIds });
write('structures.json', { note, version: 1, contexts, pop, uaAuth, member });
console.log(`kinds.json: ${valid.length} valid, ${invalid.length} invalid; structures.json written to ${OUT}`);

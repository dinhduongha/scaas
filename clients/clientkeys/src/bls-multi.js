// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// UNAUDITED. `bls12381-multi` (0x0121, spec 2026-11-19-bls12381-multi) on @noble/curves, written from the spec independently of
// ua-rs: key data d = apk (256) ‖ u16 t ‖ u16 n ‖ n × (pk_i (256) ‖ u16 w_i) (EIP-2537 G2), the EVM stored form p = ua ‖ s (s = d
// with 48-byte limbs), verify / verifyMinimal of σ ‖ signers over memberDigest(ua, ua_msg) under DST_MULTI_SIG (§5.2, §5.3), the
// registration PoP over m_i = keccak256(popMsg ‖ pk_i) under DST_MULTI_POP (§4), member parts, aggregation (§5.4), the builder.
// Off chain the key data is d (owner ruling 2026-11-19). Any throw in a check is a refusal.
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { keccak_256, concatBytes, hex, fromHex } from "./bytes.js";
import * as ua from "./ua.js";

export const KIND = 0x0121;
export const DST_MULTI_SIG = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_MULTI_SIG_";
export const DST_MULTI_POP = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_MULTI_POP_";
export const MAX_N = 64;

const { G1, G2 } = bls12_381;
const P = bls12_381.fields.Fp.ORDER;
const R = bls12_381.fields.Fr.ORDER;
const fail = (code, reason) => {
  throw new ua.UAError(code, reason);
};
const B = (v) => (v instanceof Uint8Array ? v : fromHex(v));
const int = (b) => (b.length ? BigInt(hex(b)) : 0n);
const be = (v, n) => fromHex(v.toString(16).padStart(2 * n, "0"));
const u16 = (d, o) => (d[o] << 8) | d[o + 1];
const u16b = (v) => Uint8Array.of(v >> 8, v & 0xff);
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const cmp = (a, b) => {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
};

/** One 64-byte EIP-2537 limb: 16 zero bytes, then a value < p; else a throw. */
const limb = (b) => {
  if (!b.subarray(0, 16).every((x) => x === 0)) throw new Error("padding");
  const v = int(b.subarray(16, 64));
  if (v >= P) throw new Error("range");
  return v;
};
/** A 256-byte G2 point as the precompile reads it: all zero = the identity, else on the curve and in the subgroup (noble's check). */
export const g2Point = (b) => {
  const [x0, x1, y0, y1] = [0, 1, 2, 3].map((i) => limb(b.subarray(64 * i, 64 * i + 64)));
  if (x0 === 0n && x1 === 0n && y0 === 0n && y1 === 0n) return G2.Point.ZERO;
  const pt = G2.Point.fromAffine({ x: { c0: x0, c1: x1 }, y: { c0: y0, c1: y1 } });
  pt.assertValidity();
  return pt;
};
export const g2Bytes = (pt) => {
  if (pt.is0()) return new Uint8Array(256);
  const { x, y } = pt.toAffine();
  return concatBytes(be(x.c0, 64), be(x.c1, 64), be(y.c0, 64), be(y.c1, 64));
};
export const g1Bytes = (pt) => {
  if (pt.is0()) return new Uint8Array(128);
  const { x, y } = pt.toAffine();
  return concatBytes(be(x, 64), be(y, 64));
};
/** A G1 point: canonical, on the curve, in the subgroup, not the identity. */
const g1Point = (b) => {
  if (b.length !== 128) throw new Error("length");
  const x = limb(b.subarray(0, 64));
  const y = limb(b.subarray(64, 128));
  if (x === 0n && y === 0n) throw new Error("identity");
  const pt = G1.Point.fromAffine({ x, y });
  pt.assertValidity();
  return pt;
};

/** The negation of a 256-byte G2 encoding, (x, y) ↦ (x, −y) per Fp component, `0 ↦ 0` (spec §5.2, N3): the identity maps to
 *  itself and a zero component stays canonical. On bytes, as the EVM verifier does it. */
export function negG2(b) {
  const out = Uint8Array.from(b);
  for (const o of [128, 192]) {
    const y = int(b.subarray(o + 16, o + 64));
    if (y !== 0n) out.set(be(P - y, 48), o + 16);
  }
  return out;
}

/** Spec §2 checks (ua.validateKeyData), then the parsed form `{ apk, threshold, members: [{ key, weight }] }`. */
export function parseBlsMulti(keyData) {
  const d = B(keyData);
  ua.validateKeyData(KIND, d);
  const n = u16(d, 258);
  const members = [];
  for (let i = 0; i < n; i++) {
    const o = 260 + 258 * i;
    members.push({ key: d.slice(o, o + 256), weight: u16(d, o + 256) });
  }
  return { apk: d.slice(0, 256), threshold: u16(d, 256), members };
}

const shape = (b, head, per, fixed) => {
  if (b.length < head + 2) fail("UAKeyData", "length");
  const n = u16(b, head);
  if (n < 2 || n > MAX_N) fail("UAKeyData", "n");
  if (b.length !== fixed + per * n) fail("UAKeyData", "length");
  return n;
};
/** d → s: each 64-byte limb loses its 16 zero bytes (a non-zero one is `UAKeyData`). Structure only. */
export function compressBlsMulti(keyData) {
  const d = B(keyData);
  const n = shape(d, 258, 258, 260);
  const pt = (b) =>
    [0, 1, 2, 3].map((i) => {
      const l = b.subarray(64 * i, 64 * i + 64);
      if (!l.subarray(0, 16).every((x) => x === 0)) fail("UAKeyData", "padding");
      return l.subarray(16);
    });
  const parts = [...pt(d.subarray(0, 256)), d.subarray(256, 260)];
  for (let i = 0; i < n; i++) {
    const o = 260 + 258 * i;
    parts.push(...pt(d.subarray(o, o + 256)), d.subarray(o + 256, o + 258));
  }
  return concatBytes(...parts);
}
/** s → d: a 16-byte zero prefix per 48-byte limb. */
export function expandBlsMulti(s) {
  const b = B(s);
  const n = shape(b, 194, 194, 196);
  const z = new Uint8Array(16);
  const pt = (x) => [0, 1, 2, 3].flatMap((i) => [z, x.subarray(48 * i, 48 * i + 48)]);
  const parts = [...pt(b.subarray(0, 192)), b.subarray(192, 196)];
  for (let i = 0; i < n; i++) {
    const o = 196 + 194 * i;
    parts.push(...pt(b.subarray(o, o + 192)), b.subarray(o + 192, o + 194));
  }
  return concatBytes(...parts);
}
/** The EVM key pointer p = ua ‖ compress(d) (EVM storage only). */
export const storedBlsMulti = (keyData) => concatBytes(ua.uaOf(KIND, keyData), compressBlsMulti(keyData));

/** The member indices of a 32-byte bitmap (bit 0 = member 0); null if a bit at or above n is set or none is. */
export function bitmapIndices(bitmap, n) {
  const v = int(bitmap);
  if (v === 0n || v >> BigInt(n) !== 0n) return null;
  const out = [];
  for (let i = 0; i < n; i++) if ((v >> BigInt(i)) & 1n) out.push(i);
  return out;
}
export const indicesBitmap = (signers) =>
  be(
    signers.reduce((a, i) => a | (1n << BigInt(i)), 0n),
    32,
  );

/** `[W(S), min_{i∈S} w_i]` or null unless `signers` is non-empty, strictly increasing and < n. */
function weights(kd, signers) {
  if (!signers.length) return null;
  let w = 0;
  let min = Infinity;
  for (let j = 0; j < signers.length; j++) {
    const i = signers[j];
    if (!Number.isInteger(i) || i < 0 || i >= kd.members.length || (j > 0 && i <= signers[j - 1])) return null;
    w += kd.members[i].weight;
    min = Math.min(min, kd.members[i].weight);
  }
  return [w, min];
}
/** The stored form (spec §5.3): W(S) ≥ t and every signer necessary, W(S) − min_{i∈S} w_i < t. */
export function minimalBlsMulti(kd, signers) {
  const r = weights(kd, signers);
  return !!r && r[0] >= kd.threshold && r[0] - r[1] < kd.threshold;
}

/** apk(S) on the pinned path (spec §5.2): all n → apk; 2k ≤ n + 1 → Σ_{S} pk_i; else apk + neg(Σ_{not S} pk_i), the negation on bytes. */
function apkOf(kd, signers) {
  const n = kd.members.length;
  const k = signers.length;
  if (k === n) return g2Point(kd.apk);
  const on = new Set(signers);
  const sum = (want) =>
    kd.members.reduce((acc, m, i) => (on.has(i) === want ? acc.add(g2Point(m.key)) : acc), G2.Point.ZERO);
  if (2 * k <= n + 1) return sum(true);
  return g2Point(kd.apk).add(g2Point(negG2(g2Bytes(sum(false)))));
}

const memberMessage = (d, uaMsg) => keccak_256(concatBytes(ua.uaOf(KIND, d), B(uaMsg)));
const pairsOne = (pairs) => bls12_381.fields.Fp12.eql(bls12_381.pairingBatch(pairs), bls12_381.fields.Fp12.ONE);

/** verify (`minimal` false: W(S) ≥ t) / verifyMinimal (`minimal` true) of `sig = σ ‖ signers` over `uaMsg` against key data d. */
export function blsMultiSigOk(keyData, uaMsg, sig, minimal = false) {
  try {
    const d = B(keyData);
    const s = B(sig);
    const kd = parseBlsMulti(d);
    if (s.length !== 160) return false;
    const sigma = g1Point(s.subarray(0, 128));
    const signers = bitmapIndices(s.subarray(128), kd.members.length);
    if (!signers) return false;
    const [w, min] = weights(kd, signers);
    if (w < kd.threshold || (minimal && w - min >= kd.threshold)) return false;
    const apkS = apkOf(kd, signers);
    if (apkS.is0()) return false;
    const H = G1.hashToCurve(memberMessage(d, uaMsg), { DST: DST_MULTI_SIG });
    return pairsOne([
      { g1: sigma, g2: G2.Point.BASE.negate() },
      { g1: H, g2: apkS },
    ]);
  } catch {
    return false;
  }
}

/** m_i = keccak256(popMsg ‖ pk_i) (spec §4). */
export const popMemberMessage = (popMsg, key) => keccak_256(concatBytes(B(popMsg), B(key)));

/** verifyPop (spec §4): pop ≠ O and e(pop, −g2) · Π_i e(H(m_i, DST_MULTI_POP), pk_i) = 1, over validated d. */
export function blsMultiPopOk(keyData, popMsg, pop) {
  try {
    const kd = parseBlsMulti(keyData);
    const pairs = [{ g1: g1Point(B(pop)), g2: G2.Point.BASE.negate() }];
    for (const m of kd.members)
      pairs.push({ g1: G1.hashToCurve(popMemberMessage(popMsg, m.key), { DST: DST_MULTI_POP }), g2: g2Point(m.key) });
    return pairsOne(pairs);
  } catch {
    return false;
  }
}

/** ua-verify's `0x0121` arm: `pop` → the registration PoP (msg = popMsg, sig = the pop); else verify / verifyMinimal. */
export const blsMultiOk = (keyData, msg, sig, minimal = false, pop = false) =>
  pop ? blsMultiPopOk(keyData, msg, sig) : blsMultiSigOk(keyData, msg, sig, minimal);

/** popMsg = uaMessage(0x0121, POP_V2, registrationDigest(UAPortableRecord{ua, 0x0121, 0, UAKemRecord{ua, 0, 0, 0}}, 0)) from d (N5). */
export const popMessage = (keyData) =>
  ua.holderPopMessage(KIND, { ua: ua.uaOf(KIND, keyData), keyData: B(keyData) }).message;

// --- member parts, aggregation, builder (spec §4, §5.4) ---

/** An aggregation refusal: `code` one of BadPartial (with `index`), Index, Missing, BelowThreshold, NotMember, Secret, Identity. */
export class BlsMultiError extends Error {
  constructor(code, index) {
    super(index === undefined ? code : `${code} ${index}`);
    this.code = code;
    this.index = index;
  }
}
const refuse = (code, index) => {
  throw new BlsMultiError(code, index);
};
const scalar = (sk) => {
  const s = typeof sk === "bigint" ? sk : int(B(sk));
  if (s <= 0n || s >= R) refuse("Secret");
  return s;
};
const partOk = (sig, key, msg, dst) => {
  try {
    const s = g1Point(B(sig));
    const H = G1.hashToCurve(msg, { DST: dst });
    return pairsOne([
      { g1: s, g2: G2.Point.BASE.negate() },
      { g1: H, g2: g2Point(key) },
    ])
      ? s
      : null;
  } catch {
    return null;
  }
};
const listed = (kd, sk) => {
  const pk = g2Bytes(G2.Point.BASE.multiply(scalar(sk)));
  const i = kd.members.findIndex((m) => eq(m.key, pk));
  return i < 0 ? refuse("NotMember") : i;
};

/** The member key (EIP-2537 G2) of a secret. */
export const memberKey = (sk) => g2Bytes(G2.Point.BASE.multiply(scalar(sk)));
/** Member sk's partial over memberDigest(ua, uaMsg) under DST_MULTI_SIG, ua derived from d (N5); NotMember unless d lists its key. */
export function memberSign(sk, keyData, uaMsg) {
  const d = B(keyData);
  listed(parseBlsMulti(d), sk);
  return g1Bytes(G1.hashToCurve(memberMessage(d, uaMsg), { DST: DST_MULTI_SIG }).multiply(scalar(sk)));
}
/** Member sk's PoP part over m_i = keccak256(popMsg ‖ pk_i) under DST_MULTI_POP, popMsg derived from d (never a coordinator's), pk_i
 *  its own key found in d (N5). */
export function memberPop(sk, keyData) {
  const d = B(keyData);
  const kd = parseBlsMulti(d);
  const i = listed(kd, sk);
  const H = G1.hashToCurve(popMemberMessage(popMessage(d), kd.members[i].key), { DST: DST_MULTI_POP });
  return g1Bytes(H.multiply(scalar(sk)));
}

/** The registration pop from all n parts `[[index, π_i]]`: each checked (BadPartial names it), every index once, the sum not O. */
export function aggregatePop(keyData, parts) {
  const d = B(keyData);
  const kd = parseBlsMulti(d);
  const n = kd.members.length;
  const pm = popMessage(d);
  const seen = new Set();
  let sum = G1.Point.ZERO;
  for (const [i, s] of parts) {
    if (!Number.isInteger(i) || i < 0 || i >= n || seen.has(i)) refuse("Index", i);
    seen.add(i);
    const key = kd.members[i].key;
    sum = sum.add(partOk(s, key, popMemberMessage(pm, key), DST_MULTI_POP) ?? refuse("BadPartial", i));
  }
  for (let i = 0; i < n; i++) if (!seen.has(i)) refuse("Missing", i);
  if (sum.is0()) refuse("Identity");
  return g1Bytes(sum);
}

/** Spec §5.4: partials `[[index, σ_i]]` checked against their keys, a duplicate or out-of-range index refused, a bad one named in
 *  `dropped` and left out, below t refused (BadPartial naming the first bad one, else BelowThreshold); a minimal set unless `surplus`
 *  (N6): the heaviest accepted members first (ties by index) until t. Returns `{ signature, signers, dropped }`. */
export function aggregate(keyData, uaMsg, partials, { surplus = false } = {}) {
  const d = B(keyData);
  const kd = parseBlsMulti(d);
  const n = kd.members.length;
  const m = memberMessage(d, uaMsg);
  const seen = new Set();
  let ok = [];
  const dropped = [];
  for (const [i, s] of partials) {
    if (!Number.isInteger(i) || i < 0 || i >= n || seen.has(i)) refuse("Index", i);
    seen.add(i);
    const pt = partOk(s, kd.members[i].key, m, DST_MULTI_SIG);
    if (pt) ok.push({ i, w: kd.members[i].weight, pt });
    else dropped.push(i);
  }
  dropped.sort((a, b) => a - b);
  if (ok.reduce((a, x) => a + x.w, 0) < kd.threshold)
    return dropped.length ? refuse("BadPartial", dropped[0]) : refuse("BelowThreshold");
  if (!surplus) {
    ok.sort((a, b) => b.w - a.w || a.i - b.i);
    let w = 0;
    ok = ok.slice(0, ok.findIndex((x) => (w += x.w) >= kd.threshold) + 1);
  }
  ok.sort((a, b) => a.i - b.i);
  return {
    signature: g1Bytes(ok.reduce((a, x) => a.add(x.pt), G1.Point.ZERO)),
    signers: ok.map((x) => x.i),
    dropped,
  };
}
/** σ ‖ signers, the 160-byte ABI object `UASig.signature` carries. */
export const blsMultiAbi = ({ signature, signers }) => concatBytes(B(signature), indicesBitmap(signers));

/** Key data from members `[{ key, weight = 1 }]` in the caller's order: sorted by key with weights travelling with their keys, apk the
 *  sum; `{ keyData, indexMap }`, indexMap[caller index] = key-data index (Review Focus 2). Validated as the registry would. */
export function buildKeyData(members, threshold) {
  if (members.length < 2 || members.length > MAX_N) fail("UAKeyData", "n");
  const ms = members.map((m, i) => ({ key: B(m.key), weight: m.weight ?? 1, i }));
  const order = [...ms].sort((a, b) => cmp(a.key, b.key));
  const apk = ms.reduce((a, m) => a.add(g2Point(m.key)), G2.Point.ZERO);
  const keyData = concatBytes(
    g2Bytes(apk),
    u16b(threshold),
    u16b(ms.length),
    ...order.flatMap((m) => [m.key, u16b(m.weight)]),
  );
  ua.validateKeyData(KIND, keyData);
  const indexMap = new Array(ms.length);
  order.forEach((m, pos) => (indexMap[m.i] = pos));
  return { keyData, indexMap };
}

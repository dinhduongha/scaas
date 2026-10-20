// UNAUDITED. UA identity layer (accounts.md §1.3–§1.6; CTR-UA-02…05, 07, 09, 11, 12): the kind table, ids, keyHash, purpose tags,
// ua_msg, popDigest, the registry's UAAuth digest, member digests, canonical ids and key-data validation. The same rules
// live in Solidity (src/ua/UAKinds.sol), Rust (clients/ua-rs), Python (clients/ua-py), Go (clients/ua-go) and C#
// (clients/ua-cs); smartcontracts/vectors/ua/kinds.json and structures.json, written by scripts/ua-vectors.mjs from
// this file, pin all six. No signing here (UAKey and the signers are UA F3).
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { keccak_256, concatBytes, utf8ToBytes, fromHex, hex, word } from './bytes.js';

/** An error whose `code` every implementation and the vector files share. */
export class UAError extends Error {
  constructor(code, reason) {
    super(reason ? `${code}: ${reason}` : code);
    this.code = code;
    this.reason = reason;
  }
}
const fail = (code, reason) => { throw new UAError(code, reason); };
const need = (ok, reason) => { if (!ok) fail('UAKeyData', reason); };

const bytes = (v) => (v instanceof Uint8Array ? v : typeof v === 'string' ? fromHex(v) : fail('UAKeyData', 'type'));
const sized = (v, n, what) => {
  const b = bytes(v);
  if (b.length !== n) throw new Error(`${what} must be ${n} bytes`);
  return b;
};
const be = (b) => (b.length === 0 ? 0n : BigInt(hex(b)));
const u16 = (d, o) => (d[o] << 8) | d[o + 1];
const less = (a, b) => {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
};
const tagHash = (s) => keccak_256(utf8ToBytes(s));

// [number, name, key-data lengths (empty = variable), keyHash group (null = none)]
const DERIVED = [
  [0x0100, 'webauthn-p256', [96], 'p256'],
  [0x0101, 'p256', [64], 'p256'],
  [0x0102, 'ed25519', [32], 'ed25519'],
  [0x0103, 'bip340', [32], 'secp256k1'],
  [0x0104, 'schnorr-bn254', [64], 'bn254-g1'],
  [0x0105, 'schnorr-bls12381', [128], 'bls12381-g1'],
  [0x0106, 'bls12381-minsig', [256], 'bls12381-g2'],
  [0x0107, 'bls-bn254-minsig', [128], 'bn254-g2'],
  [0x0110, 'musig2-secp256k1', [], 'secp256k1'],
  [0x0111, 'frost-secp256k1', [], 'secp256k1'],
  [0x0112, 'musig2-bn254', [], 'bn254-g1'],
  [0x0113, 'frost-bn254', [], 'bn254-g1'],
  [0x0120, 'msig', [], null],
  [0x0130, 'mldsa44', [1312], 'mldsa44'],
  [0x0131, 'mldsa65', [1952], 'mldsa65'],
  [0x0132, 'fndsa512', [897], 'fndsa512'],
  [0x0133, 'slhdsa128s', [32], 'slhdsa128s'],
  [0x0141, 'zether-bls12381', [128], 'bls12381-g1'],
  [0x0108, 'secp256k1', [64], 'secp256k1'], // 2026-10-17, appended (rows keep their positions)
];
// [number, name, native id lengths]
const NATIVE = [
  [0x0001, 'evm-eoa', [20]], [0x0002, 'evm-contract', [20]], [0x0003, 'hedera-native', [20]],
  [0x0010, 'solana-ed25519', [32]], [0x0011, 'stellar-account', [32]], [0x0012, 'soroban-contract', [32]],
  [0x0013, 'aptos-account', [32]], [0x0014, 'sui-address', [32]], [0x0015, 'cosmos-account', [20, 32]],
  [0x0016, 'ton-wallet', [32]],
];
export const KINDS = Object.freeze([
  ...NATIVE.map(([kind, name, lengths]) => Object.freeze({ kind, name, native: true, lengths, group: null })),
  ...DERIVED.map(([kind, name, lengths, group]) => Object.freeze({ kind, name, native: false, lengths, group })),
]);
/** Schemes are not kinds (UA-6 U14): 0x0142 is the PQZ key attribute of a PQ holder; it keeps its tag and keyHash group. */
export const SCHEMES = Object.freeze([Object.freeze({ kind: 0x0142, name: 'pqz-mlwe', lengths: [16384], group: 'pqz-mlwe' })]);
const BY_NUMBER = new Map(KINDS.map((k) => [k.kind, k]));
const SCHEME_BY_NUMBER = new Map(SCHEMES.map((k) => [k.kind, k]));
export const kindInfo = (kind) => BY_NUMBER.get(kind) ?? fail('UAKindUnknown', `0x${Number(kind).toString(16)}`);
const derived = (kind) => {
  if (SCHEME_BY_NUMBER.has(kind)) fail('UAKindNotDerived', SCHEME_BY_NUMBER.get(kind).name);
  const k = kindInfo(kind);
  if (k.native) fail('UAKindNotDerived', k.name);
  return k;
};
// tag / keyHash / message accept a kind or a scheme; id derivation and key-data validation accept kinds only
const tagged = (kind) => SCHEME_BY_NUMBER.get(kind) ?? derived(kind);

const singleSigning = (k) => (k >= 0x0100 && k <= 0x0108) || (k >= 0x0110 && k <= 0x0113) || (k >= 0x0130 && k <= 0x0133);
export const isNativeKind = (kind) => BY_NUMBER.get(kind)?.native === true;
export const isZetherKind = (kind) => kind === 0x0141;
export const isSigningKind = (kind) => kind === 0x0120 || kind === 0x0141 || singleSigning(kind);
/** Kinds that may hold a PQZ key attribute: mldsa44, mldsa65, fndsa512 (an `msig` per `msigPqzEligible`). */
export const isPqzHolder = (kind) => kind >= 0x0130 && kind <= 0x0132;
/** An `msig` whose members of kinds outside 0x0130–0x0133 weigh less than its threshold (CTR-PQZ-12). */
export function msigPqzEligible(keyData) {
  const d = bytes(keyData);
  need(d.length >= 4 && d.length === 4 + 36 * u16(d, 2), 'length');
  let classical = 0;
  for (let o = 4; o < d.length; o += 36) {
    const k = u16(d, o);
    if (k < 0x0130 || k > 0x0133) classical += u16(d, o + 34);
  }
  return classical < u16(d, 0);
}
export const isMemberKind = (kind, hederaNative = false) =>
  singleSigning(kind) || kind === 0x0001 || kind === 0x0002 || (hederaNative && kind === 0x0003);

export const kindTagString = (kind) => `scaas.ua.${tagged(kind).name}.v1`;
export const TAG = (kind) => tagHash(kindTagString(kind));
export const GROUPS = Object.freeze([...new Set([...DERIVED.map(([, , , g]) => g), ...SCHEMES.map((k) => k.group)].filter(Boolean))]);
export const groupTagString = (group) => {
  if (!GROUPS.includes(group)) throw new Error(`unknown keyHash group ${group}`);
  return `scaas.ua.group.${group}.v1`;
};
export const GROUP = (group) => tagHash(groupTagString(group));
export const MSG_TAG = tagHash('scaas.ua.msg.v1');
export const PURPOSES = Object.freeze(['pop', 'metatx', 'metatx-cancel', 'member', 'zether-auth', 'zether-owner',
  'keyop', 'receiver-fee', 'vp', 'vc-anchor', 'trade']);
export const purposeTag = (p) => {
  if (!PURPOSES.includes(p)) fail('UAPurposeUnknown', p);
  return tagHash(`scaas.ua.purpose.${p}.v1`);
};
export const POP_TAG = purposeTag('pop');
export const DOMAIN_TYPEHASH = tagHash('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)');
export const UAAUTH_TYPEHASH = tagHash('UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)');
export const NAME_HASH = tagHash('SCaaS UARegistry');

/** `keccak256(TAG(kind) ‖ keyData)`; no validation (use `deriveUA`). */
export const uaOf = (kind, keyData) => {
  derived(kind); // a scheme (0x0142) or a native kind has no derived id
  return keccak_256(concatBytes(TAG(kind), bytes(keyData)));
};
export const inNativeSpace = (id) => sized(id, 32, 'id').subarray(0, 12).every((b) => b === 0);

/** Validate, derive, refuse an id whose top 96 bits are zero (CTR-UA-03). */
export function deriveUA(kind, keyData, { hederaNative = false } = {}) {
  validateKeyData(kind, keyData, { hederaNative });
  const ua = uaOf(kind, keyData);
  if (inNativeSpace(ua)) fail('UAIdInNativeSpace', hex(ua));
  return ua;
}

/** A native id, left-padded to 32 bytes. */
export function nativeId(kind, raw) {
  const k = kindInfo(kind);
  if (!k.native) fail('UAKindNotNative', k.name);
  const b = bytes(raw);
  need(k.lengths.includes(b.length), 'length');
  return concatBytes(new Uint8Array(32 - b.length), b);
}

/** `keccak256(GROUP(g) ‖ canonical pubkey)`, null for structures. Call on validated key data. */
export function keyHashOf(kind, keyData) {
  const k = tagged(kind);
  if (!k.group) return null;
  const d = bytes(keyData);
  const [lo, hi] = { 0x0100: [0, 32], 0x0101: [0, 32], 0x0108: [0, 32], 0x0110: [1, 33], 0x0111: [1, 33], 0x0112: [0, 64], 0x0113: [0, 64] }[kind]
    ?? [0, d.length];
  need(d.length >= hi, 'length');
  return keccak_256(concatBytes(GROUP(k.group), d.subarray(lo, hi)));
}

export const uaMessage = (kind, purpose, digest) =>
  keccak_256(concatBytes(MSG_TAG, TAG(kind), sized(purpose, 32, 'purposeTag'), sized(digest, 32, 'digest')));
export const chainKeyHash = (chainId) => tagHash(`evm:${BigInt(chainId).toString(10)}`);
const addressWord = (a) => concatBytes(new Uint8Array(12), sized(a, 20, 'registry'));

/** `pop_digest` (CTR-UA-07): `pqzKeyHash` is the keyHash of the UA's PQZ key, 0 without one (the bytes of the former `authRef = 0`). */
export function popDigest({ chainId, chainUid, registry, ua, pqzKeyHash = new Uint8Array(32) }) {
  return keccak_256(concatBytes(POP_TAG, chainKeyHash(chainId), sized(chainUid, 32, 'chainUid'), addressWord(registry),
    sized(ua, 32, 'ua'), sized(pqzKeyHash, 32, 'pqzKeyHash')));
}

/**
 * What a PQ holder signs to register with a PQZ key (UA-6 U14): `{ pqzKeyHash, popDigest, message }` with
 * `message = uaMessage(kind, pop, popDigest(ua, h))`, `h = keyHash(0x0142, pqzKey)`; the same `h` goes to `pqzRegMessage`
 * for the native prover's `pqzPop`. Without a key (`pqzKey` omitted) `h = 0`, the plain pop.
 */
export function holderPopMessage(kind, { chainId, chainUid, registry, ua, pqzKey }) {
  const pqzKeyHash = pqzKey ? keyHashOf(0x0142, pqzKey) : new Uint8Array(32);
  const d = popDigest({ chainId, chainUid, registry, ua, pqzKeyHash });
  return { pqzKeyHash, popDigest: d, message: uaMessage(kind, POP_TAG, d) };
}

/** The message `R_REG` proves over: `uaMessage(0x0142, pop, popDigest(ua, keyHash(0x0142, pqzKey)))` (UA-6 U14). */
export function pqzRegMessage({ chainId, chainUid, registry, ua, pqzKey }) {
  const h = keyHashOf(0x0142, pqzKey);
  return uaMessage(0x0142, POP_TAG, popDigest({ chainId, chainUid, registry, ua, pqzKeyHash: h }));
}

export function uaAuthDomainSeparator({ generation, chainId, registry, chainUid }) {
  if (!Number.isInteger(generation) || generation < 1) throw new Error('generation must be a positive integer');
  return keccak_256(concatBytes(DOMAIN_TYPEHASH, NAME_HASH, tagHash(String(generation)), word(chainId), addressWord(registry),
    sized(chainUid, 32, 'chainUid')));
}

/** EIP-712 digest of `UAAuth(ua, purpose, digest)` under the registry's domain: what native signers sign. */
export function uaAuthDigest(domain, ua, purpose, digest) {
  const s = keccak_256(concatBytes(UAAUTH_TYPEHASH, sized(ua, 32, 'ua'), sized(purpose, 32, 'purposeTag'), sized(digest, 32, 'digest')));
  return keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), uaAuthDomainSeparator(domain), s));
}

export const memberDigest = (structureUa, uaMsg) =>
  keccak_256(concatBytes(sized(structureUa, 32, 'structureUa'), sized(uaMsg, 32, 'uaMsg')));

/** Lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id (CTR-UA-03). */
export function canonicalId(text) {
  const m = /^0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.exec(String(text));
  if (!m) fail('UAIdFormat', String(text));
  const h = m[1].toLowerCase();
  return h.length === 64 && h.startsWith('0'.repeat(24)) ? `0x${h.slice(24)}` : `0x${h}`;
}

export function encodeMsig(threshold, members) {
  const out = new Uint8Array(4 + 36 * members.length);
  const put16 = (o, v) => { out[o] = (v >> 8) & 0xff; out[o + 1] = v & 0xff; };
  put16(0, threshold);
  put16(2, members.length);
  members.forEach(({ kind, id, weight }, i) => {
    const o = 4 + 36 * i;
    put16(o, kind);
    out.set(sized(id, 32, 'member id'), o + 2);
    put16(o + 34, weight);
  });
  return out;
}

// --- key-data validation (§1.6 "Validation at registration") ---

const SECP_P = secp256k1.Point.Fp.ORDER;
const SECP_N = secp256k1.Point.Fn.ORDER;
const P256_P = p256.Point.Fp.ORDER;
const ED_P = 2n ** 255n - 19n;
const BN_P = bn254.fields.Fp.ORDER;
const BN_R = bn254.fields.Fr.ORDER;
const BLS_P = bls12_381.fields.Fp.ORDER;

/** Runs a noble constructor / validity check; any throw is "not a valid point". */
const point = (f) => {
  try {
    return f();
  } catch {
    return fail('UAKeyData', 'curve');
  }
};

function secpCompressed(b) {
  need(b[0] === 2 || b[0] === 3, 'prefix');
  need(be(b.subarray(1, 33)) < SECP_P, 'range');
  point(() => secp256k1.Point.fromBytes(b));
}

function secpPoint(xy) {
  need(be(xy.subarray(0, 32)) < SECP_P && be(xy.subarray(32, 64)) < SECP_P, 'range');
  point(() => secp256k1.Point.fromBytes(concatBytes(Uint8Array.of(4), xy)));
}

function p256Point(xy) {
  need(be(xy.subarray(0, 32)) < P256_P && be(xy.subarray(32, 64)) < P256_P, 'range');
  point(() => p256.Point.fromBytes(concatBytes(Uint8Array.of(4), xy)));
}

function ed25519Key(b) {
  need((be(Uint8Array.from(b).reverse()) & ((1n << 255n) - 1n)) < ED_P, 'range');
  const P = point(() => ed25519.Point.fromBytes(b, false));
  need(!(P.toAffine().x === 0n && (b[31] & 0x80)), 'sign');
  need(!P.isSmallOrder(), 'small-order');
}

function bnG1(b) {
  const x = be(b.subarray(0, 32));
  const y = be(b.subarray(32, 64));
  need(x < BN_P && y < BN_P, 'range');
  need(x !== 0n || y !== 0n, 'identity');
  point(() => bn254.G1.Point.fromAffine({ x, y }).assertValidity());
}

function bnG2(b) {
  const [xi, xr, yi, yr] = [0, 1, 2, 3].map((i) => be(b.subarray(32 * i, 32 * i + 32)));
  need([xi, xr, yi, yr].every((v) => v < BN_P), 'range');
  need([xi, xr, yi, yr].some((v) => v !== 0n), 'identity');
  // noble's assertValidity checks the twist equation and the prime-order subgroup
  point(() => bn254.G2.Point.fromAffine({ x: { c0: xr, c1: xi }, y: { c0: yr, c1: yi } }).assertValidity());
}

function blsFp(b) {
  need(b.subarray(0, 16).every((v) => v === 0), 'padding');
  const v = be(b.subarray(16, 64));
  need(v < BLS_P, 'range');
  return v;
}

function blsG1(b) {
  const x = blsFp(b.subarray(0, 64));
  const y = blsFp(b.subarray(64, 128));
  need(x !== 0n || y !== 0n, 'identity');
  point(() => bls12_381.G1.Point.fromAffine({ x, y }).assertValidity());
}

function blsG2(b) {
  const [x0, x1, y0, y1] = [0, 1, 2, 3].map((i) => blsFp(b.subarray(64 * i, 64 * i + 64)));
  need([x0, x1, y0, y1].some((v) => v !== 0n), 'identity');
  point(() => bls12_381.G2.Point.fromAffine({ x: { c0: x0, c1: x1 }, y: { c0: y0, c1: y1 } }).assertValidity());
}

/** `Q ‖ u16 n ‖ n × P_i`, 2 ≤ n ≤ 16, P_i strictly increasing. */
function musig2(d, check, size) {
  need(d.length >= size + 2, 'length');
  const n = u16(d, size);
  need(n >= 2 && n <= 16, 'n');
  need(d.length === size + 2 + n * size, 'length');
  check(d.subarray(0, size));
  for (let i = 0; i < n; i++) {
    const o = size + 2 + i * size;
    check(d.subarray(o, o + size));
    if (i > 0) need(less(d.subarray(o - size, o), d.subarray(o, o + size)), 'order');
  }
}

/** `Y ‖ u16 t ‖ u16 n ‖ n × (t × C_ik ‖ R_i ‖ μ_i)`, 2 ≤ t ≤ n ≤ 16, μ_i < order. */
function frost(d, check, size, order) {
  need(d.length >= size + 4, 'length');
  const t = u16(d, size);
  const n = u16(d, size + 2);
  need(t >= 2 && t <= n && n <= 16, 'threshold');
  const per = (t + 1) * size + 32;
  need(d.length === size + 4 + n * per, 'length');
  check(d.subarray(0, size));
  for (let i = 0; i < n; i++) {
    const o = size + 4 + i * per;
    for (let j = 0; j <= t; j++) check(d.subarray(o + j * size, o + (j + 1) * size)); // t commitments, then R_i
    need(be(d.subarray(o + (t + 1) * size, o + per)) < order, 'scalar');
  }
}

/** `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)` (CTR-UA-09; ruling U5). */
function msig(d, hederaNative) {
  need(d.length >= 4, 'length');
  const threshold = u16(d, 0);
  const count = u16(d, 2);
  need(count >= 1 && count <= 16, 'count');
  need(d.length === 4 + 36 * count, 'length');
  let total = 0;
  for (let i = 0; i < count; i++) {
    const o = 4 + 36 * i;
    const kind = u16(d, o);
    const id = d.subarray(o + 2, o + 34);
    const weight = u16(d, o + 34);
    need(isMemberKind(kind, hederaNative), 'member-kind');
    need(weight >= 1, 'weight');
    need(isNativeKind(kind) === id.subarray(0, 12).every((b) => b === 0), 'member-id');
    if (i > 0) need(less(d.subarray(o - 34, o - 2), id), 'order');
    total += weight;
  }
  need(threshold >= 1 && threshold <= total, 'threshold');
}

/** `0x09 ‖ 512 × 14-bit h_i`, big-endian bit packing, each h_i < q = 12289. */
function fndsa(d) {
  need(d[0] === 0x09, 'header');
  for (let i = 0; i < 512; i++) {
    let v = 0;
    for (let j = 0; j < 14; j++) {
      const k = i * 14 + j;
      v = (v << 1) | ((d[1 + (k >> 3)] >> (7 - (k & 7))) & 1);
    }
    need(v < 12289, 'coefficient');
  }
}

/** Throws `UAError('UAKeyData')` unless `keyData` is the unique canonical encoding of a valid key or structure. */
export function validateKeyData(kind, keyData, { hederaNative = false } = {}) {
  const k = derived(kind);
  const d = bytes(keyData);
  if (k.lengths.length) need(k.lengths.includes(d.length), 'length');
  switch (kind) {
    case 0x0100: return p256Point(d.subarray(0, 64));
    case 0x0101: return p256Point(d);
    case 0x0102: return ed25519Key(d);
    case 0x0103: return secpCompressed(concatBytes(Uint8Array.of(2), d));
    case 0x0104: return bnG1(d);
    case 0x0105: case 0x0141: return blsG1(d);
    case 0x0106: return blsG2(d);
    case 0x0107: return bnG2(d);
    case 0x0108: return secpPoint(d);
    case 0x0110: return musig2(d, secpCompressed, 33);
    case 0x0111: return frost(d, secpCompressed, 33, SECP_N);
    case 0x0112: return musig2(d, bnG1, 64);
    case 0x0113: return frost(d, bnG1, 64, BN_R);
    case 0x0120: return msig(d, hederaNative);
    case 0x0132: return fndsa(d);
    default: return undefined; // mldsa44/65, slhdsa128s: the length is the whole check (U7)
  }
}

// R33: the Zether confidentiality key `x` from the SAME seed on its own tree (design §C.4), apart
// from every BIP-32/SLIP-10 signing key:
//   - BLS12-381: EIP-2333 exactly, path `m/12381/<coin>/<account>/<use>`;
//   - bn254: the same EIP-2333 construction with bn254's `r` and salt "SCAAS-ZETHER-BN254-v1",
//     path `m/254/<coin>/<account>/<use>`.
// `<use>` 7 = conf key, 8 = disclosure (reserved). Byte-for-byte the same as S3's
// `zether-prover/src/keys.rs` + `schnorr.rs` (pinned by test/vectors/r33_keys.json and schnorr_*.json),
// so the browser does not need the 1 MB prover wasm just to register. `x` is sealed like the seed
// (vault.js) and never sent anywhere; only `Y`, `UA` and the PoP leave the device. The UA, the PoP and the
// owner-op signature are the UA registry's (accounts.md CTR-UA-07, CTR-UA-16; ids and digests from ua.js).
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { keccak_256, concatBytes, utf8ToBytes, bytesToHex, fromHex, hex, word, abiEncode, wipe } from './bytes.js';
import { createVault, openVault, seal, open } from './vault.js';
import { uaOf, popDigest, uaMessage, purposeTag } from './ua.js';

export const USE_CONF = 7;
export const USE_DISCLOSURE = 8;
const L = 48; // ceil(3 * ceil(log2 r) / 16) for both curves

export const CURVES = {
  bn254: { Point: bn254.G1.Point, root: 254, salt: 'SCAAS-ZETHER-BN254-v1', coordLen: 32 },
  bls12381: { Point: bls12_381.G1.Point, root: 12381, salt: 'BLS-SIG-KEYGEN-SALT-', coordLen: 64 },
};

function curveOf(name) {
  const c = CURVES[name];
  if (!c) throw new Error('curve must be "bn254" or "bls12381"');
  return c;
}

const toInt = (b) => BigInt('0x' + (bytesToHex(b) || '0'));
const u32 = (i) => new Uint8Array([i >>> 24, (i >>> 16) & 255, (i >>> 8) & 255, i & 255]);

/** EIP-2333 `HKDF_mod_r` with the curve's salt and `r`. */
export function hkdfModR(curve, ikm, keyInfo = new Uint8Array(0)) {
  const { Point, salt: s0 } = curveOf(curve);
  const r = Point.Fn.ORDER;
  let salt = utf8ToBytes(s0);
  const ikm0 = concatBytes(ikm, new Uint8Array([0]));
  const info = concatBytes(keyInfo, new Uint8Array([0, L]));
  try {
    for (;;) {
      salt = sha256(salt);
      const okm = hkdf(sha256, ikm0, salt, info, L);
      const sk = toInt(okm) % r;
      wipe(okm);
      if (sk !== 0n) return sk;
    }
  } finally {
    wipe(ikm0);
  }
}

function lamportPk(parent, index) {
  const salt = u32(index);
  const ikm = word(parent);
  const notIkm = ikm.map((b) => ~b & 255);
  const l0 = hkdf(sha256, ikm, salt, new Uint8Array(0), 255 * 32);
  const l1 = hkdf(sha256, notIkm, salt, new Uint8Array(0), 255 * 32);
  const parts = [];
  for (const l of [l0, l1]) for (let i = 0; i < l.length; i += 32) parts.push(sha256(l.subarray(i, i + 32)));
  wipe(ikm, notIkm, l0, l1);
  return sha256(concatBytes(...parts));
}

export function deriveMasterSk(curve, seed) {
  if (seed.length < 32) throw new Error('EIP-2333 seed must be at least 32 bytes');
  return hkdfModR(curve, seed);
}

export function deriveChildSk(curve, parent, index) {
  return hkdfModR(curve, lamportPk(parent, index));
}

export function encodePoint(curve, P) {
  const { coordLen } = curveOf(curve);
  if (P.is0()) return new Uint8Array(2 * coordLen);
  const { x, y } = P.toAffine();
  const pad = (v) => fromHex(v.toString(16).padStart(2 * coordLen, '0'));
  return concatBytes(pad(x), pad(y));
}

export function decodePoint(curve, bytes) {
  const { Point, coordLen } = curveOf(curve);
  if (bytes.length !== 2 * coordLen) throw new Error('wrong point length');
  if (bytes.every((b) => b === 0)) return Point.ZERO;
  const P = Point.fromAffine({ x: toInt(bytes.subarray(0, coordLen)), y: toInt(bytes.subarray(coordLen)) });
  P.assertValidity(); // on curve + prime-order subgroup
  return P;
}

/** The UA kind of a curve's Zether key: `zether-bn254` 0x0140, `zether-bls12381` 0x0141 (accounts.md §1.6). */
export const zetherKind = (curve) => (curveOf(curve) === CURVES.bn254 ? 0x0140 : 0x0141);

/** `Y = g^x`, `UA = keccak256(TAG(zether-<curve>) ‖ Y)` (ZetherTypes.toUA, CTR-UA-16). */
export function confPublic(curve, x) {
  const { Point } = curveOf(curve);
  const s = typeof x === 'bigint' ? x : toInt(x);
  if (s === 0n || s >= Point.Fn.ORDER) throw new Error('bad Zether scalar');
  const Y = encodePoint(curve, Point.BASE.multiply(s));
  return { Y: hex(Y), UA: hex(uaOf(zetherKind(curve), Y)) };
}

/** Same rule as the S3 prover's JSON API (`api.rs num32`): an integer in [0, 2^32 - 1], as a number
 *  or a decimal string; anything else throws instead of wrapping to another key. */
function pathIndex(i) {
  const ok = typeof i === 'number' ? Number.isInteger(i) : typeof i === 'string' && /^\+?[0-9]+$/.test(i);
  const v = ok ? Number(i) : NaN;
  if (!(v >= 0 && v <= 0xffffffff)) throw new Error(`bad path index ${JSON.stringify(i)}: need an integer in [0, 2^32 - 1]`);
  return v;
}

/**
 * The R33 key `m/<root>/<coin>/<account>/<use>`. Returns `x` as 32 bytes (caller wipes) plus the
 * public `Y`/`UA`.
 */
export function deriveConfKey(seed, { curve, coin, account, use = USE_CONF }) {
  const { root } = curveOf(curve);
  const path = [root, coin, account, use].map(pathIndex);
  let sk = deriveMasterSk(curve, seed);
  for (const i of path) sk = deriveChildSk(curve, sk, i);
  return { curve, path: `m/${root}/${coin}/${account}/${use}`, x: word(sk), ...confPublic(curve, sk) };
}

// ------------------------------------------------------------------ Schnorr + PoP (S3 schnorr.rs)

function hashToScalar(curve, seed32) {
  const r = curveOf(curve).Point.Fn.ORDER;
  return toInt(concatBytes(keccak_256(concatBytes(seed32, new Uint8Array([2]))),
                           keccak_256(concatBytes(seed32, new Uint8Array([3]))))) % r;
}

function challenge(curve, R, Y, msg) {
  return hashToScalar(curve, keccak_256(concatBytes(utf8ToBytes('SCAAS-ZETHER-SCHNORR-V1'),
                                                    encodePoint(curve, R), encodePoint(curve, Y), msg)));
}

/** `sig = R ‖ be32(z)`. `k` only for vectors; otherwise hedged `k = H(x ‖ msg ‖ CSPRNG) mod r`. */
export function schnorrSign(curve, x, msg, k) {
  const { Point } = curveOf(curve);
  const r = Point.Fn.ORDER;
  const xs = toInt(x);
  let nonce = k;
  while (!nonce) {
    const wide = sha512(concatBytes(word(xs), msg, crypto.getRandomValues(new Uint8Array(32))));
    nonce = toInt(wide) % r;
    wipe(wide);
  }
  const R = Point.BASE.multiply(nonce);
  const e = challenge(curve, R, Point.BASE.multiply(xs), msg);
  return concatBytes(encodePoint(curve, R), word((nonce + e * xs) % r));
}

export function schnorrVerify(curve, Ybytes, msg, sig) {
  const { Point, coordLen } = curveOf(curve);
  if (sig.length !== 2 * coordLen + 32) return false;
  try {
    const R = decodePoint(curve, sig.subarray(0, 2 * coordLen));
    const Y = decodePoint(curve, Ybytes);
    const z = toInt(sig.subarray(2 * coordLen));
    if (z >= Point.Fn.ORDER || R.is0() || Y.is0()) return false;
    const e = challenge(curve, R, Y, msg);
    return e !== 0n && Point.BASE.multiplyUnsafe(z).equals(R.add(Y.multiplyUnsafe(e)));
  } catch {
    return false;
  }
}

/**
 * The `pop` of `UARegistry.register(kind, Y, pop, authRef, authPop)` (CTR-UA-07): Schnorr by `x` under the Zether tag
 * over `uaMessage(kind, POP, popDigest)`, `popDigest` over the chain, its `chainUid`, the registry, the UA and `authRef`
 * (0 = self; a non-zero `authRef` also needs the authority's own `authPop`, purpose `authref`). Never bound to a caller:
 * anyone may relay the registration.
 */
export function zetherPop(curve, x, { chainId, chainUid, registry, authRef = new Uint8Array(32) }) {
  // chainUid, registry, authRef: hex strings or bytes (ua.js)
  const kind = zetherKind(curve);
  const { Y, UA } = confPublic(curve, x);
  const d = popDigest({ chainId, chainUid, registry, ua: UA, authRef });
  const m = uaMessage(kind, purposeTag('pop'), d);
  return { kind, Y, UA, popDigest: hex(d), uaMsg: hex(m), pop: hex(schnorrSign(curve, x, m)) };
}

/**
 * The `sig` of a self account's owner op (`zetherRollOverSigned`, `zetherSetRollOverMode`; `authRef = 0`):
 * `abi.encode(bytes(""), Schnorr by x over uaMessage(kind, zether-owner, digest))`; the registry reads `Y` from its record.
 */
export function zetherOwnerAuth(curve, x, digest) {
  const m = uaMessage(zetherKind(curve), purposeTag('zether-owner'), digest);
  return hex(abiEncode(['bytes', 'bytes'], [new Uint8Array(0), schnorrSign(curve, x, m)]));
}

// ------------------------------------------------------------------ at rest

export function confLabel(curve, coin, account) {
  return `zether-conf:${curve}:${coin}:${account}`;
}

/** Derive `x` from the seed and seal it under the same PIN (and PRF) as the seed vault. */
export async function sealConfKey({ seed, curve, coin, account, pin, prf }) {
  const k = deriveConfKey(seed, { curve, coin, account });
  try {
    const vault = await createVault(k.x, { label: confLabel(curve, coin, account), pin, prf });
    return { vault, Y: k.Y, UA: k.UA };
  } finally {
    wipe(k.x);
  }
}

export const openConfKey = openVault;

// ------------------------------------------------------------------ balance cache (zether-limits §5, D5)
//
// The prover needs the plaintext balance; BSGS on a phone reads only up to 2^44 (DEVICE_BOUND_BITS),
// while a balance may reach 2^54. So the wallet keeps `{ua, token, accSeq, balance}` per account on
// the device: never on-chain, never sent to a server. The box is AES-GCM under a key derived from the
// conf key `x`, so it opens only after the conf vault is unlocked (same protection as the seed);
// store it as `confVault.cache`. Every use re-checks it against the on-chain `acc`
// (`[b]G == C − [x]D`, one comparison): a stale or wrong value is dropped, never spent — the prover
// and the contract would refuse a proof built on it anyway. Balances are BigInt (they pass 2^53).

export const DEVICE_BOUND_BITS = 44;
const CACHE_INFO = utf8ToBytes('scaas-zether-balance-cache-v1');

const pointOf = (curve, h) => decodePoint(curve, fromHex(h));
const keyOf = ({ ua, token }) => `${String(ua).toLowerCase()}:${String(token).toLowerCase()}`;

/** `[balance]G == C − [x]D` for `acc = {C, D}` (hex points). */
export function checkBalance(curve, x, acc, balance) {
  const { Point } = curveOf(curve);
  const b = BigInt(balance);
  if (b < 0n || b >= Point.Fn.ORDER) return false;
  const xs = typeof x === 'bigint' ? x : toInt(x);
  const D = pointOf(curve, acc.D);
  const m = pointOf(curve, acc.C).subtract(D.is0() ? D : D.multiply(xs));
  return m.equals(b === 0n ? Point.ZERO : Point.BASE.multiply(b));
}

function cacheKey(x) {
  return hkdf(sha256, typeof x === 'bigint' ? word(x) : x, undefined, CACHE_INFO, 32);
}

/** Seal the cache entries (`{key: {ua, token, accSeq, balance}}`) under `x`. */
export async function sealBalanceCache(curve, x, entries) {
  const k = cacheKey(x);
  const json = JSON.stringify(entries, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
  try { return await seal(k, utf8ToBytes(json), `zether-cache:${curve}`); } finally { wipe(k); }
}

/** Open a box from `sealBalanceCache`; a missing or unreadable box is an empty cache. */
export async function openBalanceCache(curve, x, box) {
  if (!box) return {};
  const k = cacheKey(x);
  try {
    const entries = JSON.parse(new TextDecoder().decode(await open(k, box, `zether-cache:${curve}`)));
    for (const e of Object.values(entries)) e.balance = BigInt(e.balance);
    return entries;
  } catch {
    return {};
  } finally {
    wipe(k);
  }
}

/** `accSeq` only grows on-chain: an `acc` older than the anchor's is stale or forged (review N2) and may
 *  never replace it — a backend knowing `Y` can build an `acc` for any balance within the device bound. */
function staleSeq(entries, state) {
  const e = entries[keyOf(state)];
  return !!e && Number(state.accSeq) < e.accSeq;
}

/**
 * Record `balance` for `state = {ua, token, acc, accSeq}` (the account's CURRENT on-chain `acc`) only
 * if it checks. A value that does not check is refused and the previous entry is KEPT: it is the last
 * balance that checked, the anchor `readBalance` reads differences from. Returns whether it was recorded.
 */
export function setCachedBalance(curve, x, entries, state, balance) {
  const b = BigInt(balance);
  if (staleSeq(entries, state) || b < 0n || !checkBalance(curve, x, state.acc, b)) return false;
  entries[keyOf(state)] = { ua: state.ua, token: state.token, accSeq: Number(state.accSeq), balance: b };
  return true;
}

/** After our own transfer/burn landed: `b −= v + fee` (v = amount for a burn), checked on the new `acc`. */
export function cacheAfterDebit(curve, x, entries, state, v, fee = 0n) {
  const e = entries[keyOf(state)];
  return !!e && setCachedBalance(curve, x, entries, state, e.balance - BigInt(v) - BigInt(fee));
}

/** After a rollOver: `b += pending` (`pending` from the prover's `decryptPending`, BSGS ≤ 2^44 on pending only). */
export function cacheAfterRollOver(curve, x, entries, state, pending) {
  const e = entries[keyOf(state)];
  return !!e && setCachedBalance(curve, x, entries, state, e.balance + BigInt(pending));
}

/**
 * The spendable balance of `state = {ua, token, acc, accSeq}`:
 *   1. the cache, when it checks against `acc`;
 *   2. else, from the last balance that checked, the DIFFERENCE `acc − b_cached` by the device BSGS
 *      (`decrypt(ct)` → amount, e.g. the prover wasm `decryptPending`, bound 2^44), first as a gain then as
 *      a loss. This covers rollOvers the wallet did not do (`rollOverPublic`/`rollOverBatch` by anyone —
 *      `fund(victim, 1)` + `rollOverPublic` is free griefing — and late credits swept by `rollOverSigned`)
 *      and own debits it did not record (review M1). Each try costs one device BSGS when it misses;
 *   3. else the device BSGS on `acc` itself (no cache, or a big anchor spent down below the bound elsewhere,
 *      e.g. the same seed on another device — kept even for a big anchor, review N1).
 * An `acc` whose `accSeq` is below the anchor's is refused (review N2).
 * Every answer is re-checked with `checkBalance` before it is cached or returned. Above the device bound
 * it throws and sends the user to the desktop reader, whose output is entered with `setCachedBalance`.
 */
export async function readBalance(curve, x, entries, state, decrypt) {
  const e = entries[keyOf(state)];
  if (staleSeq(entries, state)) throw new Error(`acc with accSeq ${state.accSeq} is older than the cached ${e.accSeq}`);
  if (e && checkBalance(curve, x, state.acc, e.balance)) return { balance: e.balance, source: 'cache' };
  const tries = [];
  if (e) {
    const { Point } = curveOf(curve);
    const bG = e.balance === 0n ? Point.ZERO : Point.BASE.multiply(e.balance);
    const C = pointOf(curve, state.acc.C);
    const D = pointOf(curve, state.acc.D);
    const ct = (c, d) => ({ C: hex(encodePoint(curve, c)), D: hex(encodePoint(curve, d)) });
    tries.push(['delta', ct(C.subtract(bG), D), (d) => e.balance + d]); // decrypts to a − b_cached
    tries.push(['delta', ct(bG.subtract(C), D.negate()), (d) => e.balance - d]); // b_cached − a
  }
  tries.push(['bsgs', state.acc, (d) => d]);
  let decrypted = false;
  for (const [source, ct, balanceOf] of tries) {
    let d;
    try {
      d = BigInt(await decrypt(ct));
    } catch {
      continue;
    }
    decrypted = true;
    const b = balanceOf(d);
    if (setCachedBalance(curve, x, entries, state, b)) return { balance: b, source };
  }
  if (decrypted) throw new Error('decrypted balance does not match acc');
  throw new Error(`This balance is above what this device can read (2^${DEVICE_BOUND_BITS} units). `
    + 'Run `zether-read-balance` on a desktop, then enter the balance it prints here.');
}

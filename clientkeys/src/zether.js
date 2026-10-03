// R33: the Zether confidentiality key `x` from the SAME seed on its own tree (design §C.4), apart
// from every BIP-32/SLIP-10 signing key:
//   - BLS12-381: EIP-2333 exactly, path `m/12381/<coin>/<account>/<use>`;
//   - bn254: the same EIP-2333 construction with bn254's `r` and salt "BAMBOO-ZETHER-BN254-v1",
//     path `m/254/<coin>/<account>/<use>`.
// `<use>` 7 = conf key, 8 = disclosure (reserved). Byte-for-byte the same as S3's
// `zether-prover/src/keys.rs` + `schnorr.rs` (pinned by test/vectors/r33_keys.json and schnorr_*.json),
// so the browser does not need the 1 MB prover wasm just to register. `x` is sealed like the seed
// (vault.js) and never sent anywhere; only `Y`, `UA` and the PoP leave the device.
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { keccak_256, concatBytes, utf8ToBytes, bytesToHex, fromHex, hex, word, abiEncode, wipe } from './bytes.js';
import { createVault, openVault } from './vault.js';

export const USE_CONF = 7;
export const USE_DISCLOSURE = 8;
const L = 48; // ceil(3 * ceil(log2 r) / 16) for both curves

export const CURVES = {
  bn254: { Point: bn254.G1.Point, root: 254, salt: 'BAMBOO-ZETHER-BN254-v1', coordLen: 32 },
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

/** `Y = g^x`, `UA = keccak256(encodedY)` (ZetherTypes.toUA). */
export function confPublic(curve, x) {
  const { Point } = curveOf(curve);
  const s = typeof x === 'bigint' ? x : toInt(x);
  if (s === 0n || s >= Point.Fn.ORDER) throw new Error('bad Zether scalar');
  const Y = encodePoint(curve, Point.BASE.multiply(s));
  return { Y: hex(Y), UA: hex(keccak_256(Y)) };
}

/**
 * The R33 key `m/<root>/<coin>/<account>/<use>`. Returns `x` as 32 bytes (caller wipes) plus the
 * public `Y`/`UA`.
 */
export function deriveConfKey(seed, { curve, coin, account, use = USE_CONF }) {
  const { root } = curveOf(curve);
  let sk = deriveMasterSk(curve, seed);
  for (const i of [root, coin, account, use]) sk = deriveChildSk(curve, sk, i);
  return { curve, path: `m/${root}/${coin}/${account}/${use}`, x: word(sk), ...confPublic(curve, sk) };
}

// ------------------------------------------------------------------ Schnorr + PoP (S3 schnorr.rs)

function hashToScalar(curve, seed32) {
  const r = curveOf(curve).Point.Fn.ORDER;
  return toInt(concatBytes(keccak_256(concatBytes(seed32, new Uint8Array([2]))),
                           keccak_256(concatBytes(seed32, new Uint8Array([3]))))) % r;
}

function challenge(curve, R, Y, msg) {
  return hashToScalar(curve, keccak_256(concatBytes(utf8ToBytes('BAMBOO-ZETHER-SCHNORR-V1'),
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

/** `c = keccak256(registry ‖ encodedY ‖ account)`; `account` = the subject account (R33 binding). */
export function popMessage(curve, registry, Y, account) {
  const reg = fromHex(registry);
  const acct = fromHex(account);
  if (reg.length !== 20 || acct.length !== 20) throw new Error('registry and account are addresses');
  const y = fromHex(Y);
  if (y.length !== 2 * curveOf(curve).coordLen) throw new Error('wrong point length');
  return keccak_256(concatBytes(reg, y, acct));
}

/** Registry PoP: `schnorrPop` and `popSignature = abi.encode(bytes schnorrPop, bytes authPop="")`. */
export function zetherPop(curve, x, { registry, account }) {
  const { Y, UA } = confPublic(curve, x);
  const c = popMessage(curve, registry, Y, account);
  const pop = schnorrSign(curve, x, c);
  return { Y, UA, c: hex(c), schnorrPop: hex(pop), popSignature: hex(abiEncode(['bytes', 'bytes'], [pop, new Uint8Array(0)])) };
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

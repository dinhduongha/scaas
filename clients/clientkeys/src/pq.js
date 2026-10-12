// Post-quantum UA kinds (accounts.md CTR-UA-23, signers-clientkeys.md "PQ seeds"): mldsa44 / mldsa65 (FIPS 204),
// fndsa512 (Falcon-512, round 3, padded signatures: EIP-8052's 666 bytes), slhdsa128s (FIPS 205 SLH-DSA-SHA2-128s).
// Keys come from the BIP-39 seed by HKDF; ML-DSA and SLH-DSA sign pq_msg = keccak256(TAG(kind) ‖ ua_msg) with the empty
// context, Falcon signs ua_msg (the 32-byte message of EIP-8052). There is no "sign this digest" entry: signUA takes the
// purpose tag and the operation digest and builds ua_msg itself (CTR-UA-10 layer 1).
import { ml_dsa44, ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { falcon512padded } from '@noble/post-quantum/falcon.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { shake128, shake256 } from '@noble/hashes/sha3.js';
import { keccak_256, sha256, concatBytes, utf8ToBytes } from './bytes.js';

/** kind number, tag string, scheme, HKDF output length, signed message. */
export const PQ_KINDS = {
  mldsa44: { kind: 0x0130, tag: 'scaas.ua.mldsa44.v1', alg: ml_dsa44, seedLen: 32, pq: true },
  mldsa65: { kind: 0x0131, tag: 'scaas.ua.mldsa65.v1', alg: ml_dsa65, seedLen: 32, pq: true },
  fndsa512: { kind: 0x0132, tag: 'scaas.ua.fndsa512.v1', alg: falcon512padded, seedLen: 48, pq: false },
  slhdsa128s: { kind: 0x0133, tag: 'scaas.ua.slhdsa128s.v1', alg: slh_dsa_sha2_128s, seedLen: 48, pq: true },
};

const MSG_TAG = keccak_256(utf8ToBytes('scaas.ua.msg.v1'));

function spec(name) {
  const s = PQ_KINDS[name];
  if (!s) throw new Error(`unknown PQ kind ${name}`);
  return s;
}

const u32 = (v, what) => {
  if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) throw new Error(`${what} must be an integer in [0, 2^32)`);
  return new Uint8Array([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
};
const b32 = (x, what) => {
  if (!(x instanceof Uint8Array) || x.length !== 32) throw new Error(`${what} must be 32 bytes`);
  return x;
};

/** TAG(kind) = keccak256(kind_tag). */
export const kindTag = (name) => keccak_256(utf8ToBytes(spec(name).tag));

/** UA = keccak256(TAG(kind) ‖ key data); key data = the public key (FIPS 204 / round-3 Falcon / FIPS 205 encoding). */
export const uaId = (name, publicKey) => keccak_256(concatBytes(kindTag(name), publicKey));

/** purposeTag = keccak256("scaas.ua.purpose.<p>.v1"). */
export const purposeTag = (p) => keccak_256(utf8ToBytes(`scaas.ua.purpose.${p}.v1`));

/** ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest) (CTR-UA-12). */
export const uaMessage = (name, purpose, digest) =>
  keccak_256(concatBytes(MSG_TAG, kindTag(name), b32(purpose, 'purposeTag'), b32(digest, 'digest')));

/** pq_msg = keccak256(TAG(kind) ‖ ua_msg) (CTR-UA-23). */
export const pqMessage = (name, uaMsg) => keccak_256(concatBytes(kindTag(name), b32(uaMsg, 'ua_msg')));

/** ξ = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info = kind_tag ‖ u32 account ‖ u32 index). */
export function pqSeed(seed, name, account, index) {
  const s = spec(name);
  if (!(seed instanceof Uint8Array)) throw new Error('seed must be a Uint8Array');
  const info = concatBytes(utf8ToBytes(s.tag), u32(account, 'account'), u32(index, 'index'));
  return hkdf(sha256, seed, utf8ToBytes('scaas.ua.pq.v1'), info, s.seedLen);
}

/** Deterministic key pair of a PQ kind. Falcon keys are implementation-specific: pinned to @noble/post-quantum 0.7.1 by the vectors. */
export function pqKeygen(seed, name, account, index) {
  const xi = pqSeed(seed, name, account, index);
  const { publicKey, secretKey } = spec(name).alg.keygen(xi);
  xi.fill(0);
  return { kind: name, publicKey, secretKey, ua: uaId(name, publicKey) };
}

/** The bytes the scheme signs: pq_msg (ML-DSA, SLH-DSA; empty context) or ua_msg (Falcon). */
export function signedMessage(name, purpose, digest) {
  const ua = uaMessage(name, purpose, digest);
  return spec(name).pq ? pqMessage(name, ua) : ua;
}

/** Signs (purpose, digest) for a PQ UA. `opts` goes to noble (e.g. { extraEntropy: false } for vectors). */
export const signUA = (name, secretKey, purpose, digest, opts) =>
  spec(name).alg.sign(signedMessage(name, purpose, digest), secretKey, opts);

export const verifyUA = (name, publicKey, purpose, digest, sig) =>
  spec(name).alg.verify(sig, signedMessage(name, purpose, digest), publicKey);

// ------------------------------------------------------------------ EIP-8051 expanded key (ML-DSA-44 and -65)

const Q = 8380417;
const ZETAS = (() => {
  const z = new Array(256);
  let pw = 1n;
  for (let i = 0; i < 256; i++) {
    let r = 0;
    for (let b = 0; b < 8; b++) r = (r << 1) | ((i >> b) & 1);
    z[r] = Number(pw);
    pw = (pw * 1753n) % BigInt(Q);
  }
  return z;
})();
const mulq = (a, b) => Number((BigInt(a) * BigInt(b)) % BigInt(Q));

function ntt(w) {
  let m = 0;
  for (let len = 128; len >= 1; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const z = ZETAS[++m];
      for (let j = start; j < start + len; j++) {
        const t = mulq(z, w[j + len]);
        w[j + len] = (w[j] - t + Q) % Q;
        w[j] = (w[j] + t) % Q;
      }
    }
  }
  return w;
}

function rejNttPoly(seed34) {
  const out = [];
  const xof = shake128.create();
  xof.update(seed34);
  while (out.length < 256) {
    const b = xof.xof(168);
    for (let o = 0; o < 168 && out.length < 256; o += 3) {
      const v = b[o] | (b[o + 1] << 8) | ((b[o + 2] & 0x7f) << 16);
      if (v < Q) out.push(v);
    }
  }
  return out;
}

/** EIP-8051 expanded key: Â (k·l polynomials, row-major) ‖ tr (64, FIPS 204) ‖ NTT(t1·2^13) (k), coefficients u32 big-endian. */
export function mldsaExpandedKey(name, pk) {
  const [k, l] = name === 'mldsa44' ? [4, 4] : name === 'mldsa65' ? [6, 5] : [0, 0];
  if (!k || pk.length !== 32 + 320 * k) throw new Error('mldsaExpandedKey: ML-DSA-44 or -65 public key required');
  const out = new Uint8Array((k * l + k) * 1024 + 64);
  const dv = new DataView(out.buffer);
  let o = 0;
  const put = (poly) => { for (const c of poly) { dv.setUint32(o, c); o += 4; } };
  for (let i = 0; i < k; i++) for (let j = 0; j < l; j++) put(rejNttPoly(concatBytes(pk.subarray(0, 32), new Uint8Array([j, i]))));
  out.set(shake256(pk, { dkLen: 64 }), o);
  o += 64;
  for (let i = 0; i < k; i++) {
    const t = new Array(256);
    const base = 32 + 320 * i;
    for (let c = 0; c < 256; c++) {
      const bit = 10 * c, by = base + (bit >> 3);
      const v = ((pk[by] | (pk[by + 1] << 8)) >> (bit & 7)) & 0x3ff;
      t[c] = mulq(v, 8192);
    }
    put(ntt(t));
  }
  return out;
}

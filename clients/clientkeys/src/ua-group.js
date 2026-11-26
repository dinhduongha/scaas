// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// UNAUDITED. The registry's checks for the group kinds 0x0110–0x0113 (accounts.md §1.6.1, §1.9; ARCH-POS-18: no kind goes unchecked
// for lack of a verifier), as the EVM verifiers (`Musig2Secp256k1Verifier`, `FrostSecp256k1Verifier`, `Musig2Bn254Verifier`,
// `FrostBn254Verifier`) and ua-rs `groups.rs` apply them, written from the spec, not from a signer. `groupOk(kind, key, msg, sig,
// pop)`: `pop` false is `verify(vk)`, `key` the stored group key (33-byte SEC1 `Q` / `Y`, 64-byte bn254 `Q` / `Y`); `pop` true is
// `verifyPop(keyData)`, the key data validated, the whole group check, then the group signature. Untrusted input: anything malformed
// is false or a throw (the caller's `attempt`), never an acceptance.
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { bn254 } from "@noble/curves/bn254.js";
import { hash_to_field } from "@noble/curves/abstract/hash-to-curve.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { validateKeyData } from "./ua.js";
import { hex, keccak_256, concatBytes, utf8ToBytes, word } from "./bytes.js";
import { VERIFY, bnG1 } from "./ua-verify.js";

const Pt = secp256k1.Point;
const N = Pt.Fn.ORDER;
const P = Pt.Fp.ORDER;
const BN = bn254.G1.Point;
const R = bn254.fields.Fr.ORDER;
const int = (b) => BigInt(hex(b));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const u16 = (d, o) => (d[o] << 8) | d[o + 1];
const fail = () => {
  throw new Error("malformed");
};
/** A 32-byte big-endian scalar below `n`, else a throw. */
const scalar = (b, n) => (b.length === 32 && int(b) < n ? int(b) : fail());
/** SEC1 compressed: prefix 02 / 03, `x < p`, on the curve; else a throw. */
const secpPt = (b) =>
  b.length === 33 && (b[0] === 2 || b[0] === 3) && int(b.subarray(1)) < P ? Pt.fromBytes(b) : fail();
/** SEC1 compressed, the identity as 33 zero bytes (never equal to valid key data). */
const secpEnc = (Q) => (Q.is0() ? new Uint8Array(33) : Q.toBytes(true));
/** EIP-196 `x ‖ y`, the identity as 64 zero bytes. */
const bnEnc = (Q) => {
  if (Q.is0()) return new Uint8Array(64);
  const { x, y } = Q.toAffine();
  return concatBytes(word(x), word(y));
};
const address = (xy) => keccak_256(xy).subarray(12);
/** BIP-340 tagged hash. */
const tagged = (tag, ...parts) => {
  const t = sha256(utf8ToBytes(tag));
  return sha256(concatBytes(t, t, ...parts));
};
/** RFC 9591 §6.5 `hash_to_field`: `expand_message_xmd` SHA-256, DST "FROST-secp256k1-SHA256-v1" ‖ label, 48 bytes, mod N. */
const H = (label, m) =>
  hash_to_field(m, 1, {
    DST: utf8ToBytes(`FROST-secp256k1-SHA256-v1${label}`),
    p: N,
    m: 1,
    k: 128,
    expand: "xmd",
    hash: sha256,
  })[0][0];
/** The bn254 port's 512-bit hash: `int(h(0x00) ‖ h(0x01)) mod r`. */
const wide = (h) => ((int(h(0)) << 256n) + int(h(1))) % R;
const bnSchnorr = (vk, msg, sig) => vk.length === 64 && VERIFY[0x0104](vk, msg, sig) === true;

/** `musig2-secp256k1` `verify`: BIP-340 by `x(Q)`; Q's parity plays no role (BIP-327 output is BIP-340-valid). */
const musig2SecpVk = (vk, msg, sig) =>
  vk.length === 33 && (vk[0] === 2 || vk[0] === 3) && sig.length === 64 && schnorr.verify(sig, msg, vk.subarray(1));

/** RFC 9591 FROST(secp256k1, SHA-256) verify: `Y`, `R` SEC1 compressed, `z < N`, `z·G == R + H2(R ‖ Y ‖ msg)·Y`. */
function frostSecp(y, msg, sig) {
  if (sig.length !== 65) return false;
  const Y = secpPt(y);
  const Rp = secpPt(sig.subarray(0, 33));
  const z = scalar(sig.subarray(33), N);
  const c = H("chal", concatBytes(sig.subarray(0, 33), y, msg));
  return Pt.BASE.multiplyUnsafe(z).equals(Rp.add(Y.multiplyUnsafe(c)));
}

/** BIP-327 KeyAgg of `pks`: `L`, and `a_i` by `coef(L, pk)` (1 for the second distinct key). */
function keyAgg(pks, coef) {
  const L = tagged("KeyAgg list", ...pks);
  const second = pks.find((p) => !eq(p, pks[0]));
  return pks.map((p) => (second && eq(p, second) ? 1n : coef(L, p)));
}

/** `pop = sig (64) ‖ n × H_i (64)`: each `H_i` checked as the `ecrecover` trick does (`x(P_i) < N`, `address(a_i·P_i) ==
 *  address(H_i)`), `Σ a_i·P_i == Q` (x and parity), then BIP-340 by `x(Q)`. */
function musig2SecpPop(kd, msg, pop) {
  const n = u16(kd, 33);
  if (pop.length !== 64 + 64 * n) return false;
  const pks = Array.from({ length: n }, (_, i) => kd.subarray(35 + 33 * i, 68 + 33 * i));
  const a = keyAgg(pks, (L, p) => int(tagged("KeyAgg coefficient", L, p)) % N);
  let S = Pt.ZERO;
  for (let i = 0; i < n; i++) {
    if (int(pks[i].subarray(1)) >= N) return false; // ecrecover refuses r = x(P_i) ≥ N
    const h = secpPt(pks[i]).multiplyUnsafe(a[i]); // a_i = 0: the identity, which has no address (ecrecover's s = 0)
    if (!eq(address(h.toBytes(false).subarray(1)), address(pop.subarray(64 + 64 * i, 128 + 64 * i)))) return false;
    S = S.add(h);
  }
  return eq(secpEnc(S), kd.subarray(0, 33)) && schnorr.verify(pop.subarray(0, 64), msg, kd.subarray(1, 33));
}

/** The bn254 port of KeyAgg (`ECMUL` / `ECADD`, no hints), `Q` byte-equal, then the scaas Schnorr by `Q`. */
function musig2BnPop(kd, msg, sig) {
  const n = u16(kd, 64);
  const pks = Array.from({ length: n }, (_, i) => kd.subarray(66 + 64 * i, 130 + 64 * i));
  const a = keyAgg(pks, (L, p) => wide((b) => tagged("KeyAgg coefficient", L, p, Uint8Array.of(b))));
  const Q = pks.reduce((acc, p, i) => acc.add(bnG1(p).multiplyUnsafe(a[i])), BN.ZERO);
  return eq(bnEnc(Q), kd.subarray(0, 64)) && bnSchnorr(kd.subarray(0, 64), msg, sig);
}

/** frost-core's PoK of participant `id` (scalar identifier `1..n`, 32 bytes big-endian in the challenge): `R_i == μ_i·G − c_i·C_i0`. */
function secpPok(id, c0, r, mu) {
  const [C0, Rp, m] = [secpPt(c0), secpPt(r), scalar(mu, N)];
  const c = H("dkg", concatBytes(word(id), c0, r));
  return Rp.equals(Pt.BASE.multiplyUnsafe(m).subtract(C0.multiplyUnsafe(c)));
}
const DKG_BN = utf8ToBytes("FROST-BN254-KECCAK256-SCAAS-v1dkg");
function bnPok(id, c0, r, mu) {
  const [C0, Rp, m] = [bnG1(c0), bnG1(r), scalar(mu, R)];
  const c = wide((b) => keccak_256(concatBytes(DKG_BN, word(id), c0, r, Uint8Array.of(b))));
  return Rp.equals(BN.BASE.multiplyUnsafe(m).subtract(C0.multiplyUnsafe(c)));
}
/** The DKG transcript `Y ‖ u16 t ‖ u16 n ‖ n × (t × C_ik ‖ R_i ‖ μ_i)`: every PoK and `Y == Σ C_i0` (as encodings). secp256k1: a
 *  `C_i0` sharing its x with the partial sum (repeated or cancelling) is refused, as `FrostSecp256k1Verifier`'s mixed addition
 *  refuses it; bn254 (`ECADD`) has no such case. */
function dkgOk(kd, w, point, enc, pok) {
  const [t, n] = [u16(kd, w), u16(kd, w + 2)];
  const per = (t + 1) * w + 32;
  let S = null;
  for (let i = 0; i < n; i++) {
    const b = kd.subarray(w + 4 + i * per, w + 4 + (i + 1) * per);
    if (!pok(i + 1, b.subarray(0, w), b.subarray(t * w, (t + 1) * w), b.subarray((t + 1) * w))) return false;
    if (w === 33 && S && eq(enc(S).subarray(1), b.subarray(1, w))) return false;
    S = S ? S.add(point(b.subarray(0, w))) : point(b.subarray(0, w));
  }
  return S !== null && eq(enc(S), kd.subarray(0, w));
}

/** `verify` (`pop` false: `key` the stored vk) / `verifyPop` (`pop` true: `key` the key data) of a group kind. */
export function groupOk(kind, key, msg, sig, pop) {
  if (pop) {
    validateKeyData(kind, key); // throws UAError: the caller's refusal
    if (kind === 0x0110) return musig2SecpPop(key, msg, sig);
    if (kind === 0x0111) return dkgOk(key, 33, secpPt, secpEnc, secpPok) && frostSecp(key.subarray(0, 33), msg, sig);
    if (kind === 0x0112) return musig2BnPop(key, msg, sig);
    if (kind === 0x0113) return dkgOk(key, 64, bnG1, bnEnc, bnPok) && bnSchnorr(key.subarray(0, 64), msg, sig);
    return false;
  }
  if (kind === 0x0110) return musig2SecpVk(key, msg, sig);
  if (kind === 0x0111) return frostSecp(key, msg, sig);
  return (kind === 0x0112 || kind === 0x0113) && bnSchnorr(key, msg, sig);
}
/** The stored vk's length of a group kind (the key data's head), 0 for any other kind. */
export const groupVkLength = (kind) =>
  kind === 0x0110 || kind === 0x0111 ? 33 : kind === 0x0112 || kind === 0x0113 ? 64 : 0;

// The UA kind verifiers of accounts.md §1.9, written from the spec (not from the generators' signing code), shared by
// test/ua-sig.test.js (signatures.json) and test/ua8.test.js (portable.json): `verify(kind, keyData, msg, sig, pop)` per
// derived kind (any throw is a refusal), the native EOA rule `nativeOk`, and the ABI readers the msig decoders use.
import { p256 } from '@noble/curves/nist.js';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { schnorrVerify as zetherVerify } from '../src/zether.js';
import { PQ_KINDS, pqMessage } from '../src/pq.js';
import * as ua from '../src/ua.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, b64url } from '../src/bytes.js';
export const int = (b) => BigInt(hex(b));
export const B = (h) => fromHex(h);
export const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
export const attempt = (f) => { try { return f(); } catch { return false; } };

// --- ABI reading (offsets as the decoder sees them) ---
export const wordAt = (b, o) => Number(int(b.subarray(o, o + 32)));
export const bytesAt = (b, base, head) => { const o = base + wordAt(b, head); return b.subarray(o + 32, o + 32 + wordAt(b, o)); };

// --- verifiers (§1.9) ---
export const P256_N = p256.Point.Fn.ORDER;
export const p256Ok = (xy, h, r, s) => int(s) <= P256_N / 2n
  && p256.verify(concatBytes(r, s), h, concatBytes(Uint8Array.of(4), xy), { prehash: false, lowS: true });

/** SmartKeyAccount._clientDataOk without the origin comparison. */
export function clientDataOk(cd, challenge) {
  const prefix = `{"type":"webauthn.get","challenge":"${b64url(challenge)}","origin":"`;
  const s = new TextDecoder().decode(cd);
  const n = s.length;
  if (n < prefix.length + 2 || !s.startsWith(prefix)) return false;
  const end = s.indexOf('"', prefix.length);
  if (end < 0 || end + 1 >= n) return false;
  if (s[end + 1] === '}') return end + 2 === n;
  const cross = ',"crossOrigin":false';
  const after = end + 1 + cross.length;
  if (after >= n || s.slice(end + 1, after) !== cross) return false;
  return s[after] === '}' ? after + 1 === n : s[after] === ',';
}
/** `[authenticatorData, clientDataJSON]` only if `blob` is their canonical `abi.encode(authenticatorData, clientDataJSON,
 *  r, s)` (owner 2026-10-30, CTR-UA-33 C; WebAuthnP256Verifier._fields): heads 0x80 and 0xa0 + pad32(len a), each field
 *  its length word ‖ data ‖ zero padding, no trailing bytes; else null. */
export function webauthnFields(blob) {
  const n = blob.length;
  const pad = (x) => Math.ceil(x / 32) * 32;
  if (n < 0xc0) return null;
  const la = wordAt(blob, 0x80);
  if (la > n) return null;
  const oc = 0xa0 + pad(la);
  if (oc + 32 > n) return null;
  const lc = wordAt(blob, oc);
  if (lc > n || n !== oc + 32 + pad(lc) || wordAt(blob, 0) !== 0x80 || wordAt(blob, 32) !== oc) return null;
  const zero = (from, to) => blob.subarray(from, to).every((x) => x === 0);
  if (!zero(0xa0 + la, oc) || !zero(oc + 32 + lc, n)) return null;
  return [blob.subarray(0xa0, 0xa0 + la), blob.subarray(oc + 32, oc + 32 + lc)];
}
export function webauthnOk(kd, msg, blob) {
  const f = webauthnFields(blob); // checked first
  if (!f) return false;
  const [authData, cd] = f;
  if (authData.length < 37 || !eq(authData.subarray(0, 32), kd.subarray(64, 96)) || (authData[32] & 0x05) !== 0x05) return false;
  if (!clientDataOk(cd, msg)) return false;
  return p256Ok(kd.subarray(0, 64), sha256(concatBytes(authData, sha256(cd))), blob.subarray(64, 96), blob.subarray(96, 128));
}

export const hashToScalar = (seed, r) => ((int(keccak_256(concatBytes(seed, Uint8Array.of(2)))) << 256n)
  + int(keccak_256(concatBytes(seed, Uint8Array.of(3))))) % r;
export const bnG1 = (b) => {
  const x = int(b.subarray(0, 32)); const y = int(b.subarray(32, 64));
  if (x === 0n && y === 0n) throw new Error('identity');
  const P = bn254.G1.Point.fromAffine({ x, y }); P.assertValidity(); return P;
};
export const blsFp = (b) => { if (!b.subarray(0, 16).every((v) => v === 0)) throw new Error('padding'); return int(b.subarray(16, 64)); };
export const blsG1 = (b) => {
  const x = blsFp(b.subarray(0, 64)); const y = blsFp(b.subarray(64, 128));
  if (x === 0n && y === 0n) throw new Error('identity');
  const P = bls12_381.G1.Point.fromAffine({ x, y }); P.assertValidity(); return P; // assertValidity includes the subgroup
};
export const schnorrOk = (G, r, size, dec) => (kd, msg, sig) => {
  if (sig.length !== size + 32) return false;
  const Rb = sig.subarray(0, size);
  const z = int(sig.subarray(size));
  const R = dec(Rb); const Y = dec(kd);
  const e = hashToScalar(keccak_256(concatBytes(utf8ToBytes('scaas.ua.schnorr.v1'), Rb, kd, msg)), r);
  if (z >= r || e === 0n) return false;
  return G.BASE.multiplyUnsafe(z).equals(R.add(Y.multiply(e)));
};

export function mapToG1Bn254(prefix) {
  const { Fp } = bn254.fields;
  for (let ctr = 0; ; ctr++) {
    const c = new Uint8Array(4); new DataView(c.buffer).setUint32(0, ctr);
    const x = int(keccak_256(concatBytes(prefix, c))) % Fp.ORDER;
    const rhs = Fp.add(Fp.mul(Fp.sqr(x), x), 3n);
    let y = Fp.pow(rhs, (Fp.ORDER + 1n) / 4n);
    if (Fp.eql(Fp.sqr(y), rhs)) return bn254.G1.Point.fromAffine({ x, y: y & 1n ? Fp.ORDER - y : y });
  }
}
export const pairingEq = (curve, a, b, c, d) => curve.fields.Fp12.eql(curve.pairing(a, b), curve.pairing(c, d));
export function blsBn254Ok(kd, msg, sig, pop) {
  if (sig.length !== 64) return false;
  const S = bnG1(sig);
  const w = [0, 1, 2, 3].map((i) => int(kd.subarray(32 * i, 32 * i + 32)));
  const pk = bn254.G2.Point.fromAffine({ x: { c0: w[1], c1: w[0] }, y: { c0: w[3], c1: w[2] } });
  const H = mapToG1Bn254(concatBytes(utf8ToBytes(pop ? 'SCAAS-UA-BLS-BN254-POP-V1' : 'SCAAS-UA-BLS-BN254-SIG-V1'), msg));
  return pairingEq(bn254, S, bn254.G2.Point.BASE, H, pk);
}
export function bls12381Ok(kd, msg, sig, pop) {
  if (sig.length !== 128) return false;
  const S = blsG1(sig);
  const w = [0, 1, 2, 3].map((i) => blsFp(kd.subarray(64 * i, 64 * i + 64)));
  const pk = bls12_381.G2.Point.fromAffine({ x: { c0: w[0], c1: w[1] }, y: { c0: w[2], c1: w[3] } });
  const H = bls12_381.G1.hashToCurve(msg, { DST: `SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_${pop ? 'POP' : 'SIG'}_` });
  return pairingEq(bls12_381, S, bls12_381.G2.Point.BASE, H, pk);
}
// ed25519 (§1.9 "RFC 8032 strict"): noble zip215:false refuses non-canonical A / R, S ≥ L and small-order A and checks the
// cofactored equation; verify_strict also refuses small-order R and checks [S]B == R + [k]A without the cofactor.
export const ED_L = ed25519.Point.Fn.ORDER;
export const leInt = (b) => int(Uint8Array.from(b).reverse());
export const edNoble = (pk, msg, sig) => attempt(() => ed25519.verify(sig, msg, pk, { zip215: false }));
export function ed25519Ok(pk, msg, sig) {
  if (sig.length !== 64 || !edNoble(pk, msg, sig)) return false;
  const R = ed25519.Point.fromBytes(sig.subarray(0, 32));
  if (R.isSmallOrder()) return false;
  const k = leInt(sha512(concatBytes(sig.subarray(0, 32), pk, msg))) % ED_L;
  return ed25519.Point.BASE.multiplyUnsafe(leInt(sig.subarray(32))).equals(R.add(ed25519.Point.fromBytes(pk).multiplyUnsafe(k)));
}
export const VERIFY = {
  0x0100: webauthnOk,
  0x0102: ed25519Ok,
  0x0101: (kd, msg, sig) => sig.length === 64 && p256Ok(kd, sha256(msg), sig.subarray(0, 32), sig.subarray(32)),
  0x0103: (kd, msg, sig) => sig.length === 64 && schnorr.verify(sig, msg, kd),
  0x0104: schnorrOk(bn254.G1.Point, bn254.fields.Fr.ORDER, 64, bnG1),
  0x0105: schnorrOk(bls12_381.G1.Point, bls12_381.fields.Fr.ORDER, 128, blsG1),
  0x0106: bls12381Ok,
  0x0107: blsBn254Ok,
  // UA-6: the Zether UA's Schnorr (tag SCAAS-ZETHER-SCHNORR-V1), verified by clientkeys' own zether.js (the prover's twin)
  0x0141: (kd, msg, sig) => zetherVerify('bls12381', kd, msg, sig),
  // secp256k1 (ECDSA): r‖s‖v over ua_msg recovering address(keccak256(x ‖ y)), as the native EOA rule
  0x0108: (kd, msg, sig) => kd.length === 64 && nativeOk(hex(keccak_256(kd).subarray(12)), msg, hex(sig)),
};
/** `verify` / `verifyPop` (pop only matters for the BLS kinds); any throw is a refusal. */
export const verify = (kind, kd, msg, sig, pop = false) => attempt(() => VERIFY[kind](B(kd), B(msg), B(sig), pop) === true);

export const SECP_N = secp256k1.Point.Fn.ORDER;
/** Native EOA: low-s ECDSA r‖s‖v over UAAuth(ua, purpose, digest) under the registry domain. */
export function nativeOk(address, h, sig) {
  return attempt(() => {
    const s = B(sig);
    if (s.length !== 65 || (s[64] !== 27 && s[64] !== 28) || int(s.subarray(32, 64)) > SECP_N / 2n) return false;
    const pub = secp256k1.recoverPublicKey(concatBytes(Uint8Array.of(s[64] - 27), s.subarray(0, 64)), h, { prehash: false });
    return eq(keccak_256(secp256k1.Point.fromBytes(pub).toBytes(false).subarray(1)).subarray(12), B(address));
  });
}

// --- shared by test/ua8.test.js (portable.json) and test/soroban.test.js (ua-ops.json) ---
export const pqName = (kind) => Object.keys(PQ_KINDS).find((n) => PQ_KINDS[n].kind === kind);
/** A derived kind's signature over a 32-byte ua_msg: test/ua-verify.js (classical, BLS pop DST) or noble (PQ). */
export function sigOk(kind, keyData, msg, sig) {
  const n = pqName(kind);
  if (!n) return verify(kind, keyData, msg, sig, true);
  return attempt(() => PQ_KINDS[n].alg.verify(B(sig), PQ_KINDS[n].pq ? pqMessage(n, B(msg)) : B(msg), B(keyData)));
}
/** `abi.decode(blob, (MemberSig[]))`, MemberSig = (uint16 index, bytes keyData, bytes sig). */
export function memberSigs(blob) {
  const b = B(blob);
  const a = wordAt(b, 0);
  const base = a + 32;
  return Array.from({ length: wordAt(b, a) }, (_, i) => {
    const t = base + wordAt(b, base + 32 * i);
    return { index: wordAt(b, t), keyData: bytesAt(b, t, t + 32), sig: bytesAt(b, t, t + 64) };
  });
}
/** An msig signature: indices strictly increasing, each member verifies over `memberDigest` (derived members by key data
 *  from `keyOf`, under `member`; a native member by EIP-191 personal_sign, no key data), weight at least the threshold. */
export function msigOk(r, md, blob, keyOf) {
  let weight = 0;
  let last = -1;
  for (const s of memberSigs(blob)) {
    const m = r.members[s.index];
    if (!m || s.index <= last) return false;
    last = s.index;
    const ok = ua.isNativeKind(m.kind)
      ? s.keyData.length === 0 && nativeOk(`0x${m.id.slice(26)}`, ua.personalSignDigest(B(md)), hex(s.sig))
      : s.keyData.length === 0 && sigOk(m.kind, keyOf(m.id), hex(ua.uaMessage(m.kind, ua.purposeTag('member'), B(md))), hex(s.sig));
    if (!ok) return false;
    weight += m.weight;
  }
  return weight >= r.threshold;
}

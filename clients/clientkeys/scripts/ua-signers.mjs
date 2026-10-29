// The deterministic vector signers shared by scripts/ua-sig-vectors.mjs (signatures.json, pq_signatures.json, ...) and
// scripts/ua-portable-vectors.mjs (portable.json): per derived kind keyData(sk) and sign(sk, msg32, { pop }), the native
// EOA key, the msig MemberSig encoding and the PQ signers on pq_kat.json's seed. Test vectors only: fixed nonces.
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, b64url, abiEncode, word } from '../src/bytes.js';
import * as ua from '../src/ua.js';
import { seedFromWords } from '../src/seed.js';
import { PQ_KINDS, pqKeygen, pqMessage } from '../src/pq.js';
import { schnorrSign as zetherSchnorr } from '../src/zether.js';

const ZERO32 = new Uint8Array(32);
export const int = (b) => BigInt(hex(b));
export const be = (v, len) => fromHex(v.toString(16).padStart(2 * len, '0'));
export const secretOf = (name, n) => (int(keccak_256(utf8ToBytes(`scaas.ua.vectors.sig.${name}`))) % (n - 1n)) + 1n;
export const P256_N = p256.Point.Fn.ORDER;
export const SECP_N = secp256k1.Point.Fn.ORDER;
export const BN = bn254.fields;
export const BLS = bls12_381.fields;

export const p256Sign = (sk, h) => p256.sign(h, be(sk, 32), { prehash: false, lowS: true, format: 'compact' });
export const secpSign = (sk, h) => {
  const rec = secp256k1.sign(h, be(sk, 32), { prehash: false, lowS: true, format: 'recovered' });
  return concatBytes(rec.subarray(1), Uint8Array.of(27 + rec[0]));
};
/** The same ECDSA signature with s → n − s and v flipped: it recovers the same key, refused by the low-s rule. */
export const secpHighS = (sig) => concatBytes(sig.subarray(0, 32), be(SECP_N - int(sig.subarray(32, 64)), 32), Uint8Array.of(55 - sig[64]));
export const withV = (sig, v) => concatBytes(sig.subarray(0, 64), Uint8Array.of(v));
export const highS = (sig) => concatBytes(sig.subarray(0, 32), be(P256_N - int(sig.subarray(32, 64)), 32));

export const RP_ID = 'scaas.example';
export const ORIGIN = 'https://scaas.example';
export const CHROME_EXTRA = ',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"';
/** WebAuthn assertion as `abi.encode(bytes authenticatorData, string clientDataJSON, uint256 r, uint256 s)`. */
export function webauthnSign(sk, msg, { flags = 0x05, rpId = RP_ID, type = 'webauthn.get', tail = '', counter = 1 } = {}) {
  const authData = concatBytes(sha256(utf8ToBytes(rpId)), Uint8Array.of(flags), be(BigInt(counter), 4));
  const cd = utf8ToBytes(`{"type":"${type}","challenge":"${b64url(msg)}","origin":"${ORIGIN}"${tail}}`);
  const sig = p256Sign(sk, sha256(concatBytes(authData, sha256(cd))));
  return abiEncode(['bytes', 'bytes', 'bytes32', 'bytes32'], [authData, cd, sig.subarray(0, 32), sig.subarray(32, 64)]);
}
export const webauthnHighS = (blob) => { const c = Uint8Array.from(blob); c.set(be(P256_N - int(c.subarray(96, 128)), 32), 96); return c; };

export const hashToScalar = (seed, r) => ((int(keccak_256(concatBytes(seed, Uint8Array.of(2)))) << 256n)
  + int(keccak_256(concatBytes(seed, Uint8Array.of(3))))) % r;
export const SCHNORR_TAG = utf8ToBytes('scaas.ua.schnorr.v1');
export const bnG1enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, 32), be(y, 32)); };
export const blsG1enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, 64), be(y, 64)); };
/** scaas Schnorr (§1.9): R = kG, e = hashToScalar(keccak256(tag ‖ R ‖ Y ‖ m)), z = k + e·x. */
export const schnorrScheme = (G, r, enc) => ({
  keyData: (sk) => enc(G.BASE.multiply(sk)),
  sign(sk, msg) {
    const k = (int(keccak_256(concatBytes(be(sk, 32), msg, utf8ToBytes('scaas.ua.vectors.nonce')))) % (r - 1n)) + 1n;
    const R = enc(G.BASE.multiply(k));
    const e = hashToScalar(keccak_256(concatBytes(SCHNORR_TAG, R, enc(G.BASE.multiply(sk)), msg)), r);
    if (e === 0n) throw new Error('e = 0');
    return concatBytes(R, be((k + e * sk) % r, 32));
  },
});

/** Port of ZetherCurves.sol `G1Bn254.mapToG1`: try-and-increment over keccak256(prefix ‖ uint32 ctr), even y. */
export function mapToG1Bn254(prefix) {
  const { Fp } = BN;
  for (let ctr = 0; ; ctr++) {
    const x = int(keccak_256(concatBytes(prefix, be(BigInt(ctr), 4)))) % Fp.ORDER;
    const rhs = Fp.add(Fp.mul(Fp.sqr(x), x), 3n);
    let y = Fp.pow(rhs, (Fp.ORDER + 1n) / 4n);
    if (Fp.eql(Fp.sqr(y), rhs)) {
      if (y & 1n) y = Fp.ORDER - y;
      return bn254.G1.Point.fromAffine({ x, y });
    }
  }
}
export const BN_LABEL = { sig: utf8ToBytes('SCAAS-UA-BLS-BN254-SIG-V1'), pop: utf8ToBytes('SCAAS-UA-BLS-BN254-POP-V1') };
export const BLS_DST = { sig: 'SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_', pop: 'SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_' };
export const bnG2enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c1, 32), be(x.c0, 32), be(y.c1, 32), be(y.c0, 32)); };
export const blsG2enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c0, 64), be(x.c1, 64), be(y.c0, 64), be(y.c1, 64)); };
export const SCHEMES = {
  'webauthn-p256': { kind: 0x0100, n: P256_N,
    keyData: (sk) => concatBytes(p256.getPublicKey(be(sk, 32), false).subarray(1), sha256(utf8ToBytes(RP_ID))),
    sign: (sk, m) => webauthnSign(sk, m) },
  p256: { kind: 0x0101, n: P256_N, keyData: (sk) => p256.getPublicKey(be(sk, 32), false).subarray(1),
    sign: (sk, m) => p256Sign(sk, sha256(m)) },
  bip340: { kind: 0x0103, n: SECP_N, keyData: (sk) => schnorr.getPublicKey(be(sk, 32)),
    sign: (sk, m) => schnorr.sign(m, be(sk, 32), ZERO32) },
  'schnorr-bn254': { kind: 0x0104, n: BN.Fr.ORDER, ...schnorrScheme(bn254.G1.Point, BN.Fr.ORDER, bnG1enc) },
  'schnorr-bls12381': { kind: 0x0105, n: BLS.Fr.ORDER, ...schnorrScheme(bls12_381.G1.Point, BLS.Fr.ORDER, blsG1enc) },
  'bls12381-minsig': { kind: 0x0106, n: BLS.Fr.ORDER, keyData: (sk) => blsG2enc(bls12_381.G2.Point.BASE.multiply(sk)),
    sign: (sk, m, { pop = false } = {}) => blsG1enc(bls12_381.G1.hashToCurve(m, { DST: pop ? BLS_DST.pop : BLS_DST.sig }).multiply(sk)) },
  'bls-bn254-minsig': { kind: 0x0107, n: BN.Fr.ORDER, keyData: (sk) => bnG2enc(bn254.G2.Point.BASE.multiply(sk)),
    sign: (sk, m, { pop = false } = {}) => bnG1enc(mapToG1Bn254(concatBytes(pop ? BN_LABEL.pop : BN_LABEL.sig, m)).multiply(sk)) },
  // UA-2b, appended (signatures.json is append-only): the secret is the RFC 8032 seed
  ed25519: { kind: 0x0102, seed: true, keyData: (sk) => ed25519.getPublicKey(be(sk, 32)), sign: (sk, m) => ed25519.sign(m, be(sk, 32)) },
  // 2026-10-17, appended: ECDSA secp256k1 over the 32-byte ua_msg (no prehash), sig = r ‖ s ‖ v, low-s, v ∈ {27, 28}
  secp256k1: { kind: 0x0108, n: SECP_N, keyData: (sk) => secp256k1.getPublicKey(be(sk, 32), false).subarray(1),
    sign: (sk, m) => secpSign(sk, m) },
  // UA-6, appended: the Zether key UA signs every UA-ledger write (SIGNING set) by the Zether Schnorr (tag SCAAS-ZETHER-SCHNORR-V1,
  // clients/zether-prover/src/schnorr.rs); a stored kind, so its auth carries an empty keyData (the registry reads Y)
  'zether-bls12381': { kind: 0x0141, n: BLS.Fr.ORDER, stored: true,
    keyData: (sk) => blsG1enc(bls12_381.G1.Point.BASE.multiply(sk)),
    sign(sk, m) {
      const k = (int(keccak_256(concatBytes(be(sk, 32), m, utf8ToBytes('scaas.ua.vectors.nonce')))) % (BLS.Fr.ORDER - 1n)) + 1n;
      return zetherSchnorr('bls12381', be(sk, 32), m, k);
    } },
};
export const ecdsa = (sk, h) => {
  const rec = secp256k1.sign(h, be(sk, 32), { prehash: false, lowS: true, format: 'recovered' });
  return concatBytes(rec.subarray(1), Uint8Array.of(27 + rec[0]));
};
export const nativeSk = secretOf('native', SECP_N);
export const nativeAddr = keccak_256(secp256k1.getPublicKey(be(nativeSk, 32), false).subarray(1)).subarray(12);
export const nativeUa = ua.nativeId(0x0001, nativeAddr);
/** `abi.encode(MemberSig[])`, MemberSig = (uint16 index, bytes keyData, bytes sig). */
export function encodeMemberSigs(list) {
  const tuples = list.map(({ index, keyData, sig }) => abiEncode(['uint16', 'bytes', 'bytes'], [index, keyData, sig]));
  const offsets = [];
  let o = 32 * list.length;
  for (const t of tuples) { offsets.push(word(o)); o += t.length; }
  return concatBytes(word(32), word(list.length), ...offsets, ...tuples);
}
export const PQ_MNEMONIC = 'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author '
  + 'capable act festival slice deposit sauce coconut afford frown better'; // pq_kat.json's
export const pqSeedBytes = seedFromWords(PQ_MNEMONIC);
// Test vectors only: this fixed Falcon sampler stream repeats across messages; never copy it into a production signer.
export const pqFixed = (n) => shake256(utf8ToBytes('scaas p6a falcon randomness'), { dkLen: n });
export const pqOpts = (name) => (name === 'fndsa512' ? { random: pqFixed } : { extraEntropy: false });
/** Signs a 32-byte ua_msg the kind's way: pq_msg with the empty context (ML-DSA, SLH-DSA), ua_msg itself (Falcon). */
export const pqSignMsg = (name, sk, uaMsg, opts = pqOpts(name)) =>
  PQ_KINDS[name].alg.sign(PQ_KINDS[name].pq ? pqMessage(name, uaMsg) : uaMsg, sk, opts);
export const pqKey = (name, index) => pqKeygen(pqSeedBytes, name, 0, index);

// --- UA-8 (portable registrations): the secret of a derived row, the PQZ fillers per parameter set, the KEM keys ---
/** The secret of `SCHEMES[name]`'s signatures.json row: the 32-byte keccak itself for ed25519 (RFC 8032 seed). */
export const schemeSecret = (name) => (SCHEMES[name].seed ? int(keccak_256(utf8ToBytes(`scaas.ua.vectors.sig.${name}`)))
  : secretOf(name, SCHEMES[name].n));
/** The PQZ parameter sets: the PQZ key length (PqzSet.PK) and the R_REG proof length of the set's proof_pqzl.json REGISTER
 *  row (smartcontracts/vectors/pqz/[<set>/]proof_pqzl.json rows[4]). */
export const PQZ_SETS = Object.freeze({
  'n2048-kmax1024': { pqzKeyLength: 16384, pqzPopLength: 28191 },
  'n2304-kmax4096': { pqzKeyLength: 18432, pqzPopLength: 30381 },
  'n2560-kmax16384': { pqzKeyLength: 20480, pqzPopLength: 32539 },
  'n2816-kmax65536': { pqzKeyLength: 22528, pqzPopLength: 35479 },
});
/** A set's filler PQZ key (the n2048-kmax1024 one is kinds.json's `pqzKey`) and filler R_REG proof (UA-8 D17: of a real
 *  proof's length, not a proof; forge mocks the precompile per exact bytes). `other` labels a second filler of the same length. */
export const pqzKeyOf = (set, other = '') => shake256(utf8ToBytes(`scaas ua-1 vector pqz-mlwe key${other}`), { dkLen: PQZ_SETS[set].pqzKeyLength });
export const pqzPopOf = (set, other = '') => shake256(utf8ToBytes(`scaas ua-8 vector pqz-pop ${set}${other}`), { dkLen: PQZ_SETS[set].pqzPopLength });
/** UA-8 D15: a real KEM key, ML-KEM-1024 ek ‖ X25519 pk (X-Wing order, 1,568 + 32 bytes), from a fixed label. */
export function kemPublicKey(label) {
  const seed = shake256(utf8ToBytes(`scaas ua-8 vector kem ${label}`), { dkLen: 96 });
  return concatBytes(ml_kem1024.keygen(seed.subarray(0, 64)).publicKey, x25519.getPublicKey(seed.subarray(64)));
}

// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The PQZ three-key model on the client (spec 2026-11-13 pqz-three-keys; CLI-SGN-50, CLI-SGN-51, CTR-PQZ-38, CTR-PQZ-40):
// the key seeds of the classes `offchain-shared` and `offchain-token` (K3-2), the opening KEM key (K3-6b), the leg seed
// (K3-4), the opening coins and the sealed opening (K3-6), the `memoHash` that covers the openings. The holder check of K3-7
// re-encrypts from the leg seed with PQZ arithmetic this package does not carry: it runs in pqz-ffi / ua-rs; here the opening
// is sealed and opened, every failure the one outcome `null`. UNAUDITED.
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256, shake256 } from '@noble/hashes/sha3.js';
import { gcm } from '@noble/ciphers/aes.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { concatBytes, utf8ToBytes } from './bytes.js';
import { encaps, combine, checkKemPk, kemKey } from './pqchat.js';

const asBytes = (x, n, what) => {
  const b = typeof x === 'string' ? Uint8Array.from((x.startsWith('0x') ? x.slice(2) : x).match(/../g) ?? [], (h) => parseInt(h, 16)) : x;
  if (!(b instanceof Uint8Array) || (n !== undefined && b.length !== n)) throw new Error(`${what}: ${n ?? 'some'} bytes`);
  return b;
};
const u32 = (x) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, x); return b; };
const be64 = (v) => {
  const x = BigInt(v);
  if (x < 0n || x >= 1n << 64n) throw new Error('version must be a uint64');
  const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, x); return b;
};

/** K3-2: the PQZ key seed of class `offchain-shared` (`token` omitted) or `offchain-token` (`token` the token's address), 32 B:
 *  `HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info)`, `info` = `"scaas.ua.pqz-mlwe.offchain-shared.v1" ‖ u32 account ‖
 *  u32 index ‖ chainUid ‖ be64 v` or `"scaas.ua.pqz-mlwe.offchain-token.v1" ‖ … ‖ chainUid ‖ token ‖ be64 v` (the version always).
 *  Class `registry` stays `pqzKeySeed` (src/pq.js), byte for byte. An `msig` operator draws each class and version fresh. */
export function pqzScopedKeySeed(seed, { account, index, chainUid, token, version }) {
  asBytes(seed, 64, 'seed');
  const label = token === undefined ? 'scaas.ua.pqz-mlwe.offchain-shared.v1' : 'scaas.ua.pqz-mlwe.offchain-token.v1';
  const info = concatBytes(utf8ToBytes(label), u32(account), u32(index), asBytes(chainUid, 32, 'chainUid'),
    token === undefined ? new Uint8Array(0) : asBytes(token, 20, 'token'), be64(version));
  return hkdf(sha256, seed, utf8ToBytes('scaas.ua.pq.v1'), info, 32);
}

/** K3-6b: the opening KEM seed of a scoped record, 96 B: `HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.kem.v1", info, L = 96)`,
 *  `info` = `"scaas.kem.pqz-opening.1" ‖ ua ‖ chainUid ‖ be64 v` (offchain-shared) or `"scaas.kem.pqz-opening-token.1" ‖ ua ‖
 *  chainUid ‖ token ‖ be64 v` (offchain-token with the opening). Never given to chat code. */
export function openKemSeed(seed, { ua, chainUid, token, version }) {
  asBytes(seed, 64, 'seed');
  const label = token === undefined ? 'scaas.kem.pqz-opening.1' : 'scaas.kem.pqz-opening-token.1';
  const info = concatBytes(utf8ToBytes(label), asBytes(ua, 32, 'ua'), asBytes(chainUid, 32, 'chainUid'),
    token === undefined ? new Uint8Array(0) : asBytes(token, 20, 'token'), be64(version));
  return hkdf(sha256, seed, utf8ToBytes('scaas.ua.kem.v1'), info, 96);
}

/** The opening KEM key of a seed: `(ek, dk) = ML-KEM-1024.KeyGen_internal(d = s[0:32], z = s[32:64])`, `sk_X = s[64:96]`,
 *  `kemPk = 0x01 ‖ ek ‖ X25519(sk_X, 9)` (1,601 B, the scoped record's `openKem`). */
export function openKemKey(okSeed) {
  const s = asBytes(okSeed, 96, 'openKemSeed');
  const k = kemKey(s.subarray(0, 64), s.subarray(64));
  return { kemPk: k.kemPk, dk: k.dk, x25519Secret: s.slice(64) };
}

/** K3-4: `seed_leg = SHAKE256("SCAAS-PQZ-ENC-LEG-V1" ‖ seed_enc ‖ be4(0) ‖ toUA ‖ keccak256(pk_t))[0..32)`. */
export function legSeed(seedEnc, toUA, pkT) {
  return legSeedOfKeyHash(seedEnc, toUA, keccak_256(asBytes(pkT, undefined, 'pk_t')));
}

/** `legSeed` with `keccak256(pk_t)` given (the vectors carry the hash, a wallet the key). */
export function legSeedOfKeyHash(seedEnc, toUA, pkTHash) {
  return shake256(concatBytes(utf8ToBytes('SCAAS-PQZ-ENC-LEG-V1'), asBytes(seedEnc, 32, 'seed_enc'), u32(0),
    asBytes(toUA, 32, 'toUA'), asBytes(pkTHash, 32, 'keccak256(pk_t)')), { dkLen: 32 });
}

/** K3-6: `coins = SHAKE256("SCAAS-PQZ-OPEN-COINS-V1" ‖ seed_leg ‖ u8(role) ‖ keccak256(kemPk))[0..64)`, role 0 the recipient, 1
 *  the auditor. */
export function openingCoins(seedLeg, role, kemPk) {
  if (role !== 0 && role !== 1) throw new Error('role: 0 recipient, 1 auditor');
  return shake256(concatBytes(utf8ToBytes('SCAAS-PQZ-OPEN-COINS-V1'), asBytes(seedLeg, 32, 'seed_leg'), Uint8Array.of(role),
    keccak_256(asBytes(kemPk, 1601, 'kemPk'))), { dkLen: 64 });
}

const kek = (ss) => hkdf(sha256, ss, new Uint8Array(0), utf8ToBytes('PQZ/opening/kek/v1'), 32);
const NONCE = new Uint8Array(12);

/** K3-6: the sealed opening of `seed_leg` to a reader's `kemPk`, deterministic: `(mlkemCt, E, ss) = encaps(kemPk, m = coins[0..32),
 *  e = coins[32..64))`, `sealedSeed = AES-256-GCM(HKDF(ss, ∅, "PQZ/opening/kek/v1"), 0^96, seed_leg, aad)`. `aad` is the caller's:
 *  `chainUid ‖ token(20) ‖ ua ‖ be8(keyVersion) ‖ keccak256(…)` of the reader's leg as CTR-PQZ-40 states it. Returns the
 *  `PqzOpening` fields and its stored form `mlkemCt ‖ x25519Eph ‖ sealedSeed` (1,648 B). */
export function sealOpening({ seedLeg, role, kemPk, aad }) {
  const c = openingCoins(seedLeg, role, kemPk);
  const enc = encaps(kemPk, c.subarray(0, 32), c.subarray(32));
  const sealedSeed = gcm(kek(enc.ss), NONCE, asBytes(aad, undefined, 'aad')).encrypt(asBytes(seedLeg, 32, 'seed_leg'));
  return { mlkemCt: enc.ctM, x25519Eph: enc.E, sealedSeed, bytes: concatBytes(enc.ctM, enc.E, sealedSeed) };
}

/** The reader's side: decapsulates with its opening KEM secret and opens `seed_leg`; `null` for every failure (a wrong length,
 *  a low-order X25519 point, a tag that fails), one outcome, no detail (CLI-SGN-51). ML-KEM's implicit rejection gives a wrong
 *  `ss`, hence the same `null`. */
export function openOpening({ opening, kemPk, dk, x25519Secret, aad }) {
  try {
    const o = asBytes(opening, 1648, 'opening');
    const { pkX } = checkKemPk(kemPk);
    const ssM = ml_kem1024.decapsulate(o.subarray(0, 1568), asBytes(dk, undefined, 'dk'));
    const E = o.subarray(1568, 1600);
    const ssX = x25519.getSharedSecret(asBytes(x25519Secret, 32, 'x25519Secret'), E);
    if (ssX.every((b) => b === 0)) return null;
    return gcm(kek(combine(ssM, ssX, E, pkX)), NONCE, asBytes(aad, undefined, 'aad')).decrypt(o.subarray(1600));
  } catch {
    return null;
  }
}

/** CTR-PQZ-40 / CTR-PQZ-34's Change: an opening token's op 1 `memoHash = keccak256(memo ‖ ownTag ‖ keccak256(O_t ‖ [O_a]))`,
 *  `O` the stored form of each opening (recipient first). */
export function pqzOpeningMemoHash(memo, ownTag, openings) {
  const os = concatBytes(...openings.map((o) => asBytes(o, 1648, 'opening')));
  return keccak_256(concatBytes(asBytes(memo ?? '0x', undefined, 'memo'), asBytes(ownTag, 32, 'ownTag'), keccak_256(os)));
}

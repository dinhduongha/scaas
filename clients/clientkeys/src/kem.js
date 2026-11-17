// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// UNAUDITED. The UA KEM key, scheme 1 (CTR-UA-32: kemPk = 0x01 ‖ ek (1,568) ‖ pk_X (32), 1,601 B), its encapsulation and
// decapsulation with the checks, and the combiner (ua-rs-sign spec §6.1, §6.2):
//   kemSeed = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.kem.v1", info = "scaas.kem.1" ‖ ua ‖ be64 version, L = 96)
//   (ek, dk) = ML-KEM-1024.KeyGen_internal(d = kemSeed[0:32], z = kemSeed[32:64]);  sk_X = kemSeed[64:96], pk_X = X25519(sk_X, 9)
//   ss = SHA3-256(ss_M ‖ ss_X ‖ E ‖ pk_X ‖ "scaas.kem.1")
// A KEM key comes only through a UA key (`kemKeyOf(uaKey, version)`, the key's own seed, uakey.js): KEM holders only
// (mldsa44, mldsa65, fndsa512, mldsa87, fndsa1024); an `msig` has no KEM key (MD-11: seal to its accepted members). The JS
// reference of smartcontracts/vectors/ua/kem.json; clients/ua-rs is held to its rows (T7).
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { x25519 as X } from '@noble/curves/ed25519.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { extract, expand } from '@noble/hashes/hkdf.js';
import { concatBytes, utf8ToBytes, keccak_256, wipe } from './bytes.js';
import { UAError, isPqzHolder, KEM_PK_LENGTH } from './ua.js';

const fail = (code, reason) => { throw new UAError(code, reason); };
const EK = 1568;
const CT = 1568;
const DK = 3168;
const LABEL = utf8ToBytes('scaas.kem.1');
const SALT = utf8ToBytes('scaas.ua.kem.v1');
const u8 = (v, n, what) => (v instanceof Uint8Array && v.length === n ? v : fail('KemCheck', `${what}: ${n} bytes`));
const be64 = (v) => {
  const n = typeof v === 'bigint' ? v : Number.isInteger(v) ? BigInt(v) : -1n;
  if (n < 0n || n >= 1n << 64n) fail('Argument', 'version must be a u64');
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n);
  return b;
};
const zero = (b) => b.every((x) => x === 0);

/** FIPS 203 `ML-KEM.KeyGen_internal(d, z)` → `{ ek, dk }`. */
export function mlkemKeyGen(d, z) {
  const { publicKey, secretKey } = ml_kem1024.keygen(concatBytes(d, z));
  return { ek: publicKey, dk: secretKey };
}

/** RFC 7748 X25519(k, u); a low-order `u` gives the all-zero output of §6.1 (noble refuses it before the ladder). */
export function x25519(k, u) {
  try {
    return X.scalarMult(k, u);
  } catch (e) {
    if (/invalid private or public key/.test(e.message)) return new Uint8Array(32);
    throw e;
  }
}

/** FIPS 203 §7.2 modulus check: `ByteEncode12(ByteDecode12(ek[0:1536])) == ek[0:1536]`, i.e. every coefficient < q. */
export function ekModulusOk(ek) {
  if (!(ek instanceof Uint8Array) || ek.length !== EK) return false;
  for (let i = 0; i < 1536; i += 3) {
    if ((ek[i] | ((ek[i + 1] & 15) << 8)) >= 3329 || ((ek[i + 1] >> 4) | (ek[i + 2] << 4)) >= 3329) return false;
  }
  return true;
}

/** FIPS 203 §7.3 decapsulation-key check: length, and `H(dk[384k : 768k + 32]) == dk[768k + 32 : 768k + 64]`. */
export function dkCheckOk(dk) {
  if (!(dk instanceof Uint8Array) || dk.length !== DK) return false;
  const h = sha3_256(dk.subarray(1536, 3104));
  return h.every((b, i) => b === dk[3104 + i]);
}

const combine = (ssM, ssX, E, pkX) => sha3_256(concatBytes(ssM, ssX, E, pkX, LABEL));

function encaps(kemPk, m, e) {
  if (!(kemPk instanceof Uint8Array) || kemPk.length < 1) fail('KemCheck', 'kemPk');
  if (kemPk[0] !== 1) fail('KemCheck', `scheme ${kemPk[0]}: only scheme 1 (ML-KEM-1024 + X25519)`);
  if (kemPk.length !== KEM_PK_LENGTH) fail('KemCheck', `kemPk length ${kemPk.length}, not ${KEM_PK_LENGTH}`);
  const ek = kemPk.subarray(1, 1 + EK);
  const pkX = kemPk.subarray(1 + EK);
  if (!ekModulusOk(ek)) fail('KemCheck', 'ek modulus check (FIPS 203 §7.2)');
  const E = X.getPublicKey(e);
  const ssX = x25519(e, pkX);
  if (zero(ssX)) fail('KemCheck', 'ss_X is all zero (small-order pk_X)');
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(ek, m);
  const ss = combine(sharedSecret, ssX, E, pkX);
  wipe(ssX, sharedSecret);
  return { mlkemCt: cipherText, x25519Eph: E, ss };
}

/** `(mlkemCt, x25519Eph, ss)` to `kemPk`, `m` and `e` from the platform RNG. */
export const kemEncaps = (kemPk) => encaps(kemPk, crypto.getRandomValues(new Uint8Array(32)), crypto.getRandomValues(new Uint8Array(32)));

/** Test vectors only: `kemEncaps` with the given `m` (ML-KEM message randomness) and `e` (the X25519 ephemeral secret). */
export const kemEncapsVector = (kemPk, m, e) => encaps(kemPk, u8(m, 32, 'm'), u8(e, 32, 'e'));

function keyPair(okm, id) {
  const { ek, dk } = mlkemKeyGen(okm.subarray(0, 32), okm.subarray(32, 64));
  const skX = okm.slice(64, 96);
  wipe(okm);
  if (!dkCheckOk(dk)) fail('KemCheck', 'decapsulation-key check (FIPS 203 §7.3)'); // a self-test of the derived key
  const pkX = X.getPublicKey(skX);
  const kemPk = concatBytes(Uint8Array.of(1), ek, pkX);
  const kemPkHash = keccak_256(kemPk);
  return Object.freeze({
    ua: id?.ua ?? null,
    version: id ? id.version : null,
    kemPk,
    kemPkHash,
    /** The recipient id a container names: `{ ua, version }` for a UA's key, `{ kemPkHash }` for an ephemeral one. */
    recipient: id ? Object.freeze({ ua: id.ua, version: id.version }) : Object.freeze({ kemPkHash }),
    /** `ss` of `(mlkemCt, x25519Eph)`: lengths 1,568 / 32 and a contributory `ss_X` (else `KemCheck`); ML-KEM implicit rejection
     *  kept (a wrong `mlkemCt` gives another `ss`, never an error). */
    decaps(mlkemCt, x25519Eph) {
      if (!(mlkemCt instanceof Uint8Array) || mlkemCt.length !== CT) fail('KemCheck', `mlkemCt: ${CT} bytes`);
      if (!(x25519Eph instanceof Uint8Array) || x25519Eph.length !== 32) fail('KemCheck', 'x25519Eph: 32 bytes');
      const ssX = x25519(skX, x25519Eph);
      if (zero(ssX)) fail('KemCheck', 'ss_X is all zero (small-order E)');
      const ssM = ml_kem1024.decapsulate(mlkemCt, dk);
      const ss = combine(ssM, ssX, x25519Eph, pkX);
      wipe(ssX, ssM);
      return ss;
    },
    wipe: () => wipe(dk, skX),
  });
}

/** The KEM key of a UA from the HKDF-Extract of its seed (`prk`, held by the UA key, uakey.js): the HKDF-Expand step. */
export function kemKeyFromPrk(prk, ua, version) {
  const v = be64(version);
  return keyPair(expand(sha256, prk, concatBytes(LABEL, ua, v), 96), { ua, version: typeof version === 'bigint' ? version : Number(version) });
}

/** HKDF-Extract(salt = "scaas.ua.kem.v1", ikm = seed): what a KEM holder's UA key keeps for `kemKey`. */
export const kemPrk = (seed) => extract(sha256, seed, SALT);

/** A KEM holder's kind (CTR-UA-32); an `msig` is never one here (MD-11). */
export const isKemHolder = (kind) => isPqzHolder(kind);

/** The UA KEM key of version `version` through a UA key (`deriveUAKey`): KEM holders only, else `KemHolder`; an `msig` has no
 *  KEM key (MD-11), and anything that is not a UA key of this module (an `msig` record, a key of a non-holder) is refused. */
export function kemKeyOf(key, version) {
  // an msig is never a UA key here (deriveUAKey refuses 0x0120): its KEM key cannot be asked for
  if (typeof key?.kemKey !== 'function') fail('KemHolder', 'not a single-key UA key; an msig has no KEM key: seal to each of its accepted members');
  return key.kemKey(version);
}

/** A KEM key of no UA (a device that has no seed yet, link): the platform RNG, never stored. */
export const generateEphemeral = () => keyPair(crypto.getRandomValues(new Uint8Array(96)), null);

/** Test vectors only: the ephemeral key from 96 given bytes (the layout of kemSeed). */
export const ephemeralVector = (bytes96) => keyPair(u8(bytes96, 96, 'seed').slice(), null);

// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The key-handle operations of app cores (scaas-sdk spec §12.2, §12.3, §23.1 item 9; plan T21), on raw bytes: the reference
// `ua-rs`'s `app-core` handles reproduce. A handle's usage (`Derive`, `Data`, `KeyWrap`) is metadata only and never enters a
// byte (review K4), except `sealKey`'s key-wrap AAD, the SDK's own format: `"scaas/ua/v1/keywrap" ‖ u8(usage) ‖ aad`. The KEM
// wrap's KDF info is `label ‖ aad ‖ u8(scheme) ‖ keccak256(kemPk)`, the wrapped key sealed by AES-256-GCM, nonce 0^96, AAD
// `aad` (UA-7 §6.2, the pqvault spec §6.2). The app root key: HKDF-SHA-256(ikm = the seed set's BIP-39 seed, salt empty,
// info = "scaas/app/v1/root" ‖ appId ‖ ua, 32 B) (owner 2026-11-20, confirmed). The byte formats of
// smartcontracts/vectors/appcore/. UNAUDITED.
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { argon2id as argon2 } from "@noble/hashes/argon2.js";
import { gcm, gcmsiv } from "@noble/ciphers/aes.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { keccak_256, sha256, concatBytes, utf8ToBytes, fromHex } from "./bytes.js";
import { encaps, checkKemPk, combine } from "./pqchat.js";

const bytes = (v) => (v instanceof Uint8Array ? v : fromHex(v));
const startsWith = (a, p) => a.length >= p.length && p.every((x, i) => a[i] === x);

export class AppCoreError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/** A handle's usage, fixed when it is made (review r2 R2); its byte enters only `sealKey`'s AAD. `File` (4): a file key of
 *  CLI-UAL-65 (src/arweave.js), wrapped into a message or a vault item like any other. */
export const USAGE = Object.freeze({ Derive: 1, Data: 2, KeyWrap: 3, File: 4 });
/** The key-wrap constant: `sealKey`'s AAD starts with it, and `seal` refuses an `aad` that does. */
export const KEYWRAP = utf8ToBytes("scaas/ua/v1/keywrap");
/** The label of an app's per-account storage root. */
export const APP_ROOT = utf8ToBytes("scaas/app/v1/root");
/** The KEM scheme byte of a UA KEM key (CTR-UA-32: `kemPk = 0x01 ‖ ek ‖ pkX`). */
export const SCHEME = 1;

/** HKDF-SHA-256 over the concatenated keys: `len` 32 gives a key, 44 a key and a 12-byte nonce (`okm[32:44]`). */
export const derive = (keys, salt, info, len) =>
  hkdf(sha256, concatBytes(...keys.map(bytes)), bytes(salt), bytes(info), len);

/** HMAC-SHA-256 into a key (`mac_derive`), the message exactly `data`; `len` at most 32. */
export const macDerive = (key, data, len = 32) => hmac(sha256, bytes(key), bytes(data)).slice(0, len);

/** One public MAC output of at most 8 bytes (`mac_public`). */
export function macPublic(key, labelAndData, len) {
  if (len < 1 || len > 8) throw new AppCoreError("Argument");
  return hmac(sha256, bytes(key), bytes(labelAndData)).slice(0, len);
}

/** AES-256-GCM-SIV under `key` with the 12-byte `nonce`; the nonce is not in the output (the caller places it). */
export function seal(key, nonce, aad, pt) {
  if (startsWith(bytes(aad), KEYWRAP)) throw new AppCoreError("AppKeyUsage");
  return gcmsiv(bytes(key), bytes(nonce), bytes(aad)).encrypt(bytes(pt));
}
/** The inverse of [`seal`]. */
export function open(key, nonce, aad, ct) {
  if (startsWith(bytes(aad), KEYWRAP)) throw new AppCoreError("AppKeyUsage");
  return gcmsiv(bytes(key), bytes(nonce), bytes(aad)).decrypt(bytes(ct));
}
/** `seal` with a random nonce: `nonce ‖ ct` (`Nonce::Random`). */
export const sealRandom = (key, nonce, aad, pt) => concatBytes(bytes(nonce), seal(key, nonce, aad, pt));
/** The inverse of [`sealRandom`]. */
export function openRandom(key, aad, wire) {
  const w = bytes(wire);
  if (w.length < 28) throw new AppCoreError("Argument");
  return open(key, w.subarray(0, 12), aad, w.subarray(12));
}

const keyWrapAad = (usage, aad) => {
  if (![1, 2, 3, 4].includes(usage)) throw new AppCoreError("Argument");
  return concatBytes(KEYWRAP, Uint8Array.of(usage), bytes(aad));
};
/** `seal_key`: `nonce ‖ AES-256-GCM-SIV(under, nonce, key, "scaas/ua/v1/keywrap" ‖ u8(usage of key) ‖ aad)`, 60 B. */
export const sealKey = (under, nonce, key, usage, aad) =>
  concatBytes(bytes(nonce), gcmsiv(bytes(under), bytes(nonce), keyWrapAad(usage, aad)).encrypt(bytes(key)));
/** `open_key`: the key of the recorded `usage` (a wrong usage fails the tag). */
export function openKey(under, wire, usage, aad) {
  const w = bytes(wire);
  if (w.length !== 60) throw new AppCoreError("Argument");
  return gcmsiv(bytes(under), w.subarray(0, 12), keyWrapAad(usage, aad)).decrypt(w.subarray(12));
}

/** Argon2id (RFC 9106, version 0x13) into a key: no secret, no associated data. */
export const argon2id = (password, salt, { m, t, p, len = 32 }) =>
  argon2(bytes(password), bytes(salt), { m, t, p, dkLen: len });

/** The KEK of a wrap to `kemPk`: HKDF(ss, salt empty, info = label ‖ aad ‖ u8(scheme) ‖ keccak256(kemPk), 32). */
export const wrapKek = (ss, label, aad, kemPk) =>
  hkdf(
    sha256,
    bytes(ss),
    new Uint8Array(0),
    concatBytes(bytes(label), bytes(aad), Uint8Array.of(SCHEME), keccak_256(bytes(kemPk))),
    32,
  );

/** `kem_wrap` / `kem_wrap_to_key`: `key` sealed to `kemPk` (`m`, the X25519 ephemeral secret: fixed for vectors only). */
export function kemWrap({ key, label, aad, kemPk, m, x25519Secret }) {
  const enc = encaps(kemPk, m, x25519Secret);
  const kek = wrapKek(enc.ss, label, aad, kemPk);
  const sealedKey = gcm(kek, new Uint8Array(12), bytes(aad)).encrypt(bytes(key));
  return { kek, mlkemCt: enc.ctM, x25519Eph: enc.E, sealedKey };
}

/** `kem_unwrap`: the key of a wrap, by the receiver's ML-KEM `dk` and X25519 secret. */
export function kemUnwrap({ wrap, label, aad, kemPk, dk, x25519Secret }) {
  const { pkX } = checkKemPk(kemPk);
  const ssM = ml_kem1024.decapsulate(bytes(wrap.mlkemCt), bytes(dk));
  const E = bytes(wrap.x25519Eph);
  const ss = combine(ssM, x25519.getSharedSecret(bytes(x25519Secret), E), E, pkX);
  return gcm(wrapKek(ss, label, aad, kemPk), new Uint8Array(12), bytes(aad)).decrypt(bytes(wrap.sealedKey));
}

/** The app root key of `appId` for the account `ua`, from the seed set's BIP-39 seed. */
export function appRootKey(seed, appId, ua) {
  const id = bytes(appId);
  if (id.length !== 32 || bytes(ua).length !== 32) throw new AppCoreError("Argument");
  return hkdf(sha256, bytes(seed), new Uint8Array(0), concatBytes(APP_ROOT, id, bytes(ua)), 32);
}

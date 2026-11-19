// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Polkadot sr25519 accounts (CLI-SGN-53; spec 2026-11-17-ua-rs-native §7): the substrate-bip39 mini-secret from the BIP-39
// entropy and the passphrase as given, schnorrkel's Ed25519-mode expansion (the bare account, polkadot.js's and subkey's
// default), the junction path grammar and chain codes of sp-core / polkadot.js (with the refusals of §7.3), SS58. UNAUDITED.
import * as sr from "@scure/sr25519";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { base58 } from "@scure/base";
import { concatBytes, bytesToHex, wipe } from "./bytes.js";
import { UAError } from "./ua.js";

const fail = (code, reason) => {
  throw new UAError(code, reason);
};
const enc = new TextEncoder();
export const MAX_PATH_BYTES = 512;
export const MAX_JUNCTIONS = 16;
export const MAX_JUNCTION_BYTES = 64;
const U64_MAX = (1n << 64n) - 1n;

/** substrate-bip39 `mini_secret_from_entropy`: PBKDF2-HMAC-SHA512(entropy, "mnemonic" ‖ UTF-8(passphrase), 2048)[0..32]. The
 *  passphrase is taken as given (no NFKD, unlike BIP-39's seed): an NFC and an NFD spelling are two accounts. */
export function miniSecretFromEntropy(entropy, passphrase = "") {
  if (!(entropy instanceof Uint8Array) || entropy.length < 16 || entropy.length > 32 || entropy.length % 4)
    fail("Argument", "entropy: 16 to 32 bytes");
  if (typeof passphrase !== "string") fail("Argument", "passphrase: a string");
  const dk = pbkdf2(sha512, entropy, concatBytes(enc.encode("mnemonic"), enc.encode(passphrase)), {
    c: 2048,
    dkLen: 64,
  });
  const mini = dk.slice(0, 32);
  wipe(dk);
  return mini;
}

/** The chain code of one junction: a digit-only junction is its u64 little-endian, any other the SCALE string (compact length:
 *  one byte `len << 2` below 64, two bytes `(len << 2) | 1` LE at 64); an encoding of at most 32 bytes is zero-padded to 32, a
 *  longer one replaced by its BLAKE2b-256. */
export function chainCode(junction) {
  const b = enc.encode(junction);
  let e;
  if (/^[0-9]+$/.test(junction)) {
    e = new Uint8Array(8);
    new DataView(e.buffer).setBigUint64(0, BigInt(junction), true);
  } else if (b.length < 64) {
    e = concatBytes(Uint8Array.of(b.length << 2), b);
  } else {
    const v = (b.length << 2) | 1;
    e = concatBytes(Uint8Array.of(v & 255, v >> 8), b);
  }
  if (e.length <= 32) {
    const c = new Uint8Array(32);
    c.set(e);
    return c;
  }
  return blake2b(e, { dkLen: 32 });
}

/** Parse a junction path (`//` hard, `/` soft; "" the bare key) into [{ hard, junction, chainCode }]. Refused (Argument): `///`
 *  (a password part), an empty junction, a byte outside 0x21–0x7e, a junction over 64 bytes, a `0x` or `+` prefix, a digit-only
 *  junction outside u64 or with a leading zero (other than `0`), more than 16 junctions or 512 bytes. A path that passes is its own
 *  canonical spelling. */
export function parsePolkadotPath(path) {
  if (typeof path !== "string") fail("Argument", "path: a string");
  const bytes = enc.encode(path);
  if (bytes.length > MAX_PATH_BYTES) fail("Argument", "path: at most 512 bytes");
  const out = [];
  let i = 0;
  while (i < path.length) {
    if (path[i] !== "/") fail("Argument", "path: a junction starts with / or //");
    const hard = path[i + 1] === "/";
    i += hard ? 2 : 1;
    let j = i;
    while (j < path.length && path[j] !== "/") j++;
    const junction = path.slice(i, j);
    i = j;
    const jb = enc.encode(junction);
    if (jb.length === 0 || jb.length > MAX_JUNCTION_BYTES) fail("Argument", "junction: 1 to 64 bytes");
    if (jb.some((c) => c < 0x21 || c > 0x7e)) fail("Argument", "junction: printable ASCII only");
    if (junction.startsWith("0x") || junction.startsWith("+")) fail("Argument", "junction: no 0x or + prefix");
    if (/^[0-9]+$/.test(junction) && ((junction.length > 1 && junction[0] === "0") || BigInt(junction) > U64_MAX)) {
      fail("Argument", "junction: a number is a canonical u64");
    }
    out.push({ hard, junction, chainCode: chainCode(junction) });
    if (out.length > MAX_JUNCTIONS) fail("Argument", "path: at most 16 junctions");
  }
  return out;
}

/** SS58 of a 32-byte public key: base58(pre ‖ pk ‖ BLAKE2b-512("SS58PRE" ‖ pre ‖ pk)[0..2]); prefix 0 to 16383, not 46 / 47. */
export function ss58(publicKey, prefix = 0) {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 16383 || prefix === 46 || prefix === 47)
    fail("Argument", "SS58 prefix");
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32)
    fail("Argument", "an sr25519 public key is 32 bytes");
  const pre =
    prefix < 64
      ? Uint8Array.of(prefix)
      : Uint8Array.of(((prefix & 0xfc) >> 2) | 0x40, (prefix >> 8) | ((prefix & 0x03) << 6));
  const sum = blake2b(concatBytes(enc.encode("SS58PRE"), pre, publicKey), { dkLen: 64 });
  return base58.encode(concatBytes(pre, publicKey, sum.subarray(0, 2)));
}

/** The Polkadot key of `path` (spec §7.2, §7.3) from the BIP-39 entropy and passphrase. `privateKey`: @scure/sr25519's 64-byte
 *  secret (schnorrkel `to_ed25519_bytes`); a soft step draws a fresh nonce half (`softRandom`: the generator's fixed 32 bytes, else
 *  the CSPRNG), so a soft key's public key is reproducible, its signatures are not. Caller wipes `privateKey`. */
export function polkadotKey(entropy, passphrase, path = "", { softRandom } = {}) {
  const steps = parsePolkadotPath(path);
  const mini = miniSecretFromEntropy(entropy, passphrase);
  let secret = sr.secretFromSeed(mini);
  wipe(mini);
  for (const s of steps) {
    const next = s.hard
      ? sr.HDKD.secretHard(secret, s.chainCode)
      : sr.HDKD.secretSoft(secret, s.chainCode, softRandom ?? crypto.getRandomValues(new Uint8Array(32)));
    wipe(secret);
    secret = next;
  }
  const pk = sr.getPublicKey(secret);
  return {
    network: "polkadot",
    curve: "sr25519",
    path,
    privateKey: secret,
    publicKey: bytesToHex(pk),
    address: ss58(pk, 0),
  };
}

/** sr25519 over `message` with context "substrate" (randomness: `aux` 32 bytes in the generator, else the CSPRNG), verified
 *  before return. */
export function sr25519Sign(secret, message, aux) {
  const sig = sr.sign(secret, message, aux ?? crypto.getRandomValues(new Uint8Array(32)));
  if (!sr.verify(message, sig, sr.getPublicKey(secret))) throw new Error("sr25519 signature failed its own check");
  return sig;
}

export const sr25519Verify = (message, signature, publicKey) => sr.verify(message, signature, publicKey);

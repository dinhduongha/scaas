// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Arweave as a store of ciphertext (CLI-UAL-64, CLI-UAL-65; spec docs/superpowers/specs/2026-11-21-avax-polkadot-arweave.md
// part D; chains-arweave plan T16): ANS-104 data items as `arbundles` builds them (layout, the SHA-384 deep hash, the Avro
// tags, types 2, 3 and 4, id = base64url(SHA-256(signature))), the per-file upload key, the file frame inside the AEAD with its
// power-of-two bucket, the reader's checks, and `ar://<id>`. The reference `ua-rs` reproduces byte for byte
// (smartcontracts/vectors/arweave/). Type 4 signs the lowercase hex text of the deep hash, as `arbundles`' Solana signers do
// (HexSolanaSigner); types 2 and 3 sign the 48 bytes. No key leaves; no network. UNAUDITED.
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha384 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { gcm } from "@noble/ciphers/aes.js";
import { keccak_256, sha256, concatBytes, utf8ToBytes, bytesToHex, b64url, fromB64url } from "./bytes.js";

export class ArweaveError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
const fail = (code) => {
  throw new ArweaveError(code);
};

/** Signature and owner lengths by signature type (no type 1, no other type). */
export const TYPES = Object.freeze({ 2: { sig: 64, owner: 32 }, 3: { sig: 65, owner: 65 }, 4: { sig: 64, owner: 32 } });
export const MIN_ITEM = 80;
export const MAX_TAGS = 128;
export const MAX_NAME = 1024;
export const MAX_VALUE = 3072;
export const MAX_TAG_BYTES = 4096;
/** The smallest bucket, and the in-memory caps of 64-bit targets and of wasm32. */
export const BUCKET_MIN = 2 ** 16;
export const CAP_64 = 2 ** 30;
export const CAP_WASM32 = 2 ** 27;
export const UPLOAD_INFO = utf8ToBytes("scaas/arweave/v1/upload");
const EIP191 = utf8ToBytes("\x19Ethereum Signed Message:\n48");
const N = secp256k1.Point.CURVE().n;

// ---------------------------------------------------------------- the deep hash

/** SHA-384 deep hash: a blob `SHA384(SHA384("blob" ‖ len) ‖ SHA384(data))`, a list `acc = SHA384("list" ‖ count)`, then
 *  `acc = SHA384(acc ‖ deepHash(item))` per item. */
export function deepHash(chunk) {
  if (Array.isArray(chunk)) {
    let acc = sha384(utf8ToBytes(`list${chunk.length}`));
    for (const c of chunk) acc = sha384(concatBytes(acc, deepHash(c)));
    return acc;
  }
  return sha384(concatBytes(sha384(utf8ToBytes(`blob${chunk.length}`)), sha384(chunk)));
}

// ---------------------------------------------------------------- Avro tags

function writeLong(out, n) {
  let m = BigInt(n) >= 0n ? BigInt(n) << 1n : (-BigInt(n) << 1n) - 1n;
  do {
    let b = Number(m & 0x7fn);
    m >>= 7n;
    if (m) b |= 0x80;
    out.push(b);
  } while (m);
}

/** The tag bytes of `tags` ([{name, value}] of bytes): an empty list is 0 bytes; else one block, then the terminator 0. */
export function encodeTags(tags) {
  if (!tags.length) return new Uint8Array(0);
  const out = [];
  writeLong(out, tags.length);
  for (const { name, value } of tags) {
    writeLong(out, name.length);
    out.push(...name);
    writeLong(out, value.length);
    out.push(...value);
  }
  out.push(0);
  return Uint8Array.from(out);
}

/** The strict reader: one positive block (a negative count: `TagBlockNegative`), the terminator, nothing after it
 *  (`TagTrailing`), `count` tags (`TagCount`), each name and value non-empty and within bounds (`TagBounds`), and the bytes
 *  exactly what [`encodeTags`] writes (`TagNonCanonical`: the signed bytes are the raw ones). */
export function decodeTags(buf, count) {
  if (count === 0 && buf.length === 0) return [];
  if (count === 0 || buf.length === 0) fail("TagCount");
  let pos = 0;
  const readLong = () => {
    let m = 0n;
    for (let shift = 0n; ; shift += 7n) {
      if (pos >= buf.length || shift > 63n) fail("TagTruncated");
      const b = buf[pos++];
      m |= BigInt(b & 0x7f) << shift;
      if (!(b & 0x80)) break;
    }
    return m & 1n ? -((m + 1n) >> 1n) : m >> 1n;
  };
  const readBytes = (max) => {
    const len = readLong();
    if (len < 1n || len > BigInt(max)) fail("TagBounds");
    const n = Number(len);
    if (pos + n > buf.length) fail("TagTruncated");
    const b = buf.slice(pos, pos + n);
    pos += n;
    return b;
  };
  const tags = [];
  for (;;) {
    const n = readLong();
    if (n === 0n) break;
    if (n < 0n) fail("TagBlockNegative");
    if (BigInt(tags.length) + n > BigInt(MAX_TAGS)) fail("TagCount");
    for (let i = 0n; i < n; i++) tags.push({ name: readBytes(MAX_NAME), value: readBytes(MAX_VALUE) });
  }
  if (pos !== buf.length) fail("TagTrailing");
  if (tags.length !== count) fail("TagCount");
  const again = encodeTags(tags);
  if (again.length !== buf.length || again.some((b, i) => b !== buf[i])) fail("TagNonCanonical");
  return tags;
}

// ---------------------------------------------------------------- items

const le = (n, len) => {
  const out = new Uint8Array(len);
  let v = BigInt(n);
  for (let i = 0; i < len; i++, v >>= 8n) out[i] = Number(v & 0xffn);
  return out;
};
const readLe = (b) => b.reduceRight((acc, x) => (acc << 8n) | BigInt(x), 0n);

/** The 48 bytes an item's signature covers. */
export function signedMessage({ type, owner, target, anchor, rawTags, data }) {
  return deepHash([
    utf8ToBytes("dataitem"),
    utf8ToBytes("1"),
    utf8ToBytes(String(type)),
    owner,
    target ?? new Uint8Array(0),
    anchor ?? new Uint8Array(0),
    rawTags,
    data,
  ]);
}

/** The bytes a type's key signs: the 48 bytes (2, 3 through EIP-191), the deep hash's lowercase hex text (4). */
const signedBytes = (type, msg) => (type === 4 ? utf8ToBytes(bytesToHex(msg)) : msg);
const eip191 = (msg) => keccak_256(concatBytes(EIP191, msg));

/** The public key (owner) of a type's secret: ed25519's 32 bytes, secp256k1's uncompressed 65. */
export function ownerOf(type, secret) {
  if (type === 3) return secp256k1.getPublicKey(secret, false);
  if (type === 2 || type === 4) return ed25519.getPublicKey(secret);
  return fail("SignatureType");
}

/** A type's signature of the item message `msg`: ed25519 (2: the bytes, 4: their hex text), secp256k1 RFC 6979 with low `s`
 *  and `v ∈ {27, 28}` over EIP-191 of the 48 bytes (3). */
export function signMessage(type, secret, msg) {
  if (type === 3) {
    const rec = secp256k1.sign(eip191(msg), secret, {
      prehash: false,
      lowS: true,
      extraEntropy: false,
      format: "recovered",
    });
    return concatBytes(rec.subarray(1), Uint8Array.of(27 + rec[0]));
  }
  return ed25519.sign(signedBytes(type, msg), secret);
}

/** Whether `sig` is the type's signature of `msg` by `owner` (type 3: `v ∈ {27, 28}`, low `s`, the recovered key the owner). */
export function verifyMessage(type, owner, msg, sig) {
  if (type === 3) {
    if (sig.length !== 65 || (sig[64] !== 27 && sig[64] !== 28)) return false;
    const s = BigInt("0x" + bytesToHex(sig.subarray(32, 64)));
    if (s > N / 2n) return false;
    try {
      const rec = secp256k1.recoverPublicKey(
        concatBytes(Uint8Array.of(sig[64] - 27), sig.subarray(0, 64)),
        eip191(msg),
        {
          prehash: false,
        },
      );
      const pub = secp256k1.Point.fromBytes(rec).toBytes(false);
      return pub.length === owner.length && pub.every((b, i) => b === owner[i]);
    } catch {
      return false;
    }
  }
  try {
    return ed25519.verify(sig, signedBytes(type, msg), owner);
  } catch {
    return false;
  }
}

/** base64url, unpadded, of SHA-256 of the signature: 43 characters. */
export const itemId = (signature) => b64url(sha256(signature));

/** The unsigned layout of an item with a zero signature (tags as [{name, value}] of bytes). */
function layout(type, owner, target, anchor, tags, data) {
  const t = TYPES[type] ?? fail("SignatureType");
  if (owner.length !== t.owner) fail("Owner");
  if (target && target.length !== 32) fail("Target");
  if (anchor && anchor.length !== 32) fail("Anchor");
  if (tags.length > MAX_TAGS) fail("TagCount");
  for (const { name, value } of tags)
    if (!name.length || !value.length || name.length > MAX_NAME || value.length > MAX_VALUE) fail("TagBounds");
  const rawTags = encodeTags(tags);
  if (rawTags.length > MAX_TAG_BYTES) fail("TagBounds");
  const presence = (x) => (x ? concatBytes(Uint8Array.of(1), x) : Uint8Array.of(0));
  const head = (sig) =>
    concatBytes(
      le(type, 2),
      sig,
      owner,
      presence(target),
      presence(anchor),
      le(tags.length, 8),
      le(rawTags.length, 8),
      rawTags,
    );
  return { rawTags, head };
}

/** An item of `type` signed by `secret` over `data` (`target`, `anchor` 32 bytes or absent; `tags` [{name, value}] of bytes). */
export function buildItem({ type, secret, data, target = null, anchor = null, tags = [] }) {
  const owner = ownerOf(type, secret);
  const { rawTags, head } = layout(type, owner, target, anchor, tags, data);
  const msg = signedMessage({ type, owner, target, anchor, rawTags, data });
  const signature = signMessage(type, secret, msg);
  const item = concatBytes(head(signature), data);
  if (!verifyMessage(type, owner, msg, signature)) fail("Signature");
  return { item, id: itemId(signature), signature, message: msg, owner };
}

/** The verifying parser (spec §7.2): at least 80 bytes, types 2, 3, 4 only, presence bytes 0 or 1, the tag bounds and the
 *  strict Avro reader, the signature verified before anything is returned. `shape: "c9"` also requires no target, no anchor,
 *  no tags (`ItemShape`). */
export function parseItem(item, { shape } = {}) {
  if (item.length < MIN_ITEM) fail("ItemShort");
  const type = Number(readLe(item.subarray(0, 2)));
  const t = TYPES[type] ?? fail("SignatureType");
  let p = 2;
  const take = (n) => {
    if (p + n > item.length) fail("ItemShort");
    const b = item.slice(p, p + n);
    p += n;
    return b;
  };
  const signature = take(t.sig);
  const owner = take(t.owner);
  const opt = () => {
    const b = take(1)[0];
    if (b > 1) fail("Presence");
    return b ? take(32) : null;
  };
  const target = opt();
  const anchor = opt();
  const count = readLe(take(8));
  const len = readLe(take(8));
  if (count > BigInt(MAX_TAGS)) fail("TagCount");
  if (len > BigInt(MAX_TAG_BYTES)) fail("TagBounds");
  const rawTags = take(Number(len));
  const tags = decodeTags(rawTags, Number(count));
  const data = item.slice(p);
  if (shape === "c9" && (target || anchor || tags.length)) fail("ItemShape");
  const message = signedMessage({ type, owner, target, anchor, rawTags, data });
  if (!verifyMessage(type, owner, message, signature)) fail("Signature");
  return { type, signature, owner, target, anchor, tags, rawTags, data, id: itemId(signature), message };
}

// ---------------------------------------------------------------- the file object

/** The smallest power of two that is at least max(2^16, size + 8), in integers; above `cap`: `FileTooLarge`. */
export function bucket(size, cap = CAP_64) {
  if (!Number.isSafeInteger(size) || size < 0) fail("Argument");
  let b = BUCKET_MIN;
  while (b < size + 8) b *= 2;
  if (b > cap) fail("FileTooLarge");
  return b;
}

/** `size (8 B, big-endian) ‖ file ‖ 0x00…` of length `bucket(size)`. */
export function frame(file, cap = CAP_64) {
  const b = bucket(file.length, cap);
  const out = new Uint8Array(b);
  const be = le(file.length, 8).reverse();
  out.set(be, 0);
  out.set(file, 8);
  return out;
}

/** AES-256-GCM of a frame under the file key, nonce 0^96: exactly bucket + 16 bytes. */
export const encryptFrame = (fileKey, fr) => gcm(fileKey, new Uint8Array(12)).encrypt(fr);

/** The sealed file: the object, `ctSha256` of it, the file's `sha256` and `size`. */
export function sealFile(fileKey, file, cap = CAP_64) {
  const object = encryptFrame(fileKey, frame(file, cap));
  return { object, ctSha256: sha256(object), sha256: sha256(file), size: file.length };
}

/** The reader's check before decryption: the length exactly bucket(size) + 16 (`FileLength`), SHA-256 equal to `ctSha256`
 *  (`FileHashMismatch`). */
export function checkObject(object, size, ctSha256, cap = CAP_64) {
  if (object.length !== bucket(size, cap) + 16) fail("FileLength");
  const h = sha256(object);
  if (h.length !== ctSha256.length || h.some((b, i) => b !== ctSha256[i])) fail("FileHashMismatch");
}

/** `open_file`: first the reader's check before decryption (`checkObject`: the exact length, `FileLength`; SHA-256 of the
 *  object equal to `ctSha256`, `FileHashMismatch`), then the tag (`Aead`), the frame's `len` equal to `size` (`FileFrame`),
 *  every pad byte zero (`FileFrame`), SHA-256 of the file equal to `sha256` (`FileHashMismatch`); only then the file. */
export function openFile(fileKey, object, size, sha, ctSha256, cap = CAP_64) {
  checkObject(object, size, ctSha256, cap);
  let fr;
  try {
    fr = gcm(fileKey, new Uint8Array(12)).decrypt(object);
  } catch {
    fail("Aead");
  }
  const len = readLe(fr.slice(0, 8).reverse());
  if (len !== BigInt(size)) fail("FileFrame");
  if (fr.subarray(8 + size).some((b) => b !== 0)) fail("FileFrame");
  const file = fr.slice(8, 8 + size);
  const h = sha256(file);
  if (h.some((b, i) => b !== sha[i])) fail("FileHashMismatch");
  return file;
}

// ---------------------------------------------------------------- the upload key

/** The upload key of one object: HKDF-SHA-256(ikm = app root key ‖ file key, salt empty, info = "scaas/arweave/v1/upload" ‖
 *  type ‖ ctSha256 [‖ counter], 32): the ed25519 seed (2, 4), or a big-endian secp256k1 scalar (3), the counter byte 0x01,
 *  0x02, … appended while it is 0 or ≥ n. `refuse(k)` (a test fixture) treats the k-th candidate as invalid too. */
export function uploadKey(root, fileKey, type, ctSha256, { refuse = () => false } = {}) {
  if (!TYPES[type]) fail("SignatureType");
  const ikm = concatBytes(root, fileKey);
  const base = concatBytes(UPLOAD_INFO, Uint8Array.of(type), ctSha256);
  for (let k = 0; k < 256; k++) {
    const info = k ? concatBytes(base, Uint8Array.of(k)) : base;
    const seed = hkdf(sha256, ikm, new Uint8Array(0), info, 32);
    if (type !== 3 && !refuse(k)) return { secret: seed, counter: k, owner: ownerOf(type, seed) };
    const s = BigInt("0x" + bytesToHex(seed));
    if (type === 3 && s !== 0n && s < N && !refuse(k)) return { secret: seed, counter: k, owner: ownerOf(type, seed) };
  }
  return fail("Argument");
}

/** `seal_for_arweave`: the frame and the object under `fileKey`, `ctSha256`, the upload key from `root` and `fileKey`, the
 *  item over the object (no target, no anchor, no tags), signed and verified; `url = ar://<id>`. */
export function sealForArweave(root, fileKey, file, type, cap = CAP_64) {
  const sealed = sealFile(fileKey, file, cap);
  const uk = uploadKey(root, fileKey, type, sealed.ctSha256);
  const it = buildItem({ type, secret: uk.secret, data: sealed.object });
  return { ...sealed, ...it, url: `ar://${it.id}`, uploadOwner: uk.owner };
}

// ---------------------------------------------------------------- ar://

const B64URL = /^[A-Za-z0-9_-]{43}$/;
/** The id of `ar://<id>`: the scheme in lower case, exactly 43 canonical base64url characters (the last one of
 *  `AEIMQUYcgkosw048`), nothing after it (`ArUrl`). */
export function parseArUrl(url) {
  if (typeof url !== "string" || !url.startsWith("ar://")) fail("ArUrl");
  const id = url.slice(5);
  if (!B64URL.test(id) || !"AEIMQUYcgkosw048".includes(id[42])) fail("ArUrl");
  const raw = fromB64url(id);
  if (raw.length !== 32 || b64url(raw) !== id) fail("ArUrl");
  return id;
}

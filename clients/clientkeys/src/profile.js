// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md §4, §6, §7.1, §7.2, §10.1; plan
// docs/superpowers/plans/2026-11-27-user-profiles.md "Pinned formats"; CLI-UPR-09, CLI-UPR-19, CLI-UPR-28): the profile id
// (UUIDv7), the name helper, the envelope (Argon2id, the key derivations, the wraps and their AD, the label), the sealed store's
// items, HMAC file names, manifests and anchor, and the export file. The byte formats of smartcontracts/vectors/profile/. Every
// seal takes its nonce as an input (the generator fixes them; the SDK draws them in ua-rs). UNAUDITED.
import { argon2id } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { gcmsiv } from "@noble/ciphers/aes.js";
import { base64 } from "@scure/base";
import { sha256, bytesToHex, concatBytes, utf8ToBytes } from "./bytes.js";
import { KEYWRAP_LABEL, USAGE, passphraseBytes } from "./pqvault.js";

export class ProfileError extends Error {
  constructor(code, reason) {
    super(reason ? `${code}: ${reason}` : code);
    this.code = code;
    this.reason = reason;
  }
}

export const FORMAT = "scaas.profile";
export const MANIFEST_FORMAT = "scaas.profile-manifest";
export const EXPORT_FORMAT = "scaas.profile-export";
export const WRAP_PASS = "scaas.profile.wrap";
export const WRAP_PLATFORM = "scaas.profile.platform";
/** The default KDF set (Q-UP2) and the test set (pinned format 11: accepted only under feature `test-hooks`). */
export const KDF_DEFAULT = Object.freeze({ m: 65536, t: 3, p: 4 });
export const KDF_TEST = Object.freeze({ m: 8192, t: 1, p: 4 });
export const CHUNK = 1048576;
export const HEADER_MAX = 4096;
export const PAYLOAD_MAX = 64 * CHUNK;
export const MAGIC = utf8ToBytes("SCAASPX1");

const EMPTY = new Uint8Array(0);
const utf8 = (x) => (typeof x === "string" ? utf8ToBytes(x) : x);
const decode = (x) => new TextDecoder("utf-8", { fatal: true }).decode(x);
const be = (v, n) => {
  let x = BigInt(v);
  if (x < 0n || x >= 1n << BigInt(8 * n)) throw new ProfileError("Argument");
  const out = new Uint8Array(n);
  for (let i = n - 1; i >= 0; i--, x >>= 8n) out[i] = Number(x & 0xffn);
  return out;
};
const unbe = (x) => x.reduce((a, c) => a * 256 + c, 0);
const eq = (a, c) => a.length === c.length && a.every((x, i) => x === c[i]);
const cmpUtf8 = (a, c) => {
  const [x, y] = [utf8ToBytes(a), utf8ToBytes(c)];
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
};

/** Pinned format 1: RFC 4648 §4 base64, standard alphabet, padded. */
export const b64 = (x) => base64.encode(x);
export const unb64 = (s) => base64.decode(s);

/** `lp(x) = be16(len(x)) ‖ x`, a string as its UTF-8 bytes. */
export function lp(x) {
  const v = utf8(x);
  return concatBytes(be(v.length, 2), v);
}

// ------------------------------------------------------------------ the id and the name (§4, §6)

/** The profile id as `uuid` 1.23.0's `Builder::from_unix_timestamp_millis(ms, r)` builds it (pinned format 10). */
export function uuid7(ms, r) {
  if (!Number.isSafeInteger(ms) || ms < 0 || ms >= 2 ** 48 || r.length !== 10) throw new ProfileError("Argument");
  const x = bytesToHex(
    concatBytes(be(ms, 6), Uint8Array.of(0x70 | (r[0] & 0x0f), r[1], 0x80 | (r[2] & 0x3f)), r.subarray(3, 10)),
  );
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}
/** The one comparison key of a name: NFKC, then Unicode lower case. */
export const nameKey = (s) => String(s).normalize("NFKC").toLowerCase();
/** A name as stored: NFC, 1 to 64 UTF-8 bytes, no control (Cc) or format (Cf) character, else `ProfileNameInvalid`. */
export function checkName(s) {
  const n = String(s).normalize("NFC");
  const len = utf8ToBytes(n).length;
  if (len < 1 || len > 64 || /[\p{Cc}\p{Cf}]/u.test(n)) throw new ProfileError("ProfileNameInvalid");
  return n;
}

// ------------------------------------------------------------------ KDF and keys (§7.1, §7.5)

/** The `kdf` object of an envelope or an export header, its fields in order. */
export const kdfJson = (k) => ({ alg: k.alg, v: k.v, m: k.m, t: k.t, p: k.p, salt: k.salt });
export const makeKdf = (set, salt) => ({ alg: "argon2id", v: 1, m: set.m, t: set.t, p: set.p, salt: b64(salt) });
/** The general bounds (64 MiB to 1 GiB, 3 to 10, p 4, a 16-byte salt), the test set only under `testHooks`; else
 *  `ProfileFormat`. */
export function checkKdf(k, testHooks = false) {
  let salt;
  try {
    salt = unb64(k.salt);
  } catch {
    salt = EMPTY;
  }
  const inBounds = k.m >= 65536 && k.m <= 1048576 && k.t >= 3 && k.t <= 10;
  const test = testHooks && k.m === KDF_TEST.m && k.t === KDF_TEST.t;
  const ok = k.alg === "argon2id" && k.v === 1 && k.p === 4 && Number.isInteger(k.m) && Number.isInteger(k.t);
  if (!ok || !(inBounds || test) || salt.length !== 16) throw new ProfileError("ProfileFormat", "kdf");
}
/** Argon2id (v 0x13, 32 bytes) of the passphrase's OpaqueString bytes (ua-rs `passphrase_bytes`) under the kdf's salt. */
export const stretch = (passphrase, k) =>
  argon2id(passphraseBytes(passphrase), unb64(k.salt), { t: k.t, m: k.m, p: k.p, dkLen: 32, maxmem: 2 ** 31 });
const hk = (ikm, info) => hkdf(sha256, ikm, EMPTY, utf8ToBytes(info), 32);
export const kekPass = (stretched) => hk(stretched, "scaas.profile.wrap.v1");
/** `K_plat` from the platform secret the app returns for the handle and `platform.salt`. */
export const kPlat = (secret) => hk(secret, "scaas.profile.platform.v1");
export const exportKey = (stretched) => hk(stretched, "scaas.profile-export.v1");
export const subKeys = (dek) => ({
  label: hk(dek, "scaas.profile.label.v1"),
  item: hk(dek, "scaas.profile.item.v1"),
  name: hk(dek, "scaas.profile.item-name.v1"),
});

// ------------------------------------------------------------------ AEAD

/** `nonce ‖ AES-256-GCM-SIV(key, nonce, ad, pt)` (tag last). */
const seal = (key, nonce, ad, pt) => concatBytes(nonce, gcmsiv(key, nonce, ad).encrypt(pt));
function open(key, blob, ad) {
  if (blob.length < 28) throw new ProfileError("Aead");
  try {
    return gcmsiv(key, blob.subarray(0, 12), ad).decrypt(blob.subarray(12));
  } catch {
    throw new ProfileError("Aead");
  }
}

// ------------------------------------------------------------------ the envelope (§7.1)

/** The wraps' public JSON: exactly `format`, `v`, `id`, `state`, `gen`, `kdf` (pinned format 4). */
export const publicJson = (e) =>
  JSON.stringify({ format: FORMAT, v: 1, id: e.id, state: e.state, gen: e.gen, kdf: kdfJson(e.kdf) });
/** `profile.envelope`, its fields in the spec's order, absent ones left out (values in their stored form: base64 strings). */
export function envelopeJson(e) {
  const o = { format: FORMAT, v: 1, id: e.id, state: e.state, rev: e.rev, gen: e.gen };
  if (e.migration !== undefined) o.migration = e.migration;
  if (e.name !== undefined) o.name = e.name;
  if (e.kdf !== undefined) o.kdf = kdfJson(e.kdf);
  if (e.pass !== undefined) o.pass = e.pass;
  if (e.platform !== undefined) o.platform = { salt: e.platform.salt, wrap: e.platform.wrap };
  if (e.label !== undefined) o.label = e.label;
  return JSON.stringify(o);
}
/** A wrap's AD: ua-rs `seal_key`'s prefix (`"scaas/ua/v1/keywrap" ‖ u8(Derive)`, `DEK_p` a Derive handle) ‖ lp(domain) ‖ JSON. */
export const wrapAd = (domain, pub) =>
  concatBytes(utf8ToBytes(KEYWRAP_LABEL), Uint8Array.of(USAGE.Derive), lp(domain), utf8ToBytes(pub));
/** `pass` (domain `WRAP_PASS`, under `KEK_pass`) or `platform.wrap` (`WRAP_PLATFORM`, under `K_plat`): 60 bytes. */
export const sealWrap = (kek, nonce, dek, domain, pub) => seal(kek, nonce, wrapAd(domain, pub), dek);
export function openWrap(kek, wrap, domain, pub) {
  if (wrap.length !== 60) throw new ProfileError("Argument");
  return open(kek, wrap, wrapAd(domain, pub));
}
export const labelAd = (id) => concatBytes(lp("scaas.profile.label"), be(1, 2), lp(id));
/** The label plaintext `{"name":"<NFC>","hidden":bool}` (pinned format 5). */
export function labelJson(name, hidden) {
  if (typeof hidden !== "boolean") throw new ProfileError("ProfileFormat");
  return JSON.stringify({ name: checkName(name), hidden });
}
export const sealLabel = (kLabel, nonce, id, name, hidden) =>
  seal(kLabel, nonce, labelAd(id), utf8ToBytes(labelJson(name, hidden)));
export function openLabel(kLabel, sealed, id) {
  return parseLabel(open(kLabel, sealed, labelAd(id)));
}
function parseLabel(pt) {
  try {
    const text = decode(pt);
    const l = JSON.parse(text);
    if (labelJson(l.name, l.hidden) === text) return { name: l.name, hidden: l.hidden };
  } catch {
    // refused below
  }
  throw new ProfileError("ProfileFormat", "label");
}

// ------------------------------------------------------------------ the sealed store (§7.2)

export const itemAd = (part, name, rev) =>
  concatBytes(lp("scaas.profile.item"), be(1, 2), lp(part), lp(name), be(rev, 8));
/** The item's file name: `hex(HMAC-SHA256(K_name, lp(part) ‖ lp(item name)))`. */
export const itemFile = (kName, part, name) => bytesToHex(hmac(sha256, kName, concatBytes(lp(part), lp(name))));
export const sealItem = (kItem, nonce, part, name, rev, pt) => seal(kItem, nonce, itemAd(part, name, rev), pt);
export const openItem = (kItem, sealed, part, name, rev) => open(kItem, sealed, itemAd(part, name, rev));
/** The item on disk `{"rev":N,"sealed":"<base64>"}` (pinned format 6). */
export const itemJson = (rev, sealed) => JSON.stringify({ rev, sealed: b64(sealed) });
/** The plaintext of the item `manifest:<part>` of part `profile` (pinned format 7): each list sorted by the name's UTF-8 bytes,
 *  a name at most once in both lists (`ProfileFormat`), at most 65,536 entries (`ProfilePartFull`). */
export function manifestJson(part, rev, items, tombstones) {
  const names = [...items, ...tombstones].map(([n]) => n);
  if (new Set(names).size !== names.length) throw new ProfileError("ProfileFormat", "manifest");
  if (names.length > 65536) throw new ProfileError("ProfilePartFull");
  const sorted = (l) => [...l].sort((a, c) => cmpUtf8(a[0], c[0])).map(([n, r]) => [n, r]);
  return JSON.stringify({
    format: MANIFEST_FORMAT,
    v: 1,
    part,
    rev,
    items: sorted(items),
    tombstones: sorted(tombstones),
  });
}
/** The first 16 bytes of SHA-256 of a file, lower-case hex (the anchor's `sha256`). */
export const digest16 = (file) => bytesToHex(sha256(file).subarray(0, 16));
/** The anchor (pinned format 8), parts sorted by name. */
export function anchorJson(a) {
  const parts = Object.fromEntries(
    Object.keys(a.parts)
      .sort(cmpUtf8)
      .map((k) => [k, { rev: a.parts[k].rev, sha256: a.parts[k].sha256 }]),
  );
  return JSON.stringify({ gen: a.gen, envelope: { rev: a.envelope.rev, sha256: a.envelope.sha256 }, parts });
}
/** CLI-UPR-28: what is stored on disk against the anchor: `same`, `follow` (a value ahead: the anchor follows) or `rollback`. */
export function anchorCompare(stored, anchor) {
  const cmp = (s, a) => {
    if (!s) return "rollback";
    if (s.rev > a.rev) return "follow";
    return s.rev < a.rev || s.sha256 !== a.sha256 ? "rollback" : "same";
  };
  const has = (o, k) => Object.hasOwn(o, k);
  const v = [
    stored.gen > anchor.gen ? "follow" : stored.gen < anchor.gen ? "rollback" : "same",
    cmp(stored.envelope, anchor.envelope),
    ...Object.keys(anchor.parts).map((k) => cmp(has(stored.parts, k) ? stored.parts[k] : null, anchor.parts[k])),
    ...Object.keys(stored.parts)
      .filter((k) => !has(anchor.parts, k))
      .map(() => "follow"),
  ];
  return v.includes("rollback") ? "rollback" : v.includes("follow") ? "follow" : "same";
}

// ------------------------------------------------------------------ export and import (§10.1)

export const exportHeader = (k, prefix) =>
  utf8ToBytes(
    JSON.stringify({ format: EXPORT_FORMAT, v: 1, kdf: kdfJson(k), nonce_prefix: b64(prefix), chunk: CHUNK }),
  );
const chunkNonce = (prefix, i, last) => concatBytes(prefix, be(i, 4), Uint8Array.of(last ? 1 : 0));
const chunkAd = (header, i) => concatBytes(lp(EXPORT_FORMAT), be(header.length, 4), header, be(i, 4));
/** Chunk `i`: `AES-256-GCM-SIV(K_x, prefix ‖ be32(i) ‖ last, AD_i, pt)` as `ct ‖ tag`. */
export const sealChunk = (kx, header, prefix, i, last, pt) =>
  gcmsiv(kx, chunkNonce(prefix, i, last), chunkAd(header, i)).encrypt(pt);
const openChunk = (kx, header, prefix, i, last, c) =>
  gcmsiv(kx, chunkNonce(prefix, i, last), chunkAd(header, i)).decrypt(c);
/** `be32(len) ‖ label JSON ‖ be32(len) ‖ settings ‖ be16(count) ‖ (lp(name) ‖ be32(len) ‖ bytes)*`. */
export const payload = (label, settings, items) => {
  const l = utf8ToBytes(labelJson(label.name, label.hidden));
  return concatBytes(
    be(l.length, 4),
    l,
    be(settings.length, 4),
    settings,
    be(items.length, 2),
    ...items.flatMap(([n, v]) => [lp(n), be(v.length, 4), v]),
  );
};
/** `magic ‖ be32(header_len) ‖ header ‖ chunk_0 ‖ … ‖ chunk_last`; a payload above 64 MiB is `ProfileExportTooLarge`. */
export function exportFile(kx, k, prefix, pl) {
  if (pl.length > PAYLOAD_MAX) throw new ProfileError("ProfileExportTooLarge");
  if (pl.length === 0 || prefix.length !== 7) throw new ProfileError("Argument");
  const header = exportHeader(k, prefix);
  const n = Math.ceil(pl.length / CHUNK);
  const chunks = [];
  for (let i = 0; i < n; i++)
    chunks.push(sealChunk(kx, header, prefix, i, i === n - 1, pl.subarray(i * CHUNK, (i + 1) * CHUNK)));
  return concatBytes(MAGIC, be(header.length, 4), header, ...chunks);
}
/** Every refusal is `ProfileImportOpen` with a local `reason`: header refusals (`magic`, `header_len`, `header`, `format`,
 *  `version`, `chunk`, `kdf`) and the length bound (`size`, `truncated`) before the KDF; then `tag` (a wrong passphrase, a
 *  changed, dropped, moved or appended chunk, the last flag), then the payload (`label`, `item`, `payload`). Returns
 *  `{label: {name, hidden}, settings, items: [[name, bytes]]}`. */
export function importFile(file, passphrase, { testHooks = false } = {}) {
  const fail = (reason) => {
    throw new ProfileError("ProfileImportOpen", reason);
  };
  if (file.length < 12) fail("truncated");
  if (!eq(file.subarray(0, 8), MAGIC)) fail("magic");
  const hl = unbe(file.subarray(8, 12));
  if (hl > HEADER_MAX) fail("header_len");
  if (file.length < 12 + hl) fail("truncated");
  const header = file.subarray(12, 12 + hl);
  let h;
  try {
    h = JSON.parse(decode(header));
  } catch {
    fail("header");
  }
  if (h?.format !== EXPORT_FORMAT) fail("format");
  if (h.v !== 1) fail("version");
  if (h.chunk !== CHUNK) fail("chunk");
  try {
    checkKdf(h.kdf, testHooks);
  } catch {
    fail("kdf");
  }
  let prefix = EMPTY;
  try {
    prefix = unb64(h.nonce_prefix);
  } catch {
    fail("header");
  }
  if (prefix.length !== 7 || !eq(exportHeader(h.kdf, prefix), header)) fail("header");
  const body = file.subarray(12 + hl);
  const step = CHUNK + 16;
  if (body.length > (PAYLOAD_MAX / CHUNK) * step) fail("size");
  const n = Math.ceil(body.length / step);
  if (n === 0 || body.length - (n - 1) * step < 17) fail("truncated");
  const kx = exportKey(stretch(passphrase, h.kdf));
  const out = [];
  for (let i = 0; i < n; i++) {
    try {
      out.push(openChunk(kx, header, prefix, i, i === n - 1, body.subarray(i * step, (i + 1) * step)));
    } catch {
      fail("tag");
    }
  }
  return parsePayload(concatBytes(...out), fail);
}
function parsePayload(pl, fail) {
  let o = 0;
  const take = (n) => {
    if (o + n > pl.length) fail("payload");
    o += n;
    return pl.subarray(o - n, o);
  };
  let label;
  try {
    label = parseLabel(take(unbe(take(4))));
  } catch (e) {
    if (e.code === "ProfileImportOpen") throw e;
    fail("label");
  }
  const settings = take(unbe(take(4)));
  const count = unbe(take(2));
  const allowed = ["keystore", "sdk.state"];
  const items = [];
  for (let k = 0, next = 0; k < count; k++) {
    let name;
    try {
      name = decode(take(unbe(take(2))));
    } catch (e) {
      if (e.code === "ProfileImportOpen") throw e;
      fail("item");
    }
    const at = allowed.indexOf(name, next);
    if (at < 0) fail("item");
    next = at + 1;
    items.push([name, take(unbe(take(4)))]);
  }
  if (o !== pl.length) fail("payload");
  return { label, settings, items };
}

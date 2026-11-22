// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Generates smartcontracts/vectors/arweave/{items,objects,upload}.json and smartcontracts/vectors/pqchat/ar-urls.json (chains-
// arweave plan T16; CLI-UAL-64, CLI-UAL-65) by src/arweave.js. Every key and input is fixed:
// rnd(name, n) = the first n bytes of keccak256("scaas/arweave/vectors/<name>/0") ‖ keccak256(".../<name>/1") ‖ …
// The app root key of the upload rows is smartcontracts/vectors/appcore/handles.json's `appRoot` row. Large objects are
// pinned by SHA-256, their first 32 and last 16 bytes; every reader rebuilds them and compares.
//   node scripts/arweave-vectors.mjs [outDir]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ar from "../src/arweave.js";
import { hex, fromHex, keccak_256, sha256, utf8ToBytes, concatBytes } from "../src/bytes.js";

const VEC = fileURLToPath(new URL("../../../smartcontracts/vectors/", import.meta.url));
const OUT = process.argv[2] ?? join(VEC, "arweave");
const PQC = process.argv[2] ?? join(VEC, "pqchat");
mkdirSync(OUT, { recursive: true });
mkdirSync(PQC, { recursive: true });

const rnd = (name, n = 32) => {
  const blocks = [];
  for (let i = 0; 32 * i < n; i++) blocks.push(keccak_256(utf8ToBytes(`scaas/arweave/vectors/${name}/${i}`)));
  return concatBytes(...blocks).slice(0, n);
};
const utf8 = (s) => utf8ToBytes(s);
const h = (v) => hex(v);
const tagsJson = (tags) => tags.map((t) => ({ name: h(t.name), value: h(t.value) }));
const write = (dir, name, obj) => writeFileSync(join(dir, name), JSON.stringify(obj, null, 2) + "\n");

// ---------------------------------------------------------------- items.json

const KEYS = { 2: rnd("key/ed25519"), 3: rnd("key/secp256k1"), 4: rnd("key/solana") };
const DATA = rnd("data", 37);
// a target as arbundles takes it (32 bytes), an anchor of 32 ASCII bytes (arbundles takes the anchor as a string)
const TARGET = rnd("target");
const ANCHOR = utf8("scaas-arweave-vectors-anchor-001");
const tag = (n, v) => ({ name: utf8(n), value: utf8(v) });
const variants = [
  { name: "no tags", tags: [] },
  { name: "one tag", tags: [tag("Content-Type", "application/octet-stream")] },
  { name: "64 tags", tags: Array.from({ length: 64 }, (_, i) => tag(`n${i}`, `v${i}`)) },
  { name: "a 64-byte name (two-byte varint)", tags: [tag("x".repeat(64), "y")] },
  { name: "a target", target: TARGET },
  { name: "an anchor", anchor: ANCHOR },
  { name: "target, anchor and a tag", target: TARGET, anchor: ANCHOR, tags: [tag("App", "scaas")] },
];
const items = [];
for (const type of [2, 3, 4])
  for (const v of variants) {
    const tags = v.tags ?? [];
    const it = ar.buildItem({ type, secret: KEYS[type], data: DATA, target: v.target, anchor: v.anchor, tags });
    items.push({
      name: `type ${type}, ${v.name}`,
      type,
      secret: h(KEYS[type]),
      owner: h(it.owner),
      target: v.target ? h(v.target) : null,
      anchor: v.anchor ? h(v.anchor) : null,
      tags: tagsJson(tags),
      rawTags: h(ar.encodeTags(tags)),
      data: h(DATA),
      message: h(it.message),
      signature: h(it.signature),
      id: it.id,
      item: h(it.item),
    });
  }

// deep hash rows beside the items: a blob, an empty blob, a nested list
const deepHash = [
  { name: "blob", value: h(utf8("dataitem")) },
  { name: "empty blob", value: "0x" },
  { name: "list of two blobs", value: ["0x01", "0x0203"] },
  { name: "nested list", value: ["0x01", ["0x02", []]] },
].map((r) => {
  const conv = (x) => (Array.isArray(x) ? x.map(conv) : fromHex(x));
  return { ...r, hash: h(ar.deepHash(conv(r.value))) };
});

// refusals: each a well-formed item changed in one place; the expected code; its positive control is the row it came from
const base = (type, v = 0) => fromHex(items.find((r) => r.type === type && r.name.endsWith(variants[v].name)).item);
const tagged = fromHex(items.find((r) => r.name === "type 2, one tag").item);
const tagStart = 2 + 64 + 32 + 1 + 1; // the tag count of a type-2 item without target and anchor
const refusals = [];
const refuse = (name, item, code) => refusals.push({ name, item: h(item), code });
{
  const x = base(2);
  x[0] = 1;
  refuse("signature type 1", x, "SignatureType");
  const y = base(2);
  y[0] = 5;
  refuse("signature type 5", y, "SignatureType");
}
refuse("shorter than 80 bytes", base(2).slice(0, 79), "ItemShort");
{
  const x = base(2);
  x[2 + 64 + 32] = 2;
  refuse("a target presence byte 2", x, "Presence");
  const y = base(2);
  y[2 + 64 + 32 + 1] = 2;
  refuse("an anchor presence byte 2", y, "Presence");
}
{
  // the tag section rewritten: [count u64 LE][len u64 LE][bytes], data after it
  const data = DATA;
  const withTags = (count, raw) => concatBytes(tagged.slice(0, tagStart), le8(count), le8(raw.length), raw, data);
  const one = ar.encodeTags([tag("Content-Type", "application/octet-stream")]);
  // a negative block count: -1 then the block's byte size, the pair, the terminator
  const pair = one.slice(1, one.length - 1);
  const neg = concatBytes(Uint8Array.of(0x01), zz(pair.length), pair, Uint8Array.of(0));
  refuse("a negative Avro block count", withTags(1, neg), "TagBlockNegative");
  refuse("trailing tag bytes", withTags(1, concatBytes(one, Uint8Array.of(0))), "TagTrailing");
  refuse("a header tag count other than the Avro count", withTags(2, one), "TagCount");
  const empty = ar.encodeTags([]);
  refuse("a tag count without tag bytes", withTags(1, empty), "TagCount");
  // an empty name: count 1, name length 0, value "v", terminator
  refuse("an empty name", withTags(1, Uint8Array.of(0x02, 0x00, 0x02, 0x76, 0x00)), "TagBounds");
  refuse("an empty value", withTags(1, Uint8Array.of(0x02, 0x02, 0x6e, 0x00, 0x00)), "TagBounds");
  // two blocks of one tag each: valid Avro, not what a builder writes (the signed bytes are the raw ones)
  const two = ar.encodeTags([tag("a", "b"), tag("c", "d")]);
  const split = concatBytes(
    Uint8Array.of(0x02),
    two.slice(1, 5),
    Uint8Array.of(0x02),
    two.slice(5, 9),
    Uint8Array.of(0),
  );
  refuse("two Avro blocks", withTags(2, split), "TagNonCanonical");
  refuse("tag bytes above 4,096", withTags(1, new Uint8Array(4097)), "TagBounds");
  refuse("129 tags", withTags(129, one), "TagCount");
}
{
  // type 3: v 0 or 1 (the item's v byte at 2 + 64), and the high-s twin of a valid signature (s' = n - s, v flipped)
  for (const v of [0, 1]) {
    const x = base(3);
    x[2 + 64] = v;
    refuse(`type 3 with v = ${v}`, x, "Signature");
  }
  const x = base(3);
  const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const s = BigInt(hex(x.slice(2 + 32, 2 + 64)));
  x.set(fromHex((n - s).toString(16).padStart(64, "0")), 2 + 32);
  x[2 + 64] = x[2 + 64] === 27 ? 28 : 27;
  refuse("type 3 with a high s", x, "Signature");
}
{
  const x = base(2);
  x[x.length - 1] ^= 1;
  refuse("a data byte changed", x, "Signature");
  const y = base(4);
  y[2] ^= 1;
  refuse("a type 4 signature byte changed", y, "Signature");
}
function le8(n) {
  const o = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++, v >>= 8n) o[i] = Number(v & 0xffn);
  return o;
}
function zz(n) {
  const out = [];
  let m = BigInt(n) << 1n;
  do {
    let b = Number(m & 0x7fn);
    m >>= 7n;
    if (m) b |= 0x80;
    out.push(b);
  } while (m);
  return Uint8Array.from(out);
}
for (const r of refusals) {
  try {
    ar.parseItem(fromHex(r.item));
    throw new Error(`refusal row accepted: ${r.name}`);
  } catch (e) {
    if (e.code !== r.code) throw new Error(`${r.name}: ${e.code ?? e.message}, expected ${r.code}`);
  }
}

write(OUT, "items.json", {
  description:
    "ANS-104 data items as arbundles builds them (CLI-UAL-64; chains-arweave plan T16): layout, deep hash, Avro tags, types 2, 3 (EIP-191, low s, v 27/28) and 4 (ed25519 over the deep hash's lowercase hex text), id = base64url(SHA-256(signature)); the parser's refusals, each a well-formed row changed in one place. Generated by clients/clientkeys/scripts/arweave-vectors.mjs; cross-checked both ways by clients/clientkeys/xcheck/arbundles.",
  deepHash,
  items,
  refusals,
});

// ---------------------------------------------------------------- objects.json

const FILE_KEY = rnd("file/key");
const pin = (object) => ({
  objectLength: object.length,
  ctSha256: h(sha256(object)),
  head: h(object.slice(0, 32)),
  tail: h(object.slice(-16)),
});
const buckets = [{ size: 0 }];
for (let k = 16; k <= 31; k++) for (const d of [-1, 0, 1]) buckets.push({ size: 2 ** k + d - 8 });
for (const r of buckets) {
  const at = (cap) => {
    try {
      return ar.bucket(r.size, cap);
    } catch (e) {
      return e.code;
    }
  };
  r.bucket64 = at(ar.CAP_64);
  r.bucketWasm32 = at(ar.CAP_WASM32);
}
const fileOf = (name, n) => rnd(`file/${name}`, n);
const sealedRows = [
  { name: "empty file", size: 0 },
  { name: "5 bytes", size: 5 },
  { name: "the 2^16 bucket full (size 65,528)", size: 65528 },
  { name: "one byte over: the 2^17 bucket", size: 65529 },
].map((r) => {
  const file = fileOf(r.name, r.size);
  const s = ar.sealFile(FILE_KEY, file);
  return { ...r, fileSeed: `file/${r.name}`, sha256: h(s.sha256), ...pin(s.object) };
});
// read refusals: the frame built wrongly, encrypted under the file key (a sender who lies); each beside its control
const small = fileOf("5 bytes", 5);
const frameRows = [
  { name: "control: the frame as written", frame: {}, code: null },
  { name: "len one more than size", frame: { len: 6 }, code: "FileFrame" },
  { name: "len one less than size", frame: { len: 4 }, code: "FileFrame" },
  { name: "a non-zero pad byte", frame: { padAt: 100, padValue: 1 }, code: "FileFrame" },
  { name: "the last pad byte non-zero", frame: { padAt: 65535, padValue: 0x80 }, code: "FileFrame" },
  { name: "another plaintext sha256", frame: {}, sha256: h(sha256(utf8("other"))), code: "FileHashMismatch" },
].map((r) => {
  const fr = ar.frame(small);
  if (r.frame.len !== undefined) fr.set(le8(r.frame.len).reverse(), 0);
  if (r.frame.padAt !== undefined) fr[r.frame.padAt] = r.frame.padValue;
  const object = ar.encryptFrame(FILE_KEY, fr);
  const sha = r.sha256 ? fromHex(r.sha256) : sha256(small);
  let got = null;
  try {
    ar.openFile(FILE_KEY, object, 5, sha);
  } catch (e) {
    got = e.code;
  }
  if (got !== r.code) throw new Error(`${r.name}: ${got}, expected ${r.code}`);
  return { ...r, size: 5, sha256: h(sha), ...pin(object) };
});
// before decryption: the length and ctSha256 (a flipped byte), each with its control
const good = ar.sealFile(FILE_KEY, small).object;
const checkRows = [
  { name: "control", change: null, code: null },
  { name: "one byte short", change: "drop-last", code: "FileLength" },
  { name: "one byte long", change: "append-zero", code: "FileLength" },
  { name: "a flipped byte", change: "flip-1000", code: "FileHashMismatch" },
];
for (const r of checkRows) {
  let o = good;
  if (r.change === "drop-last") o = good.slice(0, -1);
  if (r.change === "append-zero") o = concatBytes(good, Uint8Array.of(0));
  if (r.change === "flip-1000") (o = good.slice()), (o[1000] ^= 1);
  let got = null;
  try {
    ar.checkObject(o, 5, sha256(good));
  } catch (e) {
    got = e.code;
  }
  if (got !== r.code) throw new Error(`${r.name}: ${got}`);
}
write(OUT, "objects.json", {
  description:
    "The file object of CLI-UAL-65: bucket(size) = the smallest power of two >= max(2^16, size + 8) in integers, 2^30 on 64-bit targets and 2^27 on wasm32 (above: FileTooLarge); frame = size (8 B big-endian) ‖ file ‖ zero pad; object = AES-256-GCM(file key, 0^96, frame), bucket + 16 B; the reader's checks before decryption (length, ctSha256) and after (len, pad, sha256). A file is rnd(fileSeed, size); objects are pinned by SHA-256, head and tail. Generated by clients/clientkeys/scripts/arweave-vectors.mjs.",
  rnd: 'the first n bytes of keccak256("scaas/arweave/vectors/<name>/0") ‖ keccak256(".../<name>/1") ‖ …',
  fileKey: h(FILE_KEY),
  buckets,
  sealed: sealedRows,
  frames: frameRows,
  checks: { size: 5, fileSeed: "file/5 bytes", rows: checkRows },
});

// ---------------------------------------------------------------- upload.json

const appRoot = JSON.parse(readFileSync(join(VEC, "appcore/handles.json"), "utf8")).appRoot[0];
const ROOT = fromHex(appRoot.key);
const FILE_KEY_2 = rnd("file/key-2");
const obj = ar.sealFile(FILE_KEY, small);
const upload = [];
for (const type of [2, 3, 4]) {
  const u = ar.uploadKey(ROOT, FILE_KEY, type, obj.ctSha256);
  upload.push({
    name: `type ${type}`,
    type,
    fileKey: h(FILE_KEY),
    ctSha256: h(obj.ctSha256),
    counter: u.counter,
    secret: h(u.secret),
    owner: h(u.owner),
  });
}
{
  const u = ar.uploadKey(ROOT, FILE_KEY_2, 2, obj.ctSha256);
  if (hex(u.secret) === upload[0].secret) throw new Error("another file key gave the same upload key");
  upload.push({
    name: "another file key, the same ctSha256",
    type: 2,
    fileKey: h(FILE_KEY_2),
    ctSha256: h(obj.ctSha256),
    counter: 0,
    secret: h(u.secret),
    owner: h(u.owner),
  });
  const f = ar.uploadKey(ROOT, FILE_KEY, 3, obj.ctSha256, { refuse: (k) => k === 0 });
  upload.push({
    name: "secp256k1, the first candidate refused (fixture): counter 1",
    type: 3,
    fileKey: h(FILE_KEY),
    ctSha256: h(obj.ctSha256),
    refuseFirst: true,
    counter: f.counter,
    secret: h(f.secret),
    owner: h(f.owner),
  });
}
// seal_for_arweave end to end: the 5-byte file under the fixed file key, per type
const sealForArweave = [2, 3, 4].map((type) => {
  const s = ar.sealForArweave(ROOT, FILE_KEY, small, type);
  const header = s.item.slice(0, s.item.length - s.object.length);
  return {
    name: `type ${type}`,
    type,
    fileKey: h(FILE_KEY),
    fileSeed: "file/5 bytes",
    size: 5,
    sha256: h(s.sha256),
    ctSha256: h(s.ctSha256),
    header: h(header),
    id: s.id,
    url: s.url,
    itemSha256: h(sha256(s.item)),
  };
});
write(OUT, "upload.json", {
  description:
    "The per-file upload key of CLI-UAL-64: HKDF-SHA-256(ikm = app root key ‖ file key, salt empty, info = \"scaas/arweave/v1/upload\" ‖ type (1 B) ‖ ctSha256 [‖ counter], 32): the ed25519 seed (types 2, 4) or a big-endian secp256k1 scalar (type 3, a counter byte 0x01, 0x02, … while 0 or >= n); and seal_for_arweave's item over the object. The root is appcore/handles.json's appRoot key. Generated by clients/clientkeys/scripts/arweave-vectors.mjs.",
  appRoot: appRoot.key,
  info: h(ar.UPLOAD_INFO),
  rows: upload,
  sealForArweave,
});

// ---------------------------------------------------------------- pqchat/ar-urls.json

const id = sealForArweave[0].id;
const urls = [
  { name: "accepted", url: `ar://${id}`, ok: true },
  { name: "42 characters", url: `ar://${id.slice(0, 42)}`, ok: false },
  { name: "44 characters", url: `ar://${id}A`, ok: false },
  { name: "with +", url: `ar://+${id.slice(1)}`, ok: false },
  { name: "with /", url: `ar://${id.slice(0, 10)}/${id.slice(11)}`, ok: false },
  { name: "with = padding", url: `ar://${id.slice(0, 42)}=`, ok: false },
  {
    name: "a non-canonical last character",
    url: `ar://${id.slice(0, 42)}${"AEIMQUYcgkosw048".includes("B") ? "A" : "B"}`,
    ok: false,
  },
  { name: "a trailing path", url: `ar://${id}/x`, ok: false },
  { name: "an upper-case scheme", url: `AR://${id}`, ok: false },
  { name: "https is not ar", url: `https://${id}`, ok: false },
];
for (const r of urls) {
  let ok = true;
  try {
    ar.parseArUrl(r.url);
  } catch {
    ok = false;
  }
  if (ok !== r.ok) throw new Error(`${r.name}: ${ok}`);
}
const file = {
  url: `ar://${id}`,
  ctSha256: sealForArweave[0].ctSha256,
  sha256: sealForArweave[0].sha256,
  size: 5,
  key: h(FILE_KEY),
};
write(PQC, "ar-urls.json", {
  description:
    "UA-7 §6.4.1 `file.url` of the `ar://<id>` form (CLI-UAL-65): exactly 43 canonical base64url characters (the last one of AEIMQUYcgkosw048), nothing after them, the scheme in lower case; a `file` content naming an ar:// object (the object of smartcontracts/vectors/arweave/upload.json's sealForArweave type 2 row). Generated by clients/clientkeys/scripts/arweave-vectors.mjs.",
  urls,
  file,
});
console.log(
  `items ${items.length}, refusals ${refusals.length}, buckets ${buckets.length}, upload ${upload.length}, urls ${urls.length}`,
);

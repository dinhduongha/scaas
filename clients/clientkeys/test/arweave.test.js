// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// smartcontracts/vectors/arweave/ and pqchat/ar-urls.json reproduced by src/arweave.js (chains-arweave plan T16): items of
// types 2, 3, 4, the deep hash, the parser's refusals beside their controls, buckets, frames, objects, the read checks, the
// upload key and seal_for_arweave.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as ar from "../src/arweave.js";
import * as ac from "../src/appcore.js";
import { hex, fromHex, keccak_256, sha256, utf8ToBytes, concatBytes } from "../src/bytes.js";

const vec = (p) => JSON.parse(readFileSync(new URL(`../../../smartcontracts/vectors/${p}`, import.meta.url), "utf8"));
const I = vec("arweave/items.json");
const O = vec("arweave/objects.json");
const U = vec("arweave/upload.json");
const A = vec("pqchat/ar-urls.json");
const b = (x) => fromHex(x);
const rnd = (name, n = 32) => {
  const blocks = [];
  for (let i = 0; 32 * i < n; i++) blocks.push(keccak_256(utf8ToBytes(`scaas/arweave/vectors/${name}/${i}`)));
  return concatBytes(...blocks).slice(0, n);
};
const tagsOf = (r) => r.tags.map((t) => ({ name: b(t.name), value: b(t.value) }));

test("the deep hash rows", () => {
  const conv = (x) => (Array.isArray(x) ? x.map(conv) : b(x));
  for (const r of I.deepHash) assert.equal(hex(ar.deepHash(conv(r.value))), r.hash, r.name);
  // the type string is decimal text: "2", never the byte 0x02
  const r = I.items.find((x) => x.type === 2);
  const asByte = ar.deepHash([
    utf8ToBytes("dataitem"),
    utf8ToBytes("1"),
    Uint8Array.of(2),
    b(r.owner),
    new Uint8Array(0),
    new Uint8Array(0),
    new Uint8Array(0),
    b(r.data),
  ]);
  assert.notEqual(hex(asByte), r.message);
});

test("items of types 2, 3, 4 built byte for byte, parsed and verified", () => {
  for (const r of I.items) {
    const it = ar.buildItem({
      type: r.type,
      secret: b(r.secret),
      data: b(r.data),
      target: r.target && b(r.target),
      anchor: r.anchor && b(r.anchor),
      tags: tagsOf(r),
    });
    assert.equal(hex(it.item), r.item, r.name);
    assert.equal(hex(it.message), r.message, r.name);
    assert.equal(it.id, r.id, r.name);
    assert.equal(hex(ar.encodeTags(tagsOf(r))), r.rawTags, r.name);
    const p = ar.parseItem(b(r.item));
    assert.equal(p.id, r.id);
    assert.equal(hex(p.data), r.data);
    assert.equal(p.tags.length, r.tags.length);
    // the id is SHA-256 of the signature, never of the item
    assert.notEqual(r.id, ar.itemId(b(r.item)));
  }
  // the header sizes of a C9 item: 116 B (types 2, 4) and 150 B (type 3)
  for (const [type, size] of [
    [2, 116],
    [3, 150],
    [4, 116],
  ]) {
    const r = I.items.find((x) => x.type === type && x.name.endsWith("no tags"));
    assert.equal(b(r.item).length - b(r.data).length, size);
    assert.doesNotThrow(() => ar.parseItem(b(r.item), { shape: "c9" }));
  }
  // an empty tag list is 0 bytes, not 0x00
  assert.equal(ar.encodeTags([]).length, 0);
});

test("type 3: v in {27, 28} and a low s, produced and checked", () => {
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  for (const r of I.items.filter((x) => x.type === 3)) {
    const sig = b(r.signature);
    assert.ok(sig[64] === 27 || sig[64] === 28, r.name);
    assert.ok(BigInt(hex(sig.slice(32, 64))) <= N / 2n, r.name);
  }
});

test("the parser's refusals, each beside its control", () => {
  for (const r of I.refusals) assert.throws(() => ar.parseItem(b(r.item)), { code: r.code }, r.name);
  // controls: the rows the refusals came from parse
  for (const n of ["type 2, no tags", "type 2, one tag", "type 3, no tags", "type 4, no tags"])
    assert.doesNotThrow(() => ar.parseItem(b(I.items.find((x) => x.name === n).item)), n);
  // the C9 shape: a tag, a target or an anchor refused where C9 holds, accepted otherwise
  for (const n of ["type 2, one tag", "type 2, a target", "type 2, an anchor"]) {
    const it = b(I.items.find((x) => x.name === n).item);
    assert.throws(() => ar.parseItem(it, { shape: "c9" }), { code: "ItemShape" }, n);
    assert.doesNotThrow(() => ar.parseItem(it), n);
  }
});

test("buckets in integers at every edge; the caps", () => {
  for (const r of O.buckets) {
    for (const [cap, want] of [
      [ar.CAP_64, r.bucket64],
      [ar.CAP_WASM32, r.bucketWasm32],
    ]) {
      if (typeof want === "number") assert.equal(ar.bucket(r.size, cap), want, `${r.size}`);
      else assert.throws(() => ar.bucket(r.size, cap), { code: want }, `${r.size}`);
    }
  }
  assert.equal(ar.bucket(0), 65536);
  assert.equal(ar.bucket(65528), 65536);
  assert.equal(ar.bucket(65529), 131072);
});

test("sealed objects: exactly bucket + 16 bytes, pinned by SHA-256", () => {
  const key = b(O.fileKey);
  for (const r of O.sealed) {
    const s = ar.sealFile(key, rnd(r.fileSeed, r.size));
    assert.equal(s.object.length, r.objectLength, r.name);
    assert.equal(s.object.length, ar.bucket(r.size) + 16);
    assert.equal(hex(s.ctSha256), r.ctSha256, r.name);
    assert.equal(hex(s.object.slice(0, 32)), r.head);
    assert.equal(hex(s.object.slice(-16)), r.tail);
    assert.equal(hex(s.sha256), r.sha256);
    assert.equal(hex(ar.openFile(key, s.object, r.size, s.sha256)), hex(rnd(r.fileSeed, r.size)), r.name);
  }
});

test("open_file's checks after the tag: len, the zero pad, sha256; each beside its control", () => {
  const key = b(O.fileKey);
  const file = rnd("file/5 bytes", 5);
  for (const r of O.frames) {
    const fr = ar.frame(file);
    if (r.frame.len !== undefined) fr.set(fromHex(BigInt(r.frame.len).toString(16).padStart(16, "0")), 0);
    if (r.frame.padAt !== undefined) fr[r.frame.padAt] = r.frame.padValue;
    const object = ar.encryptFrame(key, fr);
    assert.equal(hex(sha256(object)), r.ctSha256, r.name);
    if (r.code) assert.throws(() => ar.openFile(key, object, r.size, b(r.sha256)), { code: r.code }, r.name);
    else assert.equal(hex(ar.openFile(key, object, r.size, b(r.sha256))), hex(file), r.name);
  }
  // another key fails the tag
  const s = ar.sealFile(key, file);
  assert.throws(() => ar.openFile(new Uint8Array(32), s.object, 5, s.sha256), { code: "Aead" });
});

test("the reader's check before decryption: the exact length and ctSha256", () => {
  const key = b(O.fileKey);
  const good = ar.sealFile(key, rnd(O.checks.fileSeed, O.checks.size)).object;
  const ct = sha256(good);
  for (const r of O.checks.rows) {
    let o = good;
    if (r.change === "drop-last") o = good.slice(0, -1);
    if (r.change === "append-zero") o = concatBytes(good, Uint8Array.of(0));
    if (r.change === "flip-1000") (o = good.slice()), (o[1000] ^= 1);
    if (r.code) assert.throws(() => ar.checkObject(o, O.checks.size, ct), { code: r.code }, r.name);
    else assert.doesNotThrow(() => ar.checkObject(o, O.checks.size, ct), r.name);
  }
});

test("upload keys from the app root key and the file key; seal_for_arweave", () => {
  const root = b(U.appRoot);
  for (const r of U.rows) {
    const k = ar.uploadKey(root, b(r.fileKey), r.type, b(r.ctSha256), r.refuseFirst ? { refuse: (i) => i === 0 } : {});
    assert.equal(hex(k.secret), r.secret, r.name);
    assert.equal(hex(k.owner), r.owner, r.name);
    assert.equal(k.counter, r.counter, r.name);
  }
  assert.notEqual(U.rows[0].secret, U.rows[3].secret, "another file key, another upload key");
  // the upload key needs the file key: the root alone with a zero file key gives another key
  const z = ar.uploadKey(root, new Uint8Array(32), 2, b(U.rows[0].ctSha256));
  assert.notEqual(hex(z.secret), U.rows[0].secret);
  for (const r of U.sealForArweave) {
    const s = ar.sealForArweave(root, b(r.fileKey), rnd(r.fileSeed, r.size), r.type);
    assert.equal(hex(s.ctSha256), r.ctSha256, r.name);
    assert.equal(s.id, r.id, r.name);
    assert.equal(s.url, r.url);
    assert.equal(hex(s.item.slice(0, s.item.length - s.object.length)), r.header, r.name);
    assert.equal(hex(sha256(s.item)), r.itemSha256, r.name);
    const p = ar.parseItem(s.item, { shape: "c9" });
    assert.equal(hex(p.owner), hex(s.uploadOwner));
    assert.equal(hex(sha256(p.data)), r.ctSha256);
  }
});

test("items that are not C9 parse, and are refused where C9 holds", () => {
  const object = ar.sealFile(b(O.fileKey), rnd("file/5 bytes", 5)).object;
  for (const r of U.notC9) {
    const item = concatBytes(b(r.header), object);
    assert.equal(ar.parseItem(item).id, r.id, r.name);
    assert.throws(() => ar.parseItem(item, { shape: "c9" }), { code: "ItemShape" }, r.name);
  }
});

test("ar:// urls: accepted and refused rows", () => {
  for (const r of A.urls) {
    if (r.ok) assert.equal(ar.parseArUrl(r.url), r.url.slice(5), r.name);
    else assert.throws(() => ar.parseArUrl(r.url), { code: "ArUrl" }, r.name);
  }
  assert.equal(ar.parseArUrl(A.file.url), U.sealForArweave[0].id);
});

test("a file key (usage 4) wraps and unwraps by its usage only", () => {
  const under = rnd("wrap/under");
  const nonce = rnd("wrap/nonce", 12);
  const wire = ac.sealKey(under, nonce, b(O.fileKey), ac.USAGE.File, utf8ToBytes("file"));
  assert.equal(hex(ac.openKey(under, wire, ac.USAGE.File, utf8ToBytes("file"))), O.fileKey);
  assert.throws(() => ac.openKey(under, wire, ac.USAGE.Data, utf8ToBytes("file")));
  assert.throws(() => ac.sealKey(under, nonce, b(O.fileKey), 5, utf8ToBytes("file")), { code: "Argument" });
});

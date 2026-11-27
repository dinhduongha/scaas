// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// User profiles (src/profile.js) against smartcontracts/vectors/profile/ (plan UP1; spec §4, §6, §7.1, §7.2, §10.1): the
// generator reproduces the four files byte for byte; every row is recomputed from its inputs; every wrap, label, item and export
// reopens; each refusal is refused with its code (and, at import, its reason) beside its positive control.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import * as p from "../src/profile.js";
import { passphraseBytes } from "../src/pqvault.js";
import { hex, fromHex, keccak_256, sha256, utf8ToBytes, concatBytes } from "../src/bytes.js";

const dir = new URL("../../../smartcontracts/vectors/profile/", import.meta.url);
const FILES = ["ids.json", "envelope.json", "items.json", "export.json"];
const [IDS, ENV, ITEMS, EXP] = FILES.map((f) => JSON.parse(readFileSync(new URL(f, dir))));
const b = (x) => fromHex(x);
const code = (f) => {
  try {
    f();
  } catch (e) {
    return e.code ?? e.message;
  }
  return null;
};
const reason = (f) => {
  try {
    f();
  } catch (e) {
    return `${e.code}/${e.reason}`;
  }
  return null;
};
const utf8Hex = (s) => hex(utf8ToBytes(s));

test("the generator reproduces the four files byte for byte", () => {
  const out = mkdtempSync(join(tmpdir(), "profile-vectors-"));
  try {
    const r = spawnSync(
      process.execPath,
      [fileURLToPath(new URL("../scripts/profile-vectors.mjs", import.meta.url)), out],
      { encoding: "utf8" },
    );
    assert.equal(r.status, 0, r.stderr);
    for (const f of FILES) assert.equal(readFileSync(join(out, f), "utf8"), readFileSync(new URL(f, dir), "utf8"), f);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ ids.json

test("ids: UUIDv7 rows, name_key rows, checkName rows and refusals", () => {
  assert.ok(IDS.uuid7.length >= 5);
  for (const r of IDS.uuid7) {
    assert.equal(p.uuid7(r.ms, b(r.random)), r.uuid, r.case);
    assert.match(r.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  }
  assert.equal(
    code(() => p.uuid7(2 ** 48, new Uint8Array(10))),
    "Argument",
  );
  assert.equal(
    code(() => p.uuid7(0, new Uint8Array(9))),
    "Argument",
  );
  for (const r of IDS.name_key) {
    assert.equal(utf8Hex(r.input), r.input_utf8, r.case);
    assert.equal(p.nameKey(r.input), r.name_key, r.case);
    assert.equal(utf8Hex(r.name_key), r.name_key_utf8, r.case);
  }
  // NFC and NFD of one name, and both case forms of one digraph, compare equal
  const nk = Object.fromEntries(IDS.name_key.map((r) => [r.case, r.name_key]));
  assert.equal(nk["e-acute NFC"], nk["e-acute NFD"]);
  assert.equal(nk["dz-caron title case"], nk["dz-caron upper case"]);
  let refused = 0;
  for (const r of IDS.check_name) {
    assert.equal(utf8Hex(r.input), r.input_utf8, r.case);
    if (r.error) {
      refused++;
      assert.equal(
        code(() => p.checkName(r.input)),
        r.error,
        r.case,
      );
    } else assert.equal(p.checkName(r.input), r.nfc, r.case);
  }
  assert.ok(refused >= 4 && refused < IDS.check_name.length);
});

// ------------------------------------------------------------------ envelope.json

test("envelope: KDF bounds, the test set only under test-hooks", () => {
  for (const r of ENV.kdf_bounds) {
    const got = code(() => p.checkKdf(r.kdf, r.test_hooks));
    assert.equal(got, r.error ?? null, r.case);
  }
  assert.ok(ENV.kdf_bounds.some((r) => !r.error) && ENV.kdf_bounds.some((r) => r.error));
});

test("envelope: the passphrase wraps (OpaqueString, Argon2id, KEK_pass, public JSON, AD, pass)", () => {
  assert.equal(ENV.pass.filter((r) => r.set === "default").length, 1);
  for (const r of ENV.pass) {
    assert.equal(utf8Hex(r.passphrase), r.passphrase_utf8, r.case);
    assert.equal(hex(passphraseBytes(r.passphrase)), r.opaque, r.case);
    assert.equal(r.kdf.salt, p.b64(b(r.salt)));
    const stretched = p.stretch(r.passphrase, r.kdf);
    assert.equal(hex(stretched), r.argon2id, r.case);
    const kek = p.kekPass(stretched);
    assert.equal(hex(kek), r.kek_pass, r.case);
    const pub = p.publicJson({ id: r.id, state: "protected", gen: r.gen, kdf: r.kdf });
    assert.equal(pub, r.public_json, r.case);
    assert.equal(hex(p.wrapAd(p.WRAP_PASS, pub)), r.ad, r.case);
    const wrap = p.sealWrap(kek, b(r.nonce), b(r.dek), p.WRAP_PASS, pub);
    assert.equal(hex(wrap), r.pass, r.case);
    assert.equal(wrap.length, 60);
    assert.equal(p.b64(wrap), r.pass_b64);
    assert.equal(hex(p.openWrap(kek, wrap, p.WRAP_PASS, pub)), r.dek, r.case);
  }
});

test("envelope: the platform wrap, its AD and another profile's wrap refused", () => {
  for (const r of ENV.platform) {
    const k = p.kPlat(b(r.secret));
    assert.equal(hex(k), r.k_plat);
    assert.equal(b(r.salt).length, 32);
    assert.equal(p.publicJson({ id: r.id, state: "protected", gen: r.gen, kdf: r.kdf }), r.public_json);
    assert.equal(hex(p.wrapAd(p.WRAP_PLATFORM, r.public_json)), r.ad);
    const wrap = p.sealWrap(k, b(r.nonce), b(r.dek), p.WRAP_PLATFORM, r.public_json);
    assert.equal(hex(wrap), r.wrap);
    assert.equal(hex(p.openWrap(k, wrap, p.WRAP_PLATFORM, r.public_json)), r.dek);
    // the platform wrap is not the pass wrap: the domain is in the AD
    assert.equal(
      code(() => p.openWrap(k, wrap, p.WRAP_PASS, r.public_json)),
      "Aead",
    );
  }
});

test("envelope: sub-keys, labels (visible, hidden) and their refusals", () => {
  for (const r of ENV.sub_keys) {
    const k = p.subKeys(b(r.dek));
    assert.deepEqual([hex(k.label), hex(k.item), hex(k.name)], [r.k_label, r.k_item, r.k_name]);
  }
  for (const r of ENV.labels) {
    assert.equal(p.labelJson(r.label_name, r.hidden), r.plaintext, r.case);
    assert.equal(hex(p.labelAd(r.id)), r.ad, r.case);
    const sealed = p.sealLabel(b(r.k_label), b(r.nonce), r.id, r.label_name, r.hidden);
    assert.equal(hex(sealed), r.sealed, r.case);
    assert.equal(p.b64(sealed), r.sealed_b64, r.case);
    assert.deepEqual(p.openLabel(b(r.k_label), sealed, r.id), { name: r.label_name, hidden: r.hidden });
    assert.equal(
      code(() => p.openLabel(b(r.k_label), sealed, r.other_id)),
      "Aead",
      r.case,
    );
  }
});

test("envelope: whole files (protected visible, protected hidden, unprotected) reopen", () => {
  for (const r of ENV.files) {
    const env = JSON.parse(r.file);
    assert.equal(p.envelopeJson(env), r.file, r.case);
    if (env.state === "unprotected") {
      assert.equal(env.pass, undefined);
      continue;
    }
    const pub = p.publicJson(env);
    assert.equal(pub, r.public_json, r.case);
    const dek = p.openWrap(b(r.kek_pass), p.unb64(env.pass), p.WRAP_PASS, pub);
    assert.equal(hex(dek), r.dek, r.case);
    if (env.platform)
      assert.equal(hex(p.openWrap(b(r.k_plat), p.unb64(env.platform.wrap), p.WRAP_PLATFORM, pub)), r.dek);
    const label = p.openLabel(p.subKeys(dek).label, p.unb64(env.label), env.id);
    assert.equal(label.hidden, env.name === undefined, r.case);
    if (!label.hidden) assert.equal(label.name, env.name);
  }
  assert.deepEqual(ENV.files.map((r) => JSON.parse(r.file).state).sort(), ["protected", "protected", "unprotected"]);
});

test("envelope: wrap refusals (state, gen, salt, another id) are Aead; a changed name hint still opens", () => {
  for (const r of ENV.wrap_refusals) {
    assert.equal(hex(p.wrapAd(r.domain, r.public_json)), r.ad, r.case);
    assert.equal(
      code(() => p.openWrap(b(r.kek), b(r.wrap), r.domain, r.public_json)),
      r.error,
      r.case,
    );
    // positive control: the same wrap under its own public JSON
    assert.equal(hex(p.openWrap(b(r.kek), b(r.wrap), r.domain, r.control_public_json)), r.dek, r.case);
  }
  assert.ok(ENV.wrap_refusals.length >= 5);
  for (const r of ENV.name_hint) {
    const env = JSON.parse(r.file);
    assert.notEqual(env.name, JSON.parse(r.control_file).name);
    assert.equal(p.publicJson(env), r.public_json);
    assert.equal(p.publicJson(JSON.parse(r.control_file)), r.public_json);
    assert.equal(hex(p.openWrap(b(r.kek_pass), p.unb64(env.pass), p.WRAP_PASS, p.publicJson(env))), r.dek);
  }
});

// ------------------------------------------------------------------ items.json

test("items: AD, sealed bytes, file JSON and HMAC file names", () => {
  const k = p.subKeys(b(ITEMS.keys.dek));
  assert.equal(hex(k.item), ITEMS.keys.k_item);
  assert.equal(hex(k.name), ITEMS.keys.k_name);
  for (const r of ITEMS.items) {
    assert.equal(hex(p.itemAd(r.part, r.item, r.rev)), r.ad, r.case);
    const sealed = p.sealItem(k.item, b(r.nonce), r.part, r.item, r.rev, b(r.plaintext));
    assert.equal(hex(sealed), r.sealed, r.case);
    assert.equal(hex(p.openItem(k.item, sealed, r.part, r.item, r.rev)), r.plaintext, r.case);
    assert.equal(p.itemJson(r.rev, sealed), r.file_json, r.case);
    assert.equal(p.itemFile(k.name, r.part, r.item), r.file_name, r.case);
    assert.match(r.file_name, /^[0-9a-f]{64}$/);
  }
  // one item name in two parts: two file names
  const names = ITEMS.items.map((r) => r.file_name);
  assert.equal(new Set(names).size, names.length);
});

test("items: another name, part or rev fails the tag; two seals differ", () => {
  const k = p.subKeys(b(ITEMS.keys.dek));
  for (const r of ITEMS.item_refusals) {
    assert.equal(hex(p.itemAd(r.part, r.item, r.rev)), r.ad, r.case);
    assert.equal(
      code(() => p.openItem(k.item, b(r.sealed), r.part, r.item, r.rev)),
      r.error,
      r.case,
    );
    const c = r.control;
    assert.equal(hex(p.openItem(k.item, b(r.sealed), c.part, c.item, c.rev)), c.plaintext, r.case);
  }
  assert.equal(ITEMS.item_refusals.length, 3);
  const t = ITEMS.two_seals;
  assert.notEqual(t.sealed_a, t.sealed_b);
  for (const [n, s] of [
    [t.nonce_a, t.sealed_a],
    [t.nonce_b, t.sealed_b],
  ]) {
    assert.equal(hex(p.sealItem(k.item, b(n), t.part, t.item, t.rev, b(t.plaintext))), s);
    assert.equal(hex(p.openItem(k.item, b(s), t.part, t.item, t.rev)), t.plaintext);
  }
});

test("items: manifests (tombstones, a re-created item above its tombstone) and their refusals", () => {
  for (const r of ITEMS.manifests) assert.equal(p.manifestJson(r.part, r.rev, r.items, r.tombstones), r.json, r.case);
  for (const r of ITEMS.manifest_refusals)
    assert.equal(
      code(() => p.manifestJson(r.part, r.rev, r.items, r.tombstones)),
      r.error,
      r.case,
    );
  // the manifest item of part `profile` holds manifest:sdk's JSON
  const m = ITEMS.items.find((r) => r.part === "profile");
  assert.equal(m.item, "manifest:sdk");
  assert.equal(new TextDecoder().decode(b(m.plaintext)), ITEMS.manifests.find((r) => r.case === "sdk").json);
});

test("items: anchors and every anchorCompare case", () => {
  for (const r of ITEMS.anchors) {
    assert.equal(p.digest16(utf8ToBytes(r.envelope_file)), r.anchor.envelope.sha256, r.case);
    for (const [part, text] of Object.entries(r.manifest_files))
      assert.equal(p.digest16(utf8ToBytes(text)), r.anchor.parts[part].sha256, r.case);
    assert.equal(p.anchorJson(r.anchor), r.json, r.case);
  }
  const seen = new Set();
  for (const r of ITEMS.anchor_compare) {
    assert.equal(p.anchorCompare(r.stored, r.anchor), r.verdict, r.case);
    seen.add(r.verdict);
  }
  assert.deepEqual([...seen].sort(), ["follow", "rollback", "same"]);
});

// ------------------------------------------------------------------ export.json

const CH = p.CHUNK + 16;
const rnd = (name, n) => {
  const blocks = [];
  for (let i = 0; 32 * i < n; i++) blocks.push(keccak_256(utf8ToBytes(`scaas/profile/vectors/${name}/${i}`)));
  return concatBytes(...blocks).slice(0, n);
};
const itemBytes = (v) => (typeof v === "string" ? b(v) : rnd(v.filler, v.len));
const built = new Map();
function buildFile(r) {
  if (!built.has(r.case)) {
    const kx = p.exportKey(p.stretch(r.passphrase, r.kdf));
    const pl = p.payload(
      JSON.parse(r.label),
      b(r.settings),
      r.items.map(([n, v]) => [n, itemBytes(v)]),
    );
    built.set(r.case, { pl, file: p.exportFile(kx, r.kdf, b(r.nonce_prefix), pl) });
  }
  return built.get(r.case);
}
function applyEdit(file, e) {
  if (!e) return file;
  const start = 12 + new DataView(file.buffer, file.byteOffset).getUint32(8);
  const chunks = [];
  for (let o = start; o < file.length; o += CH) chunks.push(file.subarray(o, o + CH));
  if (e.op === "truncate") return file.subarray(0, file.length - e.n);
  if (e.op === "replace") {
    const f = file.slice();
    f.set(b(e.hex), e.offset);
    return f;
  }
  if (e.op === "drop_chunk") chunks.splice(e.i, 1);
  else if (e.op === "swap_chunks") [chunks[e.i], chunks[e.j]] = [chunks[e.j], chunks[e.i]];
  else if (e.op === "append_chunk") chunks.push(chunks[e.i]);
  else throw new Error(`unknown edit ${e.op}`);
  return concatBytes(file.subarray(0, start), ...chunks);
}

test("export: headers and K_x", () => {
  for (const r of EXP.headers) {
    const h = p.exportHeader(r.kdf, b(r.nonce_prefix));
    assert.equal(new TextDecoder().decode(h), r.header, r.case);
    assert.equal(h.length, r.header_len);
  }
  for (const r of EXP.keys) {
    const s = p.stretch(r.passphrase, r.kdf);
    assert.equal(hex(s), r.argon2id);
    assert.equal(hex(p.exportKey(s)), r.k_x);
  }
});

test("export: files (small whole, 1 MiB, 1 MiB + 1, 2 MiB by the filler) build and import", () => {
  assert.deepEqual(
    EXP.files.map((r) => r.payload_len),
    [EXP.files[0].payload_len, 1048576, 1048577, 2097152],
  );
  for (const r of EXP.files) {
    const { pl, file } = buildFile(r);
    assert.equal(pl.length, r.payload_len, r.case);
    if (r.payload) assert.equal(hex(pl), r.payload, r.case);
    if (r.file) assert.equal(hex(file), r.file, r.case);
    assert.equal(file.length, r.file_len, r.case);
    assert.equal(hex(sha256(file)), r.file_sha256, r.case);
    assert.equal(hex(file.subarray(0, 64)), r.first64, r.case);
    assert.equal(hex(file.subarray(file.length - 64)), r.last64, r.case);
    assert.equal(Math.ceil((file.length - 12 - r.header_len) / CH), r.chunks, r.case);
    const got = p.importFile(file, r.passphrase, { testHooks: r.test_hooks });
    assert.deepEqual(got.label, JSON.parse(r.label));
    assert.equal(hex(got.settings), r.settings);
    assert.deepEqual(
      got.items.map(([n, v]) => [n, hex(v)]),
      r.items.map(([n, v]) => [n, hex(itemBytes(v))]),
    );
  }
});

test("export: every import refusal is ProfileImportOpen with its reason", () => {
  const base = Object.fromEntries(EXP.files.map((r) => [r.case, r]));
  const seen = new Set();
  for (const r of EXP.refusals) {
    let file;
    if (r.file) file = b(r.file);
    else if (r.file_len) {
      file = new Uint8Array(r.file_len);
      file.set(b(r.prefix_bytes));
    } else file = applyEdit(buildFile(base[r.base]).file, r.edit);
    assert.equal(
      reason(() => p.importFile(file, r.passphrase, { testHooks: r.test_hooks })),
      `${r.code}/${r.reason}`,
      r.case,
    );
    seen.add(r.reason);
  }
  for (const x of [
    "magic",
    "header_len",
    "header",
    "format",
    "version",
    "chunk",
    "kdf",
    "size",
    "truncated",
    "tag",
    "item",
  ])
    assert.ok(seen.has(x), x);
  // the length bound itself is accepted by the length check (and fails later, at the tag)
  const c = EXP.size_control;
  const f = new Uint8Array(c.file_len);
  f.set(b(c.prefix_bytes));
  assert.equal(
    reason(() => p.importFile(f, c.passphrase, { testHooks: true })),
    "ProfileImportOpen/tag",
  );
});

test("export: a payload above 64 MiB is ProfileExportTooLarge", () => {
  for (const r of EXP.export_refusals) {
    const kx = b(r.k_x);
    assert.equal(
      code(() => p.exportFile(kx, r.kdf, b(r.nonce_prefix), new Uint8Array(r.payload_len))),
      r.error,
    );
  }
  assert.equal(EXP.export_refusals[0].payload_len, 64 * 1048576 + 1);
});

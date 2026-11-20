// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Generates smartcontracts/vectors/appcore/handles.json (scaas-sdk spec §12.2, §23.1 item 9; plan T21) by src/appcore.js: the
// key-handle operations of app cores on raw bytes, which `ua-rs`'s `app-core` handles reproduce. Every random input is fixed:
// rnd(name, n) = the first n bytes of keccak256("scaas/appcore/vectors/<name>/0") ‖ keccak256(".../<name>/1") ‖ …
//   node scripts/appcore-vectors.mjs [outDir]
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ac from "../src/appcore.js";
import * as pc from "../src/pqchat.js";
import { hex, keccak_256, utf8ToBytes, concatBytes } from "../src/bytes.js";

const OUT = process.argv[2] ?? fileURLToPath(new URL("../../../smartcontracts/vectors/appcore/", import.meta.url));
mkdirSync(OUT, { recursive: true });

const rnd = (name, n = 32) => {
  const blocks = [];
  for (let i = 0; 32 * i < n; i++) blocks.push(keccak_256(utf8ToBytes(`scaas/appcore/vectors/${name}/${i}`)));
  return concatBytes(...blocks).slice(0, n);
};
const utf8 = (s) => utf8ToBytes(s);
const h = (v) => hex(v);

// HKDF over handles: a plain key, a key and a nonce (44 B), two input keys (K_e ‖ P_k), an empty salt and a 16-byte one
const derive = [
  {
    name: "one key, 32 B",
    keys: [rnd("derive/k1")],
    salt: new Uint8Array(0),
    info: concatBytes(utf8("scaas/app/v1/test"), rnd("derive/ctx", 64)),
    len: 32,
  },
  {
    name: "key and nonce, 44 B",
    keys: [rnd("derive/k1")],
    salt: rnd("derive/salt", 16),
    info: concatBytes(utf8("scaas/app/v1/item"), rnd("derive/ctx", 96)),
    len: 44,
  },
  {
    name: "two keys",
    keys: [rnd("derive/k1"), rnd("derive/k2")],
    salt: new Uint8Array(0),
    info: utf8("scaas/app/v1/vkey"),
    len: 32,
  },
].map((r) => ({ ...r, okm: ac.derive(r.keys, r.salt, r.info, r.len) }));

// HMAC into a handle: the three chain-step messages of UA-7 §6.3 and a longer message; one public output of 8 bytes
const ck = rnd("mac/ck");
const mac = [
  ...[1, 2, 3].map((b) => ({ name: `chain step 0x0${b}`, key: ck, data: Uint8Array.of(b), len: 32 })),
  { name: "nonce from a handle (12 B)", key: ck, data: Uint8Array.of(3), len: 12 },
  { name: "long message", key: rnd("mac/k2"), data: rnd("mac/data", 100), len: 32 },
].map((r) => ({ ...r, out: ac.macDerive(r.key, r.data, r.len) }));
const macPublic = [{ name: "8-byte hint", key: rnd("mac/epoch"), data: utf8("scaas/app/v1/hint"), len: 8 }].map(
  (r) => ({
    ...r,
    out: ac.macPublic(r.key, r.data, r.len),
  }),
);

// AEAD by handle (AES-256-GCM-SIV): the caller's nonce, a random nonce prepended, an empty plaintext
const seal = [
  {
    name: "given nonce",
    key: rnd("seal/k"),
    nonce: rnd("seal/n", 12),
    aad: rnd("seal/aad", 40),
    pt: rnd("seal/pt", 70),
  },
  {
    name: "empty plaintext and aad",
    key: rnd("seal/k"),
    nonce: rnd("seal/n2", 12),
    aad: new Uint8Array(0),
    pt: new Uint8Array(0),
  },
].map((r) => ({ ...r, ct: ac.seal(r.key, r.nonce, r.aad, r.pt) }));
const sealRandom = [
  {
    name: "random nonce prepended",
    key: rnd("seal/k"),
    nonce: rnd("seal/rn", 12),
    aad: utf8("app aad"),
    pt: utf8("hello"),
  },
].map((r) => ({ ...r, wire: ac.sealRandom(r.key, r.nonce, r.aad, r.pt) }));

// seal_key / open_key: one row per usage; the wire opens only with its usage and never by `open`
const sealKey = Object.entries(ac.USAGE).map(([name, usage]) => {
  const r = {
    name,
    under: rnd("sealkey/under"),
    nonce: rnd(`sealkey/n/${name}`, 12),
    key: rnd(`sealkey/key/${name}`),
    usage,
    aad: rnd("sealkey/aad", 96),
  };
  return { ...r, wire: ac.sealKey(r.under, r.nonce, r.key, r.usage, r.aad) };
});

// Argon2id into a handle: small parameters (the vectors, not a recommendation)
const argon2id = [
  {
    name: "m 256 KiB, t 2, p 1",
    password: utf8("correct horse battery staple"),
    salt: rnd("argon/salt"),
    m: 256,
    t: 2,
    p: 1,
    len: 32,
  },
].map((r) => ({ ...r, out: ac.argon2id(r.password, r.salt, r) }));

// KEM wrap and unwrap of a handle: the receiver's KEM key from fixed seeds; the PqChat row equals pqchat.js's `wrapTo`
const recv = pc.kemKey(rnd("kem/mlkem", 64), rnd("kem/x25519"));
const pqchatAad = concatBytes(rnd("kem/session"), rnd("kem/epoch"), rnd("kem/member"), new Uint8Array(8));
const kemWrap = [
  { name: "an app label", key: rnd("kem/key/app"), label: utf8("scaas/app/v1/wrap"), aad: rnd("kem/aad", 72) },
  {
    name: "PqChat's form (UA-7 §6.2)",
    key: rnd("kem/key/pqchat"),
    label: utf8("scaas/pqchat/v1/wrap"),
    aad: pqchatAad,
  },
].map((r, i) => {
  const m = rnd(`kem/m/${i}`);
  const x25519Secret = rnd(`kem/eph/${i}`);
  const w = ac.kemWrap({ ...r, kemPk: recv.kemPk, m, x25519Secret });
  if (
    h(
      ac.kemUnwrap({
        wrap: w,
        label: r.label,
        aad: r.aad,
        kemPk: recv.kemPk,
        dk: recv.dk,
        x25519Secret: rnd("kem/x25519"),
      }),
    ) !== h(r.key)
  )
    throw new Error("unwrap");
  return { ...r, m, x25519Secret, ...w };
});
{
  const r = kemWrap[1];
  const ref = pc.wrapTo({
    K: r.key,
    sessionId: rnd("kem/session"),
    epochId: rnd("kem/epoch"),
    member: rnd("kem/member"),
    keyId: 0,
    kemPk: recv.kemPk,
    m: r.m,
    x25519Secret: r.x25519Secret,
  });
  if (h(ref.sealedKey) !== h(r.sealedKey) || h(ref.kek) !== h(r.kek)) throw new Error("PqChat's wrap differs");
}

const appRoot = [
  { name: "app root", seed: rnd("root/seed", 64), appId: keccak_256(utf8("scaas.pqvault.v1")), ua: rnd("root/ua") },
].map((r) => ({
  ...r,
  key: ac.appRootKey(r.seed, r.appId, r.ua),
}));

const hexed = (rows) =>
  rows.map((r) =>
    Object.fromEntries(
      Object.entries(r).map(([k, v]) => [k, v instanceof Uint8Array ? h(v) : Array.isArray(v) ? v.map(h) : v]),
    ),
  );

const out = {
  description:
    "Key-handle operations of app cores (scaas-sdk spec §12.2, §23.1 item 9) on raw bytes. All bytes 0x-hex, lower case. " +
    "Generated by clients/clientkeys/scripts/appcore-vectors.mjs (src/appcore.js); never edit by hand. Random inputs fixed: " +
    'rnd(name, n) = the first n bytes of keccak256("scaas/appcore/vectors/<name>/0") ‖ …. derive: HKDF-SHA-256(ikm = keys ' +
    "concatenated, salt, info, len). mac: HMAC-SHA-256(key, data)[0:len]. seal: AES-256-GCM-SIV(key, nonce, pt, aad), the " +
    "nonce not in ct; sealRandom: nonce ‖ ct; an aad starting with keywrap is refused (AppKeyUsage). sealKey: nonce ‖ " +
    "AES-256-GCM-SIV(under, nonce, key, keywrap ‖ u8(usage) ‖ aad) (usages Derive 1, Data 2, KeyWrap 3; a usage is metadata " +
    "and enters no other byte). argon2id: RFC 9106 v0x13, no secret, no associated data. kemWrap: (mlkemCt, x25519Eph, ss) = " +
    "the UA KEM's encaps to kemPk (m, x25519Secret fixed here), kek = HKDF(ss, salt empty, info = label ‖ aad ‖ 0x01 ‖ " +
    "keccak256(kemPk), 32), sealedKey = AES-256-GCM(kek, 0^96, key, aad); the receiver's KEM key is kemKey(rnd(kem/mlkem, 64), " +
    'rnd(kem/x25519)). appRoot: HKDF-SHA-256(ikm = the BIP-39 seed, salt empty, info = "scaas/app/v1/root" ‖ appId ‖ ua, 32) ' +
    "(owner 2026-11-20, confirmed). UNAUDITED.",
  keywrap: h(ac.KEYWRAP),
  usage: ac.USAGE,
  receiver: { kemPk: h(recv.kemPk), dk: h(recv.dk), x25519Secret: h(rnd("kem/x25519")) },
  derive: hexed(derive),
  mac: hexed(mac),
  macPublic: hexed(macPublic),
  seal: hexed(seal),
  sealRandom: hexed(sealRandom),
  sealKey: hexed(sealKey),
  argon2id: hexed(argon2id),
  kemWrap: hexed(kemWrap),
  appRoot: hexed(appRoot),
};
writeFileSync(join(OUT, "handles.json"), JSON.stringify(out, null, 1) + "\n");
console.log(`wrote ${join(OUT, "handles.json")}`);

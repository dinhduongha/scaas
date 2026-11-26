// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// PqVault (src/pqvault.js) against smartcontracts/vectors/pqvault/ (plan V1, spec §11): the generator reproduces the four files
// byte for byte; every row is recomputed from its inputs; every signature verifies; the wraps reopen K_e; K_v, sealedInfo and
// the sealed prev key reopen; every item decrypts; each refusal throws its named error beside its positive control.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { argon2id } from "@noble/hashes/argon2.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { mnemonicToSeedSync } from "@scure/bip39";
import * as pv from "../src/pqvault.js";
import * as ua from "../src/ua.js";
import { pqKeygen, pqSeed, verifyUA } from "../src/pq.js";
import { kemKey } from "../src/pqchat.js";
import { hashTypedData } from "../src/evm.js";
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, abiEncode } from "../src/bytes.js";

const dir = new URL("../../../smartcontracts/vectors/pqvault/", import.meta.url);
const FILES = ["records.json", "keys.json", "items.json", "pass.json"];
const [R, K, I, P] = FILES.map((f) => JSON.parse(readFileSync(new URL(f, dir))));
const h = (x) => hex(x);
const Z32 = hex(new Uint8Array(32));
const Z20 = hex(new Uint8Array(20));
const code = (f) => {
  try {
    f();
  } catch (e) {
    return e.code ?? e.message;
  }
  return null;
};

// The type strings as the spec's §5.2 table writes them, typed a second time here.
const SPEC = {
  MemberKey: "MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  Wrap: "Wrap(bytes32 member,uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey)",
  PqVaultCreate:
    "PqVaultCreate(bytes32 creator,uint64 nonce,uint8 mode,bytes32 homeChain,address homeVaultContract,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo,uint8 groupMode)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  PqVaultEpoch:
    "PqVaultEpoch(bytes32 vaultId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  PqVaultLeave: "PqVaultLeave(bytes32 vaultId,bytes32 epochId,bytes32 member,uint64 nonce)",
  PqVaultRemove:
    "PqVaultRemove(bytes32 vaultId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,bytes32 admin,uint64 nonce)",
  PqVaultItem: "PqVaultItem(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext)",
  PqVaultEdit:
    "PqVaultEdit(bytes32 itemId,bytes32 epochId,bytes32 author,uint64 nonce,uint32 version,bytes ciphertext)",
  PqVaultBatch:
    "PqVaultBatch(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,PqVaultItem[] items)PqVaultItem(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext)",
};
const GROUP = ["PqVaultCreate", "PqVaultEpoch", "PqVaultRemove"];
const tag = (s) => keccak_256(utf8ToBytes(s));
const signer = (name) => R.signers.find((s) => s.name === name);
const domainOfRow = (row) => (row.mode === 0 ? pv.DS_V : pv.dsB(R.domains.B.chainId, R.domains.B.verifyingContract));
const allRecords = () => R.vaults.flatMap((v) => v.records.map((r) => ({ v, r })));

test("the generator reproduces the four files byte for byte", () => {
  const out = mkdtempSync(join(tmpdir(), "pqvault-vectors-"));
  try {
    const r = spawnSync(
      process.execPath,
      [fileURLToPath(new URL("../scripts/pqvault-vectors.mjs", import.meta.url)), out],
      {
        encoding: "utf8",
      },
    );
    assert.equal(r.status, 0, r.stderr);
    for (const f of FILES) assert.equal(readFileSync(join(out, f), "utf8"), readFileSync(new URL(f, dir), "utf8"), f);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test("type strings, typehashes, DS_V, DS_B, the app purpose, tags", () => {
  assert.deepEqual(pv.TYPE_STRINGS, SPEC);
  for (const [n, s] of Object.entries(SPEC)) {
    assert.equal(R.typehashes[n].type, s);
    assert.equal(R.typehashes[n].hash, h(tag(s)));
  }
  assert.equal(Object.keys(R.typehashes).length, 9);
  // DS_V: exactly name, version, salt = PQVAULT_APP_ID, by hand
  const appId = tag("scaas.pqvault.v1");
  assert.equal(R.purpose.appId, h(appId));
  assert.equal(R.purpose.purpose, h(ua.appPurpose(appId)));
  assert.equal(R.purpose.purpose, h(keccak_256(concatBytes(tag("scaas.ua.purpose.app.v1"), appId))));
  const dsV = keccak_256(
    concatBytes(tag("EIP712Domain(string name,string version,bytes32 salt)"), tag("SCaaS PqVault"), tag("1"), appId),
  );
  assert.equal(R.domains.V.separator, h(dsV));
  assert.equal(h(pv.DS_V), h(dsV));
  const B = R.domains.B;
  const dsB = keccak_256(
    abiEncode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        tag("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        tag("SCaaS PqVault"),
        tag("1"),
        B.chainId,
        B.verifyingContract,
      ],
    ),
  );
  assert.equal(B.separator, h(dsB));
  assert.notEqual(B.separator, R.domains.V.separator);
  // no SCaaS purpose: the app's purpose is none of the registry's portable record purposes, nor PqChat's
  for (const t of [...ua.PORTABLE_RECORD_TAGS, tag("scaas.ua.purpose.pqchat.v1")])
    assert.notEqual(h(t), R.purpose.purpose);
  for (const [s, x] of Object.entries(R.tags)) assert.equal(x, h(tag(s)));
  assert.equal(Object.keys(R.tags).length, 7);
});

test("PQV_ACCOUNT: the per-vault UA derivation (FN-DSA-512) from a 24-word seed", () => {
  const d = R.pqvAccount;
  assert.equal(d.account, 0x70717600);
  assert.equal(d.mnemonic.split(" ").length, 24);
  const seed = mnemonicToSeedSync(d.mnemonic, "");
  assert.equal(h(seed), d.seed);
  for (const row of d.rows) {
    assert.equal(row.kind, 0x0132);
    assert.equal(h(pqSeed(seed, "fndsa512", d.account, row.index)), row.xi);
    const k = pqKeygen(seed, "fndsa512", d.account, row.index);
    assert.equal(h(k.publicKey), row.publicKey);
    assert.equal(h(k.ua), row.ua);
  }
});

test("typedData: each record's EIP-712 JSON hashes to its typed digest; a name outside SIGNED or another mode refused", () => {
  let n = 0;
  for (const { v, r } of allRecords()) {
    const td = pv.typedData(r.struct, r.record, v.mode, R.domains.B);
    assert.equal(h(hashTypedData(td)), r.typed, r.name);
    n++;
  }
  assert.equal(n, 23);
  const { v, r } = allRecords()[0];
  assert.equal(
    code(() => pv.typedData("MemberKey", r.record, v.mode, R.domains.B)),
    "PqVaultShape",
  );
  assert.equal(
    code(() => pv.typedData(r.struct, r.record, 2, R.domains.B)),
    "PqVaultShape",
  );
});

test("records: digests in their vault's domain, ids, scopes, signatures, sigHash, stored blobs", () => {
  let n = 0;
  const seen = new Set();
  for (const { v, r } of allRecords()) {
    const ds = domainOfRow(v);
    const s = signer(r.signer);
    assert.equal(r.hashStruct, h(pv.structHash(r.struct, r.record)), r.name);
    assert.equal(r.typed, h(pv.typed(r.struct, r.record, ds)), r.name);
    assert.equal(r.uaMessage.digest, h(ua.uaMessage(s.kind, pv.P_V, fromHex(r.typed))), r.name);
    assert.ok(verifyUA(s.kindName, fromHex(s.publicKey), pv.P_V, fromHex(r.typed), fromHex(r.uaSig.signature)), r.name);
    assert.equal(r.sigHash, h(pv.sigHash(r.uaSig)), r.name);
    if (GROUP.includes(r.struct)) assert.equal(r.blob, h(pv.groupBlob(r.struct, r.record, r.uaSig)), r.name);
    if (r.struct === "PqVaultEdit") assert.equal(r.blob, h(pv.editBlob(r.record, r.sigHash)), r.name);
    if (r.struct === "PqVaultItem") assert.equal(r.blob, h(pv.itemBlob(r.record, r.sigHash, Z32)), r.name);
    const x = r.record;
    const id = {
      PqVaultCreate: () => pv.vaultId(x.creator, x.nonce, x.mode, x.homeChain, x.homeVaultContract),
      PqVaultEpoch: () => pv.epochId(x.vaultId, x.author, x.nonce),
      PqVaultItem: () => pv.itemId(x.vaultId, x.author, x.nonce),
      PqVaultBatch: () => pv.batchId(x.vaultId, x.author, x.nonce),
    }[r.struct];
    if (id) assert.equal(r.id, h(id()), r.name);
    const scope = {
      PqVaultCreate: () => pv.scopeVault(x.creator),
      PqVaultEpoch: () => pv.scopeEpoch(x.vaultId, x.author),
      PqVaultLeave: () => pv.scopeEpoch(x.vaultId, x.member),
      PqVaultRemove: () => pv.scopeEpoch(x.vaultId, x.admin),
      PqVaultItem: () => pv.scopeItem(x.vaultId, x.author),
      PqVaultEdit: () => pv.scopeItem(v.vaultId, x.author),
      PqVaultBatch: () => pv.scopeItem(x.vaultId, x.author),
    }[r.struct];
    assert.equal(r.scope, h(scope()), r.name);
    if (r.struct === "PqVaultCreate") {
      assert.equal(r.id, v.vaultId);
      assert.equal(x.mode, v.mode);
      pv.checkPassShape(x.passKdf, x.passSalt);
    }
    if (r.struct === "PqVaultEpoch") pv.checkPassShape(x.passKdf, x.passSalt);
    if (r.struct === "PqVaultBatch") {
      const ids = x.items.map((it) => h(pv.itemId(it.vaultId, it.author, it.nonce)));
      assert.deepEqual(r.itemIds, ids);
      assert.equal(r.header, h(pv.batchHeader(x, ids, r.sigHash)));
      x.items.forEach((it, i) => {
        assert.equal(r.itemBlobs[i], h(pv.itemBlob(it, r.sigHash, r.id)));
        for (const f of ["vaultId", "epochId", "author"]) assert.equal(it[f], x[f]);
      });
      assert.ok(new Set(x.items.map((it) => it.nonce).concat(x.nonce)).size === x.items.length + 1, "distinct nonces");
    }
    seen.add(`${v.mode}/${r.struct}`);
    n++;
  }
  // every signed record type in both modes
  for (const m of [0, 1]) for (const s of pv.SIGNED) assert.ok(seen.has(`${m}/${s}`), `${m}/${s}`);
  assert.ok(n >= 14);
});

test("unbound fields: a non-zero via, homeVaultContract, author != creator, a passphrase-on epoch, in some row", () => {
  const recs = allRecords().map(({ r }) => r);
  assert.ok(recs.some((r) => r.record.members?.some((m) => m.via !== Z32)));
  assert.ok(
    recs.some((r) => r.struct === "PqVaultCreate" && r.record.homeVaultContract !== Z20 && r.record.mode === 0),
  );
  const creators = new Set(recs.filter((r) => r.struct === "PqVaultCreate").map((r) => r.record.creator));
  assert.ok(recs.some((r) => r.struct === "PqVaultItem" && !creators.has(r.record.author)));
  assert.ok(recs.some((r) => r.struct === "PqVaultEpoch" && r.record.passKdf === 1));
  assert.ok(I.items.some((it) => it.homeVaultContract !== Z20 && it.author !== it.creator));
});

test("modes: ids of one creator and nonce differ by mode, mode 2 refused, a flipped mode and another instance change the digest", () => {
  const m = R.modes;
  const ids = m.sameCreatorNonce.map((x) =>
    h(pv.vaultId(m.creator, m.nonce, x.mode, x.homeChain, x.homeVaultContract)),
  );
  assert.deepEqual(
    ids,
    m.sameCreatorNonce.map((x) => x.vaultId),
  );
  assert.notEqual(ids[0], ids[1]);
  assert.equal(
    code(() => pv.domainOf(2)),
    "PqVaultShape",
  );
  assert.equal(m.refusals.find((x) => x.mode === 2).error, "PqVaultShape");
  for (const f of m.flipped) {
    const ds = f.mode === 0 ? pv.DS_V : pv.dsB(f.chainId, f.verifyingContract);
    assert.equal(f.typed, h(pv.typed("PqVaultCreate", f.record, ds)));
    assert.notEqual(f.typed, f.signedTyped);
    assert.equal(
      f.vaultId,
      h(pv.vaultId(f.record.creator, f.record.nonce, f.mode, f.record.homeChain, f.record.homeVaultContract)),
    );
    assert.equal(f.error, "UAUnauthorized");
  }
  for (const x of m.otherInstance) {
    const { r } = allRecords().find(({ r }) => r.name === x.record);
    assert.equal(x.typedThere, h(pv.typed(r.struct, r.record, pv.dsB(R.domains.B.chainId, x.instance))));
    assert.notEqual(x.typedThere, r.typed);
  }
});

test("CTR-PQV-18: groupMode 0 in every vault's create record; createTreeKem (groupMode 1) signed, refused by name", () => {
  for (const { r } of allRecords()) if (r.struct === "PqVaultCreate") assert.equal(r.record.groupMode, 0, r.name);
  const t = R.createTreeKem;
  const x = t.record;
  assert.equal(x.groupMode, 1);
  assert.equal(t.error, "PqVaultModeUnsupported(1)");
  assert.equal(t.mode, 0);
  assert.equal(t.hashStruct, h(pv.structHash("PqVaultCreate", x)));
  assert.equal(t.typed, h(pv.typed("PqVaultCreate", x, pv.DS_V)));
  assert.notEqual(t.typed, h(pv.typed("PqVaultCreate", { ...x, groupMode: 0 }, pv.DS_V)), "groupMode is in the digest");
  const s = signer(t.signer);
  assert.equal(t.uaMessage.digest, h(ua.uaMessage(s.kind, pv.P_V, fromHex(t.typed))));
  assert.ok(verifyUA(s.kindName, fromHex(s.publicKey), pv.P_V, fromHex(t.typed), fromHex(t.uaSig.signature)));
  assert.equal(t.sigHash, h(pv.sigHash(t.uaSig)));
  assert.equal(t.blob, h(pv.groupBlob("PqVaultCreate", x, t.uaSig)));
  assert.equal(t.id, h(pv.vaultId(x.creator, x.nonce, x.mode, x.homeChain, x.homeVaultContract)));
  assert.equal(t.scope, h(pv.scopeVault(x.creator)));
});

test("a native msig member: the typed digest in mode 0, UAAuth in mode 1, each signature refused in the other mode", () => {
  const n = R.nativeMember;
  const addr = (sig, digest) => {
    const g = fromHex(sig);
    const pk = secp256k1.recoverPublicKey(concatBytes(Uint8Array.of(g[64] - 27), g.subarray(0, 64)), fromHex(digest), {
      prehash: false,
    });
    return hex(keccak_256(secp256k1.Point.fromBytes(pk).toBytes(false).subarray(1)).subarray(12));
  };
  const id = concatBytes(new Uint8Array(12), fromHex(n.address));
  const t0 = allRecords().find(({ r }) => r.name === n.mode0.record).r;
  const t1 = allRecords().find(({ r }) => r.name === n.mode1.record).r;
  assert.equal(n.mode0.digest, t0.typed);
  const md = ua.memberDigest(fromHex(n.msig), ua.uaMessage(0x0120, pv.P_V, fromHex(t1.typed)));
  assert.equal(n.mode1.memberDigest, h(md));
  assert.equal(n.mode1.digest, h(ua.uaAuthDigest(n.registryDomain, id, ua.purposeTag("member"), md)));
  assert.equal(addr(n.mode0.signature, n.mode0.digest), n.address);
  assert.equal(addr(n.mode1.signature, n.mode1.digest), n.address);
  assert.notEqual(addr(n.mode0.signature, n.mode1.digest), n.address);
  assert.notEqual(addr(n.mode1.signature, n.mode0.digest), n.address);
  assert.equal(n.refusals.length, 2);
});

test("KEM keys and wraps: kek and sealedKey recomputed, each member reopens K_e", () => {
  for (const k of K.kemKeys) {
    const kk = kemKey(fromHex(k.mlkemSeed), fromHex(k.x25519Secret));
    assert.equal(h(kk.kemPk), k.kemPk);
  }
  for (const w of K.wraps) {
    const k = K.kemKeys.find((x) => x.name === w.kemKey);
    const r = pv.wrapTo({
      Ke: w.Ke,
      vaultId: w.vaultId,
      epochId: w.epochId,
      member: w.member,
      keyId: w.keyId,
      kemPk: k.kemPk,
      m: w.mlkemM,
      x25519Secret: w.x25519Secret,
    });
    assert.equal(h(r.kek), w.kek, w.name);
    assert.equal(h(r.sealedKey), w.sealedKey, w.name);
    assert.equal(h(pv.structHash("Wrap", r.wrap)), w.hashStruct, w.name);
    const kk = kemKey(fromHex(k.mlkemSeed), fromHex(k.x25519Secret));
    const Ke = pv.openWrap({
      wrap: w.wrap,
      vaultId: w.vaultId,
      epochId: w.epochId,
      kemPk: k.kemPk,
      dk: kk.dk,
      x25519Secret: k.x25519Secret,
    });
    assert.equal(Ke.usage, pv.USAGE.Derive);
    assert.equal(h(Ke.key), w.Ke, w.name);
  }
});

test("pass.json: RFC 9106's Argon2id vector, P_k of set 1, an unknown set and a wrong passphrase refused", () => {
  const v = P.rfc9106;
  const out = argon2id(fromHex(v.password), fromHex(v.salt), {
    t: v.t,
    m: v.m,
    p: v.p,
    dkLen: v.tag.length / 2 - 1,
    version: v.version,
    key: fromHex(v.secret),
    personalization: fromHex(v.ad),
  });
  assert.equal(h(out), v.tag);
  assert.deepEqual(P.sets["1"], { algorithm: "argon2id", version: 0x13, m: 65536, t: 3, p: 4, dkLen: 32 });
  for (const r of P.rows) {
    assert.equal(r.passphraseUtf8, h(utf8ToBytes(r.passphrase)));
    assert.equal(h(pv.passKey(r.passKdf, r.passphrase, r.passSalt).key), r.Pk, r.name);
  }
  const u = P.refusals.find((x) => x.error === "PassKdfUnknown");
  assert.equal(
    code(() => pv.passKey(u.passKdf, "anything at all here", P.rows[0].passSalt)),
    "PassKdfUnknown",
  );
  assert.equal(pv.passKey(0, "", Z32), null);
  const w = P.refusals.find((x) => x.error === "PassphraseWrong");
  const ep = K.epochs.find((e) => e.name === w.epoch);
  const Pk = pv.passKey(ep.passKdf, w.passphrase, ep.passSalt);
  assert.equal(h(Pk.key), w.Pk);
  const Kv = pv.vaultKey(pv.handle(pv.USAGE.Derive, ep.Ke), Pk, ep.vaultId, ep.epochId, ep.passKdf);
  assert.equal(h(Kv.key), w.Kv);
  assert.equal(
    code(() => pv.openInfo(Kv, ep.vaultId, ep.epochId, ep.sealedInfo)),
    "PassphraseWrong",
  );
  // positive control: the right passphrase opens it
  assert.equal(
    pv.openInfo(pv.handle(pv.USAGE.Derive, ep.Kv), ep.vaultId, ep.epochId, ep.sealedInfo).name,
    ep.info.name,
  );
});

test("epochs: K_v with the passphrase off and on, kInfo, sealedInfo, the sealed prev key", () => {
  const byName = Object.fromEntries(K.epochs.map((e) => [e.name, e]));
  for (const e of K.epochs) {
    const Ke = pv.handle(pv.USAGE.Derive, e.Ke);
    const Pk = e.passKdf === 0 ? null : pv.handle(pv.USAGE.Derive, P.rows.find((r) => r.epoch === e.name).Pk);
    assert.equal(e.Pk, Pk ? h(Pk.key) : null, e.name);
    const Kv = pv.vaultKey(Ke, Pk, e.vaultId, e.epochId, e.passKdf);
    assert.equal(h(Kv.key), e.Kv, e.name);
    assert.equal(h(pv.infoKey(Kv, e.vaultId, e.epochId).key), e.kInfo, e.name);
    const s = pv.sealInfo(Kv, e.vaultId, e.epochId, e.info, e.infoNonce);
    assert.equal(s.json, e.json, e.name);
    assert.equal(h(s.sealedInfo), e.sealedInfo, e.name);
    assert.deepEqual(pv.openInfo(Kv, e.vaultId, e.epochId, e.sealedInfo), e.info, e.name);
    if (e.prev) {
      const p = e.prev;
      assert.equal(e.info.prev.epochId, p.epochId);
      assert.equal(e.info.prev.keyWrap, p.keyWrap);
      assert.equal(h(pv.prevKey(Kv, e.vaultId, e.epochId, p.epochId).key), p.kPrev);
      const kw = pv.keyWrap(
        Kv,
        e.vaultId,
        e.epochId,
        p.epochId,
        pv.handle(pv.USAGE.Derive, byName[p.epoch].Kv),
        p.nonce,
      );
      assert.equal(h(kw), p.keyWrap);
      assert.equal(kw.length, 60);
      const back = pv.openPrev(Kv, e.vaultId, e.epochId, p.epochId, p.keyWrap);
      assert.equal(back.usage, pv.USAGE.Derive);
      assert.equal(h(back.key), byName[p.epoch].Kv);
      assert.equal(
        pv.checkPrev(back, e.vaultId, p.epochId, byName[p.epoch].sealedInfo).name,
        byName[p.epoch].info.name,
      );
    }
  }
  assert.ok(K.epochs.some((e) => e.passKdf === 0) && K.epochs.some((e) => e.passKdf === 1));
  assert.ok(K.epochs.some((e) => e.prev) && K.epochs.some((e) => e.epoch > 0 && !e.prev));
  // a wrong prev key: it opens, then fails the sealedInfo of the epoch it names
  const w = K.refusals.find((x) => x.error === "PrevKeyWrong");
  const e = byName[w.epoch];
  const back = pv.openPrev(pv.handle(pv.USAGE.Derive, e.Kv), e.vaultId, e.epochId, w.prevEpochId, w.keyWrap);
  assert.equal(h(back.key), w.wrongKv);
  assert.equal(
    code(() => pv.checkPrev(back, e.vaultId, w.prevEpochId, byName[w.prevEpoch].sealedInfo)),
    "PrevKeyWrong",
  );
  // and a keyWrap under another epoch's K_v does not open
  const o = K.refusals.find((x) => x.name === "keyWrap opened under another epoch's K_v");
  assert.equal(
    code(() => pv.openPrev(pv.handle(pv.USAGE.Derive, o.Kv), e.vaultId, e.epochId, e.prev.epochId, e.prev.keyWrap)),
    o.error,
  );
});

test("key usages (§6.10): each call refuses a handle of another usage; seal and sealKey outputs never cross", () => {
  const e = K.epochs.find((x) => x.prev);
  const Kv = pv.handle(pv.USAGE.Derive, e.Kv);
  const kPrev = pv.prevKey(Kv, e.vaultId, e.epochId, e.prev.epochId);
  assert.equal(kPrev.usage, pv.USAGE.KeyWrap);
  for (const r of K.usages) {
    const f = {
      "open with a KeyWrap handle (a Data open of a keyWrap)": () => pv.open(kPrev, e.prev.keyWrap),
      "open with K_v (Derive)": () => pv.open(Kv, e.sealedInfo),
      "seal with K_v (Derive)": () => pv.seal(Kv, new Uint8Array(12), new Uint8Array(1)),
      "openKey with a Data handle": () => pv.openKey(pv.infoKey(Kv, e.vaultId, e.epochId), e.prev.keyWrap, 1, "0x"),
      "derive from a Data handle": () => pv.derive([pv.infoKey(Kv, e.vaultId, e.epochId)], "0x", "0x", 32, 2),
      "a keyWrap opened as data by a Data handle of kPrev's bytes": () =>
        pv.open(pv.handle(pv.USAGE.Data, kPrev.key), e.prev.keyWrap),
      "seal with an AAD led by the key-wrap label": () =>
        pv.seal(
          pv.handle(pv.USAGE.Data, kPrev.key),
          new Uint8Array(12),
          new Uint8Array(1),
          utf8ToBytes("scaas/ua/v1/keywrap\x01"),
        ),
      "openKey of a seal output under kPrev's bytes": () => pv.openKey(kPrev, r.sealOutput, pv.USAGE.Derive, r.ctx),
    }[r.name];
    assert.ok(f, r.name);
    assert.equal(code(f), r.error, r.name);
  }
  // positive controls: the right usage works on the same bytes
  assert.equal(
    h(pv.openPrev(Kv, e.vaultId, e.epochId, e.prev.epochId, e.prev.keyWrap).key),
    K.epochs.find((x) => x.epochId === e.prev.epochId).Kv,
  );
  const so = K.usages.find((x) => x.sealOutput);
  assert.equal(h(pv.open(pv.handle(pv.USAGE.Data, kPrev.key), so.sealOutput, so.ctx)), so.plaintext);
});

test("items: r, okm, bk, n, aad, padded plaintext and ciphertext recomputed; each opens to its JSON", () => {
  const recs = Object.fromEntries(allRecords().map(({ r }) => [r.name, r]));
  for (const it of I.items) {
    const Kv = pv.handle(pv.USAGE.Derive, it.Kv);
    const x = it;
    const k = pv.itemKeys(Kv, it.r, x);
    assert.equal(h(k.okm), it.okm, it.name);
    assert.equal(h(k.bk.key), it.bk, it.name);
    assert.equal(h(k.n), it.n, it.name);
    assert.equal(h(pv.itemAad(x)), it.aad, it.name);
    assert.equal(fromHex(it.aad).length, 224);
    assert.equal(it.json, pv.canonicalJson(it.content));
    assert.equal(h(pv.padItem(utf8ToBytes(it.json))), it.pt, it.name);
    assert.equal(h(pv.encryptItem(Kv, it.r, x, it.pt)), it.ciphertext, it.name);
    assert.deepEqual(pv.decryptItem(Kv, x, it.ciphertext), it.content, it.name);
    const rec = recs[it.record];
    assert.ok(rec, it.record);
    const ct = rec.struct === "PqVaultBatch" ? rec.record.items[it.batchIndex].ciphertext : rec.record.ciphertext;
    assert.equal(ct, it.ciphertext, it.name);
    if (it.content.type === "file") {
      const kFile = pv.fileKey(Kv, x.vaultId, x.epochId, x.itemId, x.version);
      assert.equal(h(kFile.key), it.file.kFile);
      const fk = pv.openKey(
        kFile,
        it.content.keyWrap,
        pv.USAGE.Data,
        pv.fileCtx(x.vaultId, x.epochId, x.itemId, x.version),
      );
      assert.equal(h(fk.key), it.file.key);
    }
  }
  const types = new Set(I.items.map((i) => i.content.type));
  for (const t of ["login", "note", "file", "vaultRef"]) assert.ok(types.has(t), t);
  assert.ok(I.items.some((i) => i.version === 2));
  assert.ok(I.items.some((i) => i.mode === 1));
});

test("item refusals: the length bounds, bad padding, each AAD field, a wrong K_v", () => {
  const base = I.items.find((i) => i.name === I.refusals.base);
  const Kv = pv.handle(pv.USAGE.Derive, base.Kv);
  // positive control
  assert.deepEqual(pv.decryptItem(Kv, base, base.ciphertext), base.content);
  for (const r of I.refusals.rows) {
    const x = { ...base, ...(r.aad ?? {}) };
    const key = r.Kv ? pv.handle(pv.USAGE.Derive, r.Kv) : Kv;
    assert.equal(
      code(() => pv.decryptItem(key, x, r.ciphertext ?? base.ciphertext)),
      r.error,
      r.name,
    );
    if (r.length) assert.equal(fromHex(r.ciphertext).length, r.length);
  }
  const fields = I.refusals.rows.filter((r) => r.aad).flatMap((r) => Object.keys(r.aad));
  for (const f of ["vaultId", "epochId", "itemId", "version", "author", "homeChain", "homeVaultContract"])
    assert.ok(fields.includes(f), f);
  // the bounds themselves: 32 and 16,416 B pass the length check (then fail the tag), 31 and 16,417 B do not
  for (const [n, c] of [
    [32, "AeadOpen"],
    [16416, "AeadOpen"],
    [31, "CiphertextLength"],
    [16417, "CiphertextLength"],
  ])
    assert.equal(
      code(() => pv.decryptItem(Kv, base, new Uint8Array(n))),
      c,
      String(n),
    );
  assert.equal(
    code(() => pv.padItem(new Uint8Array(16381))),
    "CiphertextLength",
  );
  assert.equal(pv.padItem(new Uint8Array(16380)).length, 16384);
});

test("passphrase bytes (Fable code review F4): RFC 8265 OpaqueString: spaces to U+0020, NFC, UTF-8; NFC and NFD give one P_k", () => {
  const N = P.normalization;
  assert.ok(N.rows.length >= 2);
  for (const r of N.rows) {
    assert.equal(h(pv.passphraseBytes(r.nfc)), r.bytes, r.name);
    assert.equal(h(pv.passphraseBytes(r.nfd)), r.bytes, r.name);
    assert.notEqual(r.nfc, r.nfd, `${r.name}: two code-point sequences`);
    assert.notEqual(h(utf8ToBytes(r.nfd)), r.bytes, `${r.name}: the raw NFD bytes differ`);
    const a = pv.passKey(1, r.nfc, N.passSalt);
    const b = pv.passKey(1, r.nfd, N.passSalt);
    assert.equal(h(a.key), r.Pk, r.name);
    assert.equal(h(b.key), r.Pk, `${r.name}: NFD gives the same P_k`);
    assert.equal(
      h(argon2id(utf8ToBytes(r.nfd), fromHex(N.passSalt), { t: 3, m: 65536, p: 4, dkLen: 32 })),
      r.rawNfdArgon2,
      r.name,
    );
    assert.notEqual(r.rawNfdArgon2, r.Pk, `${r.name}: without the normalisation the key differs`);
  }
  for (const r of N.refusals)
    assert.equal(
      code(() => pv.passphraseBytes(r.input)),
      r.error,
      r.name,
    );
  assert.equal(h(pv.passphraseBytes("plain ascii")), h(utf8ToBytes("plain ascii")), "ASCII unchanged");
});

test("F12 (owner 2026-11-21): sealedInfo padded to 1,024 B (the smallest bucket), then the next power of two", () => {
  // the reference: a prev, a 64-character (ASCII) name, a 32-character icon, settings
  const ref = {
    name: "N".repeat(64),
    shared: true,
    icon: "I".repeat(32),
    settings: { autoLockSeconds: 300, clipboardSeconds: 30 },
    prev: { epochId: `0x${"a".repeat(64)}`, keyWrap: `0x${"b".repeat(120)}` },
  };
  assert.equal(pv.padInfo(utf8ToBytes(pv.canonicalJson(ref))).length, 1024, "the reference fits 1,024 B");
  assert.equal(pv.padInfo(utf8ToBytes("{}")).length, 1024);
  assert.equal(pv.padInfo(new Uint8Array(1020)).length, 1024, "1,020 B of content: still 1,024");
  assert.equal(pv.padInfo(new Uint8Array(1021)).length, 2048, "past 1,024: the next power of two");
  assert.equal(pv.padInfo(new Uint8Array(2045)).length, 4096);
  assert.equal(pv.padInfo(new Uint8Array(16380)).length, 16384);
  assert.equal(
    code(() => pv.padInfo(new Uint8Array(16381))),
    "SealedInfoLength",
  );
  const sizes = K.epochs.map((e) => fromHex(e.sealedInfo).length);
  assert.ok(K.epochs.some((e) => e.prev) && K.epochs.some((e) => !e.prev));
  assert.deepEqual([...new Set(sizes)], [1052], "one size with and without prev: nonce, 1,024 B, tag");
  assert.equal(
    code(() => pv.unpadInfo(pv.pad(utf8ToBytes("{}")))),
    "Padding",
    "a 256-B bucket is no sealedInfo",
  );
});

test("F9: a tombstone version, the 4,096 and 16,384 B buckets, padItem's limit, a 64-bit nonce, an msig UASig in a blob", () => {
  const tomb = I.items.find((i) => i.content.type === "deleted");
  assert.ok(tomb && tomb.version >= 2, "a tombstone is a later version");
  assert.deepEqual(Object.keys(tomb.content), ["type"]);
  const buckets = new Set(I.items.map((i) => fromHex(i.pt).length));
  for (const b of [256, 4096, 16384]) assert.ok(buckets.has(b), String(b));
  assert.equal(pv.padItem(new Uint8Array(I.padItemLimit.maxContent)).length, 16384);
  assert.equal(
    code(() => pv.padItem(new Uint8Array(I.padItemLimit.refusedContent))),
    "CiphertextLength",
  );
  const b = R.extra.bigNonce;
  assert.equal(typeof b.nonce, "string");
  assert.ok(BigInt(b.nonce) >= 1n << 63n);
  assert.equal(b.vaultId, h(pv.vaultId(b.creator, BigInt(b.nonce), b.mode, b.homeChain, b.homeVaultContract)));
  assert.notEqual(
    b.vaultId,
    h(pv.vaultId(b.creator, Number(BigInt(b.nonce)), b.mode, b.homeChain, b.homeVaultContract)),
    "a double loses the low bits",
  );
  const m = R.extra.msigBlob;
  const rm = allRecords().find(({ r }) => r.name === m.record).r;
  assert.ok(m.uaSig.members.length >= 2 && m.uaSig.members.some((x) => x.members.length));
  assert.equal(m.sigHash, h(pv.sigHash(m.uaSig)));
  assert.equal(m.blob, h(pv.groupBlob(rm.struct, rm.record, m.uaSig)));
});

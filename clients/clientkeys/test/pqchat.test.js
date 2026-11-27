// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// PqChat (src/pqchat.js) against smartcontracts/vectors/pqchat/: the generator reproduces the four files byte for byte, every row
// is recomputed from its inputs, the P14 refusals throw their named errors, wraps reopen K, the envelope opens to the signed
// message of records.json and its ML-DSA-65 signature verifies, the payload decodes, one changed field changes each digest.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import * as pc from "../src/pqchat.js";
import { intWord } from "../src/evm.js";
import { uaMessage } from "../src/ua.js";
import { pqKeygen, verifyUA, uaMessage as pqUaMessage } from "../src/pq.js";
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, abiEncode } from "../src/bytes.js";

const dir = new URL("../../../smartcontracts/vectors/pqchat/", import.meta.url);
const FILES = ["records.json", "keys.json", "messages.json", "topics.json", "cards.json"];
const [R, KEYS, M, T, C] = FILES.map((f) => JSON.parse(readFileSync(new URL(f, dir))));
const h = (x) => hex(x);
const Z32 = hex(new Uint8Array(32));

// The type strings as the specs write them (UA-7 §4.1, topics P35), typed here a second time: a field order swapped in
// src/pqchat.js fails this file, not only the regeneration.
const SPEC = {
  MemberKey: "MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  Wrap: "Wrap(bytes32 member,uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey)",
  PqChatSession:
    "PqChatSession(bytes32 creator,uint64 nonce,bytes32 homeChain,address homeChatContract,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo,uint8 groupMode,uint32 pathRefreshBound,bytes32 confirmTag)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  PqChatEpoch:
    "PqChatEpoch(bytes32 sessionId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  PqChatLeave: "PqChatLeave(bytes32 sessionId,bytes32 epochId,bytes32 member,uint64 nonce)",
  PqChatRemove:
    "PqChatRemove(bytes32 sessionId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,bytes32 admin,uint64 nonce)",
  PqChatMessage:
    "PqChatMessage(bytes32 sessionId,bytes32 epochId,bytes32 sender,bytes16 device,uint64 counter,bytes32[] parents,bytes ciphertext)",
  PqTopic:
    "PqTopic(bytes32 admin,uint64 nonce,bytes32 homeChain,address homeChatContract,string name,bytes about,bool openReplies)",
  PqTopicUpdate: "PqTopicUpdate(bytes32 topicId,uint64 seq,string name,bytes about,bool openReplies)",
  PqTopicWriter: "PqTopicWriter(bytes32 topicId,bytes32 writer,bool granted,uint64 seq)",
  PqTopicEntry:
    "PqTopicEntry(bytes32 topicId,bytes32 author,uint64 nonce,bytes32 parentId,EntryRef ref,string mediaType,bytes body)EntryRef(bytes32 chainUid,address pqchat,bytes32 entryId,bytes32 contentHash)",
  EntryRef: "EntryRef(bytes32 chainUid,address pqchat,bytes32 entryId,bytes32 contentHash)",
  PqTopicEdit: "PqTopicEdit(bytes32 entryId,bytes32 author,uint64 nonce,uint32 version,string mediaType,bytes body)",
  PqTopicVote: "PqTopicVote(bytes32 entryId,bytes32 voter,int8 value,uint64 seq)",
  PqChatCard: "PqChatCard(bytes32 ua,uint64 kemVersion,string matrixId)",
};
const STRUCT_OF = {
  session: "PqChatSession",
  sessionTreeKem: "PqChatSession",
  sessionMode2: "PqChatSession",
  sessionBound0: "PqChatSession",
  sessionBound24: "PqChatSession",
  sessionBound510: "PqChatSession",
  sessionBound511: "PqChatSession",
  sessionMode0Bound1: "PqChatSession",
  sessionMode0Tag: "PqChatSession",
  epoch: "PqChatEpoch",
  epochDevices: "PqChatEpoch",
  leave: "PqChatLeave",
  remove: "PqChatRemove",
  message: "PqChatMessage",
  topic: "PqTopic",
  update: "PqTopicUpdate",
  writer: "PqTopicWriter",
  post: "PqTopicEntry",
  reply: "PqTopicEntry",
  edit: "PqTopicEdit",
  vote: "PqTopicVote",
};
const signer = Object.fromEntries(R.signers.map((s) => [s.name, s]));
const kemKey = Object.fromEntries(
  KEYS.kemKeys.map((k) => [k.name, { ...k, ...pc.kemKey(k.mlkemSeed, k.x25519Secret) }]),
);

test("the generator reproduces the five files byte for byte", () => {
  const out = mkdtempSync(join(tmpdir(), "pqchat-vectors-"));
  try {
    const r = spawnSync(
      process.execPath,
      [fileURLToPath(new URL("../scripts/pqchat-vectors.mjs", import.meta.url)), out],
      { encoding: "utf8" },
    );
    assert.equal(r.status, 0, r.stderr);
    for (const f of FILES) assert.equal(readFileSync(join(out, f), "utf8"), readFileSync(new URL(f, dir), "utf8"), f);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test("type strings, typehashes, DS_C, purpose, tags", () => {
  assert.deepEqual({ ...pc.TYPE_STRINGS }, SPEC);
  for (const [n, t] of Object.entries({ ...R.typehashes, ...T.typehashes })) {
    assert.equal(t.type, SPEC[n], n);
    assert.equal(t.hash, h(keccak_256(utf8ToBytes(SPEC[n]))), n);
  }
  assert.deepEqual(Object.keys(R.typehashes), pc.SESSION_STRUCTS);
  assert.deepEqual(Object.keys(T.typehashes), pc.TOPIC_STRUCTS);
  const k = (s) => keccak_256(utf8ToBytes(s));
  assert.equal(
    R.domain.separator,
    h(keccak_256(new Uint8Array([...k("EIP712Domain(string name,string version)"), ...k("SCaaS PqChat"), ...k("1")]))),
  );
  assert.equal(T.domain.separator, R.domain.separator);
  assert.equal(R.purpose.hash, h(k("scaas.ua.purpose.pqchat.v1")));
  for (const [t, v] of Object.entries({ ...R.tags, ...T.tags })) assert.equal(v, h(k(t)), t);
  assert.equal(Object.keys({ ...R.tags, ...T.tags }).length, 9);
});

test("signers: pq.js keys from the seed, ua.js and pq.js agree on uaMessage", () => {
  for (const s of R.signers) {
    const k = pqKeygen(fromHex(s.seed), "mldsa65", s.account, s.index);
    assert.equal(h(k.publicKey), s.publicKey, s.name);
    assert.equal(h(k.ua), s.ua, s.name);
  }
  const d = fromHex(R.message.typed);
  assert.equal(h(uaMessage(0x0131, pc.PURPOSE_PQCHAT, d)), h(pqUaMessage("mldsa65", pc.PURPOSE_PQCHAT, d)));
});

/** Every row: hashStruct, typed, uaMessage, and its id, scope, signature, sigHash and blob where it has them. */
function checkRow(name, row, kept = false) {
  const struct = STRUCT_OF[name];
  assert.equal(h(pc.structHash(struct, row.record)), row.hashStruct, name);
  assert.equal(h(pc.typed(struct, row.record)), row.typed, name);
  assert.deepEqual(
    row.uaMessage,
    { kind: 0x0131, digest: h(uaMessage(0x0131, pc.PURPOSE_PQCHAT, fromHex(row.typed))) },
    name,
  );
  if (row.uaSig) {
    assert.deepEqual([row.uaSig.keyData, row.uaSig.members], ["0x", []], name);
    assert.ok(
      verifyUA(
        "mldsa65",
        fromHex(signer[row.signer].publicKey),
        pc.PURPOSE_PQCHAT,
        fromHex(row.typed),
        fromHex(row.uaSig.signature),
      ),
      name,
    );
    assert.equal(h(pc.sigHash(row.uaSig)), row.sigHash, name);
    assert.equal(h(pc.recordBlob(struct, row.record, row.uaSig)), row.blob, name);
    // CTR-CHAT-23: an `sstore2` instance keeps abi.encode(record, sigHash, UASig) of a session record; a `none` one the blob
    // above (topic records are outside the setting)
    if (!kept) return assert.equal(row.blobSigned, undefined, name);
    assert.equal(h(pc.recordBlob(struct, row.record, row.uaSig, pc.SIG_STORE.sstore2)), row.blobSigned, name);
    assert.equal(
      row.blobSigned,
      h(
        abiEncode(
          [pc.recordAbi(struct, row.record).type, "bytes32", pc.UASIG_ABI],
          [
            pc.recordAbi(struct, row.record).value,
            fromHex(row.sigHash),
            [fromHex(row.uaSig.keyData), fromHex(row.uaSig.signature), []],
          ],
        ),
      ),
      name,
    );
  }
}

test("session records: digests, ids, scopes, the message signature and blob", () => {
  const { session: S, epoch: E, leave: L, message: Mg } = R;
  for (const n of ["session", "epoch", "epochDevices", "leave", "remove", "message"]) checkRow(n, R[n], true);
  // owner (M) 2026-11-23 (CTR-CHAT-24): a member with two keys, (ua, keyId) strictly ascending, one wrap hash per entry, the
  // MemberKey typehash unchanged
  const D = R.epochDevices.record;
  const keys = D.members.map((m) => [m.ua, m.keyId]);
  assert.ok(
    keys.every((k, i) => i === 0 || keys[i - 1][0] < k[0] || (keys[i - 1][0] === k[0] && keys[i - 1][1] < k[1])),
  );
  assert.ok(new Set(D.members.map((m) => m.ua)).size < D.members.length, "a UA twice");
  assert.equal(D.wrapHashes.length, D.members.length);
  assert.equal(h(pc.TYPEHASH.MemberKey), h(keccak_256(utf8ToBytes("MemberKey(bytes32 ua,uint64 keyId,bytes32 via)"))));
  assert.deepEqual(R.sigStore, { none: 0, sstore2: 2 }, "CTR-CHAT-23's modes, PQZ's numbering");
  assert.equal(S.id, h(pc.sessionId(S.record.creator, S.record.nonce)));
  assert.equal(S.scope, h(pc.scopeSession(S.record.creator)));
  assert.equal(E.id, h(pc.epochId(E.record.sessionId, E.record.author, E.record.nonce)));
  assert.equal(E.scope, h(pc.scopeEpoch(E.record.sessionId, E.record.author)));
  assert.equal(E.record.sessionId, S.id);
  assert.equal(E.record.parentEpochId, S.id); // epoch 0's id is the session id
  assert.equal(L.id, L.typed);
  assert.equal(L.scope, h(pc.scopeEpoch(L.record.sessionId, L.record.member)));
  assert.equal(Mg.id, Mg.typed);
  assert.equal(Mg.scope, h(pc.scopeMessage(Mg.record.epochId, Mg.record.sender, Mg.record.device)));
  // CTR-CHAT-23: every control-plane record is signed in the vectors, as a client verifies it from an `sstore2` home
  assert.ok(Mg.uaSig && S.uaSig && E.uaSig && L.uaSig && R.remove.uaSig);
  // shapes: members and admins strictly sorted, the creator in both, one non-zero via, two sorted parents, non-zero fields
  for (const rec of [S.record, E.record]) {
    const uas = rec.members.map((m) => m.ua);
    assert.deepEqual(uas, [...uas].sort());
    assert.equal(new Set(uas).size, uas.length);
    assert.deepEqual(rec.admins, [...new Set(rec.admins)].sort());
  }
  assert.ok(
    S.record.members.length >= 2 &&
      S.record.admins.includes(S.record.creator) &&
      S.record.members.some((m) => m.ua === S.record.creator),
  );
  assert.ok(S.record.members.some((m) => m.via !== Z32));
  assert.equal(Mg.record.parents.length, 2);
  assert.deepEqual(Mg.record.parents, [...Mg.record.parents].sort());
  // CTR-CHAT-25, CTR-CHAT-26: groupMode is 0 in every flat row; the sessionTreeKem row's is 1, no longer refused
  assert.equal(S.record.groupMode, 0);
  assert.equal(R.sessionTreeKem.record.groupMode, 1);
  assert.equal(R.sessionTreeKem.error, undefined);
  checkRow("sessionTreeKem", R.sessionTreeKem);
  // review C-5: the reserved mode 2 (with 3, after the freeze) is a signed record refused by name
  assert.equal(R.sessionMode2.record.groupMode, 2);
  assert.equal(R.sessionMode2.error, "PqChatModeUnsupported");
  checkRow("sessionMode2", R.sessionMode2);
  // the path-less delta §3.1: both new fields 0 in mode 0; the bound rows accepted or refused by PqChatShape
  assert.equal(S.record.pathRefreshBound, 0);
  assert.equal(S.record.confirmTag, Z32);
  assert.equal(R.sessionTreeKem.record.pathRefreshBound, 20);
  for (const [name, mode, bound, error] of [
    ["sessionBound0", 1, 0, undefined],
    ["sessionBound24", 1, 24, undefined],
    ["sessionBound510", 1, 510, undefined],
    ["sessionBound511", 1, 511, "PqChatShape"],
    ["sessionMode0Bound1", 0, 1, "PqChatShape"],
    ["sessionMode0Tag", 0, 0, "PqChatShape"],
  ]) {
    assert.equal(R[name].record.groupMode, mode, name);
    assert.equal(R[name].record.pathRefreshBound, bound, name);
    assert.equal(R[name].error, error, name);
    assert.equal(R[name].record.confirmTag === Z32, name === "sessionMode0Bound1", name);
    checkRow(name, R[name]);
  }
  for (const rec of [S.record, E.record, L.record, Mg.record]) {
    for (const [f, v] of Object.entries(rec))
      if (!["groupMode", "pathRefreshBound", "confirmTag"].includes(f))
        assert.ok(
          v !== 0 && v !== Z32 && v !== "0x" && v !== hex(new Uint8Array(20)) && !(Array.isArray(v) && !v.length),
          f,
        );
  }
  // the session signs the keys.json wraps and the messages.json sealedInfo
  const wrapsOf = (e) => KEYS.wraps.filter((w) => w.name.startsWith(`${e}/`));
  assert.deepEqual(
    S.record.wrapHashes,
    wrapsOf("session").map((w) => w.hashStruct),
  );
  assert.deepEqual(
    E.record.wrapHashes,
    wrapsOf("epoch-1").map((w) => w.hashStruct),
  );
  assert.deepEqual(
    wrapsOf("session").map((w) => [w.member, w.keyId]),
    S.record.members.map((m) => [m.ua, m.keyId]),
  );
  assert.deepEqual(
    wrapsOf("epoch-1").map((w) => [w.member, w.keyId, w.epochId]),
    E.record.members.map((m) => [m.ua, m.keyId, E.id]),
  );
  assert.equal(S.record.sealedInfo, M.sealedInfo.find((s) => s.name === "session").sealedInfo);
  assert.equal(E.record.sealedInfo, M.sealedInfo.find((s) => s.name === "epoch-1").sealedInfo);
});

test("remove (P48): the typehash, the row by hand, its scope and shape; member order and nextEpoch bind", () => {
  const X = R.remove;
  const r = X.record;
  assert.equal(h(pc.TYPEHASH.PqChatRemove), "0x8f4939ececad5be22f7917c0c8087d80d372be36af3b0afb30046be9db0b6c56");
  assert.equal(R.typehashes.PqChatRemove.hash, h(pc.TYPEHASH.PqChatRemove));
  checkRow("remove", X, true);
  // hashStruct as P48 writes it: keccak256(abi.encode(TYPEHASH, sessionId, epochId, nextEpoch, keccak256(abi.encodePacked(members)),
  // admin, nonce)), beside the generic EIP-712 encoder
  const membersHash = keccak_256(concatBytes(...r.members.map(fromHex)));
  assert.equal(
    h(
      keccak_256(
        abiEncode(
          ["bytes32", "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "uint64"],
          [pc.TYPEHASH.PqChatRemove, r.sessionId, r.epochId, r.nextEpoch, membersHash, r.admin, r.nonce],
        ),
      ),
    ),
    X.hashStruct,
  );
  // the admin's epoch scope, shared with her epoch; no id, no signature
  assert.equal(X.scope, h(pc.scopeEpoch(r.sessionId, r.admin)));
  assert.equal(X.scope, R.epoch.scope);
  assert.ok(!("id" in X) && X.uaSig, "no id; signed (CTR-CHAT-23: a client verifies it from an sstore2 home)");
  // shape: epoch 1, one of its admins, 2 of its members strictly sorted, nextEpoch = its number + 1, a fresh nonce
  assert.equal(r.epochId, R.epoch.id);
  assert.equal(r.nextEpoch, R.epoch.record.epoch + 1);
  assert.ok(R.epoch.record.admins.includes(r.admin));
  assert.equal(r.members.length, 2);
  assert.deepEqual(r.members, [...new Set(r.members)].sort());
  assert.ok(r.members.every((u) => R.epoch.record.members.some((m) => m.ua === u)));
  assert.notEqual(r.nonce, R.epoch.record.nonce);
  for (const [f, v] of Object.entries(r)) assert.ok(v !== 0 && v !== Z32 && !(Array.isArray(v) && !v.length), f);
  // one change at a time: the members swapped, nextEpoch + 1
  for (const s of [
    { ...r, members: [...r.members].reverse() },
    { ...r, nextEpoch: r.nextEpoch + 1 },
  ]) {
    assert.notEqual(h(pc.typed("PqChatRemove", s)), X.typed);
    assert.notEqual(h(pc.signedDigest(0x0131, "PqChatRemove", s)), X.uaMessage.digest);
  }
});

test("topic records: digests, ids, scopes, signatures, blobs", () => {
  for (const n of ["topic", "update", "writer", "post", "reply", "edit", "vote"]) {
    checkRow(n, T[n]);
    assert.ok(T[n].uaSig, n);
  }
  const t = T.topic.record;
  assert.equal(T.topic.id, h(pc.topicId(t.admin, t.nonce)));
  assert.equal(T.topic.scope, h(pc.scopeTopic(t.admin)));
  for (const n of ["post", "reply"]) {
    const e = T[n].record;
    assert.equal(e.topicId, T.topic.id);
    assert.equal(T[n].id, h(pc.entryId(e.topicId, e.author, e.nonce)), n);
    assert.equal(T[n].scope, h(pc.scopeEntry(e.topicId, e.author)), n);
  }
  assert.equal(T.edit.scope, h(pc.scopeEntry(T.topic.id, T.edit.record.author)));
  assert.equal(T.edit.record.entryId, T.reply.id);
  for (const n of ["update", "writer", "vote"]) assert.ok(!("id" in T[n]) && !("scope" in T[n]), n);
  // the reply: every field non-zero, ref to the post with contentHash = typed(post); the post: parentId and ref all zero
  const r = T.reply.record;
  assert.equal(r.parentId, T.post.id);
  assert.deepEqual(r.ref.entryId, T.post.id);
  assert.equal(r.ref.contentHash, T.post.typed);
  assert.equal(T.reply.refHash, h(pc.structHash("EntryRef", r.ref)));
  for (const v of Object.values(r.ref)) assert.ok(v !== Z32 && v !== hex(new Uint8Array(20)));
  assert.equal(T.post.record.parentId, Z32);
  assert.deepEqual(Object.values(T.post.record.ref), [Z32, hex(new Uint8Array(20)), Z32, Z32]);
  assert.equal(T.vote.record.value, -1);
  // int8 -1 is the all-ones word in the blob (abi.encode), the vote's third head word
  assert.equal(T.vote.blob.slice(2 + 128, 2 + 192), "f".repeat(64));
});

test("intN: the sign-extended word, refused outside the range", () => {
  assert.equal(h(intWord("int8", -1)), `0x${"f".repeat(64)}`);
  assert.equal(h(intWord("int8", -128)), `0x${"f".repeat(62)}80`);
  assert.equal(h(intWord("int8", 127)), `0x${"0".repeat(62)}7f`);
  assert.equal(h(intWord("int8", 0)), Z32);
  for (const v of [128, -129, 1000]) assert.throws(() => intWord("int8", v), /out of range/);
});

/** One change at a time: a copy of `v` with one value of type `t` changed. */
function changed(t, v) {
  if (t === "bytes32" || t === "bytes16" || t === "address")
    return `${v.slice(0, -2)}${v.endsWith("00") ? "01" : "00"}`;
  if (/^uint/.test(t)) return v + 1;
  if (t === "int8") return v === -1 ? 1 : -1;
  if (t === "bool") return !v;
  if (t === "string") return `${v}.`;
  if (t === "bytes") return `${v}00`;
  if (t === "bytes32[]") return [changed("bytes32", v[0]), ...v.slice(1)];
  if (t === "MemberKey[]") return [{ ...v[0], via: changed("bytes32", v[0].via) }, ...v.slice(1)];
  if (t === "EntryRef") return { ...v, contentHash: changed("bytes32", v.contentHash) };
  throw new Error(`no change for ${t}`);
}

test("one changed field changes the typed digest and uaMessage of every record", () => {
  for (const [name, row] of Object.entries({
    ...Object.fromEntries(["session", "epoch", "leave", "remove", "message"].map((n) => [n, R[n]])),
    ...Object.fromEntries(["topic", "update", "writer", "post", "reply", "edit", "vote"].map((n) => [n, T[n]])),
  })) {
    const struct = STRUCT_OF[name];
    for (const f of pc.TYPES[struct]) {
      const s = { ...row.record, [f.name]: changed(f.type, row.record[f.name]) };
      assert.notEqual(h(pc.typed(struct, s)), row.typed, `${name}.${f.name}`);
      assert.notEqual(h(pc.signedDigest(0x0131, struct, s)), row.uaMessage.digest, `${name}.${f.name}`);
    }
  }
  // a nested field: each EntryRef field and each MemberKey field
  for (const f of pc.TYPES.EntryRef) {
    const s = {
      ...T.reply.record,
      ref: { ...T.reply.record.ref, [f.name]: changed(f.type, T.reply.record.ref[f.name]) },
    };
    assert.notEqual(h(pc.typed("PqTopicEntry", s)), T.reply.typed, `ref.${f.name}`);
  }
  for (const f of pc.TYPES.MemberKey) {
    const m = R.session.record.members;
    const s = { ...R.session.record, members: [{ ...m[0], [f.name]: changed(f.type, m[0][f.name]) }, ...m.slice(1)] };
    assert.notEqual(h(pc.typed("PqChatSession", s)), R.session.typed, `members[0].${f.name}`);
  }
  // a domain or purpose change: another uaMessage
  assert.notEqual(
    h(uaMessage(0x0131, keccak_256(utf8ToBytes("scaas.ua.purpose.pqchat.v2")), fromHex(R.leave.typed))),
    R.leave.uaMessage.digest,
  );
  assert.notEqual(h(uaMessage(0x0130, pc.PURPOSE_PQCHAT, fromHex(R.leave.typed))), R.leave.uaMessage.digest);
});

test("KEM keys and P14: valid keys encapsulate, each refusal throws its named error", () => {
  for (const k of KEYS.kemKeys) {
    const c = kemKey[k.name];
    assert.deepEqual([h(c.ek), h(c.pkX), h(c.kemPk), h(c.kemPkHash)], [k.ek, k.pkX, k.kemPk, k.kemPkHash], k.name);
    assert.equal(c.kemPk.length, 1601);
  }
  const { mlkemM, x25519Secret, rows } = KEYS.p14;
  assert.deepEqual(
    rows.filter((r) => r.error).map((r) => r.error),
    [
      "wrong scheme byte",
      "wrong scheme byte",
      "wrong length",
      "wrong length",
      "modulus check",
      "modulus check",
      "all-zero X25519",
      "all-zero X25519",
    ],
  );
  for (const r of rows) {
    if (!r.error) {
      assert.doesNotThrow(() => pc.checkKemPk(r.kemPk), r.name);
      assert.equal(pc.encaps(r.kemPk, mlkemM, x25519Secret).ss.length, 32, r.name);
    } else {
      assert.throws(
        () => pc.encaps(r.kemPk, mlkemM, x25519Secret),
        (e) => e instanceof pc.PqChatError && e.code === r.error,
        r.name,
      );
      if (r.error !== "all-zero X25519")
        assert.throws(
          () => pc.checkKemPk(r.kemPk),
          (e) => e.code === r.error,
          r.name,
        );
      else assert.doesNotThrow(() => pc.checkKemPk(r.kemPk), r.name);
    }
  }
  // the modulus rows are alice's key with one coefficient changed: positive control at q - 1 beside q
  const alice = fromHex(rows[0].kemPk);
  const diff = (r) => [...fromHex(r.kemPk)].flatMap((b, i) => (b !== alice[i] ? [i] : []));
  assert.ok(diff(rows[1]).every((i) => i <= 2) && diff(rows[6]).every((i) => i <= 2));
  assert.ok(diff(rows[7]).every((i) => i === 1535 || i === 1536));
});

test("wraps: the combiner, kek and sealedKey recomputed; each member reopens K", () => {
  // owner (M) 2026-11-23: epoch 2's three wraps (bob's device key among them), 5 -> 8
  assert.equal(KEYS.wraps.length, 8);
  for (const w of KEYS.wraps) {
    const k = kemKey[w.kemKey];
    const got = pc.wrapTo({
      K: w.K,
      sessionId: w.sessionId,
      epochId: w.epochId,
      member: w.member,
      keyId: w.keyId,
      kemPk: k.kemPk,
      m: w.mlkemM,
      x25519Secret: w.x25519Secret,
    });
    for (const f of ["ctM", "ssM", "E", "ssX", "ss", "kek", "sealedKey"])
      assert.equal(h(got[f]), w[f], `${w.name} ${f}`);
    assert.equal(h(pc.combine(fromHex(w.ssM), fromHex(w.ssX), fromHex(w.E), k.pkX)), w.ss, w.name);
    assert.deepEqual(w.wrap, {
      member: w.member,
      keyId: w.keyId,
      mlkemCt: w.ctM,
      x25519Eph: w.E,
      sealedKey: w.sealedKey,
    });
    assert.equal(fromHex(w.wrap.mlkemCt).length, 1568);
    assert.equal(fromHex(w.wrap.sealedKey).length, 48);
    assert.equal(h(pc.structHash("Wrap", w.wrap)), w.hashStruct, w.name);
    const open = (x) =>
      h(
        pc.openWrap({
          wrap: w.wrap,
          sessionId: w.sessionId,
          epochId: w.epochId,
          kemPk: k.kemPk,
          dk: k.dk,
          x25519Secret: k.x25519Secret,
          ...x,
        }),
      );
    assert.equal(open(), w.K, w.name);
    // negative controls, one change each: another member's secret, another epoch id
    const other = kemKey[KEYS.kemKeys.find((x) => x.name !== w.kemKey).name];
    assert.throws(() => open({ dk: other.dk, x25519Secret: other.x25519Secret }), w.name);
    assert.throws(() => open({ epochId: R.message.id }), w.name);
  }
});

test("sender chains, padding, the message ciphertext", () => {
  for (const c of M.chains) {
    const got = pc.chainKeys(c.K, c.sessionId, c.epochId, c.sender, c.device, c.steps.length);
    assert.equal(h(got.ck0), c.ck0, c.name);
    assert.deepEqual(
      got.steps.map((s) => ({ i: s.i, mk: h(s.mk), n: h(s.n), ck: h(s.ck) })),
      c.steps,
      c.name,
    );
  }
  for (const p of M.padding) {
    const content = Uint8Array.from({ length: p.length }, (_, i) => i % 251);
    const pt = pc.pad(content);
    assert.deepEqual(
      [pt.length, h(pt.subarray(0, 4)), h(keccak_256(pt))],
      [p.paddedLength, p.prefix, p.ptKeccak256],
      `${p.length}`,
    );
    assert.deepEqual(pc.unpad(pt), content);
    const longer = pt.slice();
    longer.set([0, 0, 0xff, 0xff]); // a length beyond the buffer
    const shorter = pt.slice(0, pt.length - 16);
    const bad = [longer, shorter];
    if (4 + p.length < pt.length) {
      const tail = pt.slice();
      tail[4 + p.length] = 1;
      bad.push(tail);
    } // a non-zero padding byte
    for (const b of bad)
      assert.throws(
        () => pc.unpad(b),
        (e) => e.code === "padding",
        `${p.length}`,
      );
  }
  const msg = R.message.record;
  assert.equal(M.message.ciphertext, msg.ciphertext);
  assert.equal(M.message.pt, h(pc.pad(utf8ToBytes(M.message.content))));
  assert.equal(M.message.content, pc.canonicalJson(JSON.parse(M.message.content)));
  assert.equal(M.message.aad, h(pc.messageAad(msg)));
  assert.equal(M.message.parentsHash, h(pc.parentsHash(msg.parents)));
  const step = M.chains[0].steps[msg.counter];
  assert.deepEqual([M.message.mk, M.message.n], [step.mk, step.n]);
  assert.equal(h(pc.encryptMessage(M.message.K, msg, M.message.pt)), msg.ciphertext);
  assert.equal(h(pc.decryptMessage(M.message.K, msg)), M.message.pt);
  assert.equal(new TextDecoder().decode(pc.unpad(pc.decryptMessage(M.message.K, msg))), M.message.content);
  const other = M.devices.find((d) => d.device !== msg.device).device;
  assert.throws(() => pc.decryptMessage(M.message.K, { ...msg, device: other })); // the device is in the chain and the aad
});

test("a peer counter is bounded: a safe integer, at most WALK_MAX steps stateless, MAX_SKIP on a chain, a receiver chain with skipped keys (review E C-4)", () => {
  const msg = R.message.record;
  const K = M.message.K;
  const at = (counter, pt = M.message.pt) => {
    const m = { ...msg, counter };
    return { ...m, ciphertext: pc.encryptMessage(K, m, pt) };
  };
  const isCounter = (e) => e.code === "counter";
  for (const c of ["5", 1.5, -1, 2 ** 53, 10n])
    assert.throws(() => pc.decryptMessage(K, { ...msg, counter: c }), isCounter, String(c));
  // the stateless path walks from ck_0 up to the walk bound of CLI-PQC-14 (2^20), past MAX_SKIP
  assert.equal(pc.WALK_MAX, 2 ** 20);
  assert.equal(h(pc.decryptMessage(K, at(pc.MAX_SKIP + 1))), M.message.pt, "stateless past MAX_SKIP");
  assert.equal(h(pc.decryptMessage(K, at(pc.WALK_MAX))), M.message.pt, "stateless at the walk bound");
  assert.throws(
    () => pc.decryptMessage(K, { ...msg, counter: pc.WALK_MAX + 1 }),
    isCounter,
    "stateless past the walk bound",
  );
  assert.throws(() => pc.decryptMessage(K, { ...msg, counter: 2 ** 40 }), isCounter, "no 2^40 walk");
  const chain = () => pc.receiverChain(K, msg.sessionId, msg.epochId, msg.sender, msg.device);
  const ch = chain();
  assert.equal(h(pc.decryptMessage(K, msg, ch)), M.message.pt, "the vector message through a chain");
  assert.throws(() => pc.decryptMessage(K, msg, ch), isCounter, "used");
  const n = msg.counter + 1;
  assert.equal(h(pc.decryptMessage(K, at(n + 3), ch)), M.message.pt);
  assert.deepEqual([ch.i, [...ch.skipped.keys()]], [n + 4, [...Array(msg.counter).keys(), n, n + 1, n + 2]]);
  assert.equal(h(pc.decryptMessage(K, at(n + 1), ch)), M.message.pt, "a skipped key");
  assert.throws(() => pc.decryptMessage(K, at(n + 1), ch), isCounter, "a skipped key is used once");
  const before = { i: ch.i, ck: h(ch.ck), size: ch.skipped.size };
  assert.throws(() => pc.decryptMessage(K, { ...at(n + 10), ciphertext: at(n + 9).ciphertext }, ch));
  assert.deepEqual(
    { i: ch.i, ck: h(ch.ck), size: ch.skipped.size },
    before,
    "a message that does not open changes nothing",
  );
  assert.throws(() => pc.decryptMessage(K, at(ch.i + pc.MAX_SKIP + 1), ch), isCounter, "past the skip bound");
  assert.equal(h(pc.decryptMessage(K, at(ch.i + pc.MAX_SKIP), ch)), M.message.pt, "at the skip bound");
  assert.equal(ch.skipped.size, pc.MAX_SKIP, "the oldest skipped keys are dropped");
  assert.throws(() => pc.decryptMessage(K, at(n), ch), isCounter, "a dropped key");
});

test("envelope, payload, Matrix event: they open to the signed message of records.json", () => {
  const e = M.envelope;
  const msg = R.message.record;
  assert.equal(h(pc.hint(e.K)), e.hint);
  assert.equal(h(pc.envKey(e.K, e.sessionId, e.epochId)), e.kEnv);
  const got = pc.envelope(e.K, msg, R.message.uaSig, e.nonce);
  assert.deepEqual([h(got.inner), h(got.env)], [e.inner, e.env]);
  assert.equal(e.env.slice(0, 26), e.nonce);
  const inner = pc.openEnvelope(e.K, e.sessionId, e.epochId, e.env);
  assert.equal(h(inner), h(pc.messageWithSig(msg, R.message.uaSig)));
  assert.ok(
    verifyUA(
      "mldsa65",
      fromHex(signer[R.message.signer].publicKey),
      pc.PURPOSE_PQCHAT,
      pc.messageId(msg),
      fromHex(R.message.uaSig.signature),
    ),
  );
  assert.throws(() => pc.openEnvelope(e.K, e.sessionId, R.session.id, e.env)); // another epoch's k_env
  // payload: abi.encode(uint8 1, bytes8 hint, bytes env)
  const p = fromHex(M.payload.payload);
  const w = (i) => p.subarray(32 * i, 32 * i + 32);
  assert.equal(h(pc.payload(e.hint, e.env)), M.payload.payload);
  assert.equal(h(w(0)), `0x${"0".repeat(62)}01`);
  assert.equal(h(w(1)), `${e.hint}${"0".repeat(48)}`);
  assert.equal(h(w(2)), `0x${"0".repeat(62)}60`);
  const n = Number(BigInt(h(w(3))));
  assert.equal(h(p.subarray(128, 128 + n)), e.env);
  assert.equal(p.length, 128 + Math.ceil(n / 32) * 32);
  assert.deepEqual([M.payload.v, M.payload.hint, M.payload.env], [1, e.hint, e.env]);
  const c = M.matrixEvent.content;
  assert.equal(M.matrixEvent.type, "net.scaas.pqchat.v1");
  assert.deepEqual([c.v, h(Buffer.from(c.hint, "base64")), h(Buffer.from(c.env, "base64"))], [1, e.hint, e.env]);
});

test("sealedInfo rows recompute and reopen to their store list", () => {
  assert.deepEqual(
    M.sealedInfo.map((s) => s.name),
    ["session", "epoch-1", "epoch-2"], // owner (M) 2026-11-23: epoch 2's row added
  );
  for (const s of M.sealedInfo) {
    const got = pc.sealInfo(s.K, s.sessionId, s.epochId, s.info, s.nonce);
    assert.deepEqual(
      [got.json, h(got.pt), h(got.kInfo), h(got.sealedInfo)],
      [s.json, s.pt, s.kInfo, s.sealedInfo],
      s.name,
    );
    assert.deepEqual(pc.openInfo(s.K, s.sessionId, s.epochId, s.sealedInfo), s.info, s.name);
    assert.ok(!/\s(?=(?:[^"]*"[^"]*")*[^"]*$)/.test(s.json), `${s.name}: no whitespace outside strings`);
    assert.equal(
      "matrix" in s.info,
      s.info.stores.some((x) => x.kind === "matrix"),
      s.name,
    );
  }
});

test("call keys: group and 1:1", () => {
  assert.deepEqual(
    M.callKeys.map((c) => [c.name, "callSecret" in c]),
    [
      ["group", true],
      ["1:1", false],
    ],
  );
  for (const c of M.callKeys) {
    const got = pc.callKeys(c, c.senders);
    assert.equal(h(got.callBase), c.callBase, c.name);
    assert.deepEqual(
      got.baseKeys.map(h),
      c.senders.map((s) => s.baseKey),
      c.name,
    );
  }
  assert.notEqual(M.callKeys[0].callBase, M.callKeys[1].callBase);
  assert.notEqual(h(pc.callKeys({ ...M.callKeys[0], callEpoch: 4 }, []).callBase), M.callKeys[0].callBase);
});

test("two devices of one UA: different message scopes and different chains", () => {
  for (const d of M.devices) assert.equal(d.device, h(keccak_256(utf8ToBytes(d.label)).slice(0, 16)), d.name);
  assert.ok(M.chains.every((c) => M.devices.some((d) => d.device === c.device)));
  const [a1, a2] = M.chains.filter((c) => c.sender === R.message.record.sender);
  assert.ok(a1 && a2 && a1.device !== a2.device && a1.epochId === a2.epochId);
  assert.notEqual(
    h(pc.scopeMessage(a1.epochId, a1.sender, a1.device)),
    h(pc.scopeMessage(a2.epochId, a2.sender, a2.device)),
  );
  assert.equal(R.message.scope, h(pc.scopeMessage(a1.epochId, a1.sender, a1.device)));
  assert.notEqual(a1.ck0, a2.ck0);
  for (let i = 0; i < a1.steps.length; i++) assert.notEqual(a1.steps[i].mk, a2.steps[i].mk);
});

test("a chain read far from ck_0: counter 5,000 in one walk (CLI-PQC-14)", () => {
  const f = M.chainFar;
  assert.equal(f.counter, 5000);
  const c = pc.chainKeys(f.K, f.sessionId, f.epochId, f.sender, f.device, f.counter + 1);
  assert.equal(h(c.ck0), f.ck0);
  const s = c.steps[f.counter];
  assert.deepEqual({ mk: h(s.mk), n: h(s.n), ck: h(s.ck) }, { mk: f.mk, n: f.n, ck: f.ck });
  assert.equal(f.ck0, M.chains[0].ck0, "the first chain's ck_0");
});

test("canonical JSON rows: UTF-16 key order, escapes, the safe-integer bound; refusals", () => {
  assert.ok(M.canonicalJson.length >= 3);
  for (const r of M.canonicalJson) assert.equal(pc.canonicalJson(JSON.parse(r.input)), r.canonical, r.name);
  const utf16 = M.canonicalJson.find((r) => r.name.startsWith("utf-16"));
  const keys = Object.keys(JSON.parse(utf16.canonical));
  const utf8 = [...keys].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  assert.notDeepEqual(keys, utf8, "the row's order differs between UTF-16 and UTF-8");
  for (const r of M.canonicalRefused)
    assert.throws(
      () => pc.canonicalJson(JSON.parse(r.input)),
      (e) => e.code === "canonical",
      r.name,
    );
});

test("canonical JSON: integer-like keys stay in UTF-16 order (review C-9, 2026-11-27; the Rust writers give the same)", () => {
  assert.equal(pc.canonicalJson({ 2: 2, 10: 1, " ": 3, a: 4 }), '{" ":3,"10":1,"2":2,"a":4}');
  assert.equal(pc.canonicalJson({ b: [{ 1: 1, 0: 0 }], a: undefined }), '{"b":[{"0":0,"1":1}]}');
});

test("unpad refusal rows: each refused, its positive twin opens", () => {
  assert.deepEqual(
    M.unpadRefused.map((r) => r.name),
    ["non-zero fill", "wrong bucket", "length past the end"],
  );
  for (const r of M.unpadRefused) {
    assert.throws(
      () => pc.unpad(r.pt),
      (e) => e.code === "padding",
      r.name,
    );
    assert.equal(h(pc.unpad(r.twin)), r.content, `${r.name}: the twin`);
  }
});

test("contact cards (UA-7 §14 O7): digests, signatures; refused cards fail their own check; Matrix id refusals with twins", () => {
  assert.deepEqual(Object.keys(C.typehashes), pc.CARD_STRUCTS);
  assert.equal(C.typehashes.PqChatCard.hash, h(keccak_256(utf8ToBytes(SPEC.PqChatCard))));
  assert.equal(C.domain.separator, R.domain.separator);
  assert.deepEqual(C.purpose, R.purpose);
  assert.deepEqual(
    C.cards.map((c) => [c.name, c.record.matrixId === ""]),
    [
      ["alice", false],
      ["bob, no Matrix id", true],
    ],
  );
  for (const c of C.cards) {
    assert.deepEqual(pc.contactCard(c.record), c.record, c.name);
    assert.equal(c.record.ua, signer[c.signer].ua, c.name);
    assert.equal(h(pc.structHash("PqChatCard", c.record)), c.hashStruct, c.name);
    assert.equal(h(pc.typed("PqChatCard", c.record)), c.typed, c.name);
    assert.deepEqual(c.uaMessage, { kind: 0x0131, digest: h(pc.signedDigest(0x0131, "PqChatCard", c.record)) }, c.name);
    assert.deepEqual([c.uaSig.keyData, c.uaSig.members], ["0x", []], c.name);
    assert.ok(pc.verifyCard(c.record.ua, c.record, c.uaSig, signer[c.signer].publicKey), c.name);
  }
  // each refused card: its own check fails, and its twin (one change back) passes
  assert.deepEqual(
    C.refused.map((r) => [r.name, r.error]),
    [
      ["signed by another UA's key", "signature"],
      ["another UA's card", "ua"],
      ["Matrix id changed after signing", "signature"],
    ],
  );
  for (const r of C.refused) {
    const key = signer[r.key].publicKey;
    assert.equal(pc.verifyCard(r.ua, r.record, r.uaSig, key), false, r.name);
    assert.ok(pc.verifyCard(r.twin.ua, r.twin.record, r.twin.uaSig, signer[r.twin.key].publicKey), `${r.name}: twin`);
  }
  for (const id of C.matrixIdAccepted) assert.equal(pc.checkMatrixId(id), id, id);
  assert.ok(C.matrixIdAccepted.some((id) => utf8ToBytes(id).length === 255));
  for (const r of C.matrixIdRefused) {
    assert.throws(
      () => pc.checkMatrixId(r.id),
      (e) => e.code === "matrix id",
      r.name,
    );
    assert.equal(pc.checkMatrixId(r.twin), r.twin, `${r.name}: the twin`);
  }
});

// The `file` content (UA-7 §6.4.1 with its 2026-11-21 Change; pqchat-core T10b, owner 2026-11-22): PqChat's app id, the
// sealed object of the row (ar://, the padding inside the AEAD), the content the sealer is given and the one it seals (the
// key entered by the sealer), the message carrying it, and the reader's checks before decryption.
test("file content: the app id, the row reseals and opens after the length and ctSha256 checks; refusals beside their twins", async () => {
  const ar = await import("../src/arweave.js");
  const F = M.fileMessage;
  assert.equal(R.appId.tag, "scaas.pqchat.v1");
  assert.equal(h(pc.APP_ID), h(keccak_256(utf8ToBytes(R.appId.tag))));
  assert.equal(R.appId.hash, h(pc.APP_ID));
  const file = fromHex(F.file);
  const s = ar.sealForArweave(fromHex(F.appRoot), fromHex(F.fileKey), file, F.signatureType);
  assert.equal(s.url, F.url);
  assert.equal(h(s.ctSha256), F.ctSha256);
  assert.equal(h(s.sha256), F.sha256);
  assert.equal(s.object.length, F.objectLength);
  assert.equal(s.object.length, ar.bucket(F.size) + 16, "padded to its bucket inside the AEAD");
  // the sealer is given every field but the key; it enters the key, and the result is the row's content
  assert.equal(JSON.parse(F.sealed).key, undefined);
  const content = pc.sealFileContent(JSON.parse(F.sealed), fromHex(F.fileKey));
  assert.equal(content, F.content);
  assert.equal(JSON.parse(content).key, F.fileKey);
  // the message carrying it
  const K = fromHex(F.K);
  const { ciphertext, ...header } = F.record;
  assert.equal(h(pc.encryptMessage(K, header, pc.pad(utf8ToBytes(content)))), ciphertext);
  assert.equal(h(pc.messageId(F.record)), F.id);
  assert.equal(new TextDecoder().decode(pc.unpad(pc.decryptMessage(K, F.record))), F.content);
  const env = pc.envelope(K, F.record, F.uaSig, fromHex(F.envNonce));
  assert.equal(h(env.env), F.env);
  // the reader: the content checked, then the object's length and ctSha256 before decryption, then the frame and sha256
  assert.equal(h(pc.openFileContent(F.content, s.object)), F.file);
  for (const r of M.fileOpenRefused) {
    let o = s.object;
    if (r.change === "drop-last") o = o.slice(0, -1);
    if (r.change === "append-zero") o = concatBytes(o, Uint8Array.of(0));
    if (r.change === "flip-1000") (o = o.slice()), (o[1000] ^= 1);
    const c = canonical(r.content ?? JSON.parse(F.content));
    if (r.code) assert.throws(() => pc.openFileContent(c, o), { code: r.code }, r.name);
    else assert.equal(h(pc.openFileContent(c, o)), F.file, r.name);
  }
  // a refused object is refused before any decryption: a wrong key in the content changes nothing of it
  const wrongKey = { ...JSON.parse(F.content), key: Z32 };
  assert.throws(() => pc.openFileContent(canonical(wrongKey), s.object.slice(0, -1)), { code: "FileLength" });
  assert.throws(() => pc.openFileContent(canonical(wrongKey), s.object), { code: "Aead" });
  for (const r of M.fileContentRefused) {
    assert.throws(() => pc.checkFileContent(r.content), { code: "file" }, r.name);
    assert.throws(() => pc.openFileContent(canonical(r.content), s.object), { code: "file" }, r.name);
    assert.doesNotThrow(() => pc.checkFileContent(r.twin), r.name);
  }
  for (const r of M.fileSealRefused) {
    assert.throws(() => pc.sealFileContent(r.content, fromHex(F.fileKey)), { code: "file" }, r.name);
    assert.doesNotThrow(() => pc.sealFileContent(r.twin, fromHex(F.fileKey)), r.name);
  }
});
const canonical = (v) => pc.canonicalJson(v);

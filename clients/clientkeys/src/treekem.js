// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// UNAUDITED. TreeKEM secrets, T1b of docs/superpowers/plans/2026-11-23-pqchat-treekem.md; spec
// docs/superpowers/specs/2026-11-23-pqchat-treekem.md §5 (path secrets, ps[0], the path ciphertext, the schedule without the
// init chain, K, the tree wrap, the info and the marker) and §10 (replay, not followed, the compromise warning). The tree is
// app-agnostic (owner 2026-11-23): every label and the app's derivation above K are a scope's (`treeScope`); PqChat's is
// one instance (`PQCHAT_TREE`). The records are the tree's of src/pqchat-tree.js. The bytes of
// smartcontracts/vectors/pqchat/tree-secrets.json; clients/ua-rs is held to them (T2).
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { gcm, gcmsiv } from "@noble/ciphers/aes.js";
import { keccak_256, concatBytes, utf8ToBytes, fromHex, abiEncode, hex as hexOf } from "./bytes.js";
import { kemEncapsVector, kemKeyFromSeed } from "./kem.js";
import * as pc from "./pqchat.js";
import * as tr from "./pqchat-tree.js";
import * as uv from "./ua-verify.js";
import { deriveUA } from "./ua.js";

const b = (v) => (v instanceof Uint8Array ? v : fromHex(v));
const hex = (v) => (typeof v === "string" ? v.toLowerCase() : hexOf(v));
const ZERO = hex(new Uint8Array(32));
const NONCE0 = new Uint8Array(12);
const u32 = (v) => {
  const o = new Uint8Array(4);
  new DataView(o.buffer).setUint32(0, v);
  return o;
};
const refuse = (code) => {
  throw new pc.PqChatError(code);
};
/** `H(ikm, info) = HKDF-SHA-256(ikm, salt = empty, info, n)`, as pqchat.js. */
const H = (ikm, info, n = 32) => hkdf(sha256, b(ikm), new Uint8Array(0), info, n);

// ------------------------------------------------------------------ the scope (labels and the app's step above K)

/** A tree's labels under `prefix`; the app's info key `infoKey(K, sessionId, epochId)`, and how its records are signed:
 *  `typed(struct, record)` and the UA purpose. */
export function treeScope(prefix, { infoKey, typed, purpose }) {
  const l = (s) => utf8ToBytes(`${prefix}/${s}`);
  return Object.freeze({
    prefix,
    path: l("path"),
    node: l("node"),
    commit: l("commit"),
    ct: l("ct"),
    joiner: l("joiner"),
    epoch: l("epoch"),
    key: l("key"),
    // the path-less delta §4.1 (R20, C43, C47)
    next: l("next"),
    addJoiner: l("add-joiner"),
    confirm: l("confirm"),
    addNonce: l("add-nonce"),
    wrap: `${prefix}/wrap`,
    tagPath: keccak_256(l("path-context")),
    tagContext: keccak_256(l("context")),
    infoKey,
    typed,
    purpose,
  });
}
/** PqChat's instance: `scaas/pqchat/v1/tree/…`, mode 0's `infoKey` above K (spec §5), its records signed as every PqChat
 *  record (`typed` under DS_C, PURPOSE_PQCHAT; CTR-CHAT-03). */
export const PQCHAT_TREE = treeScope("scaas/pqchat/v1/tree", {
  infoKey: pc.infoKey,
  typed: (name, s) => (tr.TREE_TYPES[name] ? tr.treeTyped(name, s) : pc.typed(name, s)),
  purpose: pc.PURPOSE_PQCHAT,
});

// ------------------------------------------------------------------ path secrets and node keys (RFC 9420 §7.4)

/** `ps[0..m]`: `ps[k+1] = H(ps[k], …/path)`; `ps[m]` is the commit secret. */
export function pathSecrets(sc, ps0, m) {
  const ps = [b(ps0)];
  for (let k = 0; k < m; k++) ps.push(H(ps[k], sc.path));
  return ps;
}
/** The node key of a path secret: `kemPk` of `HKDF(ps, …/node, 96 B)`, the 96-byte seed form of kem.js. */
export const nodeKeyOf = (sc, ps) => kemKeyFromSeed(H(ps, sc.node, 96));

/** `pathContext = keccak256(abi.encode(TAG_TREE_PATH, treeId, parentEpochId, parentTreeHash, author, nonce, leaf, keyId,
 *  hash(removes), hash(adds), keccak256(abi.encodePacked(ctTargets))))` (spec §5, R4, C17). */
export const pathContext = (sc, c, ctTargets) =>
  keccak_256(
    abiEncode(
      [
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32",
        "uint64",
        "uint32",
        "uint64",
        "bytes32",
        "bytes32",
        "bytes32",
      ],
      [
        sc.tagPath,
        c.treeId,
        c.parentEpochId,
        c.parentTreeHash,
        c.author,
        c.nonce,
        c.leaf,
        c.keyId,
        tr.arrayHash("TreeRemove", c.removes),
        tr.arrayHash("TreeAdd", c.adds),
        tr.ctTargetsHash(ctTargets),
      ],
    ),
  );
/** `ps[0] = HKDF(kemSeed(ua, keyId), …/commit ‖ pathContext, 32)`. */
export const firstPathSecret = (sc, kemSeed, ctx) => H(kemSeed, concatBytes(sc.commit, b(ctx)));

// ------------------------------------------------------------------ the path ciphertext

const ctKek = (sc, ss, c) =>
  H(ss, concatBytes(sc.ct, b(c.treeId), b(c.epochId), u32(c.node), u32(c.target), keccak_256(b(c.kemPk))));
const ctAad = (c) => concatBytes(b(c.treeId), b(c.epochId), u32(c.node), u32(c.target));
/** Seals `ps[k]` (`secret`) of path node `node` to `target` with key `kemPk`; `m`, `e` the encapsulation's randomness. Returns
 *  `{ ss, kek, ct: PathCt }`. */
export function sealPathSecret(sc, c) {
  const enc = kemEncapsVector(b(c.kemPk), b(c.m), b(c.e));
  const kek = ctKek(sc, enc.ss, c);
  const sealedSecret = gcm(kek, NONCE0, ctAad(c)).encrypt(b(c.secret));
  return {
    ss: enc.ss,
    kek,
    ct: { mlkemCt: hex(enc.mlkemCt), x25519Eph: hex(enc.x25519Eph), sealedSecret: hex(sealedSecret) },
  };
}
/** Opens a `PathCt` with the target's key (`key.decaps`); a failure is "opening failed". */
export function openPathSecret(sc, c, key) {
  try {
    const ss = key.decaps(b(c.ct.mlkemCt), b(c.ct.x25519Eph));
    return gcm(ctKek(sc, ss, c), NONCE0, ctAad(c)).decrypt(b(c.ct.sealedSecret));
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ the epoch schedule without init (RFC 9420 §8 reduced; C23)

/** `ctx_e = keccak256(abi.encode(TAG_TREE_CONTEXT, treeId, epochId, epoch, parentEpochId, parentTreeHash, treeHash,
 *  keccak256(abi.encodePacked(admins))))`; epoch 0: `genesisCtx` for `treeId`, `epochId = sessionId`, the rest 0. */
export const epochContext = (sc, x) =>
  keccak_256(
    abiEncode(
      ["bytes32", "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        sc.tagContext,
        x.treeId,
        x.epochId,
        x.epoch,
        x.parentEpochId,
        x.parentTreeHash,
        x.treeHash,
        keccak_256(concatBytes(...x.admins.map(b))),
      ],
    ),
  );
export const joinerSecret = (sc, commitSecret, treeId, epochId) =>
  H(commitSecret, concatBytes(sc.joiner, b(treeId), b(epochId)));
/** A path-less Add's joiner (the delta §4.1, R20): `H(next_e, …/add-joiner ‖ treeId ‖ epochId ‖ hash(adds))`. */
export const addJoinerSecret = (sc, next, treeId, epochId, addsHash) =>
  H(next, concatBytes(sc.addJoiner, b(treeId), b(epochId), b(addsHash)));
/** `S_e = H(joiner, …/epoch ‖ ctx_e)`, `K_e = H(S_e, …/key)`, `next_e = H(S_e, …/next)` and the confirmation
 *  `confirmTag = H(S_e, …/confirm ‖ ctx_e)`, at epoch 0 over `genesisCtx` (the delta §4.1, C43): four branches of one `S`. */
export function schedule(sc, joiner, fields) {
  const ctx = epochContext(sc, fields);
  const S = H(joiner, concatBytes(sc.epoch, ctx));
  const tagCtx = fields.epoch === 0 ? b(fields.treeId) : ctx;
  return {
    ctx,
    joiner: b(joiner),
    S,
    K: H(S, sc.key),
    next: H(S, sc.next),
    tag: H(S, concatBytes(sc.confirm, tagCtx)),
  };
}
/** The most tries of a path-less Add's nonce (C47). */
export const ADD_NONCE_TRIES = 8;
/** A path-less Add's nonce (C47): the first 8 B, big-endian, of `H(kemSeed, …/add-nonce ‖ treeId ‖ parentEpochId ‖
 *  parentTreeHash ‖ hash(adds) ‖ u32be(try))`, a BigInt (a uint64). */
export function addNonce(sc, kemSeed, { treeId, parentEpochId, parentTreeHash, addsHash }, tryN) {
  if (!(Number.isInteger(tryN) && tryN >= 0 && tryN < ADD_NONCE_TRIES)) refuse("TreeAddNonce");
  const h = H(
    kemSeed,
    concatBytes(sc.addNonce, b(treeId), b(parentEpochId), b(parentTreeHash), b(addsHash), u32(tryN)),
  );
  return h.subarray(0, 8).reduce((a, x) => (a << 8n) | BigInt(x), 0n);
}
/** The `try` < ADD_NONCE_TRIES whose `addNonce` is the record's `nonce`, or -1 (the own-commit test, C47, the delta §6.5). */
export function addNonceTry(sc, kemSeed, c) {
  const x = {
    treeId: c.treeId,
    parentEpochId: c.parentEpochId,
    parentTreeHash: c.parentTreeHash,
    addsHash: tr.arrayHash("TreeAdd", c.adds),
  };
  for (let t = 0; t < ADD_NONCE_TRIES; t++) if (addNonce(sc, kemSeed, x, t) === BigInt(c.nonce)) return t;
  return -1;
}
/** The context fields of epoch 0 (C29) and of a commit. */
export const genesisFields = (session) => ({
  treeId: tr.genesisCtx(session),
  epochId: pc.sessionId(session.creator, session.nonce),
  epoch: 0,
  parentEpochId: ZERO,
  parentTreeHash: ZERO,
  treeHash: ZERO,
  admins: session.admins,
});
export const commitFields = (c) => ({
  treeId: c.treeId,
  epochId: pc.epochId(c.sessionId, c.author, c.nonce),
  epoch: c.epoch,
  parentEpochId: c.parentEpochId,
  parentTreeHash: c.parentTreeHash,
  treeHash: c.treeHash,
  admins: c.admins,
});

// ------------------------------------------------------------------ the info and the marker (C33)

/** `sealedInfo` at most 12 + 4,096 + 16 B, at creation too (codex-r2-13). */
export const TREE_INFO_MAX = 4124;
/** Mode 0's form under the scope's `infoKey`: a full info (canonical JSON, never empty) or, for `info === null`, the marker
 *  "unchanged" (empty content, 284 B). */
export function sealTreeInfo(sc, K, sessionId, epochId, info, nonce) {
  const pt = pc.pad(info === null ? new Uint8Array(0) : utf8ToBytes(pc.canonicalJson(info)));
  if (12 + pt.length + 16 > TREE_INFO_MAX) refuse("TreeInfoSize");
  const n = b(nonce);
  return hex(concatBytes(n, gcmsiv(sc.infoKey(K, sessionId, epochId), n).encrypt(pt)));
}
/** `{ marker: true }` or `{ json }`; null when it does not open, is not a padded plaintext, or holds anything but canonical
 *  JSON (what `sealTreeInfo` writes, so the info in force is re-sealed byte for byte; C-8). */
export function openTreeInfo(sc, K, sessionId, epochId, sealed) {
  const s = b(sealed);
  if (s.length > TREE_INFO_MAX) return null;
  try {
    const c = pc.unpad(gcmsiv(sc.infoKey(K, sessionId, epochId), s.subarray(0, 12)).decrypt(s.subarray(12)));
    if (c.length === 0) return { marker: true };
    const json = new TextDecoder("utf-8", { fatal: true }).decode(c);
    return pc.canonicalJson(JSON.parse(json)) === json ? { json } : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ the tree wrap (fable-13)

/** Mode 0's wrap with the tree label; `ctxId` stands where mode 0 has `sessionId`: `genesisCtx` for epoch 0, `treeId` for a
 *  Welcome; `epochId` is the epoch's (the sessionId at 0). Seals the joiner secret. */
export function sealTreeWrap(sc, { joiner, ctxId, epochId, member, keyId, kemPk, m, e }) {
  const enc = kemEncapsVector(b(kemPk), b(m), b(e));
  const kek = pc.wrapKek(enc.ss, ctxId, epochId, member, keyId, kemPk, sc.wrap);
  const sealedKey = gcm(kek, NONCE0, pc.wrapAad(ctxId, epochId, member, keyId)).encrypt(b(joiner));
  const wrap = { member, keyId, mlkemCt: hex(enc.mlkemCt), x25519Eph: hex(enc.x25519Eph), sealedKey: hex(sealedKey) };
  return { ss: enc.ss, kek, wrap, hash: hex(pc.structHash("Wrap", wrap)) };
}
export function openTreeWrap(sc, { wrap, ctxId, epochId, kemPk }, key) {
  try {
    const ss = key.decaps(b(wrap.mlkemCt), b(wrap.x25519Eph));
    const kek = pc.wrapKek(ss, ctxId, epochId, wrap.member, wrap.keyId, kemPk, sc.wrap);
    return gcm(kek, NONCE0, pc.wrapAad(ctxId, epochId, wrap.member, wrap.keyId)).decrypt(b(wrap.sealedKey));
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ creation in order (C29, codex-r2-4)

/** `session` without `wrapHashes` and `sealedInfo`; `kems[i]` the registry record `{ kemPk, sig }` of `members[i]`'s key,
 *  authenticated before it is used (`recordKey`, C-1; `uaRecordOf`, `accepted` the signers' registry records); `rand(name, n)`
 *  the randomness. In order: genesisCtx → joiner_0, K_0 → the wraps and sealedInfo → the record → treeId (the signature is the
 *  caller's). */
export function createGenesis(sc, { session, kems, uaRecordOf, accepted, info, rand }) {
  const kemPks = session.members.map((m, i) => recordKey(m.ua, m.keyId, kems[i], uaRecordOf, accepted));
  const fields = genesisFields(session);
  const joiner0 = rand("joiner-0", 32);
  const sch = schedule(sc, joiner0, fields);
  const wraps = session.members.map((mem, i) =>
    sealTreeWrap(sc, {
      joiner: joiner0,
      ctxId: fields.treeId,
      epochId: fields.epochId,
      member: mem.ua,
      keyId: mem.keyId,
      kemPk: kemPks[i],
      m: rand(`wrap/${i}/mlkem-m`, 32),
      e: rand(`wrap/${i}/x25519-ephemeral`, 32),
    }),
  );
  const sealedInfo = sealTreeInfo(sc, sch.K, fields.epochId, fields.epochId, info, rand("sealed-info-nonce", 12));
  // the record in the type's field order, epoch 0's tag last (C43)
  const record = Object.fromEntries(
    pc.TYPES.PqChatSession.map((f) => [
      f.name,
      { ...session, wrapHashes: wraps.map((w) => w.hash), sealedInfo, confirmTag: hex(sch.tag) }[f.name],
    ]),
  );
  return {
    record,
    sessionId: hex(fields.epochId),
    genesisCtx: hex(fields.treeId),
    treeId: hex(tr.treeId(record)),
    wraps,
    ...sch,
  };
}

// ------------------------------------------------------------------ building a commit

/** The filtered path of a commit from its list alone: the distinct common ancestors of the author's leaf and each target, in
 *  list order (targets are disjoint subtrees, ordered by level upward). Null when a target is not under the author's direct
 *  path. */
export function pathFromList(authorLeaf, ctTargets, leaves) {
  const up = tr.directPath(2 * authorLeaf, leaves);
  const p = [];
  for (const t of ctTargets) {
    const below = new Set([t, ...tr.directPath(t, leaves)]);
    const node = up.find((x) => below.has(x));
    if (node === undefined || t === 2 * authorLeaf) return null;
    if (p.at(-1) !== node) p.push(node);
  }
  return new Set(p).size === p.length ? p : null;
}

/** Builds a commit on `tree` (the parent tree, src/pqchat-tree.js form) at `parent` (`{ epochId, epoch, treeHash }`).
 *  `adds[i]` is a `TreeAdd` with its `kemPk` and `sig` (its registry record, authenticated by `uaRecordOf` and `accepted`,
 *  C-1); `keyOf(node)` the key of a target the parent tree holds (a leaf's registry key
 *  or a node key); `info` a full info or null (the marker); `rand(name, n)` the randomness. `pathless` (the delta §4.1, §6.5):
 *  a path-less Add on the head handle `head` (`{ epochId, treeHash, next }` of the replay, `TreeHandle` unless it is
 *  `parent`'s), its nonce `addNonce` at `try` (default 0) unless `nonce` is given. `faults` is for refusal rows
 *  only (a commit whose author signs what it built wrong: `nodeKeys`, `ct[j]` a `sealedSecret`, `eph[j]` a small-order
 *  `x25519Eph` of ciphertext j, `welcomeJoiner`, `welcomeEph[i]` the same in Welcome i, `infoK`, `tag` a confirmTag);
 *  a foreign `kemSeed` is a commit that seed did not build. Returns the record (unsigned), its pieces, the tree after
 *  it and the secrets. */
export function buildCommit(sc, a, faults = {}) {
  const adds = a.adds ?? [];
  const removes = a.removes ?? [];
  const pathless = a.pathless === true;
  const addRecs = adds.map(({ kemPk, sig, ...x }) => x);
  // C-1: each added key authenticated by its registry record, and the Add's kemHash its hash, before it is used
  for (const x of adds) {
    const k = recordKey(x.ua, x.keyId, x, a.uaRecordOf, a.accepted);
    if (kemHashOf(k) !== hex(x.kemHash)) refuse("TreeKeyHash");
  }
  const addsHash = tr.arrayHash("TreeAdd", addRecs);
  if (pathless) {
    // claude-19: the head handle is the record's parent, else nothing is built
    const hd = a.head;
    if (!hd?.next || hex(hd.epochId) !== hex(a.parent.epochId) || hex(hd.treeHash) !== hex(a.parent.treeHash))
      refuse("TreeHandle");
  }
  const nonce =
    a.nonce ??
    (pathless
      ? addNonce(
          sc,
          a.kemSeed,
          { treeId: a.treeId, parentEpochId: a.parent.epochId, parentTreeHash: a.parent.treeHash, addsHash },
          a.try ?? 0,
        )
      : refuse("TreeNonce"));
  const p = pathless ? [] : tr.filteredPathAfter(a.tree, a.leaf, { removes, adds: addRecs });
  const ctTargets = p.flatMap((q) => q.targets);
  const head = {
    sessionId: a.sessionId,
    author: a.author,
    nonce,
    epoch: a.parent.epoch + 1,
    parentEpochId: a.parent.epochId,
    treeId: a.treeId,
    parentTreeHash: a.parent.treeHash,
    leaf: a.leaf,
    keyId: a.keyId,
  };
  const ctx = pathless ? null : pathContext(sc, { ...head, removes, adds: addRecs }, ctTargets);
  const ps = pathless ? [] : pathSecrets(sc, firstPathSecret(sc, a.kemSeed, ctx), p.length);
  const nodeKeys = faults.nodeKeys ?? ps.slice(0, p.length).map((s) => hex(nodeKeyOf(sc, s).kemPk));
  const nodeKeyHashes = nodeKeys.map((k) => hex(keccak_256(b(k))));
  const epochId = hex(pc.epochId(a.sessionId, a.author, nonce));
  const added = new Map(addRecs.map((x, i) => [2 * x.leaf, adds[i].kemPk]));
  const cts = [];
  p.forEach((q, k) =>
    q.targets.forEach((t) => {
      const j = cts.length;
      const kemPk = added.get(t) ?? a.keyOf(t);
      const s = sealPathSecret(sc, {
        treeId: a.treeId,
        epochId,
        node: q.node,
        target: t,
        kemPk,
        secret: ps[k],
        m: a.rand(`ct/${j}/mlkem-m`, 32),
        e: a.rand(`ct/${j}/x25519-ephemeral`, 32),
      });
      if (faults.ct?.[j]) s.ct = { ...s.ct, sealedSecret: faults.ct[j] };
      if (faults.eph?.[j]) s.ct = { ...s.ct, x25519Eph: ZERO };
      cts.push({ node: q.node, target: t, level: k, kemPk: hex(kemPk), ...s });
    }),
  );
  const ctHashes = cts.map((c) => hex(tr.treeStructHash("PathCt", c.ct)));
  const applied = tr.applyCommit(a.tree, { ...head, pathless, removes, adds: addRecs, nodeKeyHashes });
  const rec = {
    ...head,
    leaves: applied.tree.leaves,
    admins: a.admins,
    removes,
    adds: addRecs,
    nodeKeyHashes,
    ctCount: ctTargets.length,
    ctListHash: hex(tr.pathListHash(ctTargets, ctHashes)),
    treeHash: applied.treeHash,
  };
  const commitSecret = pathless ? null : ps[p.length];
  const joiner = pathless
    ? addJoinerSecret(sc, a.head.next, a.treeId, epochId, addsHash)
    : joinerSecret(sc, commitSecret, a.treeId, epochId);
  const sch = schedule(sc, joiner, commitFields(rec));
  const wraps = adds.map((x, i) => {
    const w = sealTreeWrap(sc, {
      joiner: faults.welcomeJoiner ?? sch.joiner,
      ctxId: a.treeId,
      epochId,
      member: x.ua,
      keyId: x.keyId,
      kemPk: x.kemPk,
      m: a.rand(`welcome/${i}/mlkem-m`, 32),
      e: a.rand(`welcome/${i}/x25519-ephemeral`, 32),
    });
    if (!faults.welcomeEph?.[i]) return w;
    const wrap = { ...w.wrap, x25519Eph: ZERO };
    return { ...w, wrap, hash: hex(pc.structHash("Wrap", wrap)) };
  });
  const sealedInfo = sealTreeInfo(
    sc,
    faults.infoK ?? sch.K,
    a.sessionId,
    epochId,
    a.info,
    a.rand("sealed-info-nonce", 12),
  );
  const confirmTag = hex(faults.tag ?? sch.tag);
  // the record in the type's field order
  const record = Object.fromEntries(
    tr.TREE_TYPES.PqChatCommit.map((f) => [
      f.name,
      { ...rec, wrapHashes: wraps.map((w) => w.hash), sealedInfo, pathless, confirmTag }[f.name],
    ]),
  );
  return {
    record,
    epochId,
    pathContext: ctx === null ? null : hex(ctx),
    ps: ps.map(hex),
    ctTargets,
    ctHashes,
    nodeKeys,
    cts,
    wraps,
    tree: applied.tree,
    ...sch,
  };
}

// ------------------------------------------------------------------ the home's state, as the contract keeps it (a model)

const kemHashOf = (kemPk) => hex(keccak_256(b(kemPk)));
const clone = (v) => structuredClone(v);
/** An exit's record as the contract's `leaveAt` / `removalAt` serve it: without `treeId` (the session's, `treeOf`). */
const keptExit = ({ treeId, ...r }) => r;

/** A model of one home's state for a tree session (spec §6, §7): the records with their signatures, the pieces, the exits kept
 *  under each epoch, the leaves' `joinEpoch` and wrap index, the node keys, `gone` and the key periods. `kems`: `"<ua>/<keyId>"`
 *  → `{ kemPk, sig }` (the registry's `kemKeyAt`), `uaRecords`: ua → its registry record `{ kind, keyData }`, an updated
 *  `msig`'s with `versions` (its `msigAt` answers, CTR-UA-74; an `msig`'s members by their own). The
 *  contract's checks are pqchat-tree.js's `applyCommit` and the pieces' hashes; the model lands what it is given, as an
 *  endpoint that lies would serve it. */
export function newHome({ genesis, sig, kems, uaRecords }) {
  const s = genesis.record;
  const tree = tr.coldTree(
    s.members.map((m) => ({ ...m, kemHash: kemHashOf(kems.get(`${m.ua}/${m.keyId}`).kemPk) })),
    s.pathRefreshBound,
  );
  return {
    sessionId: genesis.sessionId,
    treeId: genesis.treeId,
    tree,
    genesisTreeHash: tr.treeHash(tree),
    epochs: [
      { id: genesis.sessionId, record: s, sig, wraps: genesis.wraps.map((w) => w.wrap), leaves: [], removals: [] },
    ],
    join: new Map(s.members.map((_, i) => [i, { joinEpoch: 0, wrapIndex: i }])),
    nodeKey: new Map(),
    gone: new Map(),
    owed: 0,
    periods: new Map(),
    kems,
    uaRecords,
  };
}
const headHash = (h) => h.tree.hash[tr.root(h.tree.leaves)];
/** Lands a built commit with its signature: the contract's acceptance and completion in one step. */
export function landCommit(h, built, sig) {
  const c = built.record;
  const n = h.epochs.length;
  if (c.epoch !== n || c.parentEpochId !== h.epochs[n - 1].id || c.treeId !== h.treeId) refuse("PqChatEpochTaken");
  if (c.parentTreeHash !== headHash(h)) refuse("PqChatTreeParent");
  const applied = tr.applyCommit(h.tree, c);
  if (applied.treeHash !== c.treeHash) refuse("PqChatTreeHash");
  if (JSON.stringify(applied.ctTargets) !== JSON.stringify(built.ctTargets)) refuse("PqChatTreeTargets");
  if (hex(tr.pathListHash(built.ctTargets, built.ctHashes)) !== c.ctListHash) refuse("PqChatPathList");
  built.cts.forEach((x, j) => hex(tr.treeStructHash("PathCt", x.ct)) === built.ctHashes[j] || refuse("PqChatPathCt"));
  built.nodeKeys.forEach((k, i) => kemHashOf(k) === c.nodeKeyHashes[i] || refuse("PqChatPathKey"));
  built.wraps.forEach((w, i) => w.hash === c.wrapHashes[i] || refuse("PqChatWrap"));
  for (const r of c.removes) {
    const k = h.tree.nodes[2 * r.leaf];
    const wide = applied.tree.goneKey.has(k.kemHash) && !h.tree.goneKey.has(k.kemHash);
    const period = { joinEpoch: h.join.get(r.leaf).joinEpoch, endEpoch: c.epoch };
    h.periods.set(wide ? `wide/${k.kemHash}` : `pair/${k.ua}/${k.kemHash}`, period);
    h.join.delete(r.leaf);
  }
  c.adds.forEach((a, i) => h.join.set(a.leaf, { joinEpoch: c.epoch, wrapIndex: i }));
  for (const x of h.nodeKey.keys()) if (!applied.tree.nodes[x]) h.nodeKey.delete(x);
  (pathFromList(c.leaf, built.ctTargets, c.leaves) ?? []).forEach((x, k) =>
    h.nodeKey.set(x, { kemPk: built.nodeKeys[k], epoch: c.epoch }),
  );
  for (const ua of applied.tree.goneUa) if (!h.gone.has(ua)) h.gone.set(ua, { kind: 2, epoch: c.epoch });
  h.tree = applied.tree;
  h.owed = 0;
  h.epochs.push({
    id: built.epochId,
    record: c,
    sig,
    ctTargets: built.ctTargets,
    ctHashes: built.ctHashes,
    nodeKeys: built.nodeKeys,
    cts: built.cts.map((x) => x.ct),
    wraps: built.wraps.map((w) => w.wrap),
    leaves: [],
    removals: [],
  });
  return h;
}
/** A landed `treeLeave` (kind 1) or `treeRemove` (kind 2): kept under the head, its UAs `gone` at the head's number (C9, C28). */
export function landGone(h, kind, struct, record, sig) {
  const uas = kind === 1 ? [record.member] : record.members;
  const head = h.epochs.at(-1);
  (kind === 1 ? head.leaves : head.removals).push({ record: keptExit(record), sig });
  // the contract's `owed`: the live leaves of each UA not gone before, owed by the next commit
  for (const ua of uas) if (!h.gone.has(ua)) h.owed += leavesOf(h.tree, ua);
  h.tree = tr.markGone(h.tree, uas);
  for (const ua of uas) if (!h.gone.has(ua)) h.gone.set(ua, { kind, epoch: h.epochs.length - 1 });
  return h;
}

/** The views a device reads (spec §6), each read logged; `tamper(read, value)` is an endpoint that lies. The views by number
 *  stand for the contract's by id (`ids[n]`). */
export function reader(h, tamper = (_, v) => v) {
  const log = [];
  const at = (n) => h.epochs[n] ?? refuse("TreeEpoch");
  const view =
    (name, f) =>
    (...a) => {
      const read = `${name}(${a.join(",")})`;
      log.push(read);
      return tamper(read, clone(f(...a)));
    };
  const period = (k) => {
    const p = h.periods.get(k);
    return p ? { gone: true, ...p } : { gone: false, joinEpoch: 0, endEpoch: 0 };
  };
  return {
    log,
    sessionOf: view("sessionOf", () => ({ record: h.epochs[0].record, sig: h.epochs[0].sig })),
    treeOf: view("treeOf", () => ({
      treeId: h.treeId,
      leaves: h.tree.leaves,
      used: h.tree.used,
      treeHash: headHash(h),
      genesisTreeHash: h.genesisTreeHash,
      sincePath: h.tree.sincePath,
      owed: h.owed,
    })),
    treeLeaves: view("treeLeaves", () =>
      Array.from({ length: h.tree.leaves }, (_, i) => {
        const n = h.tree.nodes[2 * i];
        const j = h.join.get(i);
        return n
          ? { ua: n.ua, keyId: n.keyId, joinEpoch: j.joinEpoch, wrapIndex: j.wrapIndex, kemHash: n.kemHash }
          : { ua: ZERO, keyId: 0, joinEpoch: 0, wrapIndex: 0, kemHash: ZERO };
      }),
    ),
    treeNodes: view("treeNodes", () =>
      h.tree.hash.map((hash, x) => ({
        hash,
        keyHash: h.tree.nodes[x]?.keyHash ?? ZERO,
        epoch: h.nodeKey.get(x)?.epoch ?? 0,
      })),
    ),
    treeNodeKey: view("treeNodeKey", (x) => h.nodeKey.get(x)?.kemPk ?? "0x"),
    epochsOf: view("epochsOf", () => h.epochs.map((e) => e.id)),
    commitOf: view("commitOf", (n) => ({ record: at(n).record, sig: at(n).sig })),
    pathListOf: view("pathListOf", (n) => ({ ctTargets: at(n).ctTargets, ctHashes: at(n).ctHashes })),
    pathCtAt: view("pathCtAt", (n, j) => at(n).cts[j]),
    wrapAt: view("wrapAt", (n, i) => at(n).wraps[i]),
    leaveCount: view("leaveCount", (n) => at(n).leaves.length),
    leaveAt: view("leaveAt", (n, i) => at(n).leaves[i]),
    removalCount: view("removalCount", (n) => at(n).removals.length),
    removalAt: view("removalAt", (n, i) => at(n).removals[i]),
    goneOf: view("goneOf", (ua) => h.gone.get(ua) ?? { kind: 0, epoch: 0 }),
    goneOwnKeyOf: view("goneOwnKeyOf", (ua, kemHash) => period(`pair/${ua}/${kemHash}`)),
    goneKeyOf: view("goneKeyOf", (kemHash) => period(`wide/${kemHash}`)),
    /** The registry's `kemKeyAt(ua, version)`: the key and `setKemKey`'s kept signature (§8 step 5). */
    kemKeyAt: view("kemKeyAt", (ua, keyId) => h.kems.get(`${ua}/${keyId}`) ?? { kemPk: "0x", sig: "0x" }),
    /** The registry's record of a UA `{ kind, keyData }` and an `msig` slot's acceptance, not logged: signature checks,
     *  never session reads. */
    uaRecordOf: (ua) => h.uaRecords.get(ua) ?? null,
    /** The registry's `registrationOf(ua)` `{ attrs, pop }`, the record of a UA's version-0 KEM key (ua-rs
     *  `TreeReader::registration`, C-7); none: that key is `TreeKemRecord`. */
    registrationOf: (ua) => h.registrations?.get(ua) ?? null,
    accepted: () => true,
  };
}

// ------------------------------------------------------------------ the read boundary (codex-13) and the forward walk (C25)

/** Bytes that fail a signed hash, a signature or the walk: a lying read, refused at the read boundary before any
 *  decapsulation; read again from another node, neither "followed" nor "not followed" (codex-r2-15, C25). */
const corrupt = (read) => {
  const e = new pc.PqChatError("TreeReadCorrupted");
  e.read = read;
  throw e;
};
const sameList = (x, y) => x.length === y.length && x.every((v, i) => hex(v) === hex(y[i]));
/** A served value of the shape `ok` asks for, else a lying read (C-6: never a TypeError or RangeError of the reader). */
const served = (v, ok, read) => {
  let good = false;
  try {
    good = ok(v) === true;
  } catch {
    good = false;
  }
  return good ? v : corrupt(read);
};
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isHex = (v) => typeof v === "string" && /^0x([0-9a-fA-F]{2})*$/.test(v);
const isB32 = (v) => typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v);
const isNat = (v) => Number.isSafeInteger(v) && v >= 0;
/** A signer kind the contract accepts and this reader has no verifier for (a native member it cannot check) is a defect of
 *  the reader, never a lying read (spec §10 step 5, C-7): `UANotVerifiable` by its name. */
const notVerifiable = (e) => {
  if (e?.code === "UANotVerifiable") refuse("UANotVerifiable");
};
/** A record's signature for its signer's kind, as the contract's `requirePortable` judges it (F-3): a single key of each holder
 *  kind, an `msig` by its kept members over its structure at the version its `signature` (the tag) names (CTR-UA-74, the reader
 *  rule: the reader's `uaRecordOf` gives its `versions`; never another version), WebAuthn. Returns every `[msig, version]` the
 *  signature names (C-4, R-1: the signer's tag and each signing `msig` member slot's, `uv.namedVersions`; none for a single key),
 *  for the walk's order check (step 6). */
function verified(sc, rd, struct, record, signer, sig, read) {
  let v = null;
  try {
    uv.verifyPortable(
      { ua: hex(signer), purpose: sc.purpose, digest: sc.typed(struct, record), sig },
      rd.uaRecordOf,
      rd.accepted,
    );
    v = uv.namedVersions(hex(signer), sig, rd.uaRecordOf).map(([u, x]) => [u, Number(x)]);
  } catch (e) {
    notVerifiable(e);
    v = null;
  }
  if (v === null) corrupt(read);
  return v;
}
/** CTR-UA-74 step 6: each `[msig, v]` a record names (`verified`: its signer's and each signing `msig` member's) against `floor`
 *  (the versions before its slot), raised into `slot` (versions ≥ 1 only); one below: a lying read. */
const versionUp = (floor, slot, named, read) => {
  for (const [ua, v] of named) {
    if (v < (floor.get(ua) ?? 0)) corrupt(read);
    if (v > 0) slot.set(ua, Math.max(slot.get(ua) ?? 0, v));
  }
};
/** The key of `(ua, keyId)` a cold tree's leaf takes (§8 steps 3 and 5, C-1): the registry's `kemKeyAt` `{ kemPk, sig }`,
 *  authenticated by its record (`recordKey`): `setKemKey`'s signature over `kemRecordDigest` for a version above 0; version 0
 *  the registration's key, by the registration's proof of possession the reader's `registrationOf(ua)` gives (`{ attrs, pop }`,
 *  C-7, ua-rs `kem_at`). A key that fails: `TreeKemRecord`. */
function kemAt(rd, ua, keyId) {
  const read = `kemKeyAt(${ua},${keyId})`;
  const v = served(rd.kemKeyAt(ua, keyId), (x) => isObj(x) && isHex(x.kemPk) && isHex(x.sig), read);
  const rec = keyId === 0 ? { kemPk: v.kemPk, ...(rd.registrationOf?.(ua) ?? {}) } : v;
  return recordKey(ua, keyId, rec, rd.uaRecordOf, rd.accepted);
}
const ZERO_HASH = `0x${"00".repeat(32)}`;
/** A key of `(ua, keyId)` no signed tree hash covers yet (§8 step 5, codex-1, C-1: a cold tree's leaf, an Add's key, a member's
 *  key at creation), authenticated by its registry record `rec` before it is used (ua-rs `kem_record_key`; `uaRecordOf`,
 *  `accepted`: the signers' registry records): a version above 0 as `{ kemPk, sig }`, `setKemKey`'s signature over
 *  `kemRecordDigest(ua, version, kemPk)`; version 0 (C-7, ua-rs `KemRecord::Registration`) as `{ kemPk, attrs, pop }`, the
 *  registration's attributes committing to `kemPk` (in full, or by `kemPkHash`) and its proof of possession over them (the
 *  registration of a single key: no `msig` members are read, as ua-rs). A key that fails: `TreeKemRecord`. */
export function recordKey(ua, keyId, rec, uaRecordOf, accepted) {
  if (!Number.isSafeInteger(keyId) || keyId < 0 || !isObj(rec) || !isHex(rec.kemPk) || b(rec.kemPk).length === 0)
    refuse("TreeKemRecord");
  try {
    if (keyId === 0) {
      const r = uaRecordOf(hex(ua));
      const at = rec.attrs;
      if (!r || !isObj(at) || !isHex(rec.pop) || hex(deriveUA(r.kind, r.keyData)) !== hex(ua)) refuse("TreeKemRecord");
      const committed =
        at.kemPkHash === undefined || hex(at.kemPkHash) === ZERO_HASH
          ? hex(at.kemPk ?? "0x") === hex(rec.kemPk)
          : hex(keccak_256(b(rec.kemPk))) === hex(at.kemPkHash);
      if (!committed) refuse("TreeKemRecord");
      uv.verifyRegistration({ kind: r.kind, keyData: r.keyData, attrs: at, pop: rec.pop, pqzPop: "0x" }, () => null);
    } else {
      if (!isHex(rec.sig)) refuse("TreeKemRecord");
      uv.verifyKemRecord({ ua: hex(ua), version: keyId, kemPk: rec.kemPk, sig: rec.sig }, uaRecordOf, accepted);
    }
  } catch (e) {
    notVerifiable(e);
    refuse("TreeKemRecord");
  }
  return rec.kemPk;
}
const leafView = (n) => (n ? { ua: n.ua, keyId: n.keyId, kemHash: n.kemHash } : { ua: ZERO, keyId: 0, kemHash: ZERO });
const holds = (t, ua) => t.nodes.some((n, x) => x % 2 === 0 && n?.ua === ua);
const leavesOf = (t, ua) => t.nodes.filter((n, x) => x % 2 === 0 && n?.ua === ua).length;
/** The most epochs an exit may name below the head it is applied at (C9, the spec check sc-E-2). */
export const EXIT_LAG_MAX = 16;
/** The most exits one head keeps: each newly flags a UA with a leaf or a keyless admin (A-4); ua-rs `EXITS_MAX` (C-6). */
export const EXITS_MAX = tr.TREE_LEAVES_MAX + tr.TREE_ADMINS_MAX;
const isPow2 = (n) => Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0;

/** §8 step 2, §10 steps 2, 4 and 5: the session record, the snapshot, then every record from the cold tree of the signed
 *  members (each key authenticated by its registry record, C-1) or from the public tree verified at `pin` to the head, each
 *  checked before it is applied, with the exits kept under each epoch; the snapshot only compared with the result. Returns per
 *  epoch its record, admins and the commit's targets; the tree after its commit, the `gone` register before its exits and the
 *  exits applied at it only at the start, the head and the epochs `keep` names (`"all"`: every epoch), so a long session never
 *  holds a tree per epoch (E-3, B2-2); the ids below a pin only from verified records (C-3). */
function walk(sc, rd, pin = null, keep = []) {
  const s = served(rd.sessionOf(), (x) => isObj(x) && isObj(x.record), "sessionOf()");
  const S0 = s.record;
  // B-5: the signed members and the info bounded before anything is read for them (the info as a commit's, C-5)
  served(
    S0,
    (r) =>
      isB32(r.creator) &&
      Array.isArray(r.members) &&
      r.members.length <= tr.TREE_LEAVES_MAX &&
      r.members.every((m) => isObj(m) && isB32(m.ua) && isNat(m.keyId)) &&
      Array.isArray(r.admins) &&
      isHex(r.sealedInfo) &&
      b(r.sealedInfo).length >= 1 &&
      b(r.sealedInfo).length <= TREE_INFO_MAX &&
      isNat(r.pathRefreshBound) &&
      r.pathRefreshBound <= tr.PATH_REFRESH_BOUND_MAX &&
      isB32(r.confirmTag),
    "sessionOf()",
  );
  const v0 = verified(sc, rd, "PqChatSession", S0, S0.creator, s.sig, "sessionOf()");
  if (S0.groupMode !== 1) refuse("PqChatModeEntry");
  const sid = hex(pc.sessionId(S0.creator, S0.nonce));
  const treeId = hex(tr.treeId(S0));
  const t = served(rd.treeOf(), isObj, "treeOf()");
  const leaves = served(rd.treeLeaves(), (x) => Array.isArray(x) && x.every(isObj), "treeLeaves()");
  const nodes = served(rd.treeNodes(), (x) => Array.isArray(x) && x.every(isObj), "treeNodes()");
  const ids = served(rd.epochsOf(), (x) => Array.isArray(x) && x.every(isB32), "epochsOf()").map(hex);
  const head = ids.length - 1;
  if (head < 0 || ids[0] !== sid) corrupt("epochsOf()");
  const a = {
    S0,
    sid,
    treeId,
    gctx: hex(tr.genesisCtx(S0)),
    t,
    leaves,
    ids,
    head,
    n0: pin ? pin.epoch : 0,
    recs: [S0],
    trees: [],
    admins: [],
    goneAt: [],
    exits: [],
    versionsAt: [],
    targets: [],
    below: new Map(),
  };
  const kept = (n) => keep === "all" || n === a.n0 || n === head || keep.includes(n);
  let tree;
  let gone = new Map();
  // CTR-UA-74 step 6: per `msig` the highest version its records named so far (never below the pin's)
  let versions = new Map();
  if (pin) {
    if (pin.treeId !== treeId || head < pin.epoch) refuse("TreeCheckpoint");
    if (a.n0 > 0) a.recs[a.n0] = commitAt(sc, rd, a, a.n0).c;
    if (recordHash(a, a.n0) !== pin.hash) refuse("TreeConflict");
    tree = tr.treeFromJson(pin.tree);
    gone = new Map(pin.gone.map(([ua, kind, epoch]) => [ua, { kind, epoch }]));
    versions = new Map(pin.msigVersions);
  } else {
    versionUp(new Map(), versions, v0, "sessionOf()");
    const cold = S0.members.map((m) => ({ ...m, kemHash: kemHashOf(kemAt(rd, m.ua, m.keyId)) }));
    try {
      tree = tr.coldTree(cold, S0.pathRefreshBound);
    } catch (e) {
      // a signed member list the contract refuses (one key at two leaves): a lying read
      if (e instanceof pc.PqChatError) corrupt("sessionOf()");
      throw e;
    }
  }
  for (let n = a.n0; ; n++) {
    if (n > a.n0) {
      const { c, v } = commitAt(sc, rd, a, n);
      a.recs[n] = c;
      const where = `commitOf(${n})`;
      versionUp(new Map(versions), versions, v, where);
      if (c.parentEpochId !== ids[n - 1] || c.parentTreeHash !== tr.treeHash(tree)) corrupt(where);
      let applied;
      try {
        applied = tr.applyCommit(tree, c);
        tr.judgeCommit(tree, applied.tree, c, a.admins[n - 1]);
      } catch (e) {
        if (e instanceof pc.PqChatError) corrupt(where);
        throw e;
      }
      if (
        applied.tree.leaves !== c.leaves ||
        applied.treeHash !== c.treeHash ||
        applied.ctTargets.length !== c.ctCount ||
        (c.ctCount === 0 && c.ctListHash !== hex(tr.pathListHash([], [])))
      )
        corrupt(where);
      tree = applied.tree;
      for (const ua of tree.goneUa) if (!gone.has(ua)) gone.set(ua, { kind: 2, epoch: n });
      a.targets[n] = applied.ctTargets;
    }
    a.admins[n] = (n === 0 ? S0 : a.recs[n]).admins.map(hex);
    if (kept(n)) [a.trees[n], a.goneAt[n], a.versionsAt[n]] = [tree, new Map(gone), new Map(versions)];
    const ex = exitsAt(sc, rd, a, n, tree, gone, versions);
    if (pin && n === a.n0 && !pin.exits.every(([ua, kind]) => ex.some((x) => x.ua === ua && x.kind === kind)))
      corrupt(`leaveCount(${n})`);
    for (const x of ex) if (!gone.has(x.ua)) gone.set(x.ua, { kind: x.kind, epoch: n });
    tree = tr.markGone(
      tree,
      ex.map((x) => x.ua),
    );
    if (kept(n)) a.exits[n] = ex;
    if (n === head) break;
  }
  a.tree = tree;
  a.gone = gone;
  // the snapshot, only compared with the walk's tree (a list of `used` leaves or of every position; E-4)
  const w = a.trees[head];
  const want = Array.from({ length: w.leaves }, (_, i) => leafView(w.nodes[2 * i]));
  const ok =
    t.treeId === treeId &&
    t.leaves === w.leaves &&
    t.used === w.used &&
    t.sincePath === w.sincePath &&
    t.treeHash === tr.treeHash(w) &&
    // R2-D-1 of the T4-T9 re-check: `owed` equals the leaves the head's exits the walk read owe, so a strict-majority `treeOf`
    // covers the exits (an endpoint serving the true `treeOf` and hiding an exit record is a lying read)
    t.owed === a.exits[head].reduce((sum, x) => sum + leavesOf(w, x.ua), 0) &&
    (pin || t.genesisTreeHash === tr.treeHash(a.trees[0])) &&
    leaves.length >= w.used &&
    leaves.length <= w.leaves &&
    leaves.every((l, i) => JSON.stringify(leafView(l.ua === ZERO ? null : l)) === JSON.stringify(want[i])) &&
    nodes.length === tr.nodeWidth(w.leaves) &&
    nodes.every((x, i) => i % 2 === 0 || x.keyHash === (w.nodes[i]?.keyHash ?? ZERO));
  if (!ok) refuse(head === 0 ? "TreeGenesisLeaves" : "TreeHeadRoot");
  return a;
}

/** The record at number `n` on the home's chain whose id is `id` (a verified record's `parentEpochId`): its id recomputed, its
 *  number, session and signature (C-3, below a pin). */
function recordBelow(sc, rd, a, n, id) {
  const read = `commitOf(${n})`;
  const v = served(rd.commitOf(n), (x) => isObj(x) && isObj(x.record), read);
  const c = v.record;
  served(c, (r) => r.epoch === n && r.sessionId === a.sid && hex(pc.epochId(a.sid, r.author, r.nonce)) === id, read);
  verified(sc, rd, "PqChatCommit", c, c.author, v.sig, read);
  return c;
}
/** The id at number `m` from verified data only (C-3): at or above the walk's start, the id list the records were checked
 *  against; below a pin, each record's `parentEpochId` down from the pinned record, every one read and checked. */
function idAt(sc, rd, a, m) {
  if (m >= a.n0 || m === 0) return m === 0 ? a.sid : a.ids[m];
  if (!a.below.has(m)) {
    for (let k = a.n0; k > m; k--) {
      if (a.below.has(k - 1)) continue;
      const above = k === a.n0 ? a.recs[a.n0] : recordBelow(sc, rd, a, k, a.below.get(k));
      a.below.set(k - 1, hex(above.parentEpochId));
    }
  }
  return a.below.get(m);
}

/** Commit `n`'s record: its id at its number, `sessionId`, `treeId`, the bounds of C10 and C24 before anything is allocated
 *  (sc-F-7), then its author's signature: `{ c, v }`, `v` the `[msig, version]`s it names (`verified`). */
function commitAt(sc, rd, a, n) {
  const where = `commitOf(${n})`;
  const { record: c, sig } = served(rd.commitOf(n), (x) => isObj(x) && isObj(x.record), where);
  const len = (v) => (Array.isArray(v) ? v.length : Infinity);
  const ok = served(
    c,
    (r) =>
      r.epoch === n &&
      r.sessionId === a.sid &&
      hex(pc.epochId(a.sid, r.author, r.nonce)) === a.ids[n] &&
      r.treeId === a.treeId &&
      isPow2(r.leaves) &&
      r.leaves <= tr.TREE_LEAVES_MAX &&
      Number.isInteger(r.leaf) &&
      r.leaf < r.leaves &&
      len(r.removes) + len(r.adds) <= tr.TREE_CHANGES_MAX &&
      len(r.admins) <= tr.TREE_ADMINS_MAX &&
      len(r.nodeKeyHashes) <= Math.log2(r.leaves) &&
      len(r.wrapHashes) === len(r.adds) &&
      r.ctCount < r.leaves &&
      isHex(r.sealedInfo) &&
      b(r.sealedInfo).length >= 1 &&
      b(r.sealedInfo).length <= TREE_INFO_MAX &&
      typeof r.pathless === "boolean" &&
      isB32(r.confirmTag) &&
      [...r.removes, ...r.adds].every((x) => isObj(x) && Number.isInteger(x.leaf) && x.leaf < r.leaves),
    where,
  );
  const v = verified(sc, rd, "PqChatCommit", ok, ok.author, sig, where);
  return { c, v };
}

/** §10 step 5: the exits kept under epoch `h`, each one an exit applied at `h` exactly when the contract could have accepted
 *  it there, judged order-free among those kept under `h` (on `tree`, `h`'s admins and the `gone` register before them):
 *  its signature for its signer's kind and the pinned `treeId`; an epoch named `h` or an ancestor within the lag, numbered
 *  from verified data (C-3); a leave by a UA live at `h`; a removal by an admin of `h`, of UAs live at `h` or in its admins;
 *  nobody gone before `h`. Together (B2-6): no UA exits twice under one head (A-4), the leaves they owe fit one commit (C21),
 *  and the last admin with a leaf goes by a removal only when no member keeps a leaf (C24 read with C38). Each signer's structure
 *  version at or above `versions` before them (CTR-UA-74 step 6), which they raise. */
function exitsAt(sc, rd, a, h, tree, gone, versions) {
  const out = [];
  const floor = new Map(versions);
  const before = (ua) => gone.has(ua) && gone.get(ua).epoch < h;
  const named = (r, read) => {
    if (r.sessionId !== a.sid) corrupt(read);
    for (let m = h; m >= 0 && m >= h - EXIT_LAG_MAX; m--) if (idAt(sc, rd, a, m) === hex(r.epochId)) return m;
    return corrupt(read);
  };
  const count = (v, read) => served(v, (x) => isNat(x) && x <= EXITS_MAX, read);
  const exit = (v, ok, read) =>
    served(
      v,
      (x) => isObj(x) && isObj(x.record) && isB32(x.record.sessionId) && isB32(x.record.epochId) && ok(x.record),
      read,
    );
  for (let i = 0, k = count(rd.leaveCount(h), `leaveCount(${h})`); i < k; i++) {
    const read = `leaveAt(${h},${i})`;
    const { record, sig } = exit(rd.leaveAt(h, i), (r) => isB32(r.member) && isNat(r.nonce), read);
    const r = {
      sessionId: record.sessionId,
      treeId: a.treeId,
      epochId: record.epochId,
      member: hex(record.member),
      nonce: record.nonce,
    };
    named(r, read);
    if (!holds(tree, r.member) || before(r.member)) corrupt(read);
    versionUp(floor, versions, verified(sc, rd, "PqChatTreeLeave", r, r.member, sig, read), read);
    out.push({ ua: r.member, kind: 1 });
  }
  for (let i = 0, k = count(rd.removalCount(h), `removalCount(${h})`); i < k; i++) {
    const read = `removalAt(${h},${i})`;
    const { record, sig } = exit(
      rd.removalAt(h, i),
      (r) =>
        isNat(r.nextEpoch) &&
        isNat(r.nonce) &&
        isB32(r.admin) &&
        Array.isArray(r.members) &&
        r.members.length <= EXITS_MAX &&
        r.members.every(isB32),
      read,
    );
    const r = {
      sessionId: record.sessionId,
      treeId: a.treeId,
      epochId: record.epochId,
      nextEpoch: record.nextEpoch,
      members: record.members.map(hex),
      admin: hex(record.admin),
      nonce: record.nonce,
    };
    const n = named(r, read);
    const ok =
      r.nextEpoch === n + 1 &&
      r.members.length > 0 &&
      r.members.every((m, j) => j === 0 || m > r.members[j - 1]) &&
      a.admins[h].includes(r.admin) &&
      !before(r.admin) &&
      r.members.every((m) => (holds(tree, m) || a.admins[h].includes(m)) && !before(m));
    if (!ok) corrupt(read);
    versionUp(floor, versions, verified(sc, rd, "PqChatTreeRemove", r, r.admin, sig, read), read);
    for (const m of r.members) out.push({ ua: m, kind: 2 });
  }
  const goes = new Set(out.map((x) => x.ua));
  const leafyAdmin = (u) => a.admins[h].includes(u) && holds(tree, u);
  const stays = (u) => !goes.has(u) && !before(u);
  const memberStays = tree.nodes.some((x, i) => i % 2 === 0 && x && stays(x.ua));
  if (
    goes.size !== out.length ||
    out.reduce((sum, x) => sum + leavesOf(tree, x.ua), 0) > tr.TREE_CHANGES_MAX ||
    (a.admins[h].some(leafyAdmin) &&
      !a.admins[h].some((u) => leafyAdmin(u) && stays(u)) &&
      memberStays &&
      !out.some((x) => x.kind === 1 && leafyAdmin(x.ua)))
  )
    corrupt(`removalCount(${h})`);
  return out;
}

const recordHash = (a, n) =>
  hex(n === 0 ? pc.structHash("PqChatSession", a.S0) : tr.treeStructHash("PqChatCommit", a.recs[n]));
/** The checkpoint at epoch `n` of a walk (C26, the spec check sc-F-3): the treeId, the number, the hash of the record that won
 *  there, the public tree after its commit with its no-return sets, the `gone` register before its exits (`[ua, kind, epoch]`),
 *  the exits applied at it (`[ua, kind]`) and, before its exits, each `msig`'s highest structure version its records named
 *  (`[ua, version]`, versions ≥ 1 only; CTR-UA-74 step 6), each list sorted. `n` an epoch the walk kept. */
export function pinAt(a, n) {
  const byUa = (x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : x[1] - y[1]);
  return {
    treeId: a.treeId,
    epoch: n,
    hash: recordHash(a, n),
    tree: tr.treeJson(a.trees[n]),
    gone: [...a.goneAt[n]].map(([ua, g]) => [ua, g.kind, g.epoch]).sort(byUa),
    exits: a.exits[n].map((x) => [x.ua, x.kind]).sort(byUa),
    msigVersions: [...a.versionsAt[n]].sort(byUa),
  };
}
/** The epochs whose public tree the walk from `pin` (or the cold tree) holds when it is done: its start and the head (E-3: no
 *  tree per epoch; a test's measure). */
export const walkTrees = (sc, rd, pin = null) => Object.keys(walk(sc, rd, pin).trees).map(Number);
/** The checkpoint of every epoch of the walk from the cold tree (a test's comparison: a walk from any of them reaches the
 *  same head). */
export function pinsOf(sc, rd) {
  const a = walk(sc, rd, null, "all");
  return a.recs.map((_, n) => pinAt(a, n));
}
/** A walk from the cold tree checked against the device's checkpoint: never below it, the record that won there the pinned one
 *  (`TreeConflict`: the majority read of C26), and the walk at that number holds the pinned tree, register and every pinned
 *  exit (fewer is a lying read, sc-F-3). */
function checkPin(a, store) {
  if (!store) return;
  if (store.treeId !== a.treeId || a.head < store.epoch) refuse("TreeCheckpoint");
  const p = pinAt(a, store.epoch);
  if (p.hash !== store.hash) refuse("TreeConflict");
  if (
    JSON.stringify(p.tree) !== JSON.stringify(store.tree) ||
    JSON.stringify(p.gone) !== JSON.stringify(store.gone) ||
    JSON.stringify(p.msigVersions) !== JSON.stringify(store.msigVersions) ||
    !store.exits.every(([ua, kind]) => p.exits.some((x) => x[0] === ua && x[1] === kind))
  )
    corrupt(`pin(${store.epoch})`);
}

// ------------------------------------------------------------------ replay (§10)

/** A device's replay from the home's state alone (§10). `dev`: `{ ua, keyId, kemPk, key (kem.js: decaps), kemSeed }`
 *  (`kemSeed` the 96-byte seed of the key, null for a random key); `store` its checkpoint or null; `from` the device's previous
 *  replay (its pin, the node keys it held and the info in force there), so the walk starts at that pin and only the epochs
 *  after it are read and opened: the device pays the history once (spec §10 step 3, E-3). Otherwise the forward walk from the
 *  cold tree first (C25), checked against `store`; the reads are fixed by public data and made whole before anything is
 *  opened (C22). Returns the reads, the key's period, the rosters of the secret range (the walk's leaves at each of its
 *  epochs), and per epoch of the range its state ("followed", "not followed" with a reason, "compromise"), `K`, and the info in
 *  force (C33); the compromise warnings (R10, codex-r3-3); the next pin. A record that fails the walk throws
 *  `TreeReadCorrupted`. */
export function replay(sc, rd, dev, store = null, from = null) {
  const kemHash = kemHashOf(dev.kemPk);
  const a = from ? walk(sc, rd, from.pin) : walk(sc, rd, null, store ? [store.epoch] : []);
  if (!from) checkPin(a, store);
  const { S0, ids, head, recs, leaves, n0 } = a;
  const mineAt = (t, l) => {
    const x = t.nodes[2 * l];
    return x?.ua === dev.ua && x.keyId === dev.keyId && x.kemHash === kemHash;
  };
  let leaf;
  let joinEpoch;
  let endEpoch = null;
  let wrapIndex = -1;
  if (from) {
    // the period resumed: the pinned tree holds the device's leaf; its Remove, if any, is a record of this walk
    ({ leaf, joinEpoch } = from);
    if (from.endEpoch !== null || !mineAt(a.trees[n0], leaf)) refuse("TreePeriod");
    for (let n = n0 + 1; n <= head && endEpoch === null; n++)
      if (recs[n].removes.some((r) => r.leaf === leaf && r.ua === dev.ua && r.keyId === dev.keyId)) endEpoch = n;
  } else {
    // 3. the key's one period (C28, R16)
    leaf = leaves.findIndex((l) => l.ua === dev.ua && l.keyId === dev.keyId && l.kemHash === kemHash);
    if (leaf >= 0) joinEpoch = leaves[leaf].joinEpoch;
    else {
      let g = served(rd.goneOwnKeyOf(dev.ua, kemHash), isObj, `goneOwnKeyOf(${dev.ua},${kemHash})`);
      if (g.gone !== true) g = served(rd.goneKeyOf(kemHash), isObj, `goneKeyOf(${kemHash})`);
      if (g.gone !== true) return { inSession: false, reads: rd.log };
      ({ joinEpoch, endEpoch } = g);
      if (!(isNat(joinEpoch) && isNat(endEpoch) && endEpoch > joinEpoch && endEpoch <= head)) refuse("TreePeriod");
    }
    if (!(isNat(joinEpoch) && joinEpoch <= head)) refuse("TreePeriod");
    // the join by its kind, the end by its Remove
    let at;
    if (joinEpoch === 0) {
      at = S0.members.findIndex((m) => m.ua === dev.ua && m.keyId === dev.keyId);
      if (at < 0 || a.trees[0].nodes[2 * at].kemHash !== kemHash) refuse("TreePeriod");
      wrapIndex = at;
    } else {
      wrapIndex = recs[joinEpoch].adds.findIndex(
        (x) => x.ua === dev.ua && x.keyId === dev.keyId && x.kemHash === kemHash,
      );
      if (wrapIndex < 0) refuse("TreePeriod");
      at = recs[joinEpoch].adds[wrapIndex].leaf;
    }
    if (leaf >= 0 && leaf !== at) refuse("TreePeriod");
    leaf = at;
    const mine = (r) => r.leaf === leaf && r.ua === dev.ua && r.keyId === dev.keyId;
    if (endEpoch !== null && !recs[endEpoch].removes.some(mine)) refuse("TreePeriod");
  }
  const last = endEpoch === null ? head : endEpoch - 1;
  const first = from ? n0 + 1 : joinEpoch;
  // 4. the rosters of the secret range: the walk's leaves, from its first tree through each record's Removes and Adds (C25)
  const rosters = [];
  {
    const t0 = a.trees[n0];
    const ros = Array.from({ length: t0.leaves }, (_, i) => {
      const x = t0.nodes[2 * i];
      return x ? { ua: x.ua, keyId: x.keyId } : null;
    });
    if (first <= n0) rosters[n0] = [...ros];
    for (let n = n0 + 1; n <= last; n++) {
      const c = recs[n];
      for (const r of c.removes) ros[r.leaf] = null;
      while (ros.length < c.leaves) ros.push(null);
      for (const x of c.adds) ros[x.leaf] = { ua: x.ua, keyId: x.keyId };
      if (n >= first) rosters[n] = [...ros];
    }
  }
  const adminsAt = (n) => a.admins[n];
  // 6. the secret range's pieces, by public data only, all read before anything is opened (C22); a record whose `ctCount`
  // is 0 (a path-less Add, the last live leaf's commit) has no list: the record and, at the join, the wrap (the delta §6)
  const plan = [];
  for (let n = first; n <= last; n++) {
    if (n === 0) {
      const wrap = rd.wrapAt(0, leaf);
      if (hex(pc.structHash("Wrap", wrap)) !== S0.wrapHashes[leaf]) corrupt(`wrapAt(0,${leaf})`);
      plan.push({ n, wrap });
      continue;
    }
    const c = recs[n];
    const p = { n, own: c.author === dev.ua && c.keyId === dev.keyId && c.leaf === leaf, j: -1 };
    if (c.ctCount === 0) p.list = { ctTargets: [], ctHashes: [] };
    else {
      p.list = served(
        rd.pathListOf(n),
        (x) => isObj(x) && Array.isArray(x.ctTargets) && Array.isArray(x.ctHashes),
        `pathListOf(${n})`,
      );
      if (
        JSON.stringify(p.list.ctTargets) !== JSON.stringify(a.targets[n]) ||
        p.list.ctHashes.length !== c.ctCount ||
        hex(tr.pathListHash(p.list.ctTargets, p.list.ctHashes)) !== c.ctListHash
      )
        corrupt(`pathListOf(${n})`);
    }
    if (!p.own) {
      const mine = new Set([2 * leaf, ...tr.directPath(2 * leaf, c.leaves)]);
      p.j = p.list.ctTargets.findIndex((x) => mine.has(x));
      if (p.j >= 0) {
        p.ct = served(rd.pathCtAt(n, p.j), isObj, `pathCtAt(${n},${p.j})`);
        if (hex(tr.treeStructHash("PathCt", p.ct)) !== p.list.ctHashes[p.j]) corrupt(`pathCtAt(${n},${p.j})`);
      }
    }
    if (n === joinEpoch && wrapIndex >= 0) {
      p.wrap = served(rd.wrapAt(n, wrapIndex), isObj, `wrapAt(${n},${wrapIndex})`);
      if (hex(pc.structHash("Wrap", p.wrap)) !== c.wrapHashes[wrapIndex]) corrupt(`wrapAt(${n},${wrapIndex})`);
    }
    plan.push(p);
  }
  // the secrets, from those bytes only; `chain` the previous epoch's `next` and whether the device is anchored in the run
  // (the delta §6.2, C45): null when it did not follow (or hold the chain's key of) the previous epoch
  const held = from ? new Map(from.heldKeys) : new Map([[2 * leaf, { kemPk: hex(dev.kemPk), key: dev.key }]]);
  // R2-D-6 of the T4-T9 re-check (C-4, as ua-rs): the info in force, its flag and whether the device followed the head are
  // the replay's own, kept by a resume that finds no new epoch
  let inForce = from ? from.inForce : null;
  let flagged = from ? from.flagged : false;
  let headFollowed = from ? from.headFollowed : false;
  let chain = from ? from.chain : null;
  const epochs = [];
  const warnings = [];
  const suspects = [];
  for (const p of plan) {
    const n = p.n;
    const c = recs[n];
    let res;
    if (n === 0) res = openGenesis(sc, a, dev, p);
    else if (c.pathless) res = pathlessCommit(sc, a, dev, p, chain, n === joinEpoch && wrapIndex >= 0);
    else res = (p.own ? ownCommit : othersCommit)(sc, a, dev, p, held);
    chain = res.chain ?? null;
    if (n > 0) {
      // a path-less Add blanks only its new leaves' direct paths, the root included (C6); a path commit also the author's
      const moved = c.pathless ? c.adds : [c, ...c.removes, ...c.adds];
      for (const x of moved) for (const y of tr.directPath(2 * x.leaf, c.leaves)) held.delete(y);
      for (const [x, k] of res.derived ?? []) held.set(x, { kemPk: hex(k.kemPk), key: k });
    }
    let info = null;
    if (res.state === "followed" && res.info) {
      const admin = n === 0 || adminsAt(n - 1).includes(c.author);
      if (res.info.marker) info = "marker";
      else if (inForce === null) {
        [inForce, flagged, info] = [res.info.json, !(admin || c.author === dev.ua), "full"];
      } else if (res.info.json !== inForce) {
        if (admin) [inForce, flagged, info] = [res.info.json, false, "changed"];
        else info = "ignored";
      } else {
        if (admin) flagged = false;
        info = "full";
      }
    } else {
      // a device that did not follow an epoch, or did not take its info, has no info in force from that epoch on
      // (fable-r3-1; the delta's F-8: "followed, info not taken"; C45)
      [inForce, flagged] = [null, false];
      if (res.state === "followed") info = "not taken";
    }
    // C-2, B2-7: an added leaf is left when the walk's head tree still holds that Add's key at its leaf (a pair has one
    // period, C28); the served `joinEpoch` decides nothing
    const live = (x) => {
      const y = a.trees[head].nodes[2 * x.leaf];
      return y?.ua === x.ua && y.keyId === x.keyId && y.kemHash === x.kemHash;
    };
    if (res.state === "compromise") {
      warnings.push({
        epoch: n,
        adds: c.adds.map((x) => ({ leaf: x.leaf, ua: x.ua, keyId: x.keyId })),
        removes: c.removes,
        adminsChanged: !sameList(c.admins, adminsAt(n - 1)),
        leavesLeft: c.adds.filter(live).map((x) => x.leaf),
      });
    }
    if (res.state === "author did not hold") {
      // C45: the epoch, its author and the leaves it added, shown to every member; those still live are under review
      suspects.push({
        epoch: n,
        author: c.author,
        adds: c.adds.map((x) => ({ leaf: x.leaf, ua: x.ua, keyId: x.keyId })),
        leavesLeft: c.adds.filter(live).map((x) => x.leaf),
      });
    }
    headFollowed = n === head && res.state === "followed";
    const row = { epoch: n, epochId: ids[n], state: res.state };
    if (res.reason) row.reason = res.reason;
    if (res.K) row.K = hex(res.K);
    Object.assign(row, { info, inForce, flagged });
    epochs.push(row);
  }
  // the leaves under review (F-3): every still-live leaf a compromise warning or a C45 state names
  const review = [...new Set([...warnings, ...suspects].flatMap((x) => x.leavesLeft))].sort((x, y) => x - y);
  const headTree = a.trees[head];
  const isAdmin = a.admins[head].includes(hex(dev.ua));
  return {
    inSession: true,
    reads: rd.log,
    leaf,
    joinEpoch,
    endEpoch,
    rosters,
    epochs,
    warnings,
    suspects,
    review,
    // the admins' warning (R18, C46): from `sincePath ≥ W(N)`, shown on an admin's device only
    sincePath: headTree.sincePath,
    pathWarning: isAdmin && endEpoch === null && headTree.sincePath >= warnAt(headTree.pathBound),
    held: [...held.keys()].sort((x, y) => x - y),
    heldKeys: held,
    chain,
    // the head's handle (the delta §6.5): its `next` only while the device holds the head's epoch
    head:
      chain && last === head ? { epochId: ids[head], treeHash: tr.treeHash(headTree), next: hex(chain.next) } : null,
    pin: pinAt(a, head),
    inForce,
    flagged,
    // the key's period ended before the head: the device does not follow it
    headFollowed: headFollowed && last === head,
  };
}

/** The admins' warning threshold (C46, the delta §6.4): `W(0)` = 20 (PATHLESS_WARN_LEAVES), `W(N) = max(1, N − ⌈N/4⌉)`. */
export const PATHLESS_WARN_LEAVES = 20;
export const warnAt = (N) => (N === 0 ? PATHLESS_WARN_LEAVES : Math.max(1, N - Math.ceil(N / 4)));

/** What a holder of node secrets alone (`held`: node → `{ kemPk, key }`, a leaked set) gets from commit `n`: its `K`, or the
 *  reason it gets none (fable-6, codex-15). An analysis of the leaked-set rows: no device calls it. */
export function withHeld(sc, rd, n, held) {
  const a = walk(sc, rd);
  const list = rd.pathListOf(n);
  const j = list.ctTargets.findIndex((t) => held.has(t));
  const p = { n, list, j, ct: j >= 0 ? rd.pathCtAt(n, j) : null };
  return othersCommit(sc, a, null, p, new Map(held));
}

const sameTag = (sch, tag) => hex(sch.tag) === hex(tag);
/** The tail of every kind: the tag decides the key state, `sealedInfo` only the info (C12 as amended, F-8): a good tag with
 *  an info that does not open is "followed" with no info (`info` null: "followed, info not taken"). */
const taken = (sc, a, epochId, sealed, sch, anchored) => ({
  state: "followed",
  K: sch.K,
  info: openTreeInfo(sc, sch.K, a.sid, epochId, sealed),
  chain: { next: sch.next, anchored },
});

function openGenesis(sc, a, dev, p) {
  const joiner = openTreeWrap(sc, { wrap: p.wrap, ctxId: a.gctx, epochId: a.sid, kemPk: dev.kemPk }, dev.key);
  if (!joiner) return { state: "not followed", reason: "opening failed" };
  const sch = schedule(sc, joiner, genesisFields(a.S0));
  // epoch 0's tag in the session record (C43, F-7): a genesis wrap that does not match it is not followed
  if (!sameTag(sch, a.S0.confirmTag)) return { state: "not followed", reason: "tag" };
  return taken(sc, a, a.sid, a.S0.sealedInfo, sch, true);
}

/** The tail of a path commit's processing: the joiner, the Welcome when there is one, the schedule, the tag (claude-21: "not
 *  followed (tag)"), then the info. */
function finish(sc, a, c, p, dev, commitSecret) {
  const epochId = a.ids[c.epoch];
  const joiner = joinerSecret(sc, commitSecret, a.treeId, epochId);
  if (p.wrap) {
    const w = openTreeWrap(sc, { wrap: p.wrap, ctxId: a.treeId, epochId, kemPk: dev.kemPk }, dev.key);
    if (!w || hex(w) !== hex(joiner)) return { state: "not followed", reason: "welcome disagrees" };
  }
  const sch = schedule(sc, joiner, commitFields(c));
  if (!sameTag(sch, c.confirmTag)) return { state: "not followed", reason: "tag" };
  return taken(sc, a, epochId, c.sealedInfo, sch, true);
}

/** A path-less Add (the delta §4.1, §6.2, §6.3, §6.5). Its own `(ua, keyId)` first: reproduced only when a `try` of the seed
 *  gives its nonce, else the compromise warning (C47), with or without the epoch state. A joiner at its join opens its wrap
 *  (unanchored); a device that holds the parent's `next` (`chain`) derives the joiner secret; the tag then decides: good,
 *  followed; failing at an anchored device, "author did not hold" with the chain's key kept (C45); at an unanchored one,
 *  "not followed" ("welcome may not match", F-1); at the join, "not followed" ("tag"). */
function pathlessCommit(sc, a, dev, p, chain, joining) {
  const c = a.recs[p.n];
  const epochId = a.ids[p.n];
  if (p.own && !(dev.kemSeed && addNonceTry(sc, dev.kemSeed, c) >= 0)) return { state: "compromise" };
  if (joining) {
    const joiner = openTreeWrap(sc, { wrap: p.wrap, ctxId: a.treeId, epochId, kemPk: dev.kemPk }, dev.key);
    if (!joiner) return { state: "not followed", reason: "opening failed" };
    const sch = schedule(sc, joiner, commitFields(c));
    if (!sameTag(sch, c.confirmTag)) return { state: "not followed", reason: "tag" };
    return taken(sc, a, epochId, c.sealedInfo, sch, false);
  }
  if (!chain) return { state: "not followed", reason: "parent not followed" };
  const sch = schedule(
    sc,
    addJoinerSecret(sc, chain.next, a.treeId, epochId, tr.arrayHash("TreeAdd", c.adds)),
    commitFields(c),
  );
  if (sameTag(sch, c.confirmTag)) return taken(sc, a, epochId, c.sealedInfo, sch, chain.anchored);
  if (!chain.anchored) return { state: "not followed", reason: "welcome may not match" };
  return { state: "author did not hold", K: sch.K, chain: { next: sch.next, anchored: true } };
}

/** Another member's commit: the one ciphertext over its leaf, upward with the key comparison (§10). */
function othersCommit(sc, a, dev, p, held) {
  const c = a.recs[p.n];
  const path = pathFromList(c.leaf, p.list.ctTargets, c.leaves);
  // unreachable after the walk (C-8): it holds the list to the walk's targets and the path length to `nodeKeyHashes`; kept as
  // the reason ua-rs names too
  if (!path || path.length !== c.nodeKeyHashes.length) return { state: "not followed", reason: "list" };
  if (p.j < 0) return { state: "not followed", reason: "wrong target" };
  const t = p.list.ctTargets[p.j];
  const up = new Set(tr.directPath(t, c.leaves));
  const k = path.findIndex((x) => up.has(x));
  const h = held.get(t);
  if (!h) return { state: "not followed", reason: "target not held" };
  const secret = openPathSecret(
    sc,
    { treeId: a.treeId, epochId: a.ids[p.n], node: path[k], target: t, kemPk: h.kemPk, ct: p.ct },
    h.key,
  );
  if (!secret) return { state: "not followed", reason: "opening failed" };
  const ps = pathSecrets(sc, secret, path.length - k);
  const derived = [];
  for (let i = 0; i < path.length - k; i++) {
    const key = nodeKeyOf(sc, ps[i]);
    if (kemHashOf(key.kemPk) !== c.nodeKeyHashes[k + i]) return { state: "not followed", reason: "node key mismatch" };
    derived.push([path[k + i], key]);
  }
  const r = finish(sc, a, c, p, dev, ps[path.length - k]);
  return r.state === "followed" ? { ...r, derived } : r;
}

/** Its own commit: `ps[0]` from the seed; reproduced is both tests, the node keys and the tag (codex-r3-4, claude-21; for the
 *  last live leaf the tag alone), else the compromise warning, never "not followed" (R10, fable-r2-1); the info then as any
 *  member's. */
function ownCommit(sc, a, dev, p) {
  const c = a.recs[p.n];
  if (!dev.kemSeed) return { state: "not followed", reason: "random key" };
  const path = pathFromList(c.leaf, p.list.ctTargets, c.leaves);
  // unreachable after the walk (C-8), as in othersCommit
  if (!path || path.length !== c.nodeKeyHashes.length) return { state: "compromise" };
  const ps = pathSecrets(sc, firstPathSecret(sc, dev.kemSeed, pathContext(sc, c, p.list.ctTargets)), path.length);
  const derived = [];
  for (let k = 0; k < path.length; k++) {
    const key = nodeKeyOf(sc, ps[k]);
    if (kemHashOf(key.kemPk) !== c.nodeKeyHashes[k]) return { state: "compromise" };
    derived.push([path[k], key]);
  }
  const r = finish(sc, a, c, p, dev, ps[path.length]);
  return r.state === "followed" ? { ...r, derived } : { state: "compromise" };
}

// ------------------------------------------------------------------ before a client encrypts (§8, C11, C18, C26)

/** The info a device seals in a commit of its own (C33): the full info in force only when it followed the parent (the head)
 *  and holds one not flagged; otherwise the marker (null). A changed info is the admin's own action, never this. */
export function infoToSeal(r) {
  return r.headFollowed && r.inForce !== null && !r.flagged ? JSON.parse(r.inForce) : null;
}

/** The public tree a commit is built on (§8 steps 1 to 3, C25, C26): the forward walk from the checkpoint `store` (its tree and
 *  exits) or from the cold tree of the signed members, never a served snapshot (at an epoch-0 head the cold tree itself:
 *  every target a signed member's key, B-1); `keyOf(node)`, each fetched key against the hash that entered the root (codex-1);
 *  the head's admins; the pin of the head. */
export function prepareCommit(sc, rd, store = null) {
  const a = walk(sc, rd, store);
  const t = a.tree;
  const keyOf = (x) => {
    const n = t.nodes[x];
    if (!n || (x % 2 === 1 && a.head === 0)) refuse("TreeKeyHash");
    const k =
      x % 2 === 0
        ? served(rd.kemKeyAt(n.ua, n.keyId), (v) => isObj(v) && isHex(v.kemPk), `kemKeyAt(${n.ua},${n.keyId})`).kemPk
        : served(rd.treeNodeKey(x), isHex, `treeNodeKey(${x})`);
    if (kemHashOf(k) !== (x % 2 === 0 ? n.kemHash : n.keyHash)) refuse("TreeKeyHash");
    return k;
  };
  return {
    tree: t,
    parent: { epochId: a.ids[a.head], epoch: a.head, treeHash: tr.treeHash(t) },
    admins: a.admins[a.head],
    keyOf,
    pin: pinAt(a, a.head),
  };
}

/** Receipts (R11), the rule's statement: a tree session sends none automatically, whatever the store list says; mode 0 keeps
 *  its default. Nothing in this reference sends a receipt. */
export const autoReceipts = (groupMode, storeDefault) => groupMode === 0 && storeDefault;

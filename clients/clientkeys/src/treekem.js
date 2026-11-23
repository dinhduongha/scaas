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
import { verifyUA, uaId } from "./pq.js";

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
  const ss = key.decaps(b(c.ct.mlkemCt), b(c.ct.x25519Eph));
  try {
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
/** `S_e = H(joiner, …/epoch ‖ ctx_e)`, `K_e = H(S_e, …/key)`. */
export function schedule(sc, joiner, fields) {
  const ctx = epochContext(sc, fields);
  const S = H(joiner, concatBytes(sc.epoch, ctx));
  return { ctx, joiner: b(joiner), S, K: H(S, sc.key) };
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
/** `{ marker: true }` or `{ json }`; null when it does not open (or is not a padded plaintext). */
export function openTreeInfo(sc, K, sessionId, epochId, sealed) {
  const s = b(sealed);
  if (s.length > TREE_INFO_MAX) return null;
  try {
    const c = pc.unpad(gcmsiv(sc.infoKey(K, sessionId, epochId), s.subarray(0, 12)).decrypt(s.subarray(12)));
    return c.length === 0 ? { marker: true } : { json: new TextDecoder().decode(c) };
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
  const ss = key.decaps(b(wrap.mlkemCt), b(wrap.x25519Eph));
  try {
    const kek = pc.wrapKek(ss, ctxId, epochId, wrap.member, wrap.keyId, kemPk, sc.wrap);
    return gcm(kek, NONCE0, pc.wrapAad(ctxId, epochId, wrap.member, wrap.keyId)).decrypt(b(wrap.sealedKey));
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ creation in order (C29, codex-r2-4)

/** `session` without `wrapHashes` and `sealedInfo`; `kemPks[i]` the key of `members[i]`; `rand(name, n)` the randomness.
 *  In order: genesisCtx → joiner_0, K_0 → the wraps and sealedInfo → the record → treeId (the signature is the caller's). */
export function createGenesis(sc, { session, kemPks, info, rand }) {
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
  const record = { ...session, wrapHashes: wraps.map((w) => w.hash), sealedInfo };
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
 *  `adds[i]` is a `TreeAdd` with its `kemPk`; `keyOf(node)` the key of a target the parent tree holds (a leaf's registry key
 *  or a node key); `info` a full info or null (the marker); `rand(name, n)` the randomness. `faults` is for refusal rows
 *  only (a commit whose author signs what it built wrong: `nodeKeys`, `ct[j]` a `sealedSecret`, `welcomeJoiner`, `infoK`);
 *  a foreign `kemSeed` is a commit that seed did not build. Returns the record (unsigned), its pieces, the tree after
 *  it and the secrets. */
export function buildCommit(sc, a, faults = {}) {
  const adds = a.adds ?? [];
  const removes = a.removes ?? [];
  const addRecs = adds.map(({ kemPk, ...x }) => x);
  const p = tr.filteredPathAfter(a.tree, a.leaf, { removes, adds: addRecs });
  const ctTargets = p.flatMap((q) => q.targets);
  const head = {
    sessionId: a.sessionId,
    author: a.author,
    nonce: a.nonce,
    epoch: a.parent.epoch + 1,
    parentEpochId: a.parent.epochId,
    treeId: a.treeId,
    parentTreeHash: a.parent.treeHash,
    leaf: a.leaf,
    keyId: a.keyId,
  };
  const ctx = pathContext(sc, { ...head, removes, adds: addRecs }, ctTargets);
  const ps = pathSecrets(sc, firstPathSecret(sc, a.kemSeed, ctx), p.length);
  const nodeKeys = faults.nodeKeys ?? ps.slice(0, p.length).map((s) => hex(nodeKeyOf(sc, s).kemPk));
  const nodeKeyHashes = nodeKeys.map((k) => hex(keccak_256(b(k))));
  const epochId = hex(pc.epochId(a.sessionId, a.author, a.nonce));
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
      cts.push({ node: q.node, target: t, level: k, kemPk: hex(kemPk), ...s });
    }),
  );
  const ctHashes = cts.map((c) => hex(tr.treeStructHash("PathCt", c.ct)));
  const applied = tr.applyCommit(a.tree, { ...head, removes, adds: addRecs, nodeKeyHashes });
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
  const commitSecret = ps[p.length];
  const sch = schedule(sc, joinerSecret(sc, commitSecret, a.treeId, epochId), commitFields(rec));
  const wraps = adds.map((x, i) =>
    sealTreeWrap(sc, {
      joiner: faults.welcomeJoiner ?? sch.joiner,
      ctxId: a.treeId,
      epochId,
      member: x.ua,
      keyId: x.keyId,
      kemPk: x.kemPk,
      m: a.rand(`welcome/${i}/mlkem-m`, 32),
      e: a.rand(`welcome/${i}/x25519-ephemeral`, 32),
    }),
  );
  const sealedInfo = sealTreeInfo(
    sc,
    faults.infoK ?? sch.K,
    a.sessionId,
    epochId,
    a.info,
    a.rand("sealed-info-nonce", 12),
  );
  // the record in the type's field order
  const record = Object.fromEntries(
    tr.TREE_TYPES.PqChatCommit.map((f) => [
      f.name,
      { ...rec, wrapHashes: wraps.map((w) => w.hash), sealedInfo }[f.name],
    ]),
  );
  return {
    record,
    epochId,
    pathContext: hex(ctx),
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

const KIND = "mldsa65";
const kemHashOf = (kemPk) => hex(keccak_256(b(kemPk)));
const clone = (v) => JSON.parse(JSON.stringify(v));

/** A model of one home's state for a tree session (spec §6, §7): the records with their signatures, the pieces, the leaves'
 *  `joinEpoch` and wrap index, the node keys, `gone` and the key periods. `kems`: `"<ua>/<keyId>"` → `kemPk` (the registry),
 *  `uaKeys`: ua → its public key (`mldsa65`). The contract's checks are pqchat-tree.js's `applyCommit` and the pieces' hashes. */
export function newHome({ genesis, sig, kems, uaKeys }) {
  const s = genesis.record;
  const tree = tr.coldTree(s.members.map((m) => ({ ...m, kemHash: kemHashOf(kems.get(`${m.ua}/${m.keyId}`)) })));
  return {
    sessionId: genesis.sessionId,
    treeId: genesis.treeId,
    tree,
    genesisTreeHash: tr.treeHash(tree),
    epochs: [{ id: genesis.sessionId, record: s, sig, wraps: genesis.wraps.map((w) => w.wrap) }],
    join: new Map(s.members.map((_, i) => [i, { joinEpoch: 0, wrapIndex: i }])),
    nodeKey: new Map(),
    gone: new Map(),
    periods: new Map(),
    kems,
    uaKeys,
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
  h.tree = applied.tree;
  h.epochs.push({
    id: built.epochId,
    record: c,
    sig,
    ctTargets: built.ctTargets,
    ctHashes: built.ctHashes,
    nodeKeys: built.nodeKeys,
    cts: built.cts.map((x) => x.ct),
    wraps: built.wraps.map((w) => w.wrap),
  });
  return h;
}
/** A landed `treeLeave` (kind 1) or `treeRemove` (kind 2): its UAs are `gone` at the head (C28). */
export function landGone(h, kind, struct, record, sig) {
  const uas = kind === 1 ? [record.member] : record.members;
  h.tree = tr.markGone(h.tree, uas);
  for (const ua of uas) h.gone.set(ua, { kind, epoch: h.epochs.length - 1, struct, record, sig });
  return h;
}

/** The views a device reads (spec §6), each read logged; `tamper(read, value)` is an endpoint that lies. */
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
    goneOf: view("goneOf", (ua) => {
      const g = h.gone.get(ua);
      return g ? { kind: g.kind, epoch: g.epoch } : { kind: 0, epoch: 0 };
    }),
    goneRecord: view("goneRecord", (ua) => {
      const g = h.gone.get(ua);
      return g ? { struct: g.struct, record: g.record, sig: g.sig } : null;
    }),
    goneOwnKeyOf: view("goneOwnKeyOf", (ua, kemHash) => period(`pair/${ua}/${kemHash}`)),
    goneKeyOf: view("goneKeyOf", (kemHash) => period(`wide/${kemHash}`)),
    kemKeyAt: view("kemKeyAt", (ua, keyId) => h.kems.get(`${ua}/${keyId}`) ?? "0x"),
    /** The registry's key of a UA (`mldsa65` here), not logged: a signature check, never a session read. */
    uaKeyOf: (ua) => h.uaKeys.get(ua) ?? "0x",
  };
}

// ------------------------------------------------------------------ the read boundary (codex-13) and the anchored head

/** Bytes that fail a signed hash or a signature: refused at the read boundary, before any decapsulation; read again from
 *  another node, neither "followed" nor "not followed" (codex-r2-15). */
const corrupt = (read) => {
  const e = new pc.PqChatError("TreeReadCorrupted");
  e.read = read;
  throw e;
};
const sameList = (x, y) => x.length === y.length && x.every((v, i) => hex(v) === hex(y[i]));
function verified(sc, rd, struct, record, signer, sig, read) {
  let ok = false;
  try {
    const pk = b(rd.uaKeyOf(signer));
    ok = hex(uaId(KIND, pk)) === hex(signer) && verifyUA(KIND, pk, sc.purpose, sc.typed(struct, record), b(sig));
  } catch {
    ok = false;
  }
  if (!ok) corrupt(read);
}
/** The root of a snapshot from its leaves and each parent's `keyHash` (codex-r2-6). */
function snapshotRoot(leaves, nodes) {
  const t = { leaves: leaves.length, nodes: Array(tr.nodeWidth(leaves.length)).fill(null) };
  leaves.forEach((l, i) => l.ua !== ZERO && (t.nodes[2 * i] = { ua: l.ua, keyId: l.keyId, kemHash: l.kemHash }));
  nodes.forEach((n, x) => x % 2 === 1 && n.keyHash !== ZERO && (t.nodes[x] = { keyHash: n.keyHash }));
  return tr.treeHash(t);
}
const leafView = (n) => (n ? { ua: n.ua, keyId: n.keyId, kemHash: n.kemHash } : { ua: ZERO, keyId: 0, kemHash: ZERO });

/** Steps 1 and 2 of §10 (and of "before a client encrypts", §8): the session record, the snapshot, the head anchored to its
 *  signed tree hash, or at epoch 0 the cold tree rebuilt from the signed member list (codex-r2-1). */
function anchor(sc, rd) {
  const s = rd.sessionOf();
  verified(sc, rd, "PqChatSession", s.record, s.record.creator, s.sig, "sessionOf()");
  const S0 = s.record;
  if (S0.groupMode !== 1) refuse("PqChatModeEntry");
  const sid = hex(pc.sessionId(S0.creator, S0.nonce));
  const treeId = hex(tr.treeId(S0));
  const t = rd.treeOf();
  const leaves = rd.treeLeaves();
  const nodes = rd.treeNodes();
  const ids = rd.epochsOf();
  const head = ids.length - 1;
  const recs = [S0];
  const read = (n) => {
    const { record: c, sig } = rd.commitOf(n);
    const where = `commitOf(${n})`;
    if (c.epoch !== n || hex(pc.epochId(sid, c.author, c.nonce)) !== ids[n] || c.treeId !== treeId) corrupt(where);
    verified(sc, rd, "PqChatCommit", c, c.author, sig, where);
    return (recs[n] = c);
  };
  let cold = null;
  const genesis = () =>
    (cold ??= tr.coldTree(S0.members.map((m) => ({ ...m, kemHash: kemHashOf(rd.kemKeyAt(m.ua, m.keyId)) }))));
  const a = { S0, sid, treeId, gctx: hex(tr.genesisCtx(S0)), t, leaves, nodes, ids, head, recs, read, genesis };
  if (head === 0) {
    const g = genesis();
    const want = Array.from({ length: g.leaves }, (_, i) => leafView(g.nodes[2 * i]));
    const got = leaves.map((l) => leafView(l.ua === ZERO ? null : l));
    if (JSON.stringify(want) !== JSON.stringify(got) || t.genesisTreeHash !== tr.treeHash(g))
      refuse("TreeGenesisLeaves");
  } else if (snapshotRoot(leaves, nodes) !== read(head).treeHash || t.treeHash !== recs[head].treeHash) {
    refuse("TreeHeadRoot");
  }
  return a;
}
const recordHash = (a, n) =>
  hex(n === 0 ? pc.structHash("PqChatSession", a.S0) : tr.treeStructHash("PqChatCommit", a.recs[n] ?? a.read(n)));
/** The checkpoint (C26, fable-r2-4, codex-r3-2): never below the pinned epoch, and the record that won there is the pinned one. */
function checkPin(a, store) {
  if (!store) return;
  if (store.treeId !== a.treeId || a.head < store.epoch) refuse("TreeCheckpoint");
  if (recordHash(a, store.epoch) !== store.hash) refuse("TreeConflict");
}
/** What the store pins after a verified head: the treeId, the head's number and the hash of its record. */
const pinOf = (a) => ({ treeId: a.treeId, epoch: a.head, hash: recordHash(a, a.head) });

// ------------------------------------------------------------------ replay (§10)

/** A device's replay from the home's state alone (§10). `dev`: `{ ua, keyId, kemPk, key (kem.js: decaps), kemSeed }`
 *  (`kemSeed` the 96-byte seed of the key, null for a random key); `store` its checkpoint or null. The reads are fixed by
 *  public data and made whole before anything is opened (C22). Returns the reads, the key's period, the rosters, and per
 *  epoch of the secret range its state ("followed", "not followed" with a reason, "compromise"), `K`, and the info in
 *  force (C33); the compromise warnings (R10, codex-r3-3); the next pin. */
export function replay(sc, rd, dev, store = null) {
  const kemHash = kemHashOf(dev.kemPk);
  const a = anchor(sc, rd);
  const { S0, sid, treeId, ids, head, recs, leaves } = a;
  // 3. the key's one period (C28, R16)
  let leaf = leaves.findIndex((l) => l.ua === dev.ua && l.keyId === dev.keyId && l.kemHash === kemHash);
  let joinEpoch;
  let endEpoch = null;
  if (leaf >= 0) joinEpoch = leaves[leaf].joinEpoch;
  else {
    let g = rd.goneOwnKeyOf(dev.ua, kemHash);
    if (!g.gone) g = rd.goneKeyOf(kemHash);
    if (!g.gone) return { inSession: false, reads: rd.log };
    ({ joinEpoch, endEpoch } = g);
  }
  // the public range: the join's parent to the head, records only (codex-r3-1)
  const lo = joinEpoch === 0 ? 0 : joinEpoch - 1;
  for (let n = Math.max(lo, 1); n <= head; n++) if (!recs[n]) a.read(n);
  for (let n = lo + 1; n <= head; n++) {
    const parentHash = n === 1 ? tr.treeHash(a.genesis()) : recs[n - 1].treeHash;
    if (recs[n].parentEpochId !== ids[n - 1] || recs[n].parentTreeHash !== parentHash) corrupt(`commitOf(${n})`);
  }
  checkPin(a, store);
  // the join by its kind, the end by its Remove
  let wrapIndex;
  let at;
  if (joinEpoch === 0) {
    at = S0.members.findIndex((m) => m.ua === dev.ua && m.keyId === dev.keyId);
    if (at < 0 || a.genesis().nodes[2 * at].kemHash !== kemHash) refuse("TreePeriod");
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
  const last = endEpoch === null ? head : endEpoch - 1;
  // 4. the rosters by undo from the anchored head, every later commit of the public range undone (C25, codex-r3-1)
  const rosters = [];
  rosters[head] = leaves.map((l) => (l.ua === ZERO ? null : { ua: l.ua, keyId: l.keyId }));
  const coldSize = 2 ** Math.ceil(Math.log2(Math.max(S0.members.length, 1)));
  for (let n = head; n > lo; n--) {
    const r = rosters[n].slice();
    for (const x of recs[n].adds) r[x.leaf] = null;
    for (const x of recs[n].removes) r[x.leaf] = { ua: x.ua, keyId: x.keyId };
    rosters[n - 1] = r.slice(0, n === 1 ? coldSize : recs[n - 1].leaves);
  }
  if (lo === 0) {
    const want = S0.members.map((m) => ({ ua: m.ua, keyId: m.keyId }));
    if (JSON.stringify(rosters[0].slice(0, want.length)) !== JSON.stringify(want)) refuse("TreeRoster");
  }
  // 5. rights against the parent's roster and admins, with the evidence of a UA a non-admin drops (codex-r2-6)
  const adminsAt = (n) => (n === 0 ? S0.admins : recs[n].admins);
  const evidence = new Map();
  const goneAt = (ua, n) => {
    if (!evidence.has(ua)) {
      const g = rd.goneOf(ua);
      let ok = g.kind !== 0 && recs[g.epoch] !== undefined;
      const ev = ok ? rd.goneRecord(ua) : null;
      const r = ev?.record;
      if (ok)
        ok =
          r.sessionId === sid &&
          r.treeId === treeId &&
          r.epochId === ids[g.epoch] &&
          (g.kind === 1 ? r.member === ua : r.members.includes(ua) && adminsAt(g.epoch).includes(r.admin));
      if (ok) {
        const struct = g.kind === 1 ? "PqChatTreeLeave" : "PqChatTreeRemove";
        verified(sc, rd, struct, r, g.kind === 1 ? r.member : r.admin, ev.sig, `goneRecord(${ua})`);
      }
      evidence.set(ua, ok ? g.epoch : null);
    }
    return evidence.get(ua) !== null && evidence.get(ua) <= n - 1;
  };
  const rightful = (n) => {
    const c = recs[n];
    const me = rosters[n - 1][c.leaf];
    if (!me || me.ua !== c.author || me.keyId !== c.keyId) return false;
    if (adminsAt(n - 1).includes(c.author)) return true;
    if (!sameList(c.admins, adminsAt(n - 1)) || c.adds.some((x) => x.ua !== c.author)) return false;
    return c.removes.every((x) => x.ua === c.author || goneAt(x.ua, n));
  };
  const right = new Map();
  for (let n = Math.max(joinEpoch, 1); n <= last; n++) right.set(n, rightful(n));
  if (endEpoch !== null) right.set(endEpoch, rightful(endEpoch));
  // 6. the secret range's pieces, by public data only, all read before anything is opened (C22)
  const plan = [];
  for (let n = joinEpoch; n <= last; n++) {
    if (n === 0) {
      const wrap = rd.wrapAt(0, leaf);
      if (hex(pc.structHash("Wrap", wrap)) !== S0.wrapHashes[leaf]) corrupt(`wrapAt(0,${leaf})`);
      plan.push({ n, wrap });
      continue;
    }
    const c = recs[n];
    const p = { n, own: c.author === dev.ua && c.keyId === dev.keyId && c.leaf === leaf, j: -1 };
    p.list = rd.pathListOf(n);
    if (
      p.list.ctTargets.length !== c.ctCount ||
      hex(tr.pathListHash(p.list.ctTargets, p.list.ctHashes)) !== c.ctListHash
    )
      corrupt(`pathListOf(${n})`);
    if (!p.own) {
      const mine = new Set([2 * leaf, ...tr.directPath(2 * leaf, c.leaves)]);
      p.j = p.list.ctTargets.findIndex((x) => mine.has(x));
      if (p.j >= 0) {
        p.ct = rd.pathCtAt(n, p.j);
        if (hex(tr.treeStructHash("PathCt", p.ct)) !== p.list.ctHashes[p.j]) corrupt(`pathCtAt(${n},${p.j})`);
      }
    }
    if (n === joinEpoch) {
      p.wrap = rd.wrapAt(n, wrapIndex);
      if (hex(pc.structHash("Wrap", p.wrap)) !== c.wrapHashes[wrapIndex]) corrupt(`wrapAt(${n},${wrapIndex})`);
    }
    plan.push(p);
  }
  // the secrets, from those bytes only
  const held = new Map([[2 * leaf, { kemPk: hex(dev.kemPk), key: dev.key }]]);
  let inForce = null;
  let flagged = false;
  const epochs = [];
  const warnings = [];
  for (const p of plan) {
    const n = p.n;
    const c = recs[n];
    let res;
    if (n === 0) res = openGenesis(sc, a, dev, p);
    else if (!right.get(n)) res = { state: "not followed", reason: "rights" };
    else res = (p.own ? ownCommit : othersCommit)(sc, a, dev, p, held);
    if (n > 0) {
      for (const x of [c.leaf, ...c.removes.map((r) => r.leaf), ...c.adds.map((r) => r.leaf)])
        for (const y of tr.directPath(2 * x, c.leaves)) held.delete(y);
      for (const [x, k] of res.derived ?? []) held.set(x, { kemPk: hex(k.kemPk), key: k });
    }
    let info = null;
    if (res.state === "followed") {
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
      // a device that did not follow an epoch has no info in force from that epoch on (fable-r3-1)
      [inForce, flagged] = [null, false];
    }
    if (res.state === "compromise") {
      const live = (x) =>
        leaves[x.leaf]?.ua === x.ua && leaves[x.leaf].keyId === x.keyId && leaves[x.leaf].joinEpoch === n;
      warnings.push({
        epoch: n,
        adds: c.adds.map((x) => ({ leaf: x.leaf, ua: x.ua, keyId: x.keyId })),
        removes: c.removes,
        adminsChanged: !sameList(c.admins, adminsAt(n - 1)),
        leavesLeft: c.adds.filter(live).map((x) => x.leaf),
      });
    }
    const row = { epoch: n, epochId: ids[n], state: res.state };
    if (res.reason) row.reason = res.reason;
    if (res.K) row.K = hex(res.K);
    Object.assign(row, { info, inForce, flagged });
    epochs.push(row);
  }
  return {
    inSession: true,
    reads: rd.log,
    leaf,
    joinEpoch,
    endEpoch,
    /** the right of the commit that took the key out (§10 step 4); nothing is opened there */
    endRightful: endEpoch === null ? null : right.get(endEpoch),
    rosters,
    epochs,
    warnings,
    held: [...held.keys()].sort((x, y) => x - y),
    heldKeys: held,
    pin: pinOf(a),
  };
}

/** What a holder of node secrets alone (`held`: node → `{ kemPk, key }`, a leaked set) gets from commit `n`: its `K`, or the
 *  reason it gets none (fable-6, codex-15). */
export function withHeld(sc, rd, n, held) {
  const a = anchor(sc, rd);
  if (!a.recs[n]) a.read(n);
  const list = rd.pathListOf(n);
  const j = list.ctTargets.findIndex((t) => held.has(t));
  const p = { n, list, j, ct: j >= 0 ? rd.pathCtAt(n, j) : null };
  return othersCommit(sc, a, null, p, new Map(held));
}

function openGenesis(sc, a, dev, p) {
  const joiner = openTreeWrap(sc, { wrap: p.wrap, ctxId: a.gctx, epochId: a.sid, kemPk: dev.kemPk }, dev.key);
  if (!joiner) return { state: "not followed", reason: "opening failed" };
  const sch = schedule(sc, joiner, genesisFields(a.S0));
  const info = openTreeInfo(sc, sch.K, a.sid, a.sid, a.S0.sealedInfo);
  return info ? { state: "followed", K: sch.K, info } : { state: "not followed", reason: "info does not open" };
}

/** The tail of a commit's processing: the joiner, the Welcome when there is one, the schedule, the confirmation (C12). */
function finish(sc, a, c, p, dev, commitSecret) {
  const epochId = a.ids[c.epoch];
  const joiner = joinerSecret(sc, commitSecret, a.treeId, epochId);
  if (p.wrap) {
    const w = openTreeWrap(sc, { wrap: p.wrap, ctxId: a.treeId, epochId, kemPk: dev.kemPk }, dev.key);
    if (!w || hex(w) !== hex(joiner)) return { state: "not followed", reason: "welcome disagrees" };
  }
  const sch = schedule(sc, joiner, commitFields(c));
  const info = openTreeInfo(sc, sch.K, a.sid, epochId, c.sealedInfo);
  return info ? { state: "followed", K: sch.K, info } : { state: "not followed", reason: "info does not open" };
}

/** Another member's commit: the one ciphertext over its leaf, upward with the key comparison (§10). */
function othersCommit(sc, a, dev, p, held) {
  const c = a.recs[p.n];
  const path = pathFromList(c.leaf, p.list.ctTargets, c.leaves);
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

/** Its own commit: `ps[0]` from the seed; reproduced is both tests, the node keys and the info (codex-r3-4), else the
 *  compromise warning, never "not followed" (R10, fable-r2-1). */
function ownCommit(sc, a, dev, p) {
  const c = a.recs[p.n];
  if (!dev.kemSeed) return { state: "not followed", reason: "random key" };
  const path = pathFromList(c.leaf, p.list.ctTargets, c.leaves);
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
  const e = r.epochs.at(-1);
  return e && e.epoch === r.pin.epoch && e.state === "followed" && e.inForce !== null && !e.flagged
    ? JSON.parse(e.inForce)
    : null;
}

/** The public tree a commit is built on, from the views: the checkpoint, the anchored head (the cold tree rebuilt from the
 *  signed members at epoch 0), and `keyOf(node)`, each fetched key against the hash that entered the root (codex-1). */
export function prepareCommit(sc, rd, store = null) {
  const a = anchor(sc, rd);
  checkPin(a, store);
  const tree = {
    leaves: a.t.leaves,
    used: a.t.used,
    nodes: Array(tr.nodeWidth(a.t.leaves)).fill(null),
    hash: [],
    goneUa: [],
    goneKey: [],
  };
  a.leaves.forEach((l, i) => l.ua !== ZERO && (tree.nodes[2 * i] = { ua: l.ua, keyId: l.keyId, kemHash: l.kemHash }));
  a.nodes.forEach((n, x) => x % 2 === 1 && n.keyHash !== ZERO && (tree.nodes[x] = { keyHash: n.keyHash }));
  for (const ua of new Set(a.leaves.filter((l) => l.ua !== ZERO).map((l) => l.ua)))
    if (rd.goneOf(ua).kind !== 0) tree.goneUa.push(ua);
  const t = tr.treeFromJson({ ...tree, goneOwnKey: {} });
  const keyOf = (x) => {
    const n = t.nodes[x];
    const k = x % 2 === 0 ? rd.kemKeyAt(n.ua, n.keyId) : rd.treeNodeKey(x);
    if (kemHashOf(k) !== (x % 2 === 0 ? n.kemHash : n.keyHash)) refuse("TreeKeyHash");
    return k;
  };
  const head = a.head === 0 ? { treeHash: tr.treeHash(t) } : a.recs[a.head];
  return { tree: t, parent: { epochId: a.ids[a.head], epoch: a.head, treeHash: head.treeHash }, keyOf, pin: pinOf(a) };
}

/** Receipts (R11): a tree session sends none automatically, whatever the store list says; mode 0 keeps its default. */
export const autoReceipts = (groupMode, storeDefault) => groupMode === 0 && storeDefault;

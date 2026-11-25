// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// PqChat TreeKEM mode (`groupMode = 1`), T1a of docs/superpowers/plans/2026-11-23-pqchat-treekem.md; spec
// docs/superpowers/specs/2026-11-23-pqchat-treekem.md §4, §6, §8: the tree math of RFC 9420 Appendix C, resolution, the
// filtered path, ctTargets and the target that covers a leaf, `th`, applying a commit's Removes, Adds and path with the
// contract's refusals (the no-return sets included). The byte formats of smartcontracts/vectors/pqchat/tree.json. UNAUDITED.
import { keccak_256, concatBytes, hex as hexOf } from "./bytes.js";
import { encodeType, hashStruct } from "./evm.js";
import { uaMessage } from "./ua.js";
import { PqChatError, TYPE_STRINGS, DS_C, PURPOSE_PQCHAT, structHash, checkKemPk } from "./pqchat.js";

/** `used ≤ TREE_LEAVES_MAX` (owner, R-ruling of 2026-11-23). */
export const TREE_LEAVES_MAX = 256;
/** The contract's other bounds of a commit (C10, C24; `PqGroupBase`, `PqGroupTree._treeBounds`): Adds plus Removes, the admin
 *  list, the live leaves of one UA after the commit (D-5). */
export const TREE_CHANGES_MAX = 32;
export const TREE_ADMINS_MAX = 32;
export const KEYS_PER_UA_MAX = 8;
/** 0x-hex, lower case, of bytes or of a hex string. */
const hex = (v) => (typeof v === "string" ? v.toLowerCase() : hexOf(v));
const ZERO = hex(new Uint8Array(32));
const refuse = (code) => {
  throw new PqChatError(code);
};

// ------------------------------------------------------------------ RFC 9420 Appendix C (n = the number of leaves)

/** The count of trailing one bits of `x`. */
export const level = (x) => {
  let k = 0;
  while ((x >> k) & 1) k++;
  return k;
};
export const nodeWidth = (n) => (n === 0 ? 0 : 2 * (n - 1) + 1);
export const root = (n) => (n <= 1 ? 0 : 2 ** Math.floor(Math.log2(nodeWidth(n))) - 1);
export const left = (x) => {
  const k = level(x);
  if (k === 0) throw new Error("a leaf has no children");
  return x ^ (1 << (k - 1));
};
export const right = (x) => {
  const k = level(x);
  if (k === 0) throw new Error("a leaf has no children");
  return x ^ (3 << (k - 1));
};
export const parent = (x, n) => {
  if (x === root(n)) throw new Error("the root has no parent");
  const k = level(x);
  const b = (x >> (k + 1)) & 1;
  return (x | (1 << k)) ^ (b << (k + 1));
};
export const sibling = (x, n) => {
  const p = parent(x, n);
  return x < p ? right(p) : left(p);
};
/** The ancestors of `x` up to the root, the root included. */
export const directPath = (x, n) => {
  if (!(Number.isInteger(x) && x >= 0 && x < nodeWidth(n))) refuse("PqChatShape");
  const out = [];
  for (let r = root(n); x !== r; ) out.push((x = parent(x, n)));
  return out;
};
/** The sibling of `x` and of each node of its direct path but the root. */
export const copath = (x, n) => [x, ...directPath(x, n)].slice(0, -1).map((y) => sibling(y, n));

/** RFC 9420's tree-math test vectors (mlswg/mls-implementations, test-vectors/tree-math.json), one row per tree size. */
export const treeMathRows = (sizes) =>
  sizes.map((n) => {
    const w = nodeWidth(n);
    const all = (f) => Array.from({ length: w }, (_, x) => f(x));
    const or = (f) => (x) => {
      try {
        return f(x);
      } catch {
        return null;
      }
    };
    return {
      n_leaves: n,
      n_nodes: w,
      root: root(n),
      left: all(or(left)),
      right: all(or(right)),
      parent: all(or((x) => parent(x, n))),
      sibling: all(or((x) => sibling(x, n))),
    };
  });

// ------------------------------------------------------------------ the tree (§4)

/** The smallest power of two `≥ used` (1 when used ≤ 1). */
const sizeFor = (used) => 2 ** Math.ceil(Math.log2(Math.max(used, 1)));
/** A tree: `nodes[x]` is null (blank), a leaf `{ ua, keyId, kemHash }` or a parent `{ keyHash }`; `hash[x]` its `th`. The
 *  no-return sets (C28, owner R14, R16; never cleared): `goneUa` the UAs that left or were removed; the pair set
 *  `goneOwnKey` (per UA the `kemHash`es taken out of its leaves while it stayed a member); the session-wide set `goneKey`
 *  (the `kemHash` of every key a UA's leaves held when they were blanked and that UA was gone). Hex strings. */
const clone = (t) => ({
  leaves: t.leaves,
  used: t.used,
  nodes: t.nodes.slice(),
  hash: t.hash.slice(),
  goneUa: new Set(t.goneUa),
  goneOwnKey: new Map([...(t.goneOwnKey ?? [])].map(([ua, ks]) => [ua, new Set(ks)])),
  goneKey: new Set(t.goneKey),
});
const pairOut = (t, ua, kemHash) => {
  if (!t.goneOwnKey.has(ua)) t.goneOwnKey.set(ua, new Set());
  t.goneOwnKey.get(ua).add(kemHash);
};
const norm = (k) => ({ ua: hex(k.ua), keyId: Number(k.keyId), kemHash: hex(k.kemHash) });
const live = (t) => t.nodes.filter((n, x) => n && x % 2 === 0);

/** The cold tree of a session (§8): leaf `i` = `members[i]` with its registry `kemHash`, every parent blank. */
export function coldTree(members) {
  if (members.length > TREE_LEAVES_MAX) refuse("PqChatShape");
  const leaves = sizeFor(members.length);
  const t = {
    leaves,
    used: members.length,
    nodes: Array(nodeWidth(leaves)).fill(null),
    hash: [],
    goneUa: [],
    goneKey: [],
  };
  members.forEach((m, i) => {
    if (live(t).some((n) => n.kemHash === hex(m.kemHash))) refuse("PqChatTreeKeyLive");
    t.nodes[2 * i] = norm(m);
  });
  return rehashAll(clone(t));
}

/** Mark UAs `gone` (a landed `treeLeave` or `treeRemove`, C28): their leaves are owed to the next commit, which writes
 *  their keys session-wide when it blanks them (R16). */
export function markGone(t, uas) {
  const u = clone(t);
  for (const ua of uas) u.goneUa.add(hex(ua));
  return u;
}

/** RFC 9420 §4.1.2 without unmerged leaves, in ascending node index. */
export function resolution(t, x) {
  if (t.nodes[x]) return [x];
  if (level(x) === 0) return [];
  return [...resolution(t, left(x)), ...resolution(t, right(x))];
}

/** The filtered path of leaf `leaf`: each ancestor whose copath child resolves to something, upward, with that resolution. */
export function filteredPath(t, leaf) {
  const out = [];
  let below = 2 * leaf;
  for (const node of directPath(below, t.leaves)) {
    const child = sibling(below, t.leaves);
    const targets = resolution(t, child);
    if (targets.length) out.push({ node, child, targets });
    below = node;
  }
  return out;
}

/** The targets of a commit's path ciphertexts: by path level upward, then by ascending target. */
export const ctTargets = (t, leaf) => filteredPath(t, leaf).flatMap((p) => p.targets);

/** `keccak256(abi.encodePacked(ctTargets))`, each entry 4 B big-endian, as the list is stored (§5, §7). */
export const ctTargetsHash = (list) =>
  hex(keccak_256(concatBytes(...list.map((v) => Uint8Array.of(v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255)))));

/** The ciphertext of `author`'s commit that member leaf `leaf` opens: the target of the resolution under their common
 *  ancestor that is `leaf`'s node or one of its ancestors. Null for the author itself and for a blank leaf. */
export function coverOf(t, author, leaf) {
  if (leaf === author || !t.nodes[2 * leaf]) return null;
  const mine = new Set([2 * leaf, ...directPath(2 * leaf, t.leaves)]);
  let index = 0;
  for (const [k, p] of filteredPath(t, author).entries()) {
    for (const target of p.targets) {
      if (mine.has(target)) return { index, level: k, node: p.node, target };
      index++;
    }
  }
  return null;
}

// ------------------------------------------------------------------ th (RFC 9420 §7.8, typed)

/** `th(x)` from the hashes `h` of its children. */
function th(t, x, h) {
  const n = t.nodes[x];
  if (level(x) === 0) {
    return n
      ? hex(hashStruct(TREE_TYPES, "TreeLeaf", { leaf: x / 2, ua: n.ua, keyId: n.keyId, kemHash: n.kemHash }))
      : ZERO;
  }
  const l = h[left(x)] ?? ZERO;
  const r = h[right(x)] ?? ZERO;
  if (!n && l === ZERO && r === ZERO) return ZERO;
  return hex(hashStruct(TREE_TYPES, "TreeParent", { keyHash: n ? n.keyHash : ZERO, left: l, right: r }));
}
const byLevel = (xs) => [...xs].sort((a, b) => level(a) - level(b) || a - b);

/** Every node's `th`, recomputed from the nodes alone. */
export function nodeHashes(t) {
  const h = Array(nodeWidth(t.leaves)).fill(ZERO);
  for (const x of byLevel(h.keys())) h[x] = th(t, x, h);
  return h;
}
/** The tree with its kept hashes recomputed whole. */
export function rehashAll(t) {
  t.hash = nodeHashes(t);
  return t;
}
export const treeHash = (t) => (t.leaves === 0 ? ZERO : nodeHashes(t)[root(t.leaves)]);

/** Recompute `th` along the direct paths of the changed leaves `xs`, bottom-up, every node after all the changes
 *  (fable-9, codex-19: no sibling hash of an earlier revision). */
function rehashPaths(t, xs) {
  const h = [...t.hash, ...Array(Math.max(0, nodeWidth(t.leaves) - t.hash.length)).fill(ZERO)];
  const todo = new Set();
  for (const x of xs) for (const y of [x, ...directPath(x, t.leaves)]) todo.add(y);
  for (const x of byLevel(todo)) h[x] = th(t, x, h);
  t.hash = h;
}

// ------------------------------------------------------------------ applying a commit (§8, the contract's order)

/** Blank the direct path of node `x`. */
const blankPath = (t, x) => {
  for (const y of directPath(x, t.leaves)) t.nodes[y] = null;
};
const grow = (t) => {
  t.leaves *= 2;
  t.nodes.push(...Array(nodeWidth(t.leaves) - t.nodes.length).fill(null));
};

/** The Removes and Adds of a commit, with the refusals of §8; the tree after them, its path not yet set. */
function applyChanges(tree, { author, leaf, keyId, removes = [], adds = [] }) {
  if (removes.length + adds.length > TREE_CHANGES_MAX) refuse("PqChatShape");
  const t = clone(tree);
  const me = t.nodes[2 * leaf];
  if (leaf >= t.leaves || !me || me.ua !== hex(author) || me.keyId !== Number(keyId)) refuse("PqChatTreeLeaf");
  if (t.goneUa.has(me.ua)) refuse("PqChatRemovedKept");
  const touched = new Set([2 * leaf]);
  const out = [];
  for (const r of removes) {
    const n = t.nodes[2 * r.leaf];
    const k = { ua: hex(r.ua), keyId: Number(r.keyId) };
    if (r.leaf === leaf || r.leaf >= t.leaves || !n || n.ua !== k.ua || n.keyId !== k.keyId) refuse("PqChatTreeLeaf");
    t.nodes[2 * r.leaf] = null;
    blankPath(t, 2 * r.leaf);
    out.push(n);
    touched.add(2 * r.leaf);
  }
  for (const a of adds) {
    const k = norm(a);
    if (t.goneUa.has(k.ua)) refuse("PqChatTreeReturn");
    if (live(t).some((n) => n.kemHash === k.kemHash)) refuse("PqChatTreeKeyLive");
    if (a.leaf > t.used || t.nodes[2 * a.leaf] || (a.leaf === t.used && t.used === TREE_LEAVES_MAX))
      refuse("PqChatTreeLeaf");
    if (a.leaf === t.used && ++t.used > t.leaves) grow(t);
    t.nodes[2 * a.leaf] = k;
    blankPath(t, 2 * a.leaf);
    touched.add(2 * a.leaf);
  }
  // on the tree after the Adds (fable-r3-4): a UA left with no leaf is gone; each removed key at its level (R16): its UA
  // gone, session-wide; else the pair. Then each Add's verdict, a Remove of this same commit included.
  for (const n of out) if (!live(t).some((m) => m.ua === n.ua)) t.goneUa.add(n.ua);
  for (const n of out) if (t.goneUa.has(n.ua)) t.goneKey.add(n.kemHash);
  for (const n of out) if (!t.goneUa.has(n.ua)) pairOut(t, n.ua, n.kemHash);
  if (live(t).some((n) => t.goneUa.has(n.ua))) refuse("PqChatRemovedKept");
  if (adds.some((a) => live(t).filter((n) => n.ua === hex(a.ua)).length > KEYS_PER_UA_MAX)) refuse("PqChatShape");
  for (const a of adds) {
    if (t.goneKey.has(hex(a.kemHash))) refuse("PqChatTreeKeyReturn");
    if (t.goneOwnKey.get(hex(a.ua))?.has(hex(a.kemHash))) refuse("PqChatTreeOwnKeyReturn");
  }
  return { t, touched };
}

/** The filtered path of `leaf` on the tree after `changes` (a commit's Removes and Adds): what its author keys. */
export const filteredPathAfter = (tree, leaf, changes = {}) => {
  const me = tree.nodes[2 * leaf];
  return filteredPath(applyChanges(tree, { author: me.ua, keyId: me.keyId, leaf, ...changes }).t, leaf);
};

/** A commit applied in the contract's order (§8 completion steps 2–4): Removes, Adds, the `gone` UAs after the Adds, the
 *  author's filtered path keyed by `nodeKeyHashes` (its length the walk's, `PqChatTreeTargets`), the rest of its direct path
 *  blanked, `th` recomputed along every changed path. Returns `{ tree, ctTargets, treeHash }`. */
export function applyCommit(tree, c) {
  const { t, touched } = applyChanges(tree, c);
  const p = filteredPath(t, c.leaf);
  if (p.length !== c.nodeKeyHashes.length) refuse("PqChatTreeTargets");
  blankPath(t, 2 * c.leaf);
  p.forEach((q, k) => (t.nodes[q.node] = { keyHash: hex(c.nodeKeyHashes[k]) }));
  rehashPaths(t, touched);
  return { tree: t, ctTargets: p.flatMap((q) => q.targets), treeHash: t.hash[root(t.leaves)] };
}

/** The admin list and the rights of a commit (§8, §9; `PqGroupTree._walkJudge`, `_keepsAdmins`) on the tree before it (`tree`, its
 *  `goneUa` the UAs gone at the head) and after it (`after`, `applyCommit`'s): `admins` strictly sorted, at most
 *  `TREE_ADMINS_MAX` (`PqChatShape`), none of them gone or left with no leaf by the commit (`PqChatRemovedKept`); a list other
 *  than the head's less those UAs keeps one admin with a live leaf (`PqChatTreeAdmins`); and the commit is plain (it keeps the
 *  admins in that sense, adds only its author's UA, removes only its author's leaves or a gone UA's) or its author is in the
 *  head's `admins` (`PqChatNotAdmin`, C8). Dropping a gone admin is plain (F-2, E-2). */
export function judgeCommit(tree, after, c, headAdmins) {
  const admins = c.admins.map(hex);
  const head = headAdmins.map(hex);
  if (admins.length > TREE_ADMINS_MAX || admins.some((x, i) => i > 0 && x <= admins[i - 1])) refuse("PqChatShape");
  const out = (ua) => after.goneUa.has(ua);
  if (admins.some(out)) refuse("PqChatRemovedKept");
  const keeps = JSON.stringify(admins) === JSON.stringify(head.filter((x) => !out(x)));
  if (!keeps && !admins.some((x) => live(after).some((n) => n.ua === x))) refuse("PqChatTreeAdmins");
  const author = hex(c.author);
  const plain =
    keeps &&
    c.adds.every((x) => hex(x.ua) === author) &&
    c.removes.every((x) => hex(x.ua) === author || tree.goneUa.has(hex(x.ua)));
  if (!plain && !head.includes(author)) refuse("PqChatNotAdmin");
}

// ------------------------------------------------------------------ records (§6), treeId and genesisCtx (§5)

/** The type strings, exactly as spec §6 fixes them; the field lists are parsed from them and `encodeType` must give them back. */
export const TREE_TYPE_STRINGS = Object.freeze({
  PqChatCommit:
    "PqChatCommit(bytes32 sessionId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32 treeId," +
    "bytes32 parentTreeHash,uint32 leaf,uint64 keyId,uint32 leaves,bytes32[] admins,TreeRemove[] removes,TreeAdd[] adds," +
    "bytes32[] wrapHashes,bytes32[] nodeKeyHashes,uint32 ctCount,bytes32 ctListHash,bytes32 treeHash,bytes sealedInfo)" +
    "TreeAdd(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 via,bytes32 kemHash)TreeRemove(uint32 leaf,bytes32 ua,uint64 keyId)",
  TreeAdd: "TreeAdd(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 via,bytes32 kemHash)",
  TreeRemove: "TreeRemove(uint32 leaf,bytes32 ua,uint64 keyId)",
  PathList: "PathList(uint32[] ctTargets,bytes32[] ctHashes)",
  PathCt: "PathCt(bytes mlkemCt,bytes32 x25519Eph,bytes sealedSecret)",
  PqChatTreeLeave: "PqChatTreeLeave(bytes32 sessionId,bytes32 treeId,bytes32 epochId,bytes32 member,uint64 nonce)",
  PqChatTreeRemove:
    "PqChatTreeRemove(bytes32 sessionId,bytes32 treeId,bytes32 epochId,uint64 nextEpoch,bytes32[] members," +
    "bytes32 admin,uint64 nonce)",
  // PqChatSession's fields (pqchat-sigs) in its order without wrapHashes and sealedInfo; hashed, never signed (§5, C29)
  TreeGenesis:
    "TreeGenesis(bytes32 creator,uint64 nonce,bytes32 homeChain,address homeChatContract,bytes32[] admins," +
    "MemberKey[] members,uint8 groupMode)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  TreeLeaf: "TreeLeaf(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 kemHash)",
  TreeParent: "TreeParent(bytes32 keyHash,bytes32 left,bytes32 right)",
});
const fieldsOf = (s) =>
  s
    .match(/^\w+\(([^)]*)\)/)[1]
    .split(",")
    .map((f) => {
      const [type, name] = f.split(" ");
      return { name, type };
    });
export const TREE_TYPES = Object.freeze(
  Object.fromEntries(
    [["MemberKey", TYPE_STRINGS.MemberKey], ...Object.entries(TREE_TYPE_STRINGS)].map(([n, s]) => [n, fieldsOf(s)]),
  ),
);
for (const name of Object.keys(TREE_TYPE_STRINGS)) {
  if (encodeType(TREE_TYPES, name) !== TREE_TYPE_STRINGS[name])
    throw new Error(`encodeType(${name}) differs from its type string`);
}
export const TREE_TYPEHASH = Object.freeze(
  Object.fromEntries(Object.entries(TREE_TYPE_STRINGS).map(([n, s]) => [n, keccak_256(new TextEncoder().encode(s))])),
);

export const treeStructHash = (name, s) => hashStruct(TREE_TYPES, name, s);
/** `typed(s) = keccak256(0x1901 ‖ DS_C ‖ hashStruct(s))`, as every PqChat record (CTR-CHAT-03). */
export const treeTyped = (name, s) => keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), DS_C, treeStructHash(name, s)));
/** What the signer signs: `uaMessage(kind, PURPOSE_PQCHAT, typed(s))`. */
export const treeSignedDigest = (kind, name, s) => uaMessage(kind, PURPOSE_PQCHAT, treeTyped(name, s));
/** The EIP-712 hash of an array of structs: keccak256 of their struct hashes (`hash(removes)`, `hash(adds)`, §5). */
export const arrayHash = (name, items) => keccak_256(concatBytes(...items.map((x) => treeStructHash(name, x))));
/** `ctListHash = hashStruct(PathList)`; of two empty arrays when `ctCount` is 0 (codex-r2-14). */
export const pathListHash = (ctTargets, ctHashes) => treeStructHash("PathList", { ctTargets, ctHashes });

/** `treeId = hashStruct(PqChatSession)` of the signed session record (C16). */
export const treeId = (session) => structHash("PqChatSession", session);
/** `genesisCtx = hashStruct(TreeGenesis)`: the session's fields without wrapHashes and sealedInfo (C29); each one given. */
export function genesisCtx(session) {
  const g = {};
  for (const f of TREE_TYPES.TreeGenesis) {
    if (session[f.name] === undefined) refuse("PqChatShape");
    g[f.name] = session[f.name];
  }
  return treeStructHash("TreeGenesis", g);
}

// ------------------------------------------------------------------ the key admission check (§8, C19, C32)

/** `p = 2^255 − 19`. */
export const P25519 = 2n ** 255n - 19n;
/** The canonical X25519 values of small order (0, 1, the two of order 8, p − 1): an all-zero output in kem.rs. */
export const SMALL_ORDER_X25519 = Object.freeze([
  0n,
  1n,
  325606250916557431795983626356110631294008115727848805560023387167927233504n,
  39382357235489614581723060781553021112529911719440698176882885853963445705823n,
  P25519 - 1n,
]);

/** The public admission check of a scheme-1 `kemPk`, the same in the contract, `ua-rs` and here: scheme byte 1, 1,601 B,
 *  every 12-bit coefficient of `ek` below 3,329 (checkKemPk, P14); `pk_X` canonical (bit 255 clear, below p) and of none of
 *  the five small orders. A rule on bytes: it does not make an admitted key the only one its secret opens (R15). */
export function admitKemKey(kemPk) {
  const k = checkKemPk(kemPk);
  const u = k.pkX.reduceRight((a, b) => (a << 8n) | BigInt(b), 0n);
  if (u >> 255n) refuse("pkX bit 255");
  if (u >= P25519) refuse("pkX not below p");
  if (SMALL_ORDER_X25519.includes(u)) refuse("pkX small order");
  return k;
}

// ------------------------------------------------------------------ the JSON form of tree.json

/** A tree as tree.json writes it: nodes, size, and the no-return sets sorted. */
export const treeJson = (t) => ({
  leaves: t.leaves,
  used: t.used,
  nodes: t.nodes,
  goneUa: [...t.goneUa].sort(),
  goneOwnKey: Object.fromEntries(
    [...t.goneOwnKey].sort(([a], [b]) => (a < b ? -1 : 1)).map(([u, ks]) => [u, [...ks].sort()]),
  ),
  goneKey: [...t.goneKey].sort(),
});
export const treeFromJson = (j) => rehashAll(clone({ ...j, hash: [], goneOwnKey: Object.entries(j.goneOwnKey ?? {}) }));

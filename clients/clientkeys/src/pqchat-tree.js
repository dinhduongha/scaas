// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// PqChat TreeKEM mode (`groupMode = 1`), T1a of docs/superpowers/plans/2026-11-23-pqchat-treekem.md; spec
// docs/superpowers/specs/2026-11-23-pqchat-treekem.md §4, §6, §8: the tree math of RFC 9420 Appendix C, resolution, the
// filtered path, ctTargets and the target that covers a leaf, `th`, applying a commit's Removes, Adds and path with the
// contract's refusals (the no-return sets included). The byte formats of smartcontracts/vectors/pqchat/tree.json. UNAUDITED.
import { keccak_256, concatBytes, hex as hexOf } from "./bytes.js";
import { hashStruct } from "./evm.js";
import { PqChatError } from "./pqchat.js";

/** `used ≤ TREE_LEAVES_MAX` (owner, R-ruling of 2026-11-23). */
export const TREE_LEAVES_MAX = 256;
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
  const out = [];
  for (let r = root(n); x !== r;) out.push((x = parent(x, n)));
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
 *  no-return sets (C28, owner R16; never cleared): `gone` the UAs that left or were removed; `goneKey` the session-wide
 *  `kemHash`es, every key a gone UA held; `ownKey` per UA the `kemHash`es it took out by a key change while it stayed.
 *  Hex strings. */
const clone = (t) => ({
  leaves: t.leaves,
  used: t.used,
  nodes: t.nodes.slice(),
  hash: t.hash.slice(),
  gone: new Set(t.gone),
  goneKey: new Set(t.goneKey),
  ownKey: new Map([...(t.ownKey ?? [])].map(([ua, ks]) => [ua, new Set(ks)])),
});
/** The refusal of an Add of a `(ua, kemHash)` pair its UA took out by a key change (owner R16). PROVISIONAL name: the spec
 *  commit of R16 fixes it. */
export const OWN_KEY_RETURN = "PqChatTreeOwnKeyReturn";
const takeOut = (t, ua, kemHash) => {
  if (!t.ownKey.has(ua)) t.ownKey.set(ua, new Set());
  t.ownKey.get(ua).add(kemHash);
};
/** A UA is gone: every key it held, live or taken out before, becomes session-wide (R16). */
const goneUA = (t, ua) => {
  t.gone.add(ua);
  for (const k of t.ownKey.get(ua) ?? []) t.goneKey.add(k);
  for (const n of live(t)) if (n.ua === ua) t.goneKey.add(n.kemHash);
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
    gone: [],
    goneKey: [],
  };
  members.forEach((m, i) => {
    if (live(t).some((n) => n.kemHash === hex(m.kemHash))) refuse("PqChatTreeKeyLive");
    t.nodes[2 * i] = norm(m);
  });
  return rehashAll(clone(t));
}

/** Mark UAs `gone` (a landed `treeLeave` or `treeRemove`, C28): their leaves are owed to the next commit. */
export function markGone(t, uas) {
  const u = clone(t);
  for (const ua of uas) goneUA(u, hex(ua));
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

const HASH_TYPES = {
  TreeLeaf: [
    { name: "leaf", type: "uint32" },
    { name: "ua", type: "bytes32" },
    { name: "keyId", type: "uint64" },
    { name: "kemHash", type: "bytes32" },
  ],
  TreeParent: [
    { name: "keyHash", type: "bytes32" },
    { name: "left", type: "bytes32" },
    { name: "right", type: "bytes32" },
  ],
};
/** `th(x)` from the hashes `h` of its children. */
function th(t, x, h) {
  const n = t.nodes[x];
  if (level(x) === 0) {
    return n
      ? hex(hashStruct(HASH_TYPES, "TreeLeaf", { leaf: x / 2, ua: n.ua, keyId: n.keyId, kemHash: n.kemHash }))
      : ZERO;
  }
  const l = h[left(x)] ?? ZERO;
  const r = h[right(x)] ?? ZERO;
  if (!n && l === ZERO && r === ZERO) return ZERO;
  return hex(hashStruct(HASH_TYPES, "TreeParent", { keyHash: n ? n.keyHash : ZERO, left: l, right: r }));
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
  const t = clone(tree);
  const me = t.nodes[2 * leaf];
  if (leaf >= t.leaves || !me || me.ua !== hex(author) || me.keyId !== Number(keyId)) refuse("PqChatTreeLeaf");
  if (t.gone.has(me.ua)) refuse("PqChatRemovedKept");
  const touched = new Set([2 * leaf]);
  const changed = new Set();
  for (const r of removes) {
    const n = t.nodes[2 * r.leaf];
    const k = norm(r);
    if (r.leaf === leaf || r.leaf >= t.leaves || !n || n.ua !== k.ua || n.keyId !== k.keyId) refuse("PqChatTreeLeaf");
    t.nodes[2 * r.leaf] = null;
    blankPath(t, 2 * r.leaf);
    takeOut(t, n.ua, n.kemHash);
    changed.add(n.ua);
    touched.add(2 * r.leaf);
  }
  for (const a of adds) {
    const k = norm(a);
    if (t.gone.has(k.ua)) refuse("PqChatTreeReturn");
    if (t.ownKey.get(k.ua)?.has(k.kemHash)) refuse(OWN_KEY_RETURN);
    if (t.goneKey.has(k.kemHash)) refuse("PqChatTreeKeyReturn");
    if (live(t).some((n) => n.kemHash === k.kemHash)) refuse("PqChatTreeKeyLive");
    if (a.leaf > t.used || t.nodes[2 * a.leaf] || (a.leaf === t.used && t.used === TREE_LEAVES_MAX))
      refuse("PqChatTreeLeaf");
    if (a.leaf === t.used && ++t.used > t.leaves) grow(t);
    t.nodes[2 * a.leaf] = k;
    blankPath(t, 2 * a.leaf);
    touched.add(2 * a.leaf);
  }
  // on the tree after the Adds (fable-r3-4): a UA left with no leaf is gone
  // its keys become session-wide, so an Add of one of them in this same commit is refused here
  for (const ua of changed) if (!live(t).some((n) => n.ua === ua)) goneUA(t, ua);
  if (live(t).some((n) => t.gone.has(n.ua))) refuse("PqChatRemovedKept");
  if (adds.some((a) => t.goneKey.has(hex(a.kemHash)))) refuse("PqChatTreeKeyReturn");
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

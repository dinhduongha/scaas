// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// PqChat TreeKEM, T1a (src/pqchat-tree.js; spec docs/superpowers/specs/2026-11-23-pqchat-treekem.md §4, §6, §8): the tree math
// against RFC 9420's own vectors, resolution, the filtered path, ctTargets and the target that covers a leaf, `th`, applying
// Removes, Adds and the path with each named refusal and its positive twin. UNAUDITED.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { x25519 } from "@noble/curves/ed25519.js";
import * as tr from "../src/pqchat-tree.js";
import * as pc from "../src/pqchat.js";
import { uaMessage } from "../src/ua.js";
import { hex, keccak_256, utf8ToBytes, concatBytes, abiEncode } from "../src/bytes.js";

const Z32 = hex(new Uint8Array(32));
const id = (s) => hex(keccak_256(utf8ToBytes(`scaas/pqchat/tree-test/${s}`)));
const key = (name, keyId = 1) => ({ ua: id(`ua/${name}`), keyId, kemHash: id(`kem/${name}/${keyId}`) });
const refused = (code, f) => assert.throws(f, (e) => e.code === code, `expected ${code}`);

// ------------------------------------------------------------------ tree math (RFC 9420 Appendix C)

// RFC 9420's test-vectors/tree-math.json of mlswg/mls-implementations (commit e4d3b074f3452a6fa3a7681ede6c963c410aafd9):
// the sha256 of the file, whose bytes are JSON.stringify(rows, null, 2) for n_leaves 1, 2, 4, …, 512.
const RFC_TREE_MATH_SHA256 = "27f04891f56106593b74b674445f01b845e173953770c084deb2f8cf5592e2fc";

test("tree math reproduces RFC 9420's tree-math vectors byte for byte (n_leaves 1 to 512)", () => {
  const rows = tr.treeMathRows([1, 2, 4, 8, 16, 32, 64, 128, 256, 512]);
  assert.equal(
    createHash("sha256")
      .update(JSON.stringify(rows, null, 2))
      .digest("hex"),
    RFC_TREE_MATH_SHA256,
  );
  assert.deepEqual(tr.directPath(0, 8), [1, 3, 7]);
  assert.deepEqual(tr.copath(0, 8), [2, 5, 11]);
  assert.equal(tr.root(1), 0);
  assert.deepEqual(tr.directPath(0, 1), []);
});

// ------------------------------------------------------------------ the picture of spec §4

/** Leaves A 0, B 1, C 2, D 3, E 4, G 6 of 8; node 5 (above C and D) and A's path 1, 3, 7 hold keys. */
function picture() {
  const t = tr.coldTree(["A", "B", "C", "D", "E", "x", "G"].map((n) => key(n)));
  t.nodes[10] = null; // leaf 5 blank
  t.nodes[5] = { keyHash: id("node/5") };
  for (const x of [1, 3, 7]) t.nodes[x] = { keyHash: id(`node/${x}`) };
  return tr.rehashAll(t);
}

test("spec §4's picture: resolution, filtered path, ctTargets [2, 5, 8, 12], the target that covers each leaf", () => {
  const t = picture();
  assert.equal(t.leaves, 8);
  assert.deepEqual(tr.resolution(t, 11), [8, 12]);
  assert.deepEqual(tr.resolution(t, 13), [12]);
  assert.deepEqual(tr.resolution(t, 10), []);
  assert.deepEqual(tr.resolution(t, 5), [5]);
  assert.deepEqual(
    tr.filteredPath(t, 0).map((p) => [p.node, p.child, p.targets]),
    [
      [1, 2, [2]],
      [3, 5, [5]],
      [7, 11, [8, 12]],
    ],
  );
  assert.deepEqual(tr.ctTargets(t, 0), [2, 5, 8, 12]);
  const cover = (l) => tr.coverOf(t, 0, l);
  assert.deepEqual(cover(1), { index: 0, level: 0, node: 1, target: 2 });
  assert.deepEqual(cover(2), { index: 1, level: 1, node: 3, target: 5 });
  assert.deepEqual(cover(3), { index: 1, level: 1, node: 3, target: 5 });
  assert.deepEqual(cover(4), { index: 2, level: 2, node: 7, target: 8 });
  assert.deepEqual(cover(6), { index: 3, level: 2, node: 7, target: 12 });
  assert.equal(cover(0), null);
  assert.equal(cover(5), null);
});

test("resolution: a blank leaf gives nothing, a blank parent its children left then right, ascending", () => {
  const t = tr.coldTree([key("A"), key("B"), key("C")]); // leaf 3 blank, every parent blank
  assert.deepEqual(tr.resolution(t, 6), []);
  assert.deepEqual(tr.resolution(t, 5), [4]);
  assert.deepEqual(tr.resolution(t, 3), [0, 2, 4]);
  assert.deepEqual(tr.ctTargets(t, 2), [0, 2]); // node 5's copath child (leaf 3) is blank: 5 is dropped
});

test("the filtered path drops each ancestor whose copath child resolves to nothing", () => {
  const t = tr.coldTree([key("A"), key("B")]);
  const g = tr.applyCommit(t, {
    author: key("A").ua,
    leaf: 0,
    keyId: 1,
    removes: [],
    adds: [{ leaf: 2, ...key("C") }],
    nodeKeyHashes: [id("k/1"), id("k/3")],
  }).tree;
  assert.equal(g.leaves, 4);
  assert.deepEqual(
    tr.filteredPath(g, 0).map((p) => p.node),
    [1, 3],
  );
  const lone = tr.applyCommit(g, {
    author: key("A").ua,
    leaf: 0,
    keyId: 1,
    removes: [
      { leaf: 1, ...key("B") },
      { leaf: 2, ...key("C") },
    ],
    adds: [],
    nodeKeyHashes: [],
  });
  assert.deepEqual(tr.filteredPath(lone.tree, 0), []);
  assert.deepEqual(lone.ctTargets, []);
});

// ------------------------------------------------------------------ th (RFC 9420 §7.8, typed)

const word = (v) => abiEncode(["uint256"], [v]);
const TL = keccak_256(utf8ToBytes("TreeLeaf(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 kemHash)"));
const TP = keccak_256(utf8ToBytes("TreeParent(bytes32 keyHash,bytes32 left,bytes32 right)"));
const b32 = (h) => Uint8Array.from(Buffer.from(h.slice(2), "hex"));

test("th by hand: a leaf hashes (leaf, ua, keyId, kemHash); a blank parent over one member keeps keyHash 0", () => {
  const a = key("A", 7);
  const t = tr.coldTree([a]);
  const leafHash = hex(keccak_256(concatBytes(TL, word(0), b32(a.ua), word(7), b32(a.kemHash))));
  assert.equal(tr.treeHash(t), leafHash); // one leaf: the root is the leaf
  const g = tr.applyCommit(t, { author: a.ua, leaf: 0, keyId: 7, removes: [], adds: [], nodeKeyHashes: [] });
  assert.equal(g.treeHash, leafHash);
  const t3 = tr.coldTree([a, key("B"), key("C")]);
  const h = tr.nodeHashes(t3);
  assert.equal(h[6], Z32);
  assert.equal(h[5], hex(keccak_256(concatBytes(TP, new Uint8Array(32), b32(h[4]), new Uint8Array(32)))));
  assert.equal(h[3], hex(keccak_256(concatBytes(TP, new Uint8Array(32), b32(h[1]), b32(h[5])))));
  assert.equal(tr.treeHash(t3), h[3]);
});

test("th: an empty subtree hashes to 0; growth keeps the old root's hash and costs no slot", () => {
  assert.equal(tr.treeHash(tr.coldTree([])), Z32);
  const two = tr.coldTree([key("A"), key("B")]);
  const three = tr.coldTree([key("A"), key("B"), key("C")]);
  assert.equal(tr.nodeHashes(three)[1], tr.treeHash(two));
  const g = tr.applyCommit(two, {
    author: key("B").ua,
    leaf: 1,
    keyId: 1,
    removes: [],
    adds: [{ leaf: 2, ...key("C") }],
    nodeKeyHashes: [id("k/1"), id("k/3")],
  });
  assert.deepEqual([g.tree.used, g.tree.leaves], [3, 4]);
  assert.deepEqual(g.tree.hash, tr.nodeHashes(g.tree));
});

test("th binds each leaf's kemHash: another key under the same (ua, keyId) gives another root", () => {
  const a = key("A");
  const t1 = tr.coldTree([a, key("B")]);
  const t2 = tr.coldTree([{ ...a, kemHash: id("other") }, key("B")]);
  assert.notEqual(tr.treeHash(t1), tr.treeHash(t2));
});

// ------------------------------------------------------------------ applying a commit

const A = key("A"),
  B = key("B"),
  C = key("C"),
  D = key("D"),
  E = key("E"),
  F = key("F");
const commit = (t, author, x = {}) => tr.applyCommit(t, { removes: [], adds: [], nodeKeyHashes: [], ...author, ...x });
const by = (k, leaf) => ({ author: k.ua, keyId: k.keyId, leaf });
const path = (t, leaf, n = tr.filteredPathAfter(t, leaf).length) =>
  Array.from({ length: n }, (_, i) => id(`path/${leaf}/${i}`));

/** Every commit result: the hashes kept along the changed paths equal a recomputation of the whole tree. */
const whole = (r) => {
  assert.deepEqual(r.tree.hash, tr.nodeHashes(r.tree));
  assert.equal(r.treeHash, r.tree.hash[tr.root(r.tree.leaves)]);
  return r;
};

test("a commit sets the filtered path, blanks the rest of the direct path, and every hash is of the tree after it", () => {
  const t = tr.coldTree([A, B, C, D, E]); // 8 leaves, 5 used
  const r = whole(commit(t, by(C, 2), { nodeKeyHashes: path(t, 2) }));
  assert.deepEqual(
    tr.filteredPath(r.tree, 2).map((p) => p.node),
    [5, 3, 7],
  );
  assert.deepEqual(r.ctTargets, [6, 0, 2, 8]);
  assert.deepEqual(
    [5, 3, 7].map((x) => r.tree.nodes[x].keyHash),
    path(t, 2),
  );
  // a later commit by A blanks node 5? no: 5 is not on A's direct path; A's path is 1, 3, 7
  const s = whole(commit(r.tree, by(A, 0), { nodeKeyHashes: path(r.tree, 0) }));
  assert.equal(s.tree.nodes[5].keyHash, path(t, 2)[0]);
  assert.deepEqual(s.ctTargets, [2, 5, 8]);
  // a Remove of E blanks node 11's subtree: A's root target list loses 8, and 7 drops out of the filtered path
  const u = whole(commit(s.tree, by(A, 0), { removes: [{ leaf: 4, ...E }], nodeKeyHashes: [id("p/1"), id("p/3")] }));
  assert.equal(u.tree.nodes[7], null);
  assert.deepEqual(u.ctTargets, [2, 5]);
});

test("an Add and a Remove under a copath child of the author: every sibling hash is taken after the changes (fable-9)", () => {
  const t = whole(
    commit(tr.coldTree([A, B, C, D, E, F]), by(A, 0), { nodeKeyHashes: path(tr.coldTree([A, B, C, D, E, F]), 0) }),
  ).tree;
  // C's commit keys node 5 (under A's copath child at node 3); then A removes D and adds a key in leaf 6, both under copath children
  const c = whole(commit(t, by(C, 2), { nodeKeyHashes: path(t, 2) })).tree;
  const G = key("G");
  const x = { removes: [{ leaf: 3, ...D }], adds: [{ leaf: 6, ...G }] };
  const n = tr.filteredPathAfter(c, 0, x).length;
  const r = whole(commit(c, by(A, 0), { ...x, nodeKeyHashes: path(c, 0, n) }));
  assert.deepEqual(r.ctTargets, [2, 4, 8, 10, 12]);
  assert.equal(r.tree.nodes[5], null); // D's direct path blanked
  assert.equal(r.tree.nodes[13], null); // G's direct path blanked
});

test("an Add takes a blank leaf below used or leaf used; leaves doubles; the record's leaves is the size after", () => {
  const t = tr.coldTree([A, B]);
  const r = whole(
    commit(t, by(A, 0), {
      adds: [
        { leaf: 2, ...C },
        { leaf: 3, ...D },
        { leaf: 4, ...E },
      ],
      nodeKeyHashes: [id("1"), id("3"), id("7")],
    }),
  );
  assert.equal(r.tree.leaves, 8);
  assert.equal(r.tree.used, 5);
  const s = whole(commit(r.tree, by(A, 0), { removes: [{ leaf: 1, ...B }], nodeKeyHashes: [id("3"), id("7")] }));
  const back = whole(
    commit(s.tree, by(A, 0), { adds: [{ leaf: 1, ...key("B2") }], nodeKeyHashes: [id("1"), id("3"), id("7")] }),
  );
  assert.equal(back.tree.used, 5);
  refused("PqChatTreeLeaf", () =>
    commit(t, by(A, 0), { adds: [{ leaf: 3, ...C }], nodeKeyHashes: [id("1"), id("3")] }),
  );
  refused("PqChatTreeLeaf", () => commit(t, by(A, 0), { adds: [{ leaf: 1, ...C }], nodeKeyHashes: [id("1")] }));
  refused("PqChatTreeLeaf", () =>
    commit(t, by(A, 0), {
      adds: [
        { leaf: 3, ...D },
        { leaf: 2, ...C },
      ],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  // the twins
  whole(commit(t, by(A, 0), { adds: [{ leaf: 2, ...C }], nodeKeyHashes: [id("1"), id("3")] }));
  whole(
    commit(t, by(A, 0), {
      adds: [
        { leaf: 2, ...C },
        { leaf: 3, ...D },
      ],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
});

test("the tree never grows past TREE_LEAVES_MAX", () => {
  assert.equal(tr.TREE_LEAVES_MAX, 256);
  const full = tr.coldTree(Array.from({ length: 256 }, (_, i) => key(`m${i}`)));
  assert.equal(full.leaves, 256);
  refused("PqChatShape", () => tr.coldTree(Array.from({ length: 257 }, (_, i) => key(`m${i}`))));
  refused("PqChatTreeLeaf", () =>
    commit(full, by(key("m0"), 0), { adds: [{ leaf: 256, ...key("over") }], nodeKeyHashes: path(full, 0) }),
  );
  const freed = commit(full, by(key("m0"), 0), {
    removes: [{ leaf: 255, ...key("m255") }],
    nodeKeyHashes: path(full, 0),
  });
  whole(commit(freed.tree, by(key("m0"), 0), { adds: [{ leaf: 255, ...key("over") }], nodeKeyHashes: path(full, 0) }));
});

test("refusals, each with its twin: the author's leaf, a Remove's named key, the author's own leaf removed", () => {
  const t = tr.coldTree([A, B, C]);
  const twin = () => whole(commit(t, by(A, 0), { removes: [{ leaf: 1, ...B }], nodeKeyHashes: [id("3")] }));
  twin();
  refused("PqChatTreeLeaf", () => commit(t, by(B, 0), { nodeKeyHashes: path(t, 0) }));
  refused("PqChatTreeLeaf", () => commit(t, { ...by(A, 0), keyId: 2 }, { nodeKeyHashes: path(t, 0) }));
  refused("PqChatTreeLeaf", () =>
    commit(t, by(A, 0), { removes: [{ leaf: 1, ...B, keyId: 2 }], nodeKeyHashes: [id("3")] }),
  );
  refused("PqChatTreeLeaf", () => commit(t, by(A, 0), { removes: [{ leaf: 3, ...B }], nodeKeyHashes: [id("3")] }));
  refused("PqChatTreeLeaf", () => commit(t, by(A, 0), { removes: [{ leaf: 0, ...A }], nodeKeyHashes: [] }));
});

test("refusals, each with its twin: a live key, a key added twice, a key taken out (this commit or before), a gone UA", () => {
  const t = tr.coldTree([A, B, C]);
  const D2 = key("D", 2);
  whole(commit(t, by(A, 0), { adds: [{ leaf: 3, ...D }], nodeKeyHashes: path(t, 0, 2) }));
  refused("PqChatTreeKeyLive", () =>
    commit(t, by(A, 0), { adds: [{ leaf: 3, ...D, kemHash: B.kemHash }], nodeKeyHashes: [id("1"), id("3")] }),
  );
  refused("PqChatTreeKeyLive", () =>
    commit(t, by(A, 0), {
      adds: [
        { leaf: 3, ...D },
        { leaf: 4, ...D2, kemHash: D.kemHash },
      ],
      nodeKeyHashes: [id("1"), id("3"), id("7")],
    }),
  );
  whole(
    commit(t, by(A, 0), {
      adds: [
        { leaf: 3, ...D },
        { leaf: 4, ...D2 },
      ],
      nodeKeyHashes: [id("1"), id("3"), id("7")],
    }),
  );
  // a key removed in this same commit does not come back, under any UA
  refused("PqChatTreeKeyReturn", () =>
    commit(t, by(A, 0), {
      removes: [{ leaf: 2, ...C }],
      adds: [{ leaf: 2, ...D, kemHash: C.kemHash }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  // nor one removed before
  const r = whole(commit(t, by(A, 0), { removes: [{ leaf: 2, ...C }], nodeKeyHashes: [id("1")] }));
  assert.deepEqual([...r.tree.goneKey], [C.kemHash]);
  refused("PqChatTreeKeyReturn", () =>
    commit(r.tree, by(A, 0), { adds: [{ leaf: 2, ...D, kemHash: C.kemHash }], nodeKeyHashes: [id("1"), id("3")] }),
  );
  // C held one leaf: it is gone, and no key of C comes back
  assert.deepEqual([...r.tree.goneUa], [C.ua]);
  refused("PqChatTreeReturn", () =>
    commit(r.tree, by(A, 0), { adds: [{ leaf: 2, ...key("C", 9) }], nodeKeyHashes: [id("1"), id("3")] }),
  );
  whole(commit(r.tree, by(A, 0), { adds: [{ leaf: 2, ...D }], nodeKeyHashes: [id("1"), id("3")] }));
});

test("a UA is judged after the Adds: its only leaf removed and a new key added in one commit, it stays (fable-r3-4)", () => {
  const t = tr.coldTree([A, B, C]);
  const C2 = key("C", 2);
  const r = whole(
    commit(t, by(A, 0), {
      removes: [{ leaf: 2, ...C }],
      adds: [{ leaf: 3, ...C2 }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  assert.deepEqual([...r.tree.goneUa], []);
  assert.deepEqual([...r.tree.goneKey], []);
  assert.deepEqual([...r.tree.goneOwnKey.get(C.ua)], [C.kemHash]);
  const twin = whole(commit(t, by(A, 0), { removes: [{ leaf: 2, ...C }], nodeKeyHashes: [id("1")] }));
  assert.deepEqual([...twin.tree.goneUa], [C.ua]);
});

test("no gone UA keeps a leaf, nor commits (PqChatRemovedKept); the path length is the walk's (PqChatTreeTargets)", () => {
  const t = tr.markGone(tr.coldTree([A, B, C]), [B.ua]);
  refused("PqChatRemovedKept", () => commit(t, by(A, 0), { nodeKeyHashes: path(t, 0) }));
  refused("PqChatRemovedKept", () => commit(t, by(B, 1), { removes: [{ leaf: 2, ...C }], nodeKeyHashes: [id("1")] }));
  whole(commit(t, by(A, 0), { removes: [{ leaf: 1, ...B }], nodeKeyHashes: [id("3")] }));
  const u = tr.coldTree([A, B, C]);
  refused("PqChatTreeTargets", () => commit(u, by(A, 0), { nodeKeyHashes: [id("1")] }));
  refused("PqChatTreeTargets", () => commit(u, by(A, 0), { nodeKeyHashes: [id("1"), id("3"), id("7")] }));
  whole(commit(u, by(A, 0), { nodeKeyHashes: [id("1"), id("3")] }));
});

test("ctTargetsHash: keccak256 of the targets packed 4 B big-endian, as the list is stored", () => {
  assert.equal(tr.ctTargetsHash([]), hex(keccak_256(new Uint8Array(0))));
  assert.equal(tr.ctTargetsHash([2, 0x01020304]), hex(keccak_256(Uint8Array.of(0, 0, 0, 2, 1, 2, 3, 4))));
});

test("R16: a key taken out of a UA that stays is a pair; the keys of a UA that goes are session-wide, earlier pairs stay", () => {
  const C2 = key("C", 2);
  const own = (f) => refused("PqChatTreeOwnKeyReturn", f);
  const t = tr.coldTree([A, B, C, C2]);
  // C takes out its keyId 1 and stays a member with keyId 2: only the pair (C, kemHash)
  const r = whole(commit(t, by(C2, 3), { removes: [{ leaf: 2, ...C }], nodeKeyHashes: [id("3")] }));
  assert.deepEqual([...r.tree.goneUa], []);
  assert.deepEqual([...r.tree.goneKey], []);
  assert.deepEqual([...r.tree.goneOwnKey.get(C.ua)], [C.kemHash]);
  // C may not add those bytes again under any keyId, in that commit or later
  own(() =>
    commit(t, by(C2, 3), {
      removes: [{ leaf: 2, ...C }],
      adds: [{ leaf: 2, ...C }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  own(() =>
    commit(r.tree, by(C2, 3), {
      adds: [{ leaf: 2, ...key("C", 5), kemHash: C.kemHash }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  // another UA may add the same bytes, later or in the same commit (the removed UA stays): no burn by own-key churn
  const D = { ...key("D"), kemHash: C.kemHash };
  whole(commit(r.tree, by(C2, 3), { adds: [{ leaf: 2, ...D }], nodeKeyHashes: [id("1"), id("3")] }));
  whole(
    commit(t, by(C2, 3), {
      removes: [{ leaf: 2, ...C }],
      adds: [{ leaf: 2, ...D }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  // C leaves: a mark only; the commit that blanks its last leaf writes that leaf's key session-wide; the earlier pair stays
  const g = tr.markGone(r.tree, [C.ua]);
  assert.deepEqual([...g.goneKey], []);
  const b = whole(commit(g, by(A, 0), { removes: [{ leaf: 3, ...C2 }], nodeKeyHashes: [id("1")] }));
  assert.deepEqual([...b.tree.goneKey], [C2.kemHash]);
  assert.deepEqual([...b.tree.goneOwnKey.get(C.ua)], [C.kemHash]);
  refused("PqChatTreeKeyReturn", () =>
    commit(b.tree, by(A, 0), {
      adds: [{ leaf: 2, ...key("E"), kemHash: C2.kemHash }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  refused("PqChatTreeReturn", () =>
    commit(b.tree, by(A, 0), { adds: [{ leaf: 2, ...key("C", 3) }], nodeKeyHashes: [id("1"), id("3")] }),
  );
  whole(commit(b.tree, by(A, 0), { adds: [{ leaf: 2, ...D }], nodeKeyHashes: [id("1"), id("3")] }));
  // a commit that leaves the UA no leaf: its key is session-wide in that same commit, under any UA
  refused("PqChatTreeKeyReturn", () =>
    commit(tr.coldTree([A, B, C]), by(A, 0), {
      removes: [{ leaf: 2, ...C }],
      adds: [{ leaf: 3, ...D }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
});

// ------------------------------------------------------------------ records (spec §6), treeId and genesisCtx (§5)

// The type strings as spec §6 writes them, typed here a second time: a field dropped or moved in src/pqchat-tree.js fails here.
const SPEC = {
  PqChatCommit:
    "PqChatCommit(bytes32 sessionId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32 treeId,bytes32 parentTreeHash,uint32 leaf,uint64 keyId,uint32 leaves,bytes32[] admins,TreeRemove[] removes,TreeAdd[] adds,bytes32[] wrapHashes,bytes32[] nodeKeyHashes,uint32 ctCount,bytes32 ctListHash,bytes32 treeHash,bytes sealedInfo)TreeAdd(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 via,bytes32 kemHash)TreeRemove(uint32 leaf,bytes32 ua,uint64 keyId)",
  TreeAdd: "TreeAdd(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 via,bytes32 kemHash)",
  TreeRemove: "TreeRemove(uint32 leaf,bytes32 ua,uint64 keyId)",
  PathList: "PathList(uint32[] ctTargets,bytes32[] ctHashes)",
  PathCt: "PathCt(bytes mlkemCt,bytes32 x25519Eph,bytes sealedSecret)",
  PqChatTreeLeave: "PqChatTreeLeave(bytes32 sessionId,bytes32 treeId,bytes32 epochId,bytes32 member,uint64 nonce)",
  PqChatTreeRemove:
    "PqChatTreeRemove(bytes32 sessionId,bytes32 treeId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,bytes32 admin,uint64 nonce)",
  TreeGenesis:
    "TreeGenesis(bytes32 creator,uint64 nonce,bytes32 homeChain,address homeChatContract,bytes32[] admins,MemberKey[] members,uint8 groupMode)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  TreeLeaf: "TreeLeaf(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 kemHash)",
  TreeParent: "TreeParent(bytes32 keyHash,bytes32 left,bytes32 right)",
};

test("every type string is spec §6's; its typehash is keccak256 of it; encodeType gives it back", () => {
  for (const [name, s] of Object.entries(SPEC)) {
    assert.equal(tr.TREE_TYPE_STRINGS[name], s, name);
    assert.equal(hex(tr.TREE_TYPEHASH[name]), hex(keccak_256(utf8ToBytes(s))), name);
  }
  assert.deepEqual(Object.keys(tr.TREE_TYPE_STRINGS).sort(), Object.keys(SPEC).sort());
});

/** pqchat-sigs adds `groupMode` to PqChatSession; this branch has it once rebased on pqchat-sigs (plan §1). */
const MODE = pc.TYPES.PqChatSession.some((f) => f.name === "groupMode");
const session = {
  creator: id("ua/A"),
  nonce: 3,
  homeChain: id("chain"),
  homeChatContract: "0x" + "11".repeat(20),
  admins: [id("ua/A")],
  members: [
    { ua: id("ua/A"), keyId: 1, via: Z32 },
    { ua: id("ua/B"), keyId: 1, via: id("via") },
  ],
  wrapHashes: [id("w0"), id("w1")],
  sealedInfo: "0x" + "ab".repeat(284),
  ...(MODE ? { groupMode: 1 } : {}),
};
const tree = { ...session, groupMode: 1 };

test(
  "TreeGenesis is PqChatSession's type without wrapHashes and sealedInfo",
  { todo: MODE ? false : "pqchat-sigs" },
  () => {
    const s = pc.TYPES.PqChatSession.filter((f) => f.name !== "wrapHashes" && f.name !== "sealedInfo");
    assert.deepEqual(tr.TREE_TYPES.TreeGenesis, s);
  },
);

test("genesisCtx: every genesis field moves it, wrapHashes and sealedInfo do not; treeId is PqChatSession's struct hash", () => {
  const g = hex(tr.genesisCtx(tree));
  assert.equal(hex(tr.genesisCtx({ ...tree, wrapHashes: [id("x"), id("y")], sealedInfo: "0x01" })), g);
  for (const [f, v] of Object.entries({
    creator: id("ua/B"),
    nonce: 4,
    homeChain: id("chain2"),
    homeChatContract: "0x" + "22".repeat(20),
    admins: [id("ua/B")],
    members: session.members.slice(1),
    groupMode: 2,
  }))
    assert.notEqual(hex(tr.genesisCtx({ ...tree, [f]: v })), g, f);
  refused("PqChatShape", () => tr.genesisCtx({ ...tree, groupMode: undefined }));
  assert.equal(hex(tr.treeId(session)), hex(pc.structHash("PqChatSession", session)));
  assert.notEqual(hex(tr.treeId({ ...session, wrapHashes: [id("x"), id("y")] })), hex(tr.treeId(session)));
});

test("PathList of the empty list (codex-r2-14), by hand; arrays hash as EIP-712 arrays of struct hashes", () => {
  const empty = keccak_256(new Uint8Array(0));
  assert.equal(hex(tr.pathListHash([], [])), hex(keccak_256(concatBytes(tr.TREE_TYPEHASH.PathList, empty, empty))));
  const l = tr.pathListHash([2, 5], [id("c0"), id("c1")]);
  const by = keccak_256(
    concatBytes(
      tr.TREE_TYPEHASH.PathList,
      keccak_256(concatBytes(word(2), word(5))),
      keccak_256(concatBytes(b32(id("c0")), b32(id("c1")))),
    ),
  );
  assert.equal(hex(l), hex(by));
  const adds = [{ leaf: 3, ua: id("ua/D"), keyId: 2, via: Z32, kemHash: id("kem/D") }];
  assert.equal(hex(tr.arrayHash("TreeAdd", adds)), hex(keccak_256(tr.treeStructHash("TreeAdd", adds[0]))));
  assert.equal(hex(tr.arrayHash("TreeRemove", [])), hex(empty));
});

test("typed and signed digests: 0x1901 ‖ DS_C ‖ hashStruct, under PURPOSE_PQCHAT", () => {
  const l = { sessionId: id("s"), treeId: id("t"), epochId: id("e"), member: id("ua/B"), nonce: 9 };
  const typed = keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), pc.DS_C, tr.treeStructHash("PqChatTreeLeave", l)));
  assert.equal(hex(tr.treeTyped("PqChatTreeLeave", l)), hex(typed));
  assert.equal(
    hex(tr.treeSignedDigest(0x0131, "PqChatTreeLeave", l)),
    hex(uaMessage(0x0131, pc.PURPOSE_PQCHAT, typed)),
  );
  // the flat leave of the same fields without treeId is another digest (codex-r2-5)
  const { treeId: _, ...flat } = l;
  assert.notEqual(hex(pc.typed("PqChatLeave", flat)), hex(typed));
});

// ------------------------------------------------------------------ the key admission check (spec §8, C19, C32)

const P = 2n ** 255n - 19n;
const le = (v) => {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++, v >>= 8n) out[i] = Number(v & 255n);
  return out;
};
const kh = (l) => keccak_256(utf8ToBytes(`scaas/pqchat/tree-test/${l}`));
const real = pc.kemKey(concatBytes(kh("mlkem/0"), kh("mlkem/1")), kh("x25519"));
const withX = (pkX) => concatBytes(real.kemPk.subarray(0, 1569), pkX);
const asU = (pk) => pk.subarray(1569).reduceRight((a, b) => (a << 8n) | BigInt(b), 0n);
const admitRefused = (code, pk) =>
  assert.throws(
    () => tr.admitKemKey(pk),
    (e) => e.code === code,
    code,
  );

test("admission: a real key, u = 9 and a coefficient of 3,328 pass; 3,329, the scheme byte and the length are refused", () => {
  tr.admitKemKey(real.kemPk);
  tr.admitKemKey(withX(le(9n)));
  const coeff = (c) => {
    const pk = real.kemPk.slice();
    pk[1] = c & 255;
    pk[2] = (pk[2] & 0xf0) | (c >> 8);
    return pk;
  };
  tr.admitKemKey(coeff(3328));
  admitRefused("modulus check", coeff(3329));
  admitRefused("wrong scheme byte", concatBytes(Uint8Array.of(2), real.kemPk.subarray(1)));
  admitRefused("wrong length", real.kemPk.subarray(0, 1600));
  admitRefused("wrong length", concatBytes(real.kemPk, Uint8Array.of(0)));
});

test("admission: pk_X canonical (bit 255 clear, below p) and none of the five small-order values (C32, codex-r2-2)", () => {
  assert.deepEqual(tr.SMALL_ORDER_X25519, [
    0n,
    1n,
    325606250916557431795983626356110631294008115727848805560023387167927233504n,
    39382357235489614581723060781553021112529911719440698176882885853963445705823n,
    P - 1n,
  ]);
  for (const u of tr.SMALL_ORDER_X25519) {
    admitRefused("pkX small order", withX(le(u)));
    // a positive control that the list is the right one: X25519 to it gives the all-zero output kem.rs refuses
    assert.throws(() => pc.encaps(withX(le(u)), new Uint8Array(32), keccak_256(utf8ToBytes("e"))), /all-zero X25519/);
  }
  admitRefused("pkX not below p", withX(le(P)));
  admitRefused("pkX not below p", withX(le(P + 1n)));
  admitRefused("pkX not below p", withX(le(P + 9n)));
  const hi = real.kemPk.slice();
  hi[1600] |= 0x80;
  admitRefused("pkX bit 255", hi);
  // twins: the same values reduced, as X25519 reads them, are accepted points
  tr.admitKemKey(withX(le(9n)));
  tr.admitKemKey(withX(le(asU(hi) - 2n ** 255n)));
});

// ------------------------------------------------------------------ smartcontracts/vectors/pqchat/tree.json

const V = JSON.parse(readFileSync(new URL("../../../smartcontracts/vectors/pqchat/tree.json", import.meta.url)));
const byName = (rows) => Object.fromEntries(rows.map((r) => [r.name, r]));
const asRow = (t) => ({ ...tr.treeJson(t), nodeHashes: t.hash, treeHash: t.hash[tr.root(t.leaves)] });
const json = (x) => JSON.parse(JSON.stringify(x));

test("the generator reproduces every pqchat vector file byte for byte (--check)", () => {
  const r = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("../scripts/pqchat-vectors.mjs", import.meta.url)), "--check"],
    {
      encoding: "utf8",
    },
  );
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /--check: ok \(.*tree\.json\)/);
});

test("tree.json: typehashes, keys, the RFC 9420 tree-math rows", () => {
  for (const [n, { type, hash }] of Object.entries(V.typehashes)) {
    assert.equal(type, SPEC[n]);
    assert.equal(hash, hex(tr.TREE_TYPEHASH[n]));
  }
  for (const k of V.keys) {
    assert.equal(k.kemHash, hex(keccak_256(b32(k.kemPk))));
    tr.admitKemKey(b32(k.kemPk));
  }
  assert.deepEqual(V.treeMath.rows, tr.treeMathRows(V.treeMath.rows.map((r) => r.n_leaves)));
  assert.equal(
    createHash("sha256")
      .update(JSON.stringify(V.treeMath.rows, null, 2))
      .digest("hex"),
    V.treeMath.sha256,
  );
  assert.equal(V.treeMath.sha256, RFC_TREE_MATH_SHA256);
});

test("tree.json resolution rows: every node's resolution, each filtered path, ctTargets, and the covering target", () => {
  for (const row of V.resolution) {
    const t = tr.treeFromJson(row.tree);
    assert.deepEqual(json(asRow(t)), row.tree, row.name);
    assert.deepEqual(
      t.nodes.map((_, x) => tr.resolution(t, x)),
      row.resolution,
    );
    for (const [l, p] of Object.entries(row.filteredPath)) assert.deepEqual(tr.filteredPath(t, Number(l)), p);
    for (const [l, c] of Object.entries(row.ctTargets)) assert.deepEqual(tr.ctTargets(t, Number(l)), c);
    for (const c of row.cover) {
      const { author, leaf, ...rest } = c;
      assert.deepEqual(tr.coverOf(t, author, leaf), rest, `${row.name}: ${author} → ${leaf}`);
      assert.equal(row.ctTargets[author][rest.index], rest.target);
    }
  }
  assert.deepEqual(byName(V.resolution)["spec §4's picture"].ctTargets[0], [2, 5, 8, 12]);
});

test("tree.json treeHash rows: cold trees, commits from their before tree, refusals with their named error", () => {
  const keys = Object.fromEntries(V.keys.map((k) => [k.name, k]));
  const trees = {};
  for (const row of V.treeHash.cold) {
    const t = tr.coldTree(row.members.map((n) => ({ ua: keys[n].ua, keyId: keys[n].keyId, kemHash: keys[n].kemHash })));
    assert.deepEqual(json(asRow(t)), row.tree, row.name);
    trees[row.name] = row.tree;
  }
  for (const row of V.treeHash.commits) {
    const r = tr.applyCommit(tr.treeFromJson(trees[row.before]), row.commit);
    assert.deepEqual(json(asRow(r.tree)), row.after, row.name);
    assert.deepEqual(r.ctTargets, row.ctTargets);
    assert.equal(tr.ctTargetsHash(r.ctTargets), row.ctTargetsHash);
    assert.equal(r.treeHash, row.after.treeHash);
    trees[row.name] = row.after;
  }
  for (const row of V.treeHash.refused)
    refused(row.error, () => tr.applyCommit(tr.treeFromJson(trees[row.before]), row.commit));
  const names = V.treeHash.commits.map((r) => r.name);
  for (const n of ["C commits", "A removes E", "A adds F", "growth 2 to 4", "growth 8 to 16", "a key change"])
    assert.ok(names.includes(n), n);
  assert.ok(names.includes("an Add and a Remove under a copath child of the author"));
});

test("tree.json admission rows: each refusal by its check, its twin accepted; the torsion-shifted keys admitted (R15)", () => {
  const accepted = byName(V.admission.accepted);
  for (const a of V.admission.accepted) {
    tr.admitKemKey(b32(a.kemPk));
    assert.equal(a.kemHash, hex(keccak_256(b32(a.kemPk))));
  }
  for (const r of V.admission.refused) {
    assert.throws(
      () => tr.admitKemKey(b32(r.kemPk)),
      (e) => e.message === r.error,
      r.name,
    );
    tr.admitKemKey(b32(accepted[r.twin].kemPk));
  }
  assert.equal(V.admission.refused.filter((r) => r.error === "pkX small order").length, 5);
  // what the check does not give: another admitted kemHash, the same X25519 output for the fixed ephemeral scalar
  const rel = V.admission.related;
  const base = b32(accepted[rel.base].kemPk);
  assert.equal(hex(x25519.getSharedSecret(b32(rel.ephemeral), base.subarray(1569))), rel.x25519Output);
  assert.deepEqual(
    rel.shifted.map((s) => s.order),
    [4, 8],
  );
  const hashes = new Set([hex(keccak_256(base))]);
  for (const s of rel.shifted) {
    const pk = b32(s.kemPk);
    tr.admitKemKey(pk);
    assert.equal(s.kemHash, hex(keccak_256(pk)));
    hashes.add(s.kemHash);
    assert.deepEqual(pk.subarray(0, 1569), base.subarray(0, 1569));
    assert.equal(hex(x25519.getSharedSecret(b32(rel.ephemeral), pk.subarray(1569))), rel.x25519Output);
  }
  assert.equal(hashes.size, 3);
});

test("tree.json digests: treeId, genesisCtx, ids, array hashes, struct hashes, typed and signed digests", () => {
  const d = V.digests;
  assert.equal(hex(tr.treeId(d.session)), d.treeId);
  assert.equal(hex(tr.genesisCtx({ ...d.session, groupMode: d.genesisGroupMode })), d.genesisCtx);
  assert.equal(hex(pc.sessionId(d.session.creator, d.session.nonce)), d.sessionId);
  const c = d.records[0].record;
  assert.equal(hex(pc.epochId(d.sessionId, c.author, c.nonce)), d.epochId);
  assert.equal(hex(tr.arrayHash("TreeRemove", c.removes)), d.removesHash);
  assert.equal(hex(tr.arrayHash("TreeAdd", c.adds)), d.addsHash);
  assert.equal(hex(tr.pathListHash([], [])), d.emptyPathList);
  assert.equal(c.ctListHash, hex(tr.pathListHash(d.ctTargets, d.ctHashes)));
  for (const r of d.records) {
    assert.equal(hex(tr.treeStructHash(r.struct, r.record)), r.structHash, r.struct);
    if (r.typed) {
      assert.equal(hex(tr.treeTyped(r.struct, r.record)), r.typed);
      assert.equal(hex(tr.treeSignedDigest(0x0131, r.struct, r.record)), r.signedDigest);
    }
  }
});

test("tree.json noReturn rows (R16): each step's tree and sets, and each probe's verdict, replayed from the cold tree", () => {
  const keys = Object.fromEntries(V.keys.map((k) => [k.name, k]));
  const names = V.noReturn.map((s) => s.name);
  for (const n of [
    "the burn by own-key churn",
    "the front-running loop",
    "the burn by leave: treeLeave",
    "the burn by leave: treeRemove",
    "the burn by leave: an admin's commit",
    "the replacement of a UA's only key in one commit",
    "a Remove and an Add of the same bytes in one commit",
  ])
    assert.ok(names.includes(n), n);
  for (const s of V.noReturn) {
    let t = tr.coldTree(s.start.map((n) => ({ ua: keys[n].ua, keyId: keys[n].keyId, kemHash: keys[n].kemHash })));
    for (const step of s.steps) {
      t = step.leave ? tr.markGone(t, step.leave) : tr.applyCommit(t, step.commit).tree;
      assert.deepEqual(json(asRow(t)), step.tree, `${s.name} / ${step.name}`);
      for (const p of step.probes) {
        const where = `${s.name} / ${step.name} / ${p.name}`;
        if (p.verdict === "accepted") tr.applyCommit(t, p.commit);
        else
          assert.throws(
            () => tr.applyCommit(t, p.commit),
            (e) => e.code === p.verdict,
            where,
          );
      }
    }
  }
  // the churn sets only the pair; a leave sets the session-wide keys and keeps the earlier pair
  const last = (n) => V.noReturn.find((s) => s.name === n).steps.at(-1).tree;
  const churn = last("the burn by own-key churn");
  assert.deepEqual(churn.goneKey, []);
  assert.deepEqual(churn.goneOwnKey, { [keys.B.ua]: [keys.A2.kemHash] });
  for (const n of [
    "the burn by leave: treeLeave",
    "the burn by leave: treeRemove",
    "the burn by leave: an admin's commit",
  ]) {
    assert.deepEqual(last(n).goneKey, [keys.A2.kemHash, keys.B.kemHash].sort(), n);
    assert.deepEqual(last(n).goneOwnKey, { [keys.B.ua]: [keys.A3.kemHash] }, n);
    assert.deepEqual(last(n).goneUa, [keys.B.ua], n);
  }
});

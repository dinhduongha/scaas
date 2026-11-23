// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// PqChat TreeKEM, T1a (src/pqchat-tree.js; spec docs/superpowers/specs/2026-11-23-pqchat-treekem.md §4, §6, §8): the tree math
// against RFC 9420's own vectors, resolution, the filtered path, ctTargets and the target that covers a leaf, `th`, applying
// Removes, Adds and the path with each named refusal and its positive twin. UNAUDITED.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as tr from "../src/pqchat-tree.js";
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
  assert.deepEqual([...r.tree.gone], [C.ua]);
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
  assert.deepEqual([...r.tree.gone], []);
  assert.deepEqual([...r.tree.goneKey], []);
  assert.deepEqual([...r.tree.ownKey.get(C.ua)], [C.kemHash]);
  const twin = whole(commit(t, by(A, 0), { removes: [{ leaf: 2, ...C }], nodeKeyHashes: [id("1")] }));
  assert.deepEqual([...twin.tree.gone], [C.ua]);
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

test("R16: a key change takes out only the pair (ua, kemHash); a leave or removal takes out every key the UA held", () => {
  const C2 = key("C", 2);
  const t = tr.coldTree([A, B, C, C2]);
  // C changes keys: takes out keyId 1 and stays a member with keyId 2
  const r = whole(commit(t, by(C2, 3), { removes: [{ leaf: 2, ...C }], nodeKeyHashes: [id("3")] }));
  assert.deepEqual([...r.tree.gone], []);
  assert.deepEqual([...r.tree.goneKey], []);
  // C may not add that key again, in this commit or later
  tr_refusedOwn(() =>
    commit(t, by(C2, 3), {
      removes: [{ leaf: 2, ...C }],
      adds: [{ leaf: 2, ...C }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  tr_refusedOwn(() => commit(r.tree, by(C2, 3), { adds: [{ leaf: 2, ...C }], nodeKeyHashes: [id("1"), id("3")] }));
  // another UA holding the same key bytes is not burnt by C's key change (no front-running a key out of the session)
  const D = { ...key("D"), kemHash: C.kemHash };
  whole(commit(r.tree, by(C2, 3), { adds: [{ leaf: 2, ...D }], nodeKeyHashes: [id("1"), id("3")] }));
  // once C leaves, every key it held is session-wide: the one taken out before and the live one
  const g = tr.markGone(r.tree, [C.ua]);
  assert.deepEqual([...g.goneKey].sort(), [C.kemHash, C2.kemHash].sort());
  refused("PqChatTreeKeyReturn", () =>
    commit(g, by(A, 0), {
      removes: [{ leaf: 3, ...C2 }],
      adds: [{ leaf: 2, ...D }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  refused("PqChatTreeReturn", () =>
    commit(g, by(A, 0), {
      removes: [{ leaf: 3, ...C2 }],
      adds: [{ leaf: 2, ...key("C", 3) }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  whole(
    commit(g, by(A, 0), {
      removes: [{ leaf: 3, ...C2 }],
      adds: [{ leaf: 2, ...key("E") }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
  // a removal by a commit that leaves the UA no leaf: its key is session-wide in that same commit
  refused("PqChatTreeKeyReturn", () =>
    commit(tr.coldTree([A, B, C]), by(A, 0), {
      removes: [{ leaf: 2, ...C }],
      adds: [{ leaf: 3, ...D }],
      nodeKeyHashes: [id("1"), id("3")],
    }),
  );
});
const tr_refusedOwn = (f) => refused(tr.OWN_KEY_RETURN, f);

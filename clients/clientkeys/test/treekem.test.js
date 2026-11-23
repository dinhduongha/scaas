// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// PqChat TreeKEM, T1b (src/treekem.js; spec docs/superpowers/specs/2026-11-23-pqchat-treekem.md §5, §8, §10): the path secrets,
// node keys, ps[0] over its context, the path ciphertext, the schedule without init, K, the tree wrap, the info and the marker,
// creation in order, replay, the joiner, healing, the compromise warning, the checkpoint, the info in force, and the refusals
// each with its positive twin; the rows of smartcontracts/vectors/pqchat/tree-secrets.json. UNAUDITED.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as f from "../scripts/treekem-fixture.mjs";
import * as tk from "../src/treekem.js";
import * as tr from "../src/pqchat-tree.js";
import * as pc from "../src/pqchat.js";
import { kemKeyFromSeed } from "../src/kem.js";
import { hex, keccak_256, utf8ToBytes, concatBytes, abiEncode, fromHex } from "../src/bytes.js";

const sc = tk.PQCHAT_TREE;
const Z32 = f.Z32;
const H = (ikm, info, n = 32) => hkdf(sha256, ikm, new Uint8Array(0), info, n);
const l8 = (s) => utf8ToBytes(s);
const u32 = (v) => Uint8Array.of(v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
const refused = (code, fn) => assert.throws(fn, (e) => e.code === code, `expected ${code}`);
const states = (r) => r.epochs.map((e) => [e.epoch, e.state, e.reason ?? null]);
const kAt = (r, n) => r.epochs.find((e) => e.epoch === n)?.K;
const at = (r, n) => r.epochs.find((e) => e.epoch === n);
const rnd = f.rnd;

// the worlds, built once
const MAIN = f.mainScenario();
const JOINER = f.joinerScenario();
const HEAL = f.healScenario();
const GAP = f.gapScenario(false);
const GAP_CONTROL = f.gapScenario(true);
const RETIRED = f.retiredScenario();
const EMPTY = f.emptyPathScenario(null);
const EMPTY_FOREIGN = f.emptyPathScenario("H");
const ADMIN_GAP = f.adminGapScenario();
const BEHIND = f.behindScenario();

// ------------------------------------------------------------------ derivations by hand

test("the scope: PqChat's labels; another app's scope under its own prefix gives other secrets (app-agnostic)", () => {
  for (const k of ["path", "node", "commit", "ct", "joiner", "epoch", "key"])
    assert.equal(new TextDecoder().decode(sc[k]), `scaas/pqchat/v1/tree/${k}`);
  assert.equal(sc.wrap, "scaas/pqchat/v1/tree/wrap");
  assert.equal(hex(sc.tagPath), hex(keccak_256(l8("scaas/pqchat/v1/tree/path-context"))));
  assert.equal(hex(sc.tagContext), hex(keccak_256(l8("scaas/pqchat/v1/tree/context"))));
  const other = tk.treeScope("scaas/other-app/v1/tree", { infoKey: pc.infoKey, typed: sc.typed, purpose: sc.purpose });
  const ps0 = rnd("t/ps0");
  assert.notEqual(hex(tk.pathSecrets(other, ps0, 1)[1]), hex(tk.pathSecrets(sc, ps0, 1)[1]));
  const g = tk.genesisFields(MAIN.genesis.record);
  assert.notEqual(hex(tk.schedule(other, ps0, g).K), hex(tk.schedule(sc, ps0, g).K));
});

test("path secrets and node keys by hand (RFC 9420 §7.4): ps[k+1] = H(ps[k], …/path); the node key from the 96-byte seed form", () => {
  const ps0 = rnd("t/ps0");
  const ps = tk.pathSecrets(sc, ps0, 3);
  assert.equal(ps.length, 4);
  for (let k = 0; k < 3; k++) assert.equal(hex(ps[k + 1]), hex(H(ps[k], l8("scaas/pqchat/v1/tree/path"))));
  const byHand = kemKeyFromSeed(H(ps[1], l8("scaas/pqchat/v1/tree/node"), 96));
  assert.equal(hex(tk.nodeKeyOf(sc, ps[1]).kemPk), hex(byHand.kemPk));
  assert.notEqual(hex(tk.nodeKeyOf(sc, ps[2]).kemPk), hex(byHand.kemPk));
});

test("pathContext by hand; ps[0] = HKDF(kemSeed, …/commit ‖ pathContext); every bound input moves it (R4, C17, fable-1, codex-7)", () => {
  const c = MAIN.steps[1].built.record; // A's Add of D
  const targets = MAIN.steps[1].built.ctTargets;
  const byHand = keccak_256(
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
        keccak_256(l8("scaas/pqchat/v1/tree/path-context")),
        c.treeId,
        c.parentEpochId,
        c.parentTreeHash,
        c.author,
        c.nonce,
        c.leaf,
        c.keyId,
        keccak_256(concatBytes(...c.removes.map((x) => tr.treeStructHash("TreeRemove", x)))),
        keccak_256(concatBytes(...c.adds.map((x) => tr.treeStructHash("TreeAdd", x)))),
        keccak_256(concatBytes(...targets.map(u32))),
      ],
    ),
  );
  const ctx = tk.pathContext(sc, c, targets);
  assert.equal(hex(ctx), hex(byHand));
  assert.equal(MAIN.steps[1].built.pathContext, hex(ctx));
  const seed = f.deviceOf("A").kemSeed;
  assert.equal(
    hex(tk.firstPathSecret(sc, seed, ctx)),
    hex(H(seed, concatBytes(l8("scaas/pqchat/v1/tree/commit"), ctx))),
  );
  assert.equal(MAIN.steps[1].built.ps[0], hex(tk.firstPathSecret(sc, seed, ctx)));
  const moved = {
    treeId: Z32,
    parentEpochId: Z32,
    parentTreeHash: Z32,
    author: Z32,
    nonce: c.nonce + 1,
    leaf: c.leaf + 1,
    keyId: c.keyId + 1,
    removes: [{ leaf: 1, ua: Z32, keyId: 1 }],
    adds: [{ ...c.adds[0], via: Z32 }],
  };
  for (const [k, v] of Object.entries(moved))
    assert.notEqual(hex(tk.pathContext(sc, { ...c, [k]: v }, targets)), hex(ctx), k);
  assert.notEqual(hex(tk.pathContext(sc, c, [...targets].reverse())), hex(ctx), "ctTargets");
});

test("the path ciphertext: kek and aad by hand (48 B); it opens only at its tree, epoch, node and target", () => {
  const C = f.deviceOf("C");
  const x = {
    treeId: rnd("t/tree"),
    epochId: rnd("t/epoch"),
    node: 3,
    target: 4,
    kemPk: C.kemPk,
    secret: rnd("t/secret"),
  };
  const s = tk.sealPathSecret(sc, { ...x, m: rnd("t/m"), e: rnd("t/e") });
  assert.equal(fromHex(s.ct.sealedSecret).length, 48);
  const kek = H(
    s.ss,
    concatBytes(l8("scaas/pqchat/v1/tree/ct"), x.treeId, x.epochId, u32(3), u32(4), keccak_256(fromHex(C.kemPk))),
  );
  assert.equal(hex(s.kek), hex(kek));
  const open = (y) => tk.openPathSecret(sc, { ...x, ...y, ct: s.ct }, C.key);
  assert.equal(hex(open({})), hex(x.secret));
  for (const y of [{ treeId: rnd("t/tree2") }, { epochId: rnd("t/epoch2") }, { node: 1 }, { target: 6 }])
    assert.equal(open(y), null, JSON.stringify(Object.keys(y)));
  assert.equal(tk.openPathSecret(sc, { ...x, ct: s.ct }, f.deviceOf("B").key), null, "another key");
});

test("the schedule by hand; every context field moves K; epoch 0 runs under genesisCtx, never treeId (C23, C29)", () => {
  const c = MAIN.steps[0].built.record;
  const fields = tk.commitFields(c);
  const ctx = keccak_256(
    abiEncode(
      ["bytes32", "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        keccak_256(l8("scaas/pqchat/v1/tree/context")),
        c.treeId,
        MAIN.steps[0].built.epochId,
        c.epoch,
        c.parentEpochId,
        c.parentTreeHash,
        c.treeHash,
        keccak_256(concatBytes(...c.admins.map(fromHex))),
      ],
    ),
  );
  const cs = fromHex(MAIN.steps[0].built.ps.at(-1));
  const joiner = H(cs, concatBytes(l8("scaas/pqchat/v1/tree/joiner"), fromHex(c.treeId), fields.epochId));
  const S = H(joiner, concatBytes(l8("scaas/pqchat/v1/tree/epoch"), ctx));
  const K = H(S, l8("scaas/pqchat/v1/tree/key"));
  const s = tk.schedule(sc, joiner, fields);
  assert.deepEqual([hex(s.ctx), hex(s.S), hex(s.K)], [hex(ctx), hex(S), hex(K)]);
  assert.equal(hex(MAIN.steps[0].built.K), hex(K));
  assert.equal(hex(tk.joinerSecret(sc, cs, c.treeId, fields.epochId)), hex(joiner));
  for (const k of ["treeId", "epochId", "parentEpochId", "parentTreeHash", "treeHash"])
    assert.notEqual(hex(tk.schedule(sc, joiner, { ...fields, [k]: rnd(`t/${k}`) }).K), hex(K), k);
  assert.notEqual(hex(tk.schedule(sc, joiner, { ...fields, epoch: 9 }).K), hex(K), "epoch");
  assert.notEqual(hex(tk.schedule(sc, joiner, { ...fields, admins: [Z32] }).K), hex(K), "admins");
  // epoch 0
  const g = MAIN.genesis;
  const g0 = tk.genesisFields(g.record);
  assert.deepEqual(
    [hex(g0.treeId), hex(g0.epochId), g0.epoch, g0.parentEpochId, g0.parentTreeHash, g0.treeHash],
    [g.genesisCtx, g.sessionId, 0, Z32, Z32, Z32],
  );
  assert.equal(hex(tk.schedule(sc, g.joiner, g0).K), hex(g.K));
  assert.notEqual(hex(tk.schedule(sc, g.joiner, { ...g0, treeId: g.treeId }).K), hex(g.K), "under treeId");
});

test("K carries mode 0's derivations unchanged: chain, infoKey, envKey and hint are pqchat.js's of K_e", () => {
  const K = MAIN.steps[0].built.K;
  const e = MAIN.steps[0].built.epochId;
  const s = MAIN.home.sessionId;
  assert.equal(hex(sc.infoKey(K, s, e)), hex(pc.infoKey(K, s, e)));
  const sealed = MAIN.steps[0].built.record.sealedInfo;
  assert.deepEqual(tk.openTreeInfo(sc, K, s, e, sealed), { json: pc.canonicalJson(f.INFO.I1) });
  assert.equal(hex(pc.hint(K)).length, 18);
});

test("the info: a full info, the marker 'unchanged' (284 B), at most 4,124 B at genesis and in a commit, the next bucket refused (C33, codex-r2-13)", () => {
  const K = rnd("t/K");
  const n = rnd("t/n", 12);
  const marker = tk.sealTreeInfo(sc, K, Z32, Z32, null, n);
  assert.equal(fromHex(marker).length, 284);
  assert.deepEqual(tk.openTreeInfo(sc, K, Z32, Z32, marker), { marker: true });
  const fill = (len) => ({ x: "a".repeat(len - 8) }); // canonical JSON {"x":"…"} is len bytes
  assert.equal(pc.canonicalJson(fill(4092)).length, 4092);
  const big = tk.sealTreeInfo(sc, K, Z32, Z32, fill(4092), n);
  assert.equal(fromHex(big).length, tk.TREE_INFO_MAX);
  assert.deepEqual(tk.openTreeInfo(sc, K, Z32, Z32, big), { json: pc.canonicalJson(fill(4092)) });
  refused("TreeInfoSize", () => tk.sealTreeInfo(sc, K, Z32, Z32, fill(4093), n));
  assert.equal(tk.openTreeInfo(sc, rnd("t/K2"), Z32, Z32, big), null, "another K");
  // at genesis and in a commit
  const g = (info) =>
    f.createSession({
      tag: `t/info/${info.x.length}`,
      creator: "A",
      nonce: 50,
      admins: ["A"],
      members: ["A", "B"],
      info,
    });
  const w = g(fill(4092));
  assert.equal(fromHex(w.genesis.record.sealedInfo).length, 4124);
  refused("TreeInfoSize", () => g(fill(4093)));
  assert.equal(fromHex(f.commit(w, "A", { info: fill(4092) }).built.record.sealedInfo).length, 4124);
  refused("TreeInfoSize", () => f.commit(w, "A", { info: fill(4093) }));
});

test("a tree wrap opens under no flat processing, a flat wrap under no tree processing (fable-13)", () => {
  const A = f.deviceOf("A");
  const g = MAIN.genesis;
  const w = MAIN.home.epochs[0].wraps[0];
  const open = (scope, ctxId) =>
    tk.openTreeWrap(scope, { wrap: w, ctxId, epochId: g.sessionId, kemPk: A.kemPk }, A.key);
  assert.equal(hex(open(sc, g.genesisCtx)), hex(g.joiner), "the tree label under genesisCtx");
  assert.equal(open({ ...sc, wrap: "scaas/pqchat/v1/wrap" }, g.genesisCtx), null, "the flat label");
  assert.equal(open(sc, g.sessionId), null, "sessionId in place of genesisCtx");
  assert.equal(open(sc, g.treeId), null, "treeId in place of genesisCtx");
  // a flat wrap of the same joiner, by mode 0's wrapTo, does not open as a tree wrap
  const flat = pc.wrapTo({
    K: g.joiner,
    sessionId: g.genesisCtx,
    epochId: g.sessionId,
    member: A.ua,
    keyId: 1,
    kemPk: A.kemPk,
    m: rnd("t/flat-m"),
    x25519Secret: rnd("t/flat-e"),
  });
  assert.equal(
    tk.openTreeWrap(sc, { wrap: flat.wrap, ctxId: g.genesisCtx, epochId: g.sessionId, kemPk: A.kemPk }, A.key),
    null,
  );
  assert.equal(
    hex(
      tk.openTreeWrap(
        { ...sc, wrap: "scaas/pqchat/v1/wrap" },
        { wrap: flat.wrap, ctxId: g.genesisCtx, epochId: g.sessionId, kemPk: A.kemPk },
        A.key,
      ),
    ),
    hex(g.joiner),
    "the twin: under the flat label it opens",
  );
});

// ------------------------------------------------------------------ creation, the scenario, the joiner

test("creation in order (codex-r2-4): genesisCtx, K_0, the wraps and sealedInfo, the record, treeId; a fresh store recovers K_0 from its own wrap read back", () => {
  const g = MAIN.genesis;
  assert.equal(g.genesisCtx, hex(tr.genesisCtx(g.record)));
  assert.equal(g.treeId, hex(tr.treeId(g.record)));
  assert.deepEqual(
    MAIN.home.epochs[0].wraps.map((w) => hex(pc.structHash("Wrap", w))),
    g.record.wrapHashes,
  );
  for (const n of ["A", "B", "C", "C2"]) {
    const rd = tk.reader(
      f.createSession({
        tag: "main",
        creator: "A",
        nonce: 1,
        admins: ["A"],
        members: ["A", "B", "C", "C2"],
        info: f.INFO.I1,
      }).home,
    );
    const r = tk.replay(sc, rd, f.deviceOf(n));
    assert.deepEqual(states(r), [[0, "followed", null]], n);
    assert.equal(kAt(r, 0), hex(g.K), n);
    assert.ok(rd.log.includes(`wrapAt(0,${r.leaf})`), n);
    assert.equal(at(r, 0).inForce, pc.canonicalJson(f.INFO.I1));
  }
});

test("the main scenario: every member with a leaf derives the same K at every epoch; the rosters by undo equal the leaves; a non-zero via is bound", () => {
  const head = MAIN.home.epochs.length - 1;
  const Ks = MAIN.steps.filter((s) => s.built).map((s) => hex(s.built.K));
  const replays = Object.fromEntries(["A", "B", "C", "C2", "D"].map((n) => [n, f.replayOf(MAIN, n)]));
  for (const [n, r] of Object.entries(replays)) {
    for (const e of r.epochs) {
      assert.equal(e.state, "followed", `${n} ${e.epoch}`);
      assert.equal(e.K, e.epoch === 0 ? hex(MAIN.genesis.K) : Ks[e.epoch - 1], `${n} ${e.epoch}`);
    }
    for (let e = Math.max(0, r.joinEpoch - 1); e <= head; e++)
      assert.deepEqual(r.rosters[e], MAIN.rosters[e], `${n}'s roster at ${e}`);
  }
  // the periods: B gone (removed at 5), C2 taken out of a UA that stays (6): the pair
  assert.deepEqual([replays.B.joinEpoch, replays.B.endEpoch], [0, 5]);
  assert.deepEqual([replays.C2.joinEpoch, replays.C2.endEpoch], [0, 6]);
  assert.deepEqual([replays.D.joinEpoch, replays.D.endEpoch], [2, null]);
  assert.ok(
    replays.C2.reads.includes(
      `goneOwnKeyOf(${f.deviceOf("C2").ua},${hex(keccak_256(fromHex(f.deviceOf("C2").kemPk)))})`,
    ),
  );
  // C's commit 5 drops B (gone) without admin right: the evidence, B's PqChatTreeRemove, was read and verified
  assert.ok(replays.D.reads.includes(`goneRecord(${f.deviceOf("B").ua})`));
  // the via of D's Add is non-zero and bound (no tree digest canonicalises a field)
  const add = MAIN.steps[1].built.record.adds[0];
  assert.notEqual(add.via, Z32);
  assert.notEqual(
    hex(tr.treeStructHash("PqChatCommit", { ...MAIN.steps[1].built.record, adds: [{ ...add, via: Z32 }] })),
    hex(tr.treeStructHash("PqChatCommit", MAIN.steps[1].built.record)),
  );
  // the third member's commit (3, C) right after the Add: D follows it
  assert.equal(at(replays.D, 3).state, "followed");
});

test("the joiner takes its path secret (codex-5, fable-5): A's commit right after E's Add targets node 9, which D holds only from its join ciphertext", () => {
  const a = JOINER.steps[1].built;
  assert.ok(a.ctTargets.includes(9), JSON.stringify(a.ctTargets));
  const r = f.replayOf(JOINER, "D");
  assert.deepEqual(states(r), [
    [1, "followed", null],
    [2, "followed", null],
  ]);
  assert.equal(kAt(r, 2), hex(a.K));
  // the Welcome alone gives the joiner of 1, not the node above D
  assert.ok(r.reads.includes("pathCtAt(1,0)") && r.reads.includes("wrapAt(1,0)"));
});

test("repeats (fable-1, codex-7): the same change, nonce and target indices on a tree with other keys (A) and in a twin session at another home (B): ps[0] differs", () => {
  const build = (w, tree) => {
    const prep = tk.prepareCommit(sc, tk.reader(w.home));
    const B = f.deviceOf("B");
    return tk.buildCommit(sc, {
      tree: tree ?? prep.tree,
      parent: tree ? { ...prep.parent, treeHash: tr.treeHash(tree) } : prep.parent,
      sessionId: w.home.sessionId,
      treeId: w.home.treeId,
      author: B.ua,
      leaf: 1,
      keyId: 1,
      kemSeed: B.kemSeed,
      nonce: 77,
      admins: w.genesis.record.admins,
      info: null,
      keyOf: (x) => (x === 2 * 2 ? f.deviceOf("C").kemPk : x === 6 ? f.deviceOf("C2").kemPk : f.deviceOf("A").kemPk),
      rand: (x, n) => rnd(`t/repeat/${x}`, n),
    });
  };
  const w = f.createSession({
    tag: "t/repeat",
    creator: "A",
    nonce: 60,
    admins: ["A"],
    members: ["A", "B", "C", "C2"],
    info: f.INFO.I1,
  });
  const base = build(w);
  // A: the same session and indices, another key at leaf 3 (a lying endpoint's head)
  const other = tr.coldTree(
    ["A", "B", "C", "C3"].map((n) => ({
      ua: f.deviceOf(n).ua,
      keyId: 1,
      kemHash: hex(keccak_256(fromHex(f.deviceOf(n).kemPk))),
    })),
  );
  const a = build(w, other);
  assert.deepEqual([a.ctTargets, a.record.nonce, a.record.epoch], [base.ctTargets, 77, 1]);
  assert.notEqual(a.ps[0], base.ps[0]);
  // B: the twin session (same creator and nonce, so the same sessionId) at another home
  const twin = f.createSession({
    tag: "t/repeat",
    creator: "A",
    nonce: 60,
    admins: ["A"],
    members: ["A", "B", "C", "C2"],
    info: f.INFO.I1,
    homeChain: hex(rnd("t/other-home")),
  });
  assert.equal(twin.home.sessionId, w.home.sessionId);
  const b = build(twin);
  assert.deepEqual([b.ctTargets, b.record.epochId, b.epochId], [base.ctTargets, undefined, base.epochId]);
  assert.notEqual(b.ps[0], base.ps[0]);
});

// ------------------------------------------------------------------ not followed and healing

test("healing (fable-4, fable-r2-7): a member that did not follow follows the next commit that reaches its leaf; one that missed two epochs is not restored by the commit that restores the others", () => {
  const r = Object.fromEntries(["A", "B", "C", "C2", "F"].map((n) => [n, f.replayOf(HEAL, n)]));
  assert.deepEqual(states(r.B), [
    [0, "followed", null],
    [1, "not followed", "opening failed"],
    [2, "not followed", "target not held"],
    [3, "not followed", "target not held"],
    [4, "followed", null],
    [5, "followed", null],
  ]);
  for (const n of ["A", "C", "C2", "F"]) {
    assert.deepEqual(at(r[n], 2).state, "not followed", n);
    assert.equal(at(r[n], 3).state, "followed", `${n}: F's commit falls back to node 3`);
  }
  assert.deepEqual(HEAL.steps[3].built.ctTargets, [3]);
  for (const n of ["A", "B", "C", "F"]) assert.equal(kAt(r[n], 5), hex(HEAL.steps.at(-1).built.K), n);
});

test("a leaked node set (codex-15, fable-6): F's commit of 3 targets node 3 and opens to it; A's commit of 4 locks it out", () => {
  // the leak: what C holds after epoch 1 (nodes 3 and 7 of A's path), without its leaf key
  const w1 = f.createSession({
    tag: "heal",
    creator: "A",
    nonce: 3,
    admins: ["A"],
    members: ["A", "B", "C", "C2", "E", "F"],
    info: f.INFO.I1,
  });
  tk.landCommit(w1.home, HEAL.steps[0].built, HEAL.steps[0].sig);
  const held = f.replayOf(w1, "C").heldKeys;
  held.delete(4);
  assert.deepEqual([...held.keys()].sort(), [3, 7]);
  const rd = tk.reader(HEAL.home);
  const three = tk.withHeld(sc, rd, 3, held);
  assert.equal(three.state, "followed");
  assert.equal(hex(three.K), hex(HEAL.steps[3].built.K), "not locked out by F's commit");
  const four = tk.withHeld(sc, rd, 4, held);
  assert.deepEqual([four.state, four.reason], ["not followed", "wrong target"], "locked out by A's commit");
});

test("a refresh by a device two epochs behind seals the marker; it has no info in force from its gap on; the members that followed keep theirs (codex-r2-3, fable-r2-5)", () => {
  const c2 = f.replayOf(BEHIND, "C2");
  assert.deepEqual(states(c2).slice(1), [
    [1, "not followed", "opening failed"],
    [2, "not followed", "opening failed"],
    [3, "followed", null],
  ]);
  assert.equal(
    tk.openTreeInfo(
      sc,
      BEHIND.steps[2].built.K,
      BEHIND.home.sessionId,
      BEHIND.steps[2].built.epochId,
      BEHIND.steps[2].built.record.sealedInfo,
    ).marker,
    true,
  );
  assert.equal(at(c2, 3).inForce, null);
  for (const n of ["A", "B", "C"]) assert.equal(at(f.replayOf(BEHIND, n), 3).inForce, pc.canonicalJson(f.INFO.I1), n);
});

// ------------------------------------------------------------------ the compromise warning, the checkpoint

test("an own (ua, keyId) commit the seed does not reproduce is the compromise warning, never 'not followed'; the others follow it (R10, fable-r2-1)", () => {
  const w = f.createSession({
    tag: "t/foreign",
    creator: "A",
    nonce: 61,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: f.INFO.I1,
  });
  f.commit(w, "B", { seedOf: "H" });
  const b = f.replayOf(w, "B");
  assert.deepEqual(states(b), [
    [0, "followed", null],
    [1, "compromise", null],
  ]);
  assert.equal(b.warnings.length, 1);
  assert.equal(at(b, 1).inForce, null);
  for (const n of ["A", "C"]) assert.equal(at(f.replayOf(w, n), 1).state, "followed", n);
  // twin: B's own commit from its seed is followed
  f.commit(w, "B");
  assert.equal(at(f.replayOf(w, "B"), 2).state, "followed");
});

test("the checkpoint (C26, fable-r2-4, codex-r2-11): a same-id twin of the head with another treeHash is refused by the pinned record hash; a child on it has another ps[0]", () => {
  const mk = () =>
    f.createSession({
      tag: "t/twin",
      creator: "A",
      nonce: 62,
      admins: ["A"],
      members: ["A", "B", "C"],
      info: f.INFO.I1,
    });
  const t1 = mk();
  const t2 = mk();
  f.commit(t1, "A", { nonce: 9 });
  f.commit(t2, "A", { nonce: 9, adds: [["D", 3]] });
  assert.equal(t1.home.epochs[1].id, t2.home.epochs[1].id);
  assert.notEqual(t1.home.epochs[1].record.treeHash, t2.home.epochs[1].record.treeHash);
  const pin = f.replayOf(t1, "B").pin;
  assert.equal(pin.epoch, 1);
  refused("TreeConflict", () => f.replayOf(t2, "B", undefined, pin));
  refused("TreeConflict", () => tk.prepareCommit(sc, tk.reader(t2.home), pin));
  assert.equal(f.replayOf(t1, "B", undefined, pin).epochs.at(-1).state, "followed", "the twin: the true head");
  refused("TreeCheckpoint", () => f.replayOf(mk(), "B", undefined, pin));
  const c1 = f.commit(t1, "B", { nonce: 10 }).built;
  const c2 = f.commit(t2, "B", { nonce: 10 }).built;
  assert.equal(c1.epochId, c2.epochId);
  assert.notEqual(c1.ps[0], c2.ps[0]);
});

test("the twin outside the tree (codex-r3-2): one id, one parent, one treeHash, another sealedInfo: two hashStructs, the true child fits both, the pin decides", () => {
  const mk = () =>
    f.createSession({
      tag: "t/twin2",
      creator: "A",
      nonce: 63,
      admins: ["A"],
      members: ["A", "B", "C"],
      info: f.INFO.I1,
    });
  const t1 = mk();
  const t2 = mk();
  f.commit(t1, "A", { nonce: 9, info: f.INFO.I1 });
  f.commit(t2, "A", { nonce: 9, info: f.INFO.I2 });
  const [r1, r2] = [t1.home.epochs[1].record, t2.home.epochs[1].record];
  assert.deepEqual([r1.parentEpochId, r1.treeHash], [r2.parentEpochId, r2.treeHash]);
  assert.equal(t1.home.epochs[1].id, t2.home.epochs[1].id);
  assert.notEqual(hex(tr.treeStructHash("PqChatCommit", r1)), hex(tr.treeStructHash("PqChatCommit", r2)));
  const child = f.commit(t1, "B", { nonce: 10 }).built.record;
  assert.deepEqual([child.parentEpochId, child.parentTreeHash], [t2.home.epochs[1].id, r2.treeHash]);
  const pinned = f.replayOf(t2, "C").pin; // a device that pinned the twin
  refused("TreeConflict", () => f.replayOf(t1, "C", undefined, pinned));
  assert.equal(f.replayOf(t1, "C", undefined, f.replayOf(t1, "C").pin).epochs.length, 3);
});

test("the foreign commit that adds a leaf (codex-r3-3): after B's refresh that leaf is still a target and the warning names it; after the commit that removes it, it is not", () => {
  const w = f.createSession({
    tag: "foreign",
    creator: "A",
    nonce: 6,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: f.INFO.I1,
  });
  f.commit(w, "B", { seedOf: "H", adds: [["B2", 3]], info: null });
  let b = f.replayOf(w, "B");
  assert.deepEqual(b.warnings, [
    {
      epoch: 1,
      adds: [{ leaf: 3, ua: f.deviceOf("B2").ua, keyId: 2 }],
      removes: [],
      adminsChanged: false,
      leavesLeft: [3],
    },
  ]);
  const refresh = f.commit(w, "B").built;
  assert.ok(refresh.ctTargets.includes(6), "B2's leaf is still a recipient");
  b = f.replayOf(w, "B");
  assert.equal(at(b, 2).state, "followed");
  assert.deepEqual(b.warnings[0].leavesLeft, [3]);
  const out = f.commit(w, "B", { removes: ["B2"] }).built;
  assert.ok(!out.ctTargets.includes(6));
  assert.deepEqual(f.replayOf(w, "B").warnings[0].leavesLeft, []);
});

test("the empty path (codex-r3-4): the last live leaf's commit from another seed does not open its sealedInfo: the warning; from the seed: followed; a byte changed: read corrupted, neither", () => {
  assert.deepEqual(EMPTY_FOREIGN.steps[1].built.record.nodeKeyHashes, []);
  assert.deepEqual(EMPTY_FOREIGN.steps[1].built.ctTargets, []);
  assert.deepEqual(states(f.replayOf(EMPTY_FOREIGN, "A")).at(-1), [2, "compromise", null]);
  assert.deepEqual(states(f.replayOf(EMPTY, "A")).at(-1), [2, "followed", null]);
  const flip = (read, v) => {
    if (read === "commitOf(2)")
      v.record.sealedInfo = v.record.sealedInfo.slice(0, -2) + (v.record.sealedInfo.endsWith("00") ? "01" : "00");
    return v;
  };
  for (const w of [EMPTY, EMPTY_FOREIGN])
    assert.throws(
      () => f.replayOf(w, "A", flip),
      (e) => e.code === "TreeReadCorrupted" && e.read === "commitOf(2)",
    );
});

// ------------------------------------------------------------------ the info in force (C33)

test("fable-r3-1: E misses the admin's new info of 1, follows C's commit of 2 from its sibling side, adds its own key: it seals the marker and the retired info is in no later record; in the control it seals the full info", () => {
  const e = f.replayOf(GAP, "E");
  assert.deepEqual(
    states(e).map((x) => x[1]),
    ["followed", "not followed", "followed", "followed"],
  );
  assert.equal(GAP.steps[1].built.ctTargets[0], 6); // C's commit: E's leaf, its sibling
  assert.deepEqual([at(e, 2).flagged, at(e, 3).info], [true, "marker"]);
  const sid = GAP.home.sessionId;
  for (const s of GAP.steps.slice(1)) {
    const o = tk.openTreeInfo(sc, s.built.K, sid, s.built.epochId, s.built.record.sealedInfo);
    assert.notEqual(o.json, pc.canonicalJson(f.INFO.I1), "the retired info");
  }
  const last = GAP.steps.at(-1).built;
  assert.equal(tk.openTreeInfo(sc, last.K, sid, last.epochId, last.record.sealedInfo).marker, true);
  const c = GAP_CONTROL.steps.at(-1).built;
  assert.deepEqual(tk.openTreeInfo(sc, c.K, GAP_CONTROL.home.sessionId, c.epochId, c.record.sealedInfo), {
    json: pc.canonicalJson(f.INFO.I2),
  });
});

test("a non-admin's changed info is ignored and shown; the epoch is still followed (C33)", () => {
  const w = f.createSession({
    tag: "t/non-admin",
    creator: "A",
    nonce: 64,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: f.INFO.I1,
  });
  f.commit(w, "B", { info: f.INFO.NON_ADMIN });
  f.commit(w, "A", { info: f.INFO.I2 });
  for (const n of ["A", "C"]) {
    const r = f.replayOf(w, n);
    assert.deepEqual(
      [at(r, 1).state, at(r, 1).info, at(r, 1).inForce],
      ["followed", "ignored", pc.canonicalJson(f.INFO.I1)],
      n,
    );
    assert.deepEqual([at(r, 2).info, at(r, 2).inForce], ["changed", pc.canonicalJson(f.INFO.I2)], n);
  }
});

test("the info after a gap (codex-r3-7): the only admin behind seals markers only; it establishes a new info, which the members take as changed; the cached info is sealed by no automatic step", () => {
  const a = f.replayOf(ADMIN_GAP, "A");
  assert.deepEqual([at(a, 1).state, at(a, 2).flagged, at(a, 3).info], ["not followed", true, "marker"]);
  const s3 = ADMIN_GAP.steps[2].built;
  assert.equal(tk.openTreeInfo(sc, s3.K, ADMIN_GAP.home.sessionId, s3.epochId, s3.record.sealedInfo).marker, true);
  for (const n of ["B", "C"])
    assert.deepEqual(
      [at(f.replayOf(ADMIN_GAP, n), 4).info, at(f.replayOf(ADMIN_GAP, n), 4).inForce],
      ["changed", pc.canonicalJson(f.INFO.I3)],
      n,
    );
  assert.equal(tk.infoToSeal(f.replayOf(ADMIN_GAP, "A")).stores[0].kind, "hcs");
});

// ------------------------------------------------------------------ replay's reads (codex-r3-1)

test("the retired key (codex-r3-1): D joins at 2 and goes at 5, the head is 9: records of 1 to 9, ciphertexts of 2 to 4, nothing at 5; the rosters of 2 to 4 by undo; C, a genesis key taken out at 7, the same", () => {
  const d = f.replayOf(RETIRED, "D");
  assert.deepEqual([d.joinEpoch, d.endEpoch], [2, 5]);
  const reads = (r, name) => r.reads.filter((x) => x.startsWith(`${name}(`)).map((x) => x.slice(name.length));
  const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => `(${a + i})`);
  assert.deepEqual(reads(d, "commitOf").sort(), range(1, 9).sort());
  assert.deepEqual(reads(d, "pathListOf"), range(2, 4));
  assert.deepEqual(
    reads(d, "pathCtAt").map((x) => x.split(",")[0] + ")"),
    range(2, 4),
  );
  assert.deepEqual(reads(d, "wrapAt"), ["(2,0)"]);
  assert.deepEqual(
    d.epochs.map((e) => e.epoch),
    [2, 3, 4],
  );
  for (let n = 1; n <= 9; n++) assert.deepEqual(d.rosters[n], RETIRED.rosters[n], `D's roster at ${n}`);
  const c = f.replayOf(RETIRED, "C");
  assert.deepEqual([c.joinEpoch, c.endEpoch], [0, 7]);
  assert.deepEqual(reads(c, "wrapAt"), ["(0,2)"]);
  assert.deepEqual(
    reads(c, "pathCtAt").map((x) => x.split(",")[0] + ")"),
    range(1, 6).filter((x) => x !== "(4)"),
  );
  assert.deepEqual(reads(c, "pathListOf"), range(1, 6));
  for (let n = 0; n <= 9; n++) assert.deepEqual(c.rosters[n], RETIRED.rosters[n], `C's roster at ${n}`);
  assert.deepEqual(
    c.epochs.map((e) => e.state),
    Array(7).fill("followed"),
  );
});

test("the reads are fixed by public data (C22): a member that follows every epoch and one that follows none read the same list", () => {
  const good = f.replayOf(BEHIND, "C");
  const w = f.createSession({
    tag: "behind",
    creator: "A",
    nonce: 9,
    admins: ["A"],
    members: ["A", "B", "C", "C2"],
    info: f.INFO.I1,
  });
  for (const s of BEHIND.steps) tk.landCommit(w.home, s.built, s.sig);
  // C2 misses 1 and 2, C follows all: same shape of reads (their own ciphertext indices aside)
  const shape = (r) => r.reads.map((x) => x.replace(/,\d+\)$/, ",j)").replace(/\(0x[0-9a-f]+/, "(ua"));
  assert.deepEqual(
    shape(f.replayOf(w, "C2")).filter((x) => !x.startsWith("pathCtAt")).length,
    shape(good).filter((x) => !x.startsWith("pathCtAt")).length,
  );
  assert.equal(
    f.replayOf(w, "C2").reads.filter((x) => x.startsWith("pathCtAt")).length,
    2,
    "one ciphertext per commit of another, followed or not",
  );
});

// ------------------------------------------------------------------ refusals, each with its twin

test("before a client encrypts (codex-r2-1, codex-1, codex-13): an epoch-0 head with a leaf outside the signed members, a substituted leaf key, an altered node key are refused; the honest views build", () => {
  const w = f.createSession({
    tag: "t/prep",
    creator: "A",
    nonce: 65,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: f.INFO.I1,
  });
  assert.equal(tk.prepareCommit(sc, tk.reader(w.home)).parent.epoch, 0);
  const H = f.deviceOf("H");
  const hHash = hex(keccak_256(fromHex(H.kemPk)));
  const outsider = (read, v) => {
    if (read === "treeLeaves()") v[2] = { ...v[2], ua: H.ua, kemHash: hHash };
    if (read === "treeOf()") {
      const t = tr.coldTree([
        ...["A", "B"].map((n) => ({
          ua: f.deviceOf(n).ua,
          keyId: 1,
          kemHash: hex(keccak_256(fromHex(f.deviceOf(n).kemPk))),
        })),
        { ua: H.ua, keyId: 1, kemHash: hHash },
      ]);
      v.genesisTreeHash = tr.treeHash(t);
      v.treeHash = v.genesisTreeHash;
    }
    return v;
  };
  refused("TreeGenesisLeaves", () => tk.prepareCommit(sc, tk.reader(w.home, outsider)));
  const swapLeaf = (read, v) => (read.startsWith(`kemKeyAt(${f.deviceOf("C").ua}`) ? f.deviceOf("C3").kemPk : v);
  refused("TreeGenesisLeaves", () => tk.prepareCommit(sc, tk.reader(w.home, swapLeaf)));
  f.commit(w, "A");
  // a valid substituted leaf key with the tree unchanged (codex-1): the key against the kemHash that entered the root
  refused("TreeKeyHash", () => tk.prepareCommit(sc, tk.reader(w.home, swapLeaf)).keyOf(4));
  assert.equal(tk.prepareCommit(sc, tk.reader(w.home)).keyOf(4), f.deviceOf("C").kemPk);
  const node = tk.prepareCommit(sc, tk.reader(w.home)).tree.nodes.findIndex((n, x) => x % 2 === 1 && n);
  const swapNode = (read, v) => (read === `treeNodeKey(${node})` ? f.deviceOf("H").kemPk : v);
  refused("TreeKeyHash", () => tk.prepareCommit(sc, tk.reader(w.home, swapNode)).keyOf(node));
  assert.equal(
    hex(keccak_256(fromHex(tk.prepareCommit(sc, tk.reader(w.home)).keyOf(node)))),
    w.home.tree.nodes[node].keyHash,
  );
  // a head whose snapshot does not hash to its signed treeHash (a wrong treeHash)
  const badRoot = (read, v) =>
    read === "treeNodes()" ? v.map((n, x) => (x === node ? { ...n, keyHash: Z32 } : n)) : v;
  refused("TreeHeadRoot", () => tk.prepareCommit(sc, tk.reader(w.home, badRoot)));
  refused("TreeHeadRoot", () => f.replayOf(w, "B", badRoot));
});

test("the contract's side of the negative rows: a wrong treeHash, a wrong target list, a parent other than the head are refused; the honest commit lands", () => {
  const mk = () =>
    f.createSession({
      tag: "t/land",
      creator: "A",
      nonce: 66,
      admins: ["A"],
      members: ["A", "B", "C"],
      info: f.INFO.I1,
    });
  const w = mk();
  const { built, sig } = f.commit(w, "B", { land: false });
  refused("PqChatTreeHash", () =>
    tk.landCommit(mk().home, { ...built, record: { ...built.record, treeHash: Z32 } }, sig),
  );
  const wrong = [...built.ctTargets].reverse();
  refused("PqChatTreeTargets", () => tk.landCommit(mk().home, { ...built, ctTargets: wrong }, sig));
  refused("PqChatTreeParent", () =>
    tk.landCommit(mk().home, { ...built, record: { ...built.record, parentTreeHash: Z32 } }, sig),
  );
  tk.landCommit(w.home, built, sig);
});

test("negative rows (codex-1, codex-13, codex-r2-15): read corrupted (bytes changed, signed hashes kept: refused at the read boundary, before any decapsulation) and opening failed (a validly signed bad ciphertext) are two results", () => {
  const w = f.createSession({
    tag: "t/neg",
    creator: "A",
    nonce: 67,
    admins: ["A"],
    members: ["A", "B", "C", "C2"],
    info: f.INFO.I1,
  });
  f.commit(w, "A", {
    faults: { ct: { [f.ctIndexFor(f.commit(w, "A", { land: false }).built, "C")]: hex(rnd("t/neg/bad", 48)) } },
  });
  w.steps.splice(-2, 1);
  const r = f.replayOf(w, "C");
  assert.deepEqual(states(r).at(-1), [1, "not followed", "opening failed"]);
  assert.equal(at(f.replayOf(w, "B"), 1).state, "followed", "the twin: B's ciphertext");
  // read corrupted: no decapsulation at all
  const C = f.deviceOf("C");
  let decaps = 0;
  const counted = { ...C, key: { kemPk: C.key.kemPk, decaps: (...x) => (decaps++, C.key.decaps(...x)) } };
  const run = (tamper) => tk.replay(sc, tk.reader(w.home, tamper), counted);
  const alter = (name) => (read, v) => {
    if (read.startsWith(name)) {
      if (name === "pathCtAt") v.sealedSecret = hex(rnd("t/neg/x", 48));
      if (name === "pathListOf") v.ctHashes[0] = Z32;
      if (name === "wrapAt") v.sealedKey = hex(rnd("t/neg/w", 48));
      if (name === "commitOf") v.record.sealedInfo = hex(rnd("t/neg/i", 284));
    }
    return v;
  };
  for (const name of ["pathCtAt", "pathListOf", "wrapAt", "commitOf"]) {
    decaps = 0;
    assert.throws(
      () => run(alter(name)),
      (e) => e.code === "TreeReadCorrupted" && e.read.startsWith(name),
      name,
    );
    assert.equal(decaps, 0, name);
  }
  decaps = 0;
  run();
  assert.ok(decaps > 0, "the twin: the honest reads decapsulate");
});

test("negative rows: a node key that does not match its secret, a Welcome that disagrees with the path, a sealedInfo that does not open: not followed, each with its reason; the honest commit is followed", () => {
  const mk = (tag) =>
    f.createSession({ tag, creator: "A", nonce: 68, admins: ["A"], members: ["A", "B", "C"], info: f.INFO.I1 });
  const w1 = mk("t/neg1");
  f.commit(w1, "A", { faults: { nodeKeys: [f.deviceOf("H").kemPk, f.deviceOf("G").kemPk] } });
  assert.deepEqual(states(f.replayOf(w1, "C")).at(-1), [1, "not followed", "node key mismatch"]);
  const w2 = mk("t/neg2");
  f.commit(w2, "A", { adds: [["D", 3]], faults: { welcomeJoiner: rnd("t/neg/joiner") } });
  assert.deepEqual(states(f.replayOf(w2, "D")).at(-1), [1, "not followed", "welcome disagrees"]);
  assert.equal(at(f.replayOf(w2, "C"), 1).state, "followed");
  const w3 = mk("t/neg3");
  f.commit(w3, "A", { faults: { infoK: rnd("t/neg/K") } });
  for (const n of ["B", "C"])
    assert.deepEqual(states(f.replayOf(w3, n)).at(-1), [1, "not followed", "info does not open"], n);
  const w4 = mk("t/neg4");
  f.commit(w4, "A", { adds: [["D", 3]] });
  for (const n of ["B", "C", "D"]) assert.equal(at(f.replayOf(w4, n), 1).state, "followed", n);
});

test("PqChatTreeLeave and PqChatTreeRemove of a twin session at another home have another digest (codex-r2-5)", () => {
  const mk = (homeChain) =>
    f.createSession({
      tag: "t/twin3",
      creator: "A",
      nonce: 69,
      admins: ["A"],
      members: ["A", "B", "C"],
      info: f.INFO.I1,
      homeChain,
    });
  const [x, y] = [mk(), mk(hex(rnd("t/other-home-2")))];
  assert.equal(x.home.sessionId, y.home.sessionId);
  for (const kind of [1, 2]) {
    const a = f.gone(x, kind, kind === 1 ? "B" : "A", ["B"], 3);
    const b = f.gone(y, kind, kind === 1 ? "B" : "A", ["B"], 3);
    assert.notEqual(hex(sc.typed(a.struct, a.record)), hex(sc.typed(b.struct, b.record)), a.struct);
  }
});

test("rights (§9): a non-admin's commit that drops another UA needs that UA's signed leave or removal; without it, it is not followed", () => {
  const replays = ["A", "C", "D"].map((n) => at(f.replayOf(MAIN, n), 5));
  for (const e of replays) assert.equal(e.state, "followed");
  const noEvidence = (read, v) => (read.startsWith("goneRecord(") ? { ...v, sig: v.sig.slice(0, -2) + "00" } : v);
  assert.throws(
    () => f.replayOf(MAIN, "D", noEvidence),
    (e) => e.code === "TreeReadCorrupted" && e.read.startsWith("goneRecord("),
  );
  const notGone = (read, v) => (read.startsWith("goneOf(") ? { kind: 0, epoch: 0 } : v);
  assert.deepEqual(
    states(f.replayOf(MAIN, "D", notGone)).find((x) => x[0] === 5),
    [5, "not followed", "rights"],
  );
});

test("receipts (R11): a tree session sends none automatically, whatever the store list says; mode 0 keeps its default", () => {
  assert.equal(tk.autoReceipts(1, true), false);
  assert.equal(tk.autoReceipts(1, false), false);
  assert.equal(tk.autoReceipts(0, true), true);
  assert.equal(tk.autoReceipts(0, false), false);
});

// ------------------------------------------------------------------ the frozen rows

const V = JSON.parse(
  readFileSync(new URL("../../../smartcontracts/vectors/pqchat/tree-secrets.json", import.meta.url)),
);

test("tree-secrets.json: secrets, pathCt and schedule rows recomputed from their inputs", () => {
  for (const r of V.secrets) {
    const ps = tk.pathSecrets(sc, r.ps0, r.ps.length - 1);
    assert.deepEqual(ps.map(hex), r.ps);
    assert.deepEqual(
      ps.slice(0, -1).map((s) => hex(keccak_256(tk.nodeKeyOf(sc, s).kemPk))),
      r.nodeKeyHashes,
    );
    if (r.pathContext) {
      assert.equal(hex(tk.pathContext(sc, r.record, r.ctTargets)), r.pathContext);
      assert.equal(hex(tk.firstPathSecret(sc, r.kemSeed, r.pathContext)), r.ps0);
    }
  }
  for (const r of V.pathCt) {
    const s = tk.sealPathSecret(sc, r.input);
    assert.deepEqual({ ss: hex(s.ss), kek: hex(s.kek), ct: s.ct }, r.output);
  }
  for (const r of V.schedule) {
    const s = tk.schedule(sc, r.joiner, r.fields);
    assert.deepEqual([hex(s.ctx), hex(s.S), hex(s.K)], [r.ctx, r.S, r.K]);
  }
});

test("tree-secrets.json scenario rows: every step's record, pieces and tree hash land on a home rebuilt from the file, and every member's replay gives the K of the row", () => {
  for (const sRow of V.scenarios) {
    const h = tk.newHome({
      genesis: {
        record: sRow.genesis.record,
        sessionId: sRow.genesis.sessionId,
        treeId: sRow.genesis.treeId,
        wraps: sRow.genesis.wraps.map((wrap) => ({ wrap })),
      },
      sig: sRow.genesis.sig,
      kems: new Map(Object.values(V.devices).map((d) => [`${d.ua}/${d.keyId}`, d.kemPk])),
      uaKeys: new Map(Object.values(V.people).map((p) => [p.ua, p.publicKey])),
    });
    for (const step of sRow.steps) {
      if (step.gone) tk.landGone(h, step.gone.kind, step.gone.struct, step.gone.record, step.gone.sig);
      else
        tk.landCommit(
          h,
          {
            ...step,
            wraps: step.wraps.map((wrap) => ({ wrap, hash: hex(pc.structHash("Wrap", wrap)) })),
            cts: step.cts.map((ct) => ({ ct })),
          },
          step.sig,
        );
      if (step.treeHash) assert.equal(h.tree.hash[tr.root(h.tree.leaves)], step.treeHash, `${sRow.name} ${step.name}`);
    }
    for (const [name, want] of Object.entries(sRow.replays)) {
      const d = f.deviceOf(name);
      const r = tk.replay(sc, tk.reader(h), d);
      assert.deepEqual(states(r), want.states, `${sRow.name} ${name}`);
      assert.deepEqual(
        r.epochs.map((e) => e.K ?? null),
        want.K,
        `${sRow.name} ${name}`,
      );
    }
  }
});

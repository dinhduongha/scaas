// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// PqChat TreeKEM, T1b (src/treekem.js; spec docs/superpowers/specs/2026-11-23-pqchat-treekem.md §5, §8, §10): the path secrets,
// node keys, ps[0] over its context, the path ciphertext, the schedule without init, K, the tree wrap, the info and the marker,
// creation in order, replay, the joiner, healing, the compromise warning, the checkpoint, the info in force, and the refusals
// each with its positive twin; the rows of smartcontracts/vectors/pqchat/tree-secrets.json. UNAUDITED.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { gcmsiv } from "@noble/ciphers/aes.js";
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

// the worlds, built once before the tests (inside the runner, so a fault while building fails named tests; C-6)
let MAIN, JOINER, HEAL, GAP, GAP_CONTROL, RETIRED, EMPTY, EMPTY_FOREIGN, ADMIN_GAP, BEHIND;
before(() => {
  MAIN = f.mainScenario();
  JOINER = f.joinerScenario();
  HEAL = f.healScenario();
  GAP = f.gapScenario(false);
  GAP_CONTROL = f.gapScenario(true);
  RETIRED = f.retiredScenario();
  EMPTY = f.emptyPathScenario(null);
  EMPTY_FOREIGN = f.emptyPathScenario("H");
  ADMIN_GAP = f.adminGapScenario();
  BEHIND = f.behindScenario();
});

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

test("C-8: an info that is not canonical JSON does not open, so the info in force is re-sealed byte for byte; its canonical twin opens", () => {
  const K = rnd("t/c8/K");
  const [sid, eid] = [hex(rnd("t/c8/sid")), hex(rnd("t/c8/eid"))];
  const n = rnd("t/c8/nonce", 12);
  const raw = (text) => hex(concatBytes(n, gcmsiv(sc.infoKey(K, sid, eid), n).encrypt(pc.pad(utf8ToBytes(text)))));
  assert.deepEqual(tk.openTreeInfo(sc, K, sid, eid, raw('{"a":1,"b":2}')), { json: '{"a":1,"b":2}' });
  assert.equal(tk.openTreeInfo(sc, K, sid, eid, raw('{"b":2,"a":1}')), null);
  assert.equal(tk.openTreeInfo(sc, K, sid, eid, raw('{"a": 1}')), null);
  assert.equal(tk.openTreeInfo(sc, K, sid, eid, raw("not json")), null);
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

test("the main scenario: every member with a leaf derives the same K at every epoch; the rosters of the forward walk equal the leaves; a non-zero via is bound", () => {
  const head = MAIN.home.epochs.length - 1;
  const Ks = MAIN.steps.filter((s) => s.built).map((s) => hex(s.built.K));
  const replays = Object.fromEntries(["A", "B", "C", "C2", "D"].map((n) => [n, f.replayOf(MAIN, n)]));
  for (const [n, r] of Object.entries(replays)) {
    for (const e of r.epochs) {
      assert.equal(e.state, "followed", `${n} ${e.epoch}`);
      assert.equal(e.K, e.epoch === 0 ? hex(MAIN.genesis.K) : Ks[e.epoch - 1], `${n} ${e.epoch}`);
    }
    // the rosters of the secret range only (E-3): from its join to its last epoch
    const last = r.endEpoch === null ? head : r.endEpoch - 1;
    assert.equal(Object.keys(r.rosters).length, last - r.joinEpoch + 1, `${n}'s rosters`);
    for (let e = r.joinEpoch; e <= last; e++) assert.deepEqual(r.rosters[e], MAIN.rosters[e], `${n}'s roster at ${e}`);
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
  // C's commit 5 drops B (gone) without admin right: the evidence, B's PqChatTreeRemove kept under 4, was read and verified,
  // and every device, D (a commit joiner) included, reads every record and the exits of every epoch from the session record
  for (const r of Object.values(replays)) {
    assert.ok(r.reads.includes("removalAt(4,0)"));
    for (let e = 1; e <= head; e++)
      assert.ok(r.reads.includes(`commitOf(${e})`) && r.reads.includes(`leaveCount(${e})`));
  }
  // the via of D's Add is non-zero and bound (no tree digest canonicalises a field)
  const add = MAIN.steps[1].built.record.adds[0];
  assert.notEqual(add.via, Z32);
  assert.notEqual(
    hex(tr.treeStructHash("PqChatCommit", { ...MAIN.steps[1].built.record, adds: [{ ...add, via: Z32 }] })),
    hex(tr.treeStructHash("PqChatCommit", MAIN.steps[1].built.record)),
  );
  // what the commits blanked is dropped: C held node 5 from its own commit of 3; A's Remove of C2 (6) blanked it
  assert.deepEqual(replays.C.held, [3, 4, 7]);
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
  // B reads the one ciphertext over its leaf in every commit of another, held or not (C22)
  assert.deepEqual(
    r.B.reads.filter((x) => x.startsWith("pathCtAt(")).map((x) => x.split(",")[0]),
    ["pathCtAt(1", "pathCtAt(2", "pathCtAt(3", "pathCtAt(4"],
  );
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
  // below the head: the twin (validly signed, same id) breaks the chain at its child; a record of another number, its id
  const twinAt1 = (read, v) =>
    read === "commitOf(1)" ? { record: t2.home.epochs[1].record, sig: t2.home.epochs[1].sig } : v;
  assert.throws(
    () => f.replayOf(t1, "C", twinAt1),
    (e) => e.code === "TreeReadCorrupted" && e.read === "commitOf(2)",
  );
  const twoAt1 = (read, v) =>
    read === "commitOf(1)" ? { record: t1.home.epochs[2].record, sig: t1.home.epochs[2].sig } : v;
  assert.throws(
    () => f.replayOf(t1, "C", twoAt1),
    (e) => e.code === "TreeReadCorrupted" && e.read === "commitOf(1)",
  );
  assert.equal(f.replayOf(t1, "C").epochs.length, 3);
});

test("a record of the twin session at another home, same id, parent and treeHash (an empty path), is refused by its treeId", () => {
  const mk = (homeChain) =>
    f.createSession({
      tag: "t/solo",
      creator: "A",
      nonce: 72,
      admins: ["A"],
      members: ["A"],
      info: f.INFO.I1,
      homeChain,
    });
  const [x, y] = [mk(), mk(hex(rnd("t/other-home-3")))];
  f.commit(x, "A", { nonce: 9 });
  f.commit(y, "A", { nonce: 9 });
  const [rx, ry] = [x.home.epochs[1].record, y.home.epochs[1].record];
  assert.deepEqual(
    [x.home.epochs[1].id, rx.parentTreeHash, rx.treeHash],
    [y.home.epochs[1].id, ry.parentTreeHash, ry.treeHash],
  );
  assert.notEqual(rx.treeId, ry.treeId);
  const swap = (read, v) => (read === "commitOf(1)" ? { record: ry, sig: y.home.epochs[1].sig } : v);
  assert.throws(
    () => f.replayOf(x, "A", swap),
    (e) => e.code === "TreeReadCorrupted" && e.read === "commitOf(1)",
  );
  assert.equal(at(f.replayOf(x, "A"), 1).state, "followed");
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

test("the retired key (codex-r3-1): D joins at 2 and goes at 5, the head is 9: records of 1 to 9, ciphertexts of 2 to 4, nothing at 5; the rosters of 2 to 4 (its range, E-3); C, a genesis key taken out at 7, the same", () => {
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
  assert.deepEqual(Object.keys(d.rosters).map(Number), [2, 3, 4]);
  for (let n = 2; n <= 4; n++) assert.deepEqual(d.rosters[n], RETIRED.rosters[n], `D's roster at ${n}`);
  // C-5: a device whose period ended seals no info of its own (its last epoch is not the head)
  assert.equal(tk.infoToSeal(d), null);
  const c = f.replayOf(RETIRED, "C");
  assert.deepEqual([c.joinEpoch, c.endEpoch], [0, 7]);
  assert.deepEqual(reads(c, "wrapAt"), ["(0,2)"]);
  assert.deepEqual(
    reads(c, "pathCtAt").map((x) => x.split(",")[0] + ")"),
    range(1, 6).filter((x) => x !== "(4)"),
  );
  assert.deepEqual(reads(c, "pathListOf"), range(1, 6));
  assert.deepEqual(Object.keys(c.rosters).map(Number), [0, 1, 2, 3, 4, 5, 6]);
  for (let n = 0; n <= 6; n++) assert.deepEqual(c.rosters[n], RETIRED.rosters[n], `C's roster at ${n}`);
  assert.deepEqual(
    c.epochs.map((e) => e.state),
    Array(7).fill("followed"),
  );
});

test("the reads are fixed by public data (C22): one device that follows every epoch and the same device that follows none read the same list", () => {
  // BEHIND: C2 misses 1 and 2 (validly signed bad ciphertexts); its control: the same session with honest commits
  const w = f.createSession({
    tag: "behind",
    creator: "A",
    nonce: 9,
    admins: ["A"],
    members: ["A", "B", "C", "C2"],
    info: f.INFO.I1,
  });
  f.commit(w, "A");
  f.commit(w, "B");
  f.commit(w, "C2");
  const bad = f.replayOf(BEHIND, "C2");
  const good = f.replayOf(w, "C2");
  assert.deepEqual(states(bad).slice(1, 3), [
    [1, "not followed", "opening failed"],
    [2, "not followed", "opening failed"],
  ]);
  assert.ok(good.epochs.every((e) => e.state === "followed"));
  assert.deepEqual(bad.reads, good.reads);
  assert.equal(bad.reads.filter((x) => x.startsWith("pathCtAt")).length, 2, "one ciphertext per commit of another");
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
  // C-1: another key served under C's signed record: the registry record does not authenticate it (the consistent liar,
  // treeLeaves and treeOf with it, is the lie row "an epoch-0 head with a consistent substituted member key")
  const swapLeaf = (read, v) =>
    read.startsWith(`kemKeyAt(${f.deviceOf("C").ua}`) ? { ...v, kemPk: f.deviceOf("C3").kemPk } : v;
  refused("TreeKemRecord", () => tk.prepareCommit(sc, tk.reader(w.home, swapLeaf)));
  refused("TreeKemRecord", () => f.replayOf(w, "A", swapLeaf));
  // C's own record of version 3 served as version 1: the record names its version
  const other = (read, v) => (read.startsWith(`kemKeyAt(${f.deviceOf("C").ua}`) ? f.kemRecOf("C3") : v);
  refused("TreeKemRecord", () => tk.prepareCommit(sc, tk.reader(w.home, other)));
  f.commit(w, "A");
  // the same key served for the cold tree above epoch 0: refused by its record before the walk reaches epoch 1
  refused("TreeKemRecord", () => tk.prepareCommit(sc, tk.reader(w.home, swapLeaf)));
  // a valid substituted leaf key with the tree unchanged (codex-1), the walk from the pin: the key against the kemHash that
  // entered the root
  const pin = tk.prepareCommit(sc, tk.reader(w.home)).pin;
  refused("TreeKeyHash", () => tk.prepareCommit(sc, tk.reader(w.home, swapLeaf), pin).keyOf(4));
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
  const w2 = f.createSession({
    tag: "t/neg-join",
    creator: "A",
    nonce: 70,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: f.INFO.I1,
  });
  f.commit(w2, "A", { adds: [["D", 3]] });
  assert.equal(at(f.replayOf(w2, "D"), 1).state, "followed");
  assert.throws(
    () => f.replayOf(w2, "D", alter("wrapAt")),
    (e) => e.code === "TreeReadCorrupted" && e.read === "wrapAt(1,0)",
  );
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

test("rights (§9, C25): a non-admin's commit that drops another UA needs that UA's signed exit; without it, or with its signature changed, the commit cannot be the home's: a lying read", () => {
  const replays = ["A", "C", "D"].map((n) => at(f.replayOf(MAIN, n), 5));
  for (const e of replays) assert.equal(e.state, "followed");
  const noEvidence = (read, v) => (read === "removalAt(4,0)" ? { ...v, sig: v.sig.slice(0, -2) + "00" } : v);
  assert.throws(
    () => f.replayOf(MAIN, "D", noEvidence),
    (e) => e.code === "TreeReadCorrupted" && e.read === "removalAt(4,0)",
  );
  const hidden = (read, v) => (read === "removalCount(4)" ? 0 : v);
  assert.throws(
    () => f.replayOf(MAIN, "D", hidden),
    (e) => e.code === "TreeReadCorrupted" && e.read === "commitOf(5)",
  );
  // goneOf is compared with nothing the walk decides: an endpoint that lies about it changes nothing
  const notGone = (read, v) => (read.startsWith("goneOf(") ? { kind: 0, epoch: 0 } : v);
  assert.deepEqual(states(f.replayOf(MAIN, "D", notGone)), states(f.replayOf(MAIN, "D")));
});

test("the key's period (C28, codex-r2-10): a wrong join or end from an endpoint is refused; a non-admin's Add of another UA is a lying read (C25)", () => {
  const D = f.deviceOf("D");
  const kh = hex(keccak_256(fromHex(D.kemPk)));
  const period = (join, end) => (read, v) =>
    read === `goneKeyOf(${kh})` ? { ...v, joinEpoch: join, endEpoch: end } : v;
  refused("TreePeriod", () => f.replayOf(RETIRED, "D", period(3, 5)));
  refused("TreePeriod", () => f.replayOf(RETIRED, "D", period(2, 6)));
  refused("TreePeriod", () => f.replayOf(RETIRED, "D", period(2, 0)));
  refused("TreePeriod", () => f.replayOf(RETIRED, "D", period(2, 99)));
  assert.deepEqual(f.replayOf(RETIRED, "D", period(2, 5)).epochs.length, 3, "the twin: the true period");
  const joinPast = (read, v) =>
    read === "treeLeaves()" ? v.map((l, i) => (i === 3 ? { ...l, joinEpoch: 99 } : l)) : v;
  refused("TreePeriod", () => f.replayOf(RETIRED, "E", joinPast));
  const mk = (tag) =>
    f.createSession({ tag, creator: "A", nonce: 71, admins: ["A"], members: ["A", "B", "C"], info: f.INFO.I1 });
  const w = mk("t/rights");
  f.commit(w, "B", { adds: [["D", 3]] });
  for (const n of ["A", "C", "D"]) refused("TreeReadCorrupted", () => f.replayOf(w, n));
  refused("TreeReadCorrupted", () => tk.prepareCommit(sc, tk.reader(w.home)));
  const v = mk("t/rights-twin");
  f.commit(v, "A", { adds: [["D", 3]] });
  for (const n of ["B", "C", "D"]) assert.equal(at(f.replayOf(v, n), 1).state, "followed", n);
});

test("the exits (C9, F-2, F-3, sc-F-1, sc-F-2): an msig's removal naming an ancestor, a WebAuthn admin's removal of a keyless admin and of itself, a removal and its signer's leave on one head, each honoured by a non-admin: every device follows every epoch", () => {
  const w = f.exitsScenario();
  for (const n of ["A", "B", "C", "D", "E"]) {
    const r = f.replayOf(w, n);
    assert.ok(r.epochs.length > 0 && r.epochs.every((e) => e.state === "followed"), n);
  }
  const r = f.replayOf(w, "B");
  // M's removal of D names epoch 0 and is kept under 2; W's of M under 3; W's of itself, A's of E and A's leave under 4
  assert.deepEqual(
    r.pin.gone,
    [
      [f.uaOf("A"), 1, 4],
      [f.uaOf("D"), 2, 2],
      [f.uaOf("E"), 2, 4],
      [f.uaOf("M"), 2, 3],
      [f.uaOf("W"), 2, 4],
    ].sort((x, y) => (x[0] < y[0] ? -1 : 1)),
  );
  // the twins: W's WebAuthn signature changed, one member's signature of M's msig changed: each a lying read
  // (the assertion's r: the third word of abi.encode(authData, clientDataJSON, r, s))
  const flipAt = (h, i) => h.slice(0, i) + (h[i] === "0" ? "1" : "0") + h.slice(i + 1);
  const sigFlip = (read, v) => (read === "removalAt(3,0)" ? { ...v, sig: flipAt(v.sig, 2 + 64 * 2 + 10) } : v);
  refused("TreeReadCorrupted", () => f.replayOf(w, "B", sigFlip));
  const msigFlip = (read, v) =>
    read === "removalAt(2,0)"
      ? { ...v, sig: { ...v.sig, members: flipAt(v.sig.members, v.sig.members.length - 300) } }
      : v;
  refused("TreeReadCorrupted", () => f.replayOf(w, "B", msigFlip));
});

test("C-2: a validly signed ciphertext or Welcome with a small-order x25519Eph is 'opening failed' / 'welcome disagrees', never an abort", () => {
  const w = f.smallOrderScenario();
  assert.deepEqual(at(f.replayOf(w, "A"), 1).reason, "opening failed");
  assert.deepEqual(states(f.replayOf(w, "D")), [[2, "not followed", "welcome disagrees"]]);
  assert.equal(at(f.replayOf(w, "C"), 1).state, "followed");
});

test("the lies of plan T11 (E-1, F-1, sc-F-3, sc-F-7, E-4, the lag): replay and prepare give the row's result", () => {
  const worlds = new Map([
    ["small", f.smallScenario("small")],
    ["pin-exit", f.smallScenario("pin-exit", true)],
    ["returned", f.returnedScenario()],
    ["lag", f.lagScenario()],
    ["empty-path", f.emptyPathScenario(null)],
    ["msig-updated", f.msigUpdatedScenario()],
    ["genesis", f.genesisScenario()],
    ["backlog", f.backlogScenario()],
    ["msig-history", f.msigHistoryScenario()],
    ["msig-nested", f.msigNestedScenario()],
  ]);
  const code = (fn) => {
    try {
      fn();
      return null;
    } catch (e) {
      return e.code;
    }
  };
  const rows = f.lies(worlds);
  assert.ok(rows.length >= 13);
  for (const r of rows) {
    const w = worlds.get(r.world);
    const d = f.deviceOf(r.device);
    assert.equal(
      code(() => tk.replay(sc, f.lyingReader(w, r.overrides), d, r.pin)),
      r.expect.replay,
      r.name,
    );
    assert.equal(
      code(() => tk.prepareCommit(sc, f.lyingReader(w, r.overrides), r.pin)),
      r.expect.prepare,
      r.name,
    );
    // the honest views: accepted, and with the device's own pin too
    const honest = tk.replay(sc, tk.reader(w.home), d);
    assert.ok(honest.inSession, r.name);
    tk.prepareCommit(sc, tk.reader(w.home), honest.pin);
  }
});

test("the forward walk from any checkpoint reaches the tree of the walk from the cold tree (C25, C26); a pin of another session or above the head is refused", () => {
  for (const w of [MAIN, RETIRED, HEAL, f.exitsScenario()]) {
    const cold = tk.prepareCommit(sc, tk.reader(w.home));
    const pins = tk.pinsOf(sc, tk.reader(w.home));
    assert.equal(pins.length, w.home.epochs.length);
    for (const pin of pins) {
      const p = tk.prepareCommit(sc, tk.reader(w.home), pin);
      assert.deepEqual(tr.treeJson(p.tree), tr.treeJson(cold.tree), `${w.tag} from ${pin.epoch}`);
      assert.deepEqual(p.pin, cold.pin);
      assert.deepEqual(p.admins, cold.admins);
    }
    const head = pins.at(-1);
    refused("TreeCheckpoint", () => tk.prepareCommit(sc, tk.reader(w.home), { ...head, epoch: head.epoch + 1 }));
    refused("TreeCheckpoint", () => tk.prepareCommit(sc, tk.reader(w.home), { ...head, treeId: Z32 }));
    refused("TreeConflict", () => tk.prepareCommit(sc, tk.reader(w.home), { ...head, hash: Z32 }));
  }
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
      kems: new Map(Object.values(V.devices).map((d) => [`${d.ua}/${d.keyId}`, { kemPk: d.kemPk, sig: d.kemSig }])),
      uaRecords: new Map(V.signers.map(({ ua, ...r }) => [ua, r])),
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
      assert.deepEqual(r.reads, want.reads, `${sRow.name} ${name}`);
      assert.deepEqual(r.pin, want.pin, `${sRow.name} ${name}`);
      // the info in force and the warnings of the file too (C-5: an admin's same full info clears the flag; C-2)
      assert.deepEqual(
        r.epochs.map((e) => [e.info, e.inForce, e.flagged]),
        want.info,
        `${sRow.name} ${name} info`,
      );
      assert.deepEqual(r.warnings, want.warnings, `${sRow.name} ${name} warnings`);
    }
    assert.deepEqual(tk.pinsOf(sc, tk.reader(h)), sRow.pins, sRow.name);
  }
});

test("C-2, B2-7: the compromise warning's leaves left come from the walk's head tree; a served joinEpoch moved off the Add changes nothing", () => {
  const w = f.createSession({
    tag: "foreign",
    creator: "A",
    nonce: 6,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: f.INFO.I1,
  });
  f.commit(w, "B", { seedOf: "H", adds: [["B2", 3]], info: null });
  const moved = (read, v) => (read === "treeLeaves()" ? v.map((l, i) => (i === 3 ? { ...l, joinEpoch: 2 } : l)) : v);
  assert.deepEqual(f.replayOf(w, "B", moved).warnings[0].leavesLeft, [3]);
  assert.deepEqual(f.replayOf(w, "B").warnings[0].leavesLeft, [3]);
});

test("C-7: a signer kind the reader has no verifier for is UANotVerifiable by name, never a lying read; another refusal is", () => {
  const w = f.smallScenario("small");
  const A = f.uaOf("A");
  const lacking = (code) => {
    const rd = tk.reader(w.home);
    const of = rd.uaRecordOf;
    rd.uaRecordOf = (ua) => {
      if (ua === A) throw new Error(code);
      return of(ua);
    };
    return rd;
  };
  const unverifiable = (rd) => {
    const of = rd.uaRecordOf;
    rd.uaRecordOf = (ua) => {
      if (ua !== A) return of(ua);
      const e = new Error("UANotVerifiable");
      e.code = "UANotVerifiable";
      throw e;
    };
    return rd;
  };
  refused("UANotVerifiable", () => tk.replay(sc, unverifiable(tk.reader(w.home)), f.deviceOf("B")));
  refused("UANotVerifiable", () => tk.prepareCommit(sc, unverifiable(tk.reader(w.home))));
  refused("TreeReadCorrupted", () => tk.prepareCommit(sc, lacking("other")));
  assert.ok(tk.replay(sc, tk.reader(w.home), f.deviceOf("B")).inSession);
});

test("E-3, B2-2: a replay resumed from the device's previous one walks from its pin and opens only the epochs after it, with the same K and info; the walk keeps the trees at its start and head only", () => {
  const w = f.createSession({
    tag: "t/resume",
    creator: "A",
    nonce: 70,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: f.INFO.I1,
  });
  for (let n = 1; n <= 6; n++) f.commit(w, n % 2 ? "B" : "C");
  const B = f.deviceOf("B");
  const r6 = tk.replay(sc, tk.reader(w.home), B);
  f.commit(w, "A", { adds: [["D", 3]] }); // 7
  for (let n = 8; n <= 12; n++) f.commit(w, n % 2 ? "B" : "C");
  const full = tk.replay(sc, tk.reader(w.home), B);
  const rd = tk.reader(w.home);
  const more = tk.replay(sc, rd, B, null, r6);
  assert.deepEqual(
    more.epochs.map((e) => e.epoch),
    [7, 8, 9, 10, 11, 12],
  );
  for (const e of more.epochs) {
    const g = at(full, e.epoch);
    assert.deepEqual([e.state, e.K, e.inForce, e.flagged], [g.state, g.K, g.inForce, g.flagged], `epoch ${e.epoch}`);
    assert.deepEqual(more.rosters[e.epoch], full.rosters[e.epoch]);
  }
  assert.deepEqual(more.pin, full.pin);
  // the work: no record below the pin, no key of the cold tree, no wrap of the join
  const commits = rd.log.filter((x) => x.startsWith("commitOf(")).map((x) => Number(x.slice(9, -1)));
  assert.deepEqual(commits, [6, 7, 8, 9, 10, 11, 12]);
  assert.ok(!rd.log.some((x) => x.startsWith("kemKeyAt(") || x.startsWith("wrapAt(0,")));
  // the memory: the walk holds the tree at its start and at the head, never one per epoch
  assert.deepEqual(tk.walkTrees(sc, tk.reader(w.home)), [0, 12]);
  assert.deepEqual(tk.walkTrees(sc, tk.reader(w.home), r6.pin), [6, 12]);
  // a previous replay whose pin is not the record that won there is refused
  refused("TreeConflict", () => tk.replay(sc, tk.reader(w.home), B, null, { ...r6, pin: { ...r6.pin, hash: Z32 } }));
});

test("R2-D-6 (C-4 as ua-rs): a resume that finds no new epoch keeps the info in force, its flag and the head followed, so it seals what the replay it resumed from sealed", () => {
  const w = f.createSession({
    tag: "t/resume-twice",
    creator: "A",
    nonce: 72,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: f.INFO.I1,
  });
  f.commit(w, "B");
  const B = f.deviceOf("B");
  const r1 = tk.replay(sc, tk.reader(w.home), B);
  assert.notEqual(tk.infoToSeal(r1), null);
  const r2 = tk.replay(sc, tk.reader(w.home), B, null, r1);
  assert.deepEqual(r2.epochs, []);
  assert.deepEqual(tk.infoToSeal(r2), tk.infoToSeal(r1));
  const r3 = tk.replay(sc, tk.reader(w.home), B, null, r2);
  assert.deepEqual(tk.infoToSeal(r3), tk.infoToSeal(r1));
});

test("C-1: a key no signed tree hash covers is authenticated by its registry record before it is used: an Add's, a member's at creation", () => {
  const w = f.createSession({
    tag: "t/auth",
    creator: "A",
    nonce: 71,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: f.INFO.I1,
  });
  const prep = tk.prepareCommit(sc, tk.reader(w.home));
  const A = f.deviceOf("A");
  const D = f.deviceOf("D");
  const add = (rec) => ({
    leaf: 3,
    ua: D.ua,
    keyId: 1,
    via: Z32,
    kemHash: hex(keccak_256(fromHex(D.kemPk))),
    ...rec,
  });
  const build = (rec) =>
    tk.buildCommit(sc, {
      tree: prep.tree,
      parent: prep.parent,
      sessionId: w.home.sessionId,
      treeId: w.home.treeId,
      author: A.ua,
      leaf: 0,
      keyId: 1,
      kemSeed: A.kemSeed,
      nonce: 9,
      admins: prep.admins,
      info: null,
      adds: [add(rec)],
      uaRecordOf: (u) => f.uaRecords().get(u) ?? null,
      accepted: () => true,
      keyOf: prep.keyOf,
      rand: (x, n) => rnd(`t/auth/${x}`, n),
    });
  assert.equal(build(f.kemRecOf("D")).record.adds[0].ua, D.ua);
  // another key under D's signature (the record does not authenticate it), D's signature of another version
  refused("TreeKemRecord", () => build({ kemPk: f.deviceOf("H").kemPk, sig: f.kemRecOf("D").sig }));
  refused("TreeKemRecord", () => build({ kemPk: D.kemPk, sig: f.kemRecOf("D2").sig }));
  // creation: a member's key authenticated the same way
  const session = { ...w.genesis.record };
  delete session.wrapHashes;
  delete session.sealedInfo;
  const make = (kems) =>
    tk.createGenesis(sc, {
      session,
      kems,
      uaRecordOf: (u) => f.uaRecords().get(u) ?? null,
      accepted: () => true,
      info: f.INFO.I1,
      rand: (x, n) => rnd(`tree-secrets/t/auth/genesis/${x}`, n),
    });
  const good = ["A", "B", "C"].map(f.kemRecOf);
  assert.equal(make(good).sessionId, w.home.sessionId);
  refused("TreeKemRecord", () => make([good[0], good[1], { ...good[2], kemPk: f.deviceOf("H").kemPk }]));
});

test("C-6: an exit count above EXITS_MAX is refused before any record is read (ua-rs's bound, 544)", () => {
  const w = f.smallScenario("small");
  for (const [n, want] of [
    [tk.EXITS_MAX + 1, "TreeReadCorrupted"],
    [0, null],
  ]) {
    const rd = f.lyingReader(w, { "leaveCount(1)": n });
    let got = null;
    try {
      tk.prepareCommit(sc, rd);
    } catch (e) {
      got = e.code;
    }
    assert.equal(got, want, `count ${n}`);
    assert.ok(!rd.log.some((x) => x.startsWith("leaveAt(1,")), `count ${n}: no record read`);
  }
});

// The fix check's C-7 (2026-11-26; ua-rs `tree_kem_record_check`, the same rows of `ua/portable.json`): a member's KEM key at version 0 is the registration's,
// authenticated by its proof of possession (in full and as the hash commit), as ua-rs `kem_record_key` takes it; a substituted
// key, a flipped proof, another UA's registration and another version: `TreeKemRecord`. Before C-7 the reference refused
// every version-0 key.
test("a version-0 KEM key by the registration's proof of possession (fix check C-7)", () => {
  const p = JSON.parse(readFileSync(new URL("../../../smartcontracts/vectors/ua/portable.json", import.meta.url)));
  const g = p.registrations.find((r) => r.kemCommit);
  const other = p.registrations.find((r) => r.ua !== g.ua && r.kind === g.kind);
  const records = new Map(p.registrations.map((r) => [r.ua, { kind: r.kind, keyData: r.keyData }]));
  const uaRecordOf = (u) => records.get(u) ?? null;
  const v1 = p.kemRecords.find((r) => r.id === "mldsa65/v1");
  const key = g.attrs.kemPk;
  const flip = (h) => {
    const x = fromHex(h);
    x[9] ^= 1;
    return hex(x);
  };
  for (const [form, rec] of [
    ["in full", { kemPk: key, attrs: g.attrs, pop: g.pop }],
    ["as the hash commit", { kemPk: key, attrs: g.kemCommit.register.attrs, pop: g.kemCommit.register.pop }],
  ]) {
    assert.equal(tk.recordKey(g.ua, 0, rec, uaRecordOf), key, form);
    refused("TreeKemRecord", () => tk.recordKey(g.ua, 0, { ...rec, kemPk: v1.kemPk }, uaRecordOf));
    refused("TreeKemRecord", () => tk.recordKey(g.ua, 0, { ...rec, pop: flip(rec.pop) }, uaRecordOf));
    refused("TreeKemRecord", () => tk.recordKey(other.ua, 0, rec, uaRecordOf));
    refused("TreeKemRecord", () => tk.recordKey(g.ua, 1, rec, uaRecordOf));
  }
  // a reader with no registration for the UA (`registrationOf` null): refused
  refused("TreeKemRecord", () => tk.recordKey(g.ua, 0, { kemPk: key }, uaRecordOf));
});

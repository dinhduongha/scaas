// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The fixed people, devices and sessions of the PqChat TreeKEM secrets (plan T1b): shared by scripts/pqchat-vectors.mjs (the
// rows of smartcontracts/vectors/pqchat/tree-secrets.json) and test/treekem.test.js. Every random input is
// rnd("tree-secrets/<name>", n) of the generator. UNAUDITED.
import * as pc from "../src/pqchat.js";
import * as tr from "../src/pqchat-tree.js";
import * as tk from "../src/treekem.js";
import { pqKeygen, signUA } from "../src/pq.js";
import { kemPrk, kemKeyFromPrk, kemSeedFromPrk } from "../src/kem.js";
import { hex, keccak_256, utf8ToBytes, concatBytes, fromHex } from "../src/bytes.js";

export const sc = tk.PQCHAT_TREE;
/** keccak256("scaas/pqchat/vectors/<name>/0") ‖ keccak256("…/1") ‖ …, the first n bytes (as pqchat-vectors.mjs). */
export const rnd = (name, n = 32) => {
  const blocks = [];
  for (let i = 0; 32 * i < n; i++) blocks.push(keccak_256(utf8ToBytes(`scaas/pqchat/vectors/${name}/${i}`)));
  return concatBytes(...blocks).slice(0, n);
};
export const Z32 = hex(new Uint8Array(32));
const SEED = rnd("tree-secrets/mldsa65-bip39-seed", 64);
const PEOPLE = ["A", "B", "C", "D", "E", "F", "G", "H"];
/** Every device a scenario names; the registry holds them all. */
const DEVICES = [...PEOPLE, "A2", "B2", "C2", "C3", "E2"];

/** People `names` of one seed (mldsa65, account 0, indexes 0 … n-1), named in the order of their UAs: the first name gets
 *  the lowest UA. A session's members listed by name are then strictly sorted by (ua, keyId), as the contract requires. */
export function rankedPeople(seed, names) {
  const keys = names
    .map((_, index) => ({ index, ...pqKeygen(seed, "mldsa65", 0, index) }))
    .sort((a, b) => (hex(a.ua) < hex(b.ua) ? -1 : 1));
  return new Map(names.map((n, r) => [n, keys[r]]));
}
/** Throws unless `members` ({ua, keyId}) are strictly sorted by (ua, keyId): `PqGroupBase` refuses any other session. */
export function assertSorted(members, what) {
  for (let i = 1; i < members.length; i++) {
    const [a, b] = [members[i - 1], members[i]];
    if (!(a.ua < b.ua || (a.ua === b.ua && a.keyId < b.keyId)))
      throw new Error(`${what}: members not strictly sorted by (ua, keyId) at ${i}`);
  }
}
let ranked;
/** A person: its UA (mldsa65, account 0, the index rankedPeople gives it) and the HKDF-Extract of its KEM seed. */
const person = (name) => {
  ranked ??= rankedPeople(SEED, PEOPLE);
  const k = ranked.get(name);
  return {
    name,
    index: k.index,
    ua: hex(k.ua),
    publicKey: hex(k.publicKey),
    secretKey: k.secretKey,
    prk: kemPrk(rnd(`tree-secrets/kem/${name}`, 64)),
  };
};
const people = new Map();
export const personOf = (name) => people.get(name) ?? people.set(name, person(name)).get(name);
/** A device: a person's KEM version `keyId`, seed-derived (kem.js). Named `A`, `A2` (A's version 2), … */
const devices = new Map();
export function deviceOf(name) {
  if (devices.has(name)) return devices.get(name);
  const p = personOf(name[0]);
  const keyId = Number(name.slice(1)) || 1;
  const key = kemKeyFromPrk(p.prk, fromHex(p.ua), keyId);
  const d = { name, ua: p.ua, keyId, kemPk: hex(key.kemPk), key, kemSeed: kemSeedFromPrk(p.prk, fromHex(p.ua), keyId) };
  devices.set(name, d);
  return d;
}
export const sign = (who, struct, record) =>
  hex(signUA("mldsa65", personOf(who).secretKey, sc.purpose, sc.typed(struct, record), { extraEntropy: false }));
const registry = (names) => ({
  kems: new Map(names.map((n) => [`${deviceOf(n).ua}/${deviceOf(n).keyId}`, deviceOf(n).kemPk])),
  uaKeys: new Map(PEOPLE.map((n) => [personOf(n).ua, personOf(n).publicKey])),
});
/** The leaves of the head as `(ua, keyId)` or null: what a replay's roster by undo must give back. */
const roster = (h) =>
  Array.from({ length: h.tree.leaves }, (_, i) => {
    const n = h.tree.nodes[2 * i];
    return n ? { ua: n.ua, keyId: n.keyId } : null;
  });
const sortedUas = (names) => [...new Set(names.map((n) => personOf(n).ua))].sort();

/** A session's world: its home, the devices it knows (the registry), and its tag for the randomness. */
export function createSession({
  tag,
  creator,
  nonce,
  admins,
  members,
  info,
  devicesKnown,
  homeChain,
  homeChatContract,
}) {
  const session = {
    creator: personOf(creator).ua,
    nonce,
    homeChain: homeChain ?? hex(rnd("tree-secrets/home-chain")),
    homeChatContract: homeChatContract ?? hex(rnd("tree-secrets/home-contract", 20)),
    admins: sortedUas(admins),
    members: members.map((n) => ({ ua: deviceOf(n).ua, keyId: deviceOf(n).keyId, via: Z32 })),
    groupMode: 1,
  };
  assertSorted(session.members, `session ${tag}`);
  const genesis = tk.createGenesis(sc, {
    session,
    kemPks: members.map((n) => deviceOf(n).kemPk),
    info,
    rand: (name, n) => rnd(`tree-secrets/${tag}/genesis/${name}`, n),
  });
  const sig = sign(creator, "PqChatSession", genesis.record);
  const home = tk.newHome({ genesis, sig, ...registry(devicesKnown ?? DEVICES) });
  return { tag, home, genesis, sig, steps: [], rosters: [roster(home)] };
}

/** `name`'s device commits on the head: `adds` are `[device, leaf]` (or with a `via`), `removes` device names; `info`
 *  "auto" (the device's rule, C33), null (the marker) or a full info; `admins` names or the head's list. Lands it unless
 *  `land` is false. `faults` and `seedOf` (a foreign seed) are for refusal rows. */
export function commit(w, name, o = {}) {
  const d = deviceOf(name);
  const rd = tk.reader(w.home);
  const prep = tk.prepareCommit(sc, rd);
  const leaf = prep.tree.nodes.findIndex((n, x) => x % 2 === 0 && n?.ua === d.ua && n.keyId === d.keyId) / 2;
  const headRecord = w.home.epochs.at(-1).record;
  const nonce = o.nonce ?? 100 + w.home.epochs.length;
  let info = o.info === undefined ? "auto" : o.info;
  if (info === "auto") info = tk.infoToSeal(tk.replay(sc, tk.reader(w.home), d));
  const step = `${w.tag}/${o.tag ?? `epoch-${w.home.epochs.length}`}`;
  const built = tk.buildCommit(
    sc,
    {
      tree: prep.tree,
      parent: prep.parent,
      sessionId: w.home.sessionId,
      treeId: w.home.treeId,
      author: d.ua,
      leaf,
      keyId: d.keyId,
      kemSeed: o.seedOf ? deviceOf(o.seedOf).kemSeed : d.kemSeed,
      nonce,
      removes: (o.removes ?? []).map((n) => {
        const r = deviceOf(n);
        const l = prep.tree.nodes.findIndex((x, i) => i % 2 === 0 && x?.ua === r.ua && x.keyId === r.keyId) / 2;
        return { leaf: l, ua: r.ua, keyId: r.keyId };
      }),
      adds: (o.adds ?? []).map(([n, l, via]) => ({
        leaf: l,
        ua: deviceOf(n).ua,
        keyId: deviceOf(n).keyId,
        via: via ?? Z32,
        kemHash: hex(keccak_256(fromHex(deviceOf(n).kemPk))),
        kemPk: deviceOf(n).kemPk,
      })),
      admins: o.admins ? sortedUas(o.admins) : headRecord.admins,
      info,
      keyOf: prep.keyOf,
      rand: (x, n) => rnd(`tree-secrets/${step}/${x}`, n),
    },
    o.faults,
  );
  const sig = sign(name[0], "PqChatCommit", built.record);
  if (o.land !== false) {
    tk.landCommit(w.home, built, sig);
    w.rosters.push(roster(w.home));
  }
  w.steps.push({ name: step, author: name, built, sig });
  return { built, sig };
}

/** A landed `treeLeave` by `name` or `treeRemove` by admin `name` of `members` (names of people), on the head. */
export function gone(w, kind, name, members, nonce) {
  const h = w.home;
  const base = { sessionId: h.sessionId, treeId: h.treeId, epochId: h.epochs.at(-1).id };
  const [struct, record] =
    kind === 1
      ? ["PqChatTreeLeave", { ...base, member: personOf(name).ua, nonce }]
      : [
          "PqChatTreeRemove",
          {
            ...base,
            nextEpoch: h.epochs.length,
            members: members.map((n) => personOf(n).ua),
            admin: personOf(name).ua,
            nonce,
          },
        ];
  const sig = sign(name, struct, record);
  tk.landGone(h, kind, struct, record, sig);
  w.steps.push({ name: `${w.tag}/${struct}`, gone: { kind, struct, record, sig } });
  return { struct, record, sig };
}

/** A device's replay of the home (an endpoint that lies by `tamper`). */
export const replayOf = (w, name, tamper, store) => tk.replay(sc, tk.reader(w.home, tamper), deviceOf(name), store);
export { pc, tr, tk, hex };

// ------------------------------------------------------------------ the scenarios of plan T1b

export const INFO = {
  I1: { stores: [{ kind: "matrix", room: "!tree-vectors:example.org" }] },
  I2: { stores: [{ kind: "matrix", room: "!tree-vectors-2:example.org" }] },
  I3: { stores: [{ kind: "hcs", topic: "0.0.7622" }] },
  NON_ADMIN: { stores: [{ kind: "matrix", room: "!not-an-admins:example.org" }] },
};
const badCt = (tag, j) => ({ ct: { [j]: hex(rnd(`tree-secrets/${tag}/bad-sealed-secret/${j}`, 48)) } });
/** The index of the ciphertext of commit `built` over `device`'s leaf. */
export const ctIndexFor = (built, device) => {
  const d = deviceOf(device);
  const leaf = built.tree.nodes.findIndex((n, x) => x % 2 === 0 && n?.ua === d.ua && n.keyId === d.keyId) / 2;
  const mine = new Set([2 * leaf, ...tr.directPath(2 * leaf, built.tree.leaves)]);
  return built.ctTargets.findIndex((t) => mine.has(t));
};
/** A commit as `commit` builds it, but with the ciphertext over `victims`' leaves replaced (a validly signed bad ciphertext). */
function commitBadFor(w, name, victims, o = {}) {
  const probe = commit(w, name, { ...o, land: false });
  w.steps.pop();
  const faults = { ct: {} };
  for (const v of victims) Object.assign(faults.ct, badCt(w.tag, ctIndexFor(probe.built, v)).ct);
  return commit(w, name, { ...o, faults });
}

/** create (3 UAs, one with 2 keys) → B → an Add of D (a non-zero via) → a third member → the new member → treeRemove of B
 *  then a non-admin's commit that drops B → a Remove by (ua, keyId) (spec §5, §10; plan T1b). */
export function mainScenario() {
  const w = createSession({
    tag: "main",
    creator: "A",
    nonce: 1,
    admins: ["A"],
    members: ["A", "B", "C", "C2"],
    info: INFO.I1,
  });
  commit(w, "B");
  commit(w, "A", { adds: [["D", 4, hex(rnd("tree-secrets/main/via-D"))]] });
  commit(w, "C");
  commit(w, "D");
  gone(w, 2, "A", ["B"], 1);
  commit(w, "C", { removes: ["B"] });
  commit(w, "A", { removes: ["C2"] });
  return w;
}
/** The joiner's path secret (codex-5, fable-5): E adds D next to itself; A's commit right after targets the node above D. */
export function joinerScenario() {
  const w = createSession({
    tag: "joiner",
    creator: "A",
    nonce: 2,
    admins: ["A", "E"],
    members: ["A", "B", "C", "C2", "E"],
    info: INFO.I1,
  });
  commit(w, "E", { adds: [["D", 5]] });
  commit(w, "A");
  return w;
}
/** Healing (codex-15, fable-6, fable-4, fable-r2-7): A's commit is bad for B; E's is bad for all; E is removed and F's commit
 *  falls back to node 3, which B never held; A's commit reaches B's leaf; then B refreshes. */
export function healScenario() {
  const w = createSession({
    tag: "heal",
    creator: "A",
    nonce: 3,
    admins: ["A"],
    members: ["A", "B", "C", "C2", "E", "F"],
    info: INFO.I1,
  });
  commitBadFor(w, "A", ["B"]); // 1
  commitBadFor(w, "E", ["A", "C", "F"]); // 2: its ciphertexts to node 3 and to F
  gone(w, 2, "A", ["E"], 1);
  commit(w, "F", { removes: ["E"] }); // 3: back to node 3 of epoch 1
  commit(w, "A"); // 4: reaches B's leaf, locks the leaked set of epoch 1 out
  commit(w, "B"); // 5: B's refresh
  return w;
}
/** fable-r3-1: the admin changes the info in epoch 1, E misses it, follows C's commit of 2 from its sibling side, then adds its
 *  own new key (3). `follow`: the control, in which E followed epoch 1. */
export function gapScenario(follow) {
  const tag = follow ? "gap-control" : "gap";
  const w = createSession({ tag, creator: "A", nonce: 4, admins: ["A"], members: ["A", "B", "C", "E"], info: INFO.I1 });
  if (follow) commit(w, "A", { info: INFO.I2 });
  else commitBadFor(w, "A", ["E"], { info: INFO.I2 });
  commit(w, "C");
  commit(w, "E", { adds: [["E2", 4]] });
  return w;
}
/** codex-r2-3, fable-r2-5: C2 misses epochs 1 and 2 (bad ciphertexts), then refreshes (3). */
export function behindScenario() {
  const w = createSession({
    tag: "behind",
    creator: "A",
    nonce: 9,
    admins: ["A"],
    members: ["A", "B", "C", "C2"],
    info: INFO.I1,
  });
  commitBadFor(w, "A", ["C2"]); // 1
  commitBadFor(w, "B", ["C2"]); // 2
  commit(w, "C2"); // 3: the refresh
  return w;
}
/** codex-r3-1: D joins at 2 and is removed at 5, C (a genesis key) is removed at 7, the head is 9. */
export function retiredScenario() {
  const w = createSession({
    tag: "retired",
    creator: "A",
    nonce: 5,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: INFO.I1,
  });
  commit(w, "B"); // 1
  commit(w, "A", { adds: [["D", 3]] }); // 2
  commit(w, "B"); // 3
  commit(w, "C"); // 4
  commit(w, "A", { removes: ["D"] }); // 5
  commit(w, "A", { adds: [["E", 3]] }); // 6
  commit(w, "A", { removes: ["C"] }); // 7
  commit(w, "A", { adds: [["F", 4]] }); // 8
  commit(w, "B"); // 9
  return w;
}
/** codex-r3-3: B's UA signs a commit B's seed did not build that also adds B2; B refreshes; B removes B2. */
export function foreignScenario() {
  const w = createSession({
    tag: "foreign",
    creator: "A",
    nonce: 6,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: INFO.I1,
  });
  commit(w, "B", { seedOf: "H", adds: [["B2", 3]], info: null }); // 1
  commit(w, "B"); // 2
  commit(w, "B", { removes: ["B2"] }); // 3
  return w;
}
/** codex-r3-4: the last live leaf commits, its path empty; `seedOf` a foreign seed. */
export function emptyPathScenario(seedOf) {
  const w = createSession({
    tag: seedOf ? "empty-path-foreign" : "empty-path",
    creator: "A",
    nonce: 7,
    admins: ["A"],
    members: ["A", "B"],
    info: INFO.I1,
  });
  commit(w, "A", { removes: ["B"] }); // 1
  commit(w, "A", { seedOf }); // 2
  return w;
}
/** codex-r3-7: the only admin misses epoch 1, follows 2 (B's) with the info flagged, seals the marker in 3, establishes I3 in 4. */
export function adminGapScenario() {
  const w = createSession({
    tag: "admin-gap",
    creator: "A",
    nonce: 8,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: INFO.I1,
  });
  commitBadFor(w, "B", ["A"]); // 1
  commit(w, "B"); // 2
  commit(w, "A"); // 3: auto, the marker
  commit(w, "A", { info: INFO.I3 }); // 4: established anew
  return w;
}

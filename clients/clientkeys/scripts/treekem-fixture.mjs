// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The fixed people, devices and sessions of the PqChat TreeKEM secrets (plan T1b): shared by scripts/pqchat-vectors.mjs (the
// rows of smartcontracts/vectors/pqchat/tree-secrets.json) and test/treekem.test.js. Every random input is
// rnd("tree-secrets/<name>", n) of the generator. UNAUDITED.
import * as pc from "../src/pqchat.js";
import * as tr from "../src/pqchat-tree.js";
import * as tk from "../src/treekem.js";
import { pqKeygen, signUA, PQ_KINDS } from "../src/pq.js";
import * as ua from "../src/ua.js";
import { encodeMemberSigs } from "../src/ua-verify.js";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { kemPrk, kemKeyFromPrk, kemSeedFromPrk } from "../src/kem.js";
import { hex, keccak_256, utf8ToBytes, concatBytes, fromHex, b64url, abiEncode } from "../src/bytes.js";

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
const MLDSA65 = PQ_KINDS.mldsa65.kind;
const pqSign = (secretKey, purpose, digest) => signUA("mldsa65", secretKey, purpose, digest, { extraEntropy: false });
/** The keyless admins (no KEM key, never a leaf; spec §9: they act by `treeRemove` only), each with its registry record and its
 *  portable signature (F-3): `M`, a 2-of-2 `msig` over two ML-DSA-65 UAs of the seed (indexes 8 and 9, outside the people);
 *  `W`, a WebAuthn P-256 UA. */
let keyless;
export function keylessOf(name) {
  if (!keyless) {
    const subs = [8, 9].map((i) => ({ i, ...pqKeygen(SEED, "mldsa65", 0, i) }));
    const members = subs
      .map((k) => ({ kind: MLDSA65, id: hex(k.ua), weight: 1, k }))
      .sort((x, y) => (x.id < y.id ? -1 : 1));
    const mKey = ua.encodeMsig(2, members);
    const mUa = hex(ua.deriveUA(0x0120, mKey));
    // WebAuthn P-256 (ua-signers.mjs's form; its import chain needs packages this fixture does not): the key data
    // `x ‖ y ‖ sha256(rpId)`, the assertion `abi.encode(authenticatorData, clientDataJSON, r, s)`
    const wSk = rnd("tree-secrets/webauthn-admin");
    const rp = sha256(utf8ToBytes("scaas.example"));
    const wKey = concatBytes(p256.getPublicKey(wSk, false).subarray(1), rp);
    const webauthn = (msg) => {
      const authData = concatBytes(rp, Uint8Array.of(0x05), Uint8Array.of(0, 0, 0, 1));
      const cd = utf8ToBytes(`{"type":"webauthn.get","challenge":"${b64url(msg)}","origin":"https://scaas.example"}`);
      const sig = p256.sign(sha256(concatBytes(authData, sha256(cd))), wSk, {
        prehash: false,
        lowS: true,
        format: "compact",
      });
      return abiEncode(
        ["bytes", "bytes", "bytes32", "bytes32"],
        [authData, cd, sig.subarray(0, 32), sig.subarray(32, 64)],
      );
    };
    keyless = {
      M: {
        ua: mUa,
        kind: 0x0120,
        keyData: hex(mKey),
        subs: members.map((m) => ({ ua: m.id, kind: MLDSA65, keyData: hex(m.k.publicKey) })),
        sign: (purpose, digest) => {
          const md = ua.memberDigest(mUa, ua.uaMessage(0x0120, purpose, digest));
          const list = members.map((m, index) => ({
            index,
            members: [],
            sig: pqSign(m.k.secretKey, ua.purposeTag("member"), md),
          }));
          return { signature: "0x", members: hex(encodeMemberSigs(list)) };
        },
      },
      W: {
        ua: hex(ua.deriveUA(0x0100, wKey)),
        kind: 0x0100,
        keyData: hex(wKey),
        subs: [],
        sign: (purpose, digest) => hex(webauthn(ua.uaMessage(0x0100, purpose, digest))),
      },
    };
  }
  return keyless[name];
}
/** A record's signature by `who` (a person: ML-DSA-65; `M` or `W`: a keyless admin's portable signature). */
export const sign = (who, struct, record) =>
  who === "M" || who === "W"
    ? keylessOf(who).sign(sc.purpose, sc.typed(struct, record))
    : hex(pqSign(personOf(who).secretKey, sc.purpose, sc.typed(struct, record)));
/** The registry records of every signer: `ua` → `{ kind, keyData }`. */
export const uaRecords = () =>
  new Map([
    ...PEOPLE.map((n) => [personOf(n).ua, { kind: MLDSA65, keyData: personOf(n).publicKey }]),
    ...["M", "W"].flatMap((n) =>
      [keylessOf(n), ...keylessOf(n).subs].map((k) => [k.ua, { kind: k.kind, keyData: k.keyData }]),
    ),
  ]);
const registry = (names) => ({
  kems: new Map(names.map((n) => [`${deviceOf(n).ua}/${deviceOf(n).keyId}`, deviceOf(n).kemPk])),
  uaRecords: uaRecords(),
});
/** A person's or a keyless admin's UA by name. */
export const uaOf = (name) => (name === "M" || name === "W" ? keylessOf(name).ua : personOf(name).ua);
/** The leaves of the head as `(ua, keyId)` or null: what a replay's roster by undo must give back. */
const roster = (h) =>
  Array.from({ length: h.tree.leaves }, (_, i) => {
    const n = h.tree.nodes[2 * i];
    return n ? { ua: n.ua, keyId: n.keyId } : null;
  });
const sortedUas = (names) => [...new Set(names.map(uaOf))].sort();

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

/** A landed `treeLeave` by `name` or `treeRemove` by admin `name` of `members` (names), naming the head or, with `named`, the
 *  ancestor at that number (C9: applied at the head either way). */
export function gone(w, kind, name, members, nonce, named = null) {
  const h = w.home;
  const at = named ?? h.epochs.length - 1;
  const base = { sessionId: h.sessionId, treeId: h.treeId, epochId: h.epochs[at].id };
  const [struct, record] =
    kind === 1
      ? ["PqChatTreeLeave", { ...base, member: uaOf(name), nonce }]
      : [
          "PqChatTreeRemove",
          {
            ...base,
            nextEpoch: at + 1,
            members: [...members.map(uaOf)].sort(),
            admin: uaOf(name),
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

// ------------------------------------------------------------------ the rows of the code review of 2026-11-24 (plan T11)

/** C9, F-2, F-3, the spec check sc-F-1 and sc-F-2: the keyless admins M (an `msig`) and W (WebAuthn) beside A. M removes D naming
 *  epoch 0 two below the head (applied at 2); the non-admin B honours it (3); W removes M, a keyless admin (at 3); the
 *  non-admin C drops the gone M from `admins` (4); W removes itself, A removes E and leaves, all on head 4; the non-admin B
 *  drops A, E and W (5); C commits (6). Every chain the home accepted: every device follows. */
export function exitsScenario() {
  const w = createSession({
    tag: "exits",
    creator: "A",
    nonce: 10,
    admins: ["A", "M", "W"],
    members: ["A", "B", "C", "D", "E"],
    info: INFO.I1,
  });
  commit(w, "B"); // 1
  commit(w, "C"); // 2
  gone(w, 2, "M", ["D"], 1, 0);
  commit(w, "B", { removes: ["D"] }); // 3
  gone(w, 2, "W", ["M"], 1);
  commit(w, "C", { admins: ["A", "W"] }); // 4
  gone(w, 2, "W", ["W"], 2);
  gone(w, 2, "A", ["E"], 1);
  gone(w, 1, "A", [], 2);
  commit(w, "B", { removes: ["A", "E"], admins: [] }); // 5
  commit(w, "C"); // 6
  return w;
}
/** C-2: a validly signed ciphertext with a small-order `x25519Eph` over A's leaf (1), a Welcome to D with one (2): "opening
 *  failed" and "welcome disagrees" in both readers, never an abort. */
export function smallOrderScenario() {
  const w = createSession({
    tag: "small-order",
    creator: "A",
    nonce: 11,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: INFO.I1,
  });
  const probe = commit(w, "B", { land: false });
  w.steps.pop();
  commit(w, "B", { faults: { eph: { [ctIndexFor(probe.built, "A")]: true } } }); // 1
  commit(w, "A", { adds: [["D", 3]], faults: { welcomeEph: { 0: true } } }); // 2
  return w;
}
/** The base of the lies below: A (admin), B, C; B commits (1); with `removeC`, A removes C on head 1, not honoured yet. */
export function smallScenario(tag, removeC = false) {
  const w = createSession({ tag, creator: "A", nonce: 12, admins: ["A"], members: ["A", "B", "C"], info: INFO.I1 });
  commit(w, "B"); // 1
  if (removeC) gone(w, 2, "A", ["C"], 1);
  return w;
}
/** The lag (C9, EXIT_LAG_MAX): 17 plain commits by B and C. */
export function lagScenario() {
  const w = createSession({
    tag: "lag",
    creator: "A",
    nonce: 13,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: INFO.I1,
  });
  for (let n = 1; n <= 17; n++) commit(w, n % 2 ? "B" : "C");
  return w;
}

const leafOf = (t, d) => t.nodes.findIndex((n, x) => x % 2 === 0 && n?.ua === d.ua && n.keyId === d.keyId) / 2;
/** What an endpoint serves for a commit `built` (signed `sig`) it adds on the head of `w` with the tree after it: the views of
 *  the walk's reads that change, by read name. */
function served(w, built, sig) {
  const h = w.home;
  const n = h.epochs.length;
  const t = built.tree;
  return {
    "epochsOf()": [...h.epochs.map((e) => e.id), built.epochId],
    [`commitOf(${n})`]: { record: built.record, sig },
    "treeOf()": {
      treeId: h.treeId,
      leaves: t.leaves,
      used: t.used,
      treeHash: t.hash[tr.root(t.leaves)],
      genesisTreeHash: h.genesisTreeHash,
    },
    "treeLeaves()": Array.from({ length: t.leaves }, (_, i) => {
      const x = t.nodes[2 * i];
      const j = h.join.get(i) ?? { joinEpoch: n, wrapIndex: 0 };
      return x
        ? { ua: x.ua, keyId: x.keyId, joinEpoch: j.joinEpoch, wrapIndex: j.wrapIndex, kemHash: x.kemHash }
        : { ua: Z32, keyId: 0, joinEpoch: 0, wrapIndex: 0, kemHash: Z32 };
    }),
    "treeNodes()": t.hash.map((hash, x) => ({ hash, keyHash: t.nodes[x]?.keyHash ?? Z32, epoch: 0 })),
    [`leaveCount(${n})`]: 0,
    [`removalCount(${n})`]: 0,
    [`pathListOf(${n})`]: { ctTargets: built.ctTargets, ctHashes: built.ctHashes },
    ...Object.fromEntries(built.cts.map((c, j) => [`pathCtAt(${n},${j})`, c.ct])),
  };
}
/** A commit by device `name` on the head of `w` built on `tree` (a lie's tree, or the true one), signed, never landed:
 *  `o.admins` names, `o.removes` device names, `o.adds` `[device, leaf]`, `o.edit(record)` changes the record before it is
 *  signed (an author that signs what the contract would refuse). */
function forgedCommit(w, name, tree, o = {}) {
  const d = deviceOf(name);
  const h = w.home;
  const head = h.epochs.at(-1);
  const built = tk.buildCommit(sc, {
    tree,
    parent: { epochId: head.id, epoch: h.epochs.length - 1, treeHash: tr.treeHash(tree) },
    sessionId: h.sessionId,
    treeId: h.treeId,
    author: d.ua,
    leaf: leafOf(tree, d),
    keyId: d.keyId,
    kemSeed: d.kemSeed,
    nonce: 900 + h.epochs.length,
    removes: (o.removes ?? []).map((n) => {
      const r = deviceOf(n);
      return { leaf: leafOf(tree, r), ua: r.ua, keyId: r.keyId };
    }),
    adds: (o.adds ?? []).map(([n, leaf]) => ({
      leaf,
      ua: deviceOf(n).ua,
      keyId: deviceOf(n).keyId,
      via: Z32,
      kemHash: hex(keccak_256(fromHex(deviceOf(n).kemPk))),
      kemPk: deviceOf(n).kemPk,
    })),
    admins: o.admins ? sortedUas(o.admins) : head.record.admins,
    info: null,
    keyOf: (x) => (x % 2 === 0 ? h.kems.get(`${tree.nodes[x].ua}/${tree.nodes[x].keyId}`) : h.nodeKey.get(x).kemPk),
    rand: (x, n) => rnd(`tree-secrets/${w.tag}/forged/${name}/${x}`, n),
  });
  if (o.edit) built.record = o.edit({ ...built.record });
  return { built, sig: sign(name[0], "PqChatCommit", built.record) };
}
/** A removal record by `admin` of `members` on world `w`, kept under its head, naming epoch `named` (an id or a number). */
function keptRemoval(w, admin, members, named, nonce, treeId = w.home.treeId, o = {}) {
  const h = w.home;
  const epochId = typeof named === "number" ? h.epochs[named].id : named;
  const record = {
    sessionId: h.sessionId,
    treeId,
    epochId,
    nextEpoch: o.nextEpoch ?? (typeof named === "number" ? named : 0) + 1,
    members: o.unsorted ? members.map(uaOf).sort().reverse() : members.map(uaOf).sort(),
    admin: uaOf(admin),
    nonce,
  };
  const { treeId: _, ...kept } = record;
  return { record: kept, sig: sign(admin, "PqChatTreeRemove", record) };
}

/** The lying reads of plan T11 (C25, C26, E-1, F-1, sc-F-3, sc-F-7, E-4): per row the world, the device, the views the endpoint
 *  replaces (by read name), the pin the device holds, and what replay and prepare give (null: accepted). `worlds` by name. */
export function lies(worlds) {
  const rows = [];
  const add = (name, world, device, overrides, expect, pin = null) =>
    rows.push({ name, world, device, overrides, pin, expect });
  const W = (n) => worlds.get(n);
  {
    // E-1: H, a UA of no roster, signs the next epoch from the blank leaf 3 of the true tree
    const w = W("small");
    const fake = tr.treeFromJson(JSON.parse(JSON.stringify(tr.treeJson(w.home.tree))));
    const H = deviceOf("H");
    fake.nodes[6] = { ua: H.ua, keyId: H.keyId, kemHash: hex(keccak_256(fromHex(H.kemPk))) };
    fake.used = 4;
    tr.rehashAll(fake);
    const f = forgedCommit(w, "H", fake);
    add("forged head by a non-member (E-1)", "small", "A", served(w, f.built, f.sig), {
      replay: "TreeReadCorrupted",
      prepare: "TreeReadCorrupted",
    });
    // a non-admin's commit that drops a live admin: rights (§9), a lying read
    const g = forgedCommit(w, "C", w.home.tree, { admins: [] });
    add("a non-admin drops a live admin", "small", "A", served(w, g.built, g.sig), {
      replay: "TreeReadCorrupted",
      prepare: "TreeReadCorrupted",
    });
    // sc-F-7: a record with leaves 2^31, refused before anything is allocated
    const big = served(w, g.built, g.sig);
    big["commitOf(2)"].record = { ...big["commitOf(2)"].record, leaves: 2 ** 31 };
    add("a record with leaves 2^31 (sc-F-7)", "small", "A", big, {
      replay: "TreeReadCorrupted",
      prepare: "TreeReadCorrupted",
    });
    // E-4: the contract serves `used` leaves, not `leaves`: accepted
    const used = { "treeLeaves()": tk.reader(w.home).treeLeaves().slice(0, w.home.tree.used) };
    add("the leaf list of used positions only (E-4)", "small", "A", used, { replay: null, prepare: null });
    // exits kept under the head: an ancestor (epoch 0, one below) accepted; an unknown epoch, another treeId, a non-admin's
    const ok = keptRemoval(w, "A", ["C"], 0, 5);
    add(
      "a removal naming the parent of the head",
      "small",
      "C",
      { "removalCount(1)": 1, "removalAt(1,0)": ok },
      {
        replay: null,
        prepare: null,
      },
    );
    const lose = keptRemoval(w, "A", ["C"], hex(rnd("tree-secrets/lies/losing-epoch")), 5);
    add(
      "a removal naming an epoch that is not the home's",
      "small",
      "A",
      {
        "removalCount(1)": 1,
        "removalAt(1,0)": lose,
      },
      { replay: "TreeReadCorrupted", prepare: "TreeReadCorrupted" },
    );
    const other = keptRemoval(w, "A", ["C"], 1, 5, hex(rnd("tree-secrets/lies/other-tree")));
    add(
      "a removal signed for another treeId",
      "small",
      "A",
      { "removalCount(1)": 1, "removalAt(1,0)": other },
      {
        replay: "TreeReadCorrupted",
        prepare: "TreeReadCorrupted",
      },
    );
    const nonAdmin = keptRemoval(w, "B", ["C"], 1, 5);
    add(
      "a removal by a non-admin of the head",
      "small",
      "A",
      {
        "removalCount(1)": 1,
        "removalAt(1,0)": nonAdmin,
      },
      { replay: "TreeReadCorrupted", prepare: "TreeReadCorrupted" },
    );
    const lie = { replay: "TreeReadCorrupted", prepare: "TreeReadCorrupted" };
    const next = keptRemoval(w, "A", ["C"], 1, 5, w.home.treeId, { nextEpoch: 1 });
    add(
      "a removal whose nextEpoch is not the named number plus one",
      "small",
      "A",
      {
        "removalCount(1)": 1,
        "removalAt(1,0)": next,
      },
      lie,
    );
    const unsorted = keptRemoval(w, "A", ["B", "C"], 1, 5, w.home.treeId, { unsorted: true });
    add("a removal of two UAs out of order", "small", "A", { "removalCount(1)": 1, "removalAt(1,0)": unsorted }, lie);
    const hLeave = {
      sessionId: w.home.sessionId,
      treeId: w.home.treeId,
      epochId: w.home.epochs[1].id,
      member: uaOf("H"),
      nonce: 5,
    };
    const { treeId: _t, ...keptLeave } = hLeave;
    add(
      "a leave by a UA that holds no leaf",
      "small",
      "A",
      {
        "leaveCount(1)": 1,
        "leaveAt(1,0)": { record: keptLeave, sig: sign("H", "PqChatTreeLeave", hLeave) },
      },
      lie,
    );
    // what only the bounds or a check of the walk refuse, each validly signed by its author (the contract refuses them)
    const forged = (what, o, device = "C", author = "B") => {
      const f = forgedCommit(w, author, w.home.tree, o);
      add(what, "small", device, served(w, f.built, f.sig), lie);
    };
    forged("a commit with 4,125 B of sealedInfo", { edit: (r) => ({ ...r, sealedInfo: hex(new Uint8Array(4125)) }) });
    forged("a commit with a wrap hash and no Add", {
      edit: (r) => ({ ...r, wrapHashes: [hex(rnd("tree-secrets/lies/wrap"))] }),
    });
    forged("an admin's admin list with no admin that holds a leaf", { admins: ["H"] }, "C", "A");
    forged("a non-admin's Remove of a live UA's leaf", { removes: ["C"] }, "A");
    forged("a non-admin's Add of another UA", { adds: [["D", 3]] }, "A");
    forged("a commit whose leaves is not its tree's", { edit: (r) => ({ ...r, leaves: 8 }) });
    forged("a commit signed for another treeId", {
      edit: (r) => ({ ...r, treeId: hex(rnd("tree-secrets/lies/tree-id")) }),
    });
    forged("a commit of another sessionId", { edit: (r) => ({ ...r, sessionId: hex(rnd("tree-secrets/lies/sid")) }) });
    forged("a commit whose parentEpochId is not its parent's", {
      edit: (r) => ({ ...r, parentEpochId: hex(rnd("tree-secrets/lies/parent")) }),
    });
    forged("a commit whose parentTreeHash is not its parent's tree", {
      edit: (r) => ({ ...r, parentTreeHash: hex(rnd("tree-secrets/lies/parent-tree")) }),
    });
    {
      // a signed treeHash that is not the tree's, the snapshot served under it
      const f = forgedCommit(w, "B", w.home.tree, {
        edit: (r) => ({ ...r, treeHash: hex(rnd("tree-secrets/lies/tree")) }),
      });
      const o = served(w, f.built, f.sig);
      o["treeOf()"] = { ...o["treeOf()"], treeHash: f.built.record.treeHash };
      add("a commit whose treeHash is not its tree's", "small", "C", o, lie);
    }
    {
      // a record that is not the epoch epochsOf holds at its number: B's twin of epoch 1 under another nonce
      const w0 = createSession({
        tag: "small",
        creator: "A",
        nonce: 12,
        admins: ["A"],
        members: ["A", "B", "C"],
        info: INFO.I1,
      });
      const t = forgedCommit(w0, "B", w0.home.tree);
      add(
        "a record that is not the one epochsOf holds at its number",
        "small",
        "A",
        {
          "commitOf(1)": { record: t.built.record, sig: t.sig },
        },
        lie,
      );
    }
    const lose0 = keptRemoval(w, "A", ["C"], hex(rnd("tree-secrets/lies/losing-epoch")), 5, w.home.treeId, {
      nextEpoch: 0,
    });
    add(
      "a removal naming an epoch that is not the home's, nextEpoch 0",
      "small",
      "A",
      {
        "removalCount(1)": 1,
        "removalAt(1,0)": lose0,
      },
      lie,
    );
    forged("a commit whose ctCount is not its path's", { edit: (r) => ({ ...r, ctCount: r.ctCount - 1 }) });
    const stranger = keptRemoval(w, "A", ["H"], 1, 5);
    add("a removal of a UA that is no member", "small", "A", { "removalCount(1)": 1, "removalAt(1,0)": stranger }, lie);
    const bLeave = { ...hLeave, member: uaOf("B") };
    const { treeId: _b, ...keptB } = bLeave;
    add(
      "a leave signed by another UA",
      "small",
      "A",
      {
        "leaveCount(1)": 1,
        "leaveAt(1,0)": { record: keptB, sig: sign("A", "PqChatTreeLeave", bLeave) },
      },
      lie,
    );
    // a list whose targets are not the walk's: the author signs the hash of the reversed list
    const g2 = forgedCommit(w, "B", w.home.tree);
    const rev = [...g2.built.ctTargets].reverse();
    const revH = [...g2.built.ctHashes].reverse();
    g2.built.record = { ...g2.built.record, ctListHash: hex(tr.pathListHash(rev, revH)) };
    const revSig = sign("B", "PqChatCommit", g2.built.record);
    add(
      "a list whose targets are not the walk's",
      "small",
      "C",
      {
        ...served(w, g2.built, revSig),
        "pathListOf(2)": { ctTargets: rev, ctHashes: revH },
        ...Object.fromEntries([...g2.built.cts].reverse().map((c, j) => [`pathCtAt(2,${j})`, c.ct])),
      },
      { replay: "TreeReadCorrupted", prepare: null },
    );
  }
  {
    // F-1 (a): C removed by A at 1 and the removal honoured at 2 by B; C served back on its old leaf signs epoch 3
    const w = W("returned");
    const fake = tr.treeFromJson(JSON.parse(JSON.stringify({ ...tr.treeJson(w.home.tree), goneUa: [], goneKey: [] })));
    const C = deviceOf("C");
    fake.nodes[4] = { ua: C.ua, keyId: C.keyId, kemHash: hex(keccak_256(fromHex(C.kemPk))) };
    tr.rehashAll(fake);
    const f = forgedCommit(w, "C", fake);
    add("a removed member served back on its leaf (F-1)", "returned", "A", served(w, f.built, f.sig), {
      replay: "TreeReadCorrupted",
      prepare: "TreeReadCorrupted",
    });
  }
  {
    // sc-F-3: A's pin holds C's removal at 1; after a restart the endpoint hides it and serves an epoch 2 signed by C
    const w = W("pin-exit");
    const pin = replayOf(w, "A").pin;
    const fake = tr.treeFromJson(JSON.parse(JSON.stringify({ ...tr.treeJson(w.home.tree), goneUa: [] })));
    const f = forgedCommit(w, "C", fake);
    const hidden = { ...served(w, f.built, f.sig), "removalCount(1)": 0 };
    add(
      "the pin's exit hidden, then an epoch by the exited UA (sc-F-3)",
      "pin-exit",
      "A",
      hidden,
      {
        replay: "TreeReadCorrupted",
        prepare: "TreeReadCorrupted",
      },
      pin,
    );
    add("the same without a pin: the residual of §14", "pin-exit", "A", hidden, { replay: null, prepare: null });
    // the removal not hidden: the exited UA's epoch is refused by the walk itself
    add("an epoch by a UA whose removal the walk read", "pin-exit", "A", served(w, f.built, f.sig), {
      replay: "TreeReadCorrupted",
      prepare: "TreeReadCorrupted",
    });
  }
  {
    // an empty path (the last live leaf) whose record signs another list hash than the empty one (codex-r2-14)
    const w = W("empty-path");
    const f = forgedCommit(w, "A", w.home.tree, {
      edit: (r) => ({ ...r, ctListHash: hex(rnd("tree-secrets/lies/list")) }),
    });
    add("an empty path with another list hash", "empty-path", "A", served(w, f.built, f.sig), {
      replay: "TreeReadCorrupted",
      prepare: "TreeReadCorrupted",
    });
  }
  {
    // the lag: an exit kept under 17 naming 1 (16 below) accepted, naming 0 (17 below) a lying read
    const w = W("lag");
    const at16 = keptRemoval(w, "A", ["C"], 1, 5);
    add(
      "an exit 16 epochs below the head",
      "lag",
      "B",
      { "removalCount(17)": 1, "removalAt(17,0)": at16 },
      {
        replay: null,
        prepare: null,
      },
    );
    const at17 = keptRemoval(w, "A", ["C"], 0, 5);
    add(
      "an exit 17 epochs below the head",
      "lag",
      "B",
      { "removalCount(17)": 1, "removalAt(17,0)": at17 },
      {
        replay: "TreeReadCorrupted",
        prepare: "TreeReadCorrupted",
      },
    );
  }
  return rows;
}
/** `returned`: A, B, C, E; B commits (1); A removes C at 1; B honours it (2). */
export function returnedScenario() {
  const w = createSession({
    tag: "returned",
    creator: "A",
    nonce: 14,
    admins: ["A"],
    members: ["A", "B", "C", "E"],
    info: INFO.I1,
  });
  commit(w, "B"); // 1
  gone(w, 2, "A", ["C"], 1);
  commit(w, "B", { removes: ["C"] }); // 2
  return w;
}
/** A reader of world `w` with a lie row's views in place of the home's (by read name; each still logged). */
export function lyingReader(w, overrides) {
  const rd = tk.reader(w.home);
  const out = { ...rd };
  for (const [k, f] of Object.entries(rd)) {
    if (typeof f !== "function" || k === "uaRecordOf" || k === "accepted") continue;
    out[k] = (...a) => {
      const read = `${k}(${a.join(",")})`;
      if (!(read in overrides)) return f(...a);
      rd.log.push(read);
      return JSON.parse(JSON.stringify(overrides[read]));
    };
  }
  return out;
}

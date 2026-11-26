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
import { hex, keccak_256, utf8ToBytes, concatBytes, fromHex, b64url, abiEncode, word } from "../src/bytes.js";

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
/** A device's KEM key as the registry's `kemKeyAt` serves it: the key and its person's `setKemKey` signature over
 *  `kemRecordDigest(ua, keyId, kemPk)` (§8 step 5, C-1). */
const kemRecs = new Map();
export function kemRecOf(name) {
  if (!kemRecs.has(name)) {
    const d = deviceOf(name);
    const digest = ua.kemRecordDigest({ ua: d.ua, version: d.keyId, kemPk: d.kemPk });
    kemRecs.set(name, { kemPk: d.kemPk, sig: hex(pqSign(personOf(name[0]).secretKey, ua.KEM_TAG, digest)) });
  }
  return kemRecs.get(name);
}
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
    // `N` (F-1): a 2-of-2 `msig` over the seed's indexes 10 and 11, then updated on its registry (CTR-UA-44): slot 2 (index
    // 12) appended, the threshold lowered to 1, slot 0 disabled (version 1). Its id is its first structure's; it signs by slot 2
    // alone, its tag version 1 (CTR-UA-74); `signV0` signs as it did before the update (version 0, both first slots, no tag: F-1b).
    const nFirst = [10, 11]
      .map((i) => ({ i, ...pqKeygen(SEED, "mldsa65", 0, i) }))
      .map((k) => ({ kind: MLDSA65, id: hex(k.ua), weight: 1, k }))
      .sort((x, y) => (x.id < y.id ? -1 : 1));
    const n2 = { ...pqKeygen(SEED, "mldsa65", 0, 12) };
    const nSlots = [...nFirst, { kind: MLDSA65, id: hex(n2.ua), weight: 1, k: n2 }];
    const nKey = ua.encodeMsig(2, nFirst);
    const nUa = hex(ua.deriveUA(0x0120, nKey));
    const nSign =
      (slots, version = 1) =>
      (purpose, digest) => {
        const md = ua.memberDigest(nUa, ua.uaMessage(0x0120, purpose, digest));
        const list = slots.map((index) => ({
          index,
          members: [],
          sig: pqSign(nSlots[index].k.secretKey, ua.purposeTag("member"), md),
        }));
        return { signature: hex(ua.versionTag(version)), members: hex(encodeMemberSigs(list)) };
      };
    // `X` (the fix check's C-4, R-1, 2026-11-26): a 1-of-2 `msig` whose slots are N (an `msig` member) and a key of the seed (index 13), never updated (its
    // tag empty). It signs by its key (`sign`) or through N (`signVia(slots, version)`: N's slots over the inner digest, N's tag
    // that version), so a record names N's version as well as its own
    const xK = { ...pqKeygen(SEED, "mldsa65", 0, 13) };
    const xSlots = [
      { kind: 0x0120, id: nUa, weight: 1 },
      { kind: MLDSA65, id: hex(xK.ua), weight: 1 },
    ].sort((x, y) => (x.id < y.id ? -1 : 1));
    const xKey = ua.encodeMsig(1, xSlots);
    const xUa = hex(ua.deriveUA(0x0120, xKey));
    const xSign = (via) => (purpose, digest) => {
      const md = ua.memberDigest(xUa, ua.uaMessage(0x0120, purpose, digest));
      const at = xSlots.findIndex((x) => (via ? x.id === nUa : x.id === hex(xK.ua)));
      const inner = ua.innerDigest(fromHex(nUa), md);
      const slot = via
        ? {
            index: at,
            members: via.slots.map((index) => ({
              index,
              sig: pqSign(nSlots[index].k.secretKey, ua.purposeTag("member"), inner),
            })),
            sig: hex(ua.versionTag(via.version)),
          }
        : { index: at, members: [], sig: pqSign(xK.secretKey, ua.purposeTag("member"), md) };
      return { signature: "0x", members: hex(encodeMemberSigs([slot])) };
    };
    keyless = {
      X: {
        ua: xUa,
        kind: 0x0120,
        keyData: hex(xKey),
        subs: [{ ua: hex(xK.ua), kind: MLDSA65, keyData: hex(xK.publicKey) }],
        sign: xSign(null),
        signVia: (slots, version) => xSign({ slots, version }),
      },
      N: {
        ua: nUa,
        kind: 0x0120,
        keyData: hex(nKey),
        versions: [{ version: 1, msig: hex(ua.encodeMsig(1, nSlots)), enabled: hex(word(6n)) }],
        subs: nSlots.map((m) => ({ ua: m.id, kind: MLDSA65, keyData: hex(m.k.publicKey) })),
        sign: nSign([2]),
        signBy: nSign,
        signV0: nSign([0, 1], 0),
      },
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
const KEYLESS = ["M", "W", "N", "X"];
/** A record's signature by `who` (a person: ML-DSA-65; `M`, `W` or `N`: a keyless admin's portable signature). */
export const sign = (who, struct, record) =>
  KEYLESS.includes(who)
    ? keylessOf(who).sign(sc.purpose, sc.typed(struct, record))
    : hex(pqSign(personOf(who).secretKey, sc.purpose, sc.typed(struct, record)));
/** The registry records of every signer: `ua` → `{ kind, keyData }`, an updated `msig`'s with `versions` (`msigAt`, CTR-UA-74). */
export const uaRecords = () =>
  new Map([
    ...PEOPLE.map((n) => [personOf(n).ua, { kind: MLDSA65, keyData: personOf(n).publicKey }]),
    ...KEYLESS.flatMap((n) => {
      const k = keylessOf(n);
      const top = {
        kind: k.kind,
        keyData: k.keyData,
        ...(k.versions ? { versions: k.versions } : {}),
      };
      return [[k.ua, top], ...k.subs.map((x) => [x.ua, { kind: x.kind, keyData: x.keyData }])];
    }),
  ]);
const registry = (names) => ({
  kems: new Map(names.map((n) => [`${deviceOf(n).ua}/${deviceOf(n).keyId}`, kemRecOf(n)])),
  uaRecords: uaRecords(),
});
const uaRecordOf = (u) => uaRecords().get(u) ?? null;
/** A person's or a keyless admin's UA by name. */
export const uaOf = (name) => (KEYLESS.includes(name) ? keylessOf(name).ua : personOf(name).ua);
/** The leaves of the head as `(ua, keyId)` or null: what the forward walk's roster of that epoch is (C25). */
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
  pathRefreshBound = 20,
}) {
  const session = {
    creator: personOf(creator).ua,
    nonce,
    homeChain: homeChain ?? hex(rnd("tree-secrets/home-chain")),
    homeChatContract: homeChatContract ?? hex(rnd("tree-secrets/home-contract", 20)),
    admins: sortedUas(admins),
    members: members.map((n) => ({ ua: deviceOf(n).ua, keyId: deviceOf(n).keyId, via: Z32 })),
    groupMode: 1,
    pathRefreshBound,
  };
  assertSorted(session.members, `session ${tag}`);
  const genesis = tk.createGenesis(sc, {
    session,
    kems: members.map(kemRecOf),
    uaRecordOf,
    accepted: () => true,
    info,
    rand: (name, n) => rnd(`tree-secrets/${tag}/genesis/${name}`, n),
  });
  const sig = sign(creator, "PqChatSession", genesis.record);
  const home = tk.newHome({ genesis, sig, ...registry(devicesKnown ?? DEVICES) });
  return { tag, home, genesis, sig, steps: [], rosters: [roster(home)] };
}

/** `name`'s device commits on the head: `adds` are `[device, leaf]` (or with a `via`), `removes` device names; `info`
 *  "auto" (the device's rule, C33), null (the marker) or a full info; `admins` names or the head's list. Lands it unless
 *  `land` is false. `faults` and `seedOf` (a foreign seed) are for refusal rows. `pathless` (the delta §4.1): a path-less
 *  Add on the head handle of `headFrom`'s replay (default the author's; another device's is an insider holding the epoch),
 *  its nonce `addNonce` at `try` unless `nonce` is given. */
export function commit(w, name, o = {}) {
  const d = deviceOf(name);
  const rd = tk.reader(w.home);
  const prep = tk.prepareCommit(sc, rd);
  const leaf = prep.tree.nodes.findIndex((n, x) => x % 2 === 0 && n?.ua === d.ua && n.keyId === d.keyId) / 2;
  const headRecord = w.home.epochs.at(-1).record;
  const nonce = o.pathless ? o.nonce : (o.nonce ?? 100 + w.home.epochs.length);
  const own = tk.replay(sc, tk.reader(w.home), o.headFrom ? deviceOf(o.headFrom) : d);
  let info = o.info === undefined ? "auto" : o.info;
  if (info === "auto") info = tk.infoToSeal(own);
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
        ...kemRecOf(n),
      })),
      admins: o.admins ? sortedUas(o.admins) : headRecord.admins,
      info,
      uaRecordOf,
      accepted: () => true,
      keyOf: prep.keyOf,
      rand: (x, n) => rnd(`tree-secrets/${step}/${x}`, n),
      pathless: o.pathless === true,
      head: own.head,
      try: o.try,
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
export function gone(w, kind, name, members, nonce, named = null, signBy = null) {
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
  const sig = signBy ? signBy(sc.purpose, sc.typed(struct, record)) : sign(name, struct, record);
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

/** F-1: the keyless admin N, an `msig` updated on its registry (CTR-UA-44: slot 2 appended, threshold 1, slot 0 disabled),
 *  removes D by slot 2 alone after the update (applied at 1); the non-admin B honours it (2); C commits (3). Every device
 *  follows: N is verified on its current structure and enabled slots. */
export function msigUpdatedScenario() {
  const w = createSession({
    tag: "msig-updated",
    creator: "A",
    nonce: 15,
    admins: ["A", "N"],
    members: ["A", "B", "C", "D"],
    info: INFO.I1,
  });
  commit(w, "B"); // 1
  gone(w, 2, "N", ["D"], 1);
  commit(w, "B", { removes: ["D"] }); // 2
  commit(w, "C"); // 3
  return w;
}
/** F-1b (CTR-UA-74): the keyless admin N removes C at version 0, by both first slots, before the update that disables slot 0
 *  (applied at 1); B honours it (2); N, at version 1, removes D by slot 2 (applied at 2); B honours it (3). Every device follows:
 *  each removal verified at the version its tag names, the first one by a slot now disabled. */
export function msigHistoryScenario() {
  const w = createSession({
    tag: "msig-history",
    creator: "A",
    nonce: 19,
    admins: ["A", "N"],
    members: ["A", "B", "C", "D"],
    info: INFO.I1,
  });
  commit(w, "B"); // 1
  gone(w, 2, "N", ["C"], 1, null, keylessOf("N").signV0);
  commit(w, "B", { removes: ["C"] }); // 2
  gone(w, 2, "N", ["D"], 2);
  commit(w, "B", { removes: ["D"] }); // 3
  return w;
}
/** The fix check's C-4, R-1 (2026-11-26; CTR-UA-74 steps 5 and 6): the keyless admin X (an `msig` with the `msig` N as a member) removes C through N at N's
 *  version 1 (N's slot 2, applied at 1); B honours it (2); D commits (3). Every device follows; the walk keeps
 *  N's version beside X's (a signing `msig` member's tag), so a later record through N at version 0 is a lying read (the lies). */
export function msigNestedScenario() {
  const w = createSession({
    tag: "msig-nested",
    creator: "A",
    nonce: 20,
    admins: ["A", "X"],
    members: ["A", "B", "C", "D"],
    info: INFO.I1,
  });
  commit(w, "B"); // 1
  gone(w, 2, "X", ["C"], 1, null, keylessOf("X").signVia([2], 1));
  commit(w, "B", { removes: ["C"] }); // 2
  commit(w, "D"); // 3
  return w;
}
/** C-1: an epoch-0 head (A the admin, B, C): every target of the first commit a key the registry record authenticates. */
export function genesisScenario() {
  return createSession({
    tag: "genesis",
    creator: "A",
    nonce: 16,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: INFO.I1,
  });
}
/** The extra keys of B, C and D (versions 2 to 8, KEYS_PER_UA_MAX) the world `backlog` holds. */
export const BACKLOG_KEYS = ["B", "C", "D"].flatMap((n) => [2, 3, 4, 5, 6, 7, 8].map((k) => `${n}${k}`));
/** B2-6 (C21): A (the admin) and B, C, D with eight keys each, 25 leaves of 32; nothing committed. */
export function backlogScenario() {
  const keys = (n) => [n, ...BACKLOG_KEYS.filter((x) => x[0] === n)];
  return createSession({
    tag: "backlog",
    creator: "A",
    nonce: 17,
    admins: ["A"],
    members: ["A", ...keys("B"), ...keys("C"), ...keys("D")],
    info: INFO.I1,
    devicesKnown: [...new Set([...DEVICES, ...BACKLOG_KEYS])],
  });
}
/** C-5 (the flag): C misses B's commit (1); B's full info at 2 is the first C takes from a non-admin, so C flags it; A, an
 *  admin, seals the same full info at 3, which clears the flag. */
export function flagClearScenario() {
  const w = createSession({
    tag: "flag-clear",
    creator: "A",
    nonce: 18,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: INFO.I1,
  });
  commitBadFor(w, "B", ["C"]); // 1
  commit(w, "B"); // 2
  commit(w, "A", { info: INFO.I1 }); // 3
  return w;
}

/** `overrides` with the `treeOf()` the contract serves over the exit records they put at the head (R2-D-1 of the T4-T9
 *  re-check): `owed`, the live leaves of each UA they name that was not gone before the head. Overrides that serve their own
 *  `treeOf()` are kept as they are. */
function owing(w, overrides) {
  if ("treeOf()" in overrides) return overrides;
  const h = w.home;
  const head = h.epochs.length - 1;
  const view = (k, f) => (k in overrides ? overrides[k] : f());
  const uas = new Set();
  for (const [kind, list] of [
    ["leave", h.epochs[head].leaves],
    ["removal", h.epochs[head].removals],
  ]) {
    const n = view(`${kind}Count(${head})`, () => list.length);
    for (let i = 0; i < n; i++) {
      const r = view(`${kind}At(${head},${i})`, () => list[i])?.record;
      for (const ua of kind === "leave" ? [r?.member] : (r?.members ?? [])) if (ua) uas.add(ua);
    }
  }
  let owed = 0;
  for (const ua of uas)
    if (!(h.gone.get(ua)?.epoch < head)) owed += h.tree.nodes.filter((x, i) => i % 2 === 0 && x?.ua === ua).length;
  return owed === h.owed ? overrides : { ...overrides, "treeOf()": { ...tk.reader(h).treeOf(), owed } };
}

// ------------------------------------------------------------------ the path-less delta's worlds (§13)

/** A run on a warm tree (rows 1, 18, §13's clients list): B and F commit; A (an admin) adds D path-less in the far half (A's
 *  path nodes 1 and 3 keep their keys, the root is blanked); B adds its own key B2 path-less; F's path commit resets the
 *  counter, its targets the two joiners' leaves and node 3 (held by A, B, C, E through the run); A adds G path-less. */
export function pathlessScenario() {
  const w = createSession({
    tag: "pathless",
    creator: "A",
    nonce: 30,
    admins: ["A"],
    members: ["A", "B", "C", "E", "F"],
    info: INFO.I1,
    pathRefreshBound: 24,
  });
  commit(w, "B"); // 1
  commit(w, "F"); // 2
  // two path-less children of one parent, and a twin under A's id with other Adds (§13): built, never landed
  const probe = (n, o) => {
    const r = commit(w, n, { ...o, land: false });
    w.steps.pop();
    return r.built;
  };
  const a = probe("A", { pathless: true, adds: [["D", 5]] });
  w.twins = {
    a,
    b: probe("B", { pathless: true, adds: [["B2", 5]] }),
    twin: probe("A", { pathless: true, nonce: a.record.nonce, adds: [["H", 5]] }),
  };
  commit(w, "A", { pathless: true, adds: [["D", 5]] }); // 3: sincePath 1
  commit(w, "B", { pathless: true, adds: [["B2", 6]] }); // 4: sincePath 2
  commit(w, "F"); // 5: the reset path commit
  commit(w, "A", { pathless: true, adds: [["G", 7]] }); // 6: sincePath 1
  return w;
}
/** Row 20: the first commit after creation is path-less (parent epoch 0, `next_0` under genesisCtx), bound 0. */
export function pathlessFirstScenario() {
  const w = createSession({
    tag: "pathless-first",
    creator: "A",
    nonce: 31,
    admins: ["A"],
    members: ["A", "B"],
    info: INFO.I1,
    pathRefreshBound: 0,
  });
  commit(w, "A", { pathless: true, adds: [["C", 2]] }); // 1
  commit(w, "C", { pathless: true, adds: [["C2", 3]] }); // 2: the joiner adds its own second key
  return w;
}
/** The faults a path-less record can carry (§6.2, §6.3, §6.5): a bad Welcome (D: not followed at its join); a wrong tag
 *  (members: "author did not hold", the chain's key kept, no info in force; E: not followed at its join); an admin's full
 *  info (C33 after C45); a bad sealedInfo with a good tag ("followed, info not taken" for the members, the author and the
 *  joiner C2); a wrong tag while F and C2 are in their first run ("Welcome may not match"); A's path commit reaching them
 *  all; B's path commit with a wrong tag ("not followed (tag)", B's own: the warning). */
export function pathlessFaultsScenario() {
  const w = createSession({
    tag: "pathless-faults",
    creator: "A",
    nonce: 32,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: INFO.I1,
    pathRefreshBound: 24,
  });
  commit(w, "A"); // 1
  const bad = (tag) => ({ welcomeJoiner: hex(rnd(`tree-secrets/pathless-faults/${tag}`)) });
  commit(w, "A", { pathless: true, adds: [["D", 3]], faults: bad("welcome") }); // 2
  commit(w, "B", {
    pathless: true,
    adds: [["B2", 4]],
    faults: { tag: hex(rnd("tree-secrets/pathless-faults/tag-3")) },
  }); // 3
  commit(w, "A", { pathless: true, adds: [["F", 5]], info: INFO.I2 }); // 4
  commit(w, "C", {
    pathless: true,
    adds: [["C2", 6]],
    faults: { infoK: hex(rnd("tree-secrets/pathless-faults/info")) },
  }); // 5
  commit(w, "A", { pathless: true, adds: [["G", 7]], faults: { tag: hex(rnd("tree-secrets/pathless-faults/tag-6")) } }); // 6
  commit(w, "A", { info: INFO.I2 }); // 7: the reset
  commit(w, "B", { faults: { tag: hex(rnd("tree-secrets/pathless-faults/tag-8")) } }); // 8
  return w;
}
/** The own-commit test (C47, F-2): B's own Add at try 1 is reproduced; then an insider holding the epoch signs a path-less
 *  Add under B's UA (A's head, a random nonce, a correct tag): the members follow it, B's device shows the compromise
 *  warning. `behind`: B did not follow the parent (a bad ciphertext at 1), and shows the warning all the same. */
export function pathlessOwnScenario(behind) {
  const tag = behind ? "pathless-own-behind" : "pathless-own";
  const w = createSession({
    tag,
    creator: "A",
    nonce: behind ? 34 : 33,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: INFO.I1,
    pathRefreshBound: 24,
    devicesKnown: [...DEVICES, "B3"],
  });
  if (behind) commitBadFor(w, "A", ["B"]);
  else commit(w, "A"); // 1
  if (!behind) commit(w, "B", { pathless: true, try: 1, adds: [["B3", 3]] }); // 2
  const random = BigInt(`0x${hex(rnd(`tree-secrets/${tag}/insider-nonce`, 8)).slice(2)}`);
  commit(w, "B", { pathless: true, headFrom: "A", nonce: random, adds: [["B2", behind ? 3 : 4]] }); // 3 (2 when behind)
  return w;
}
/** The bound at N and N + 1 (R18; N = 2): two path-less leaves accepted, the third only after the reset (A's path commit). */
export function pathlessBoundScenario() {
  const w = createSession({
    tag: "pathless-bound",
    creator: "A",
    nonce: 35,
    admins: ["A"],
    members: ["A", "B"],
    info: INFO.I1,
    pathRefreshBound: 2,
  });
  commit(w, "A", { pathless: true, adds: [["C", 2]] }); // 1
  commit(w, "A", { pathless: true, adds: [["D", 3]] }); // 2: sincePath 2 = N
  commit(w, "B"); // 3: the reset
  commit(w, "A", { pathless: true, adds: [["E", 4]] }); // 4
  return w;
}
/** The admins' warning (R18, C46): bound 0; B, C and D add their own seven keys path-less, then D one more: sincePath 21 at the
 *  head, past W(0) = 20; A's device (an admin) is warned, B's is not. */
export function pathlessWarnScenario() {
  const keys = (n) => BACKLOG_KEYS.filter((x) => x[0] === n);
  const w = createSession({
    tag: "pathless-warn",
    creator: "A",
    nonce: 36,
    admins: ["A"],
    members: ["A", "B", "C", "D"],
    info: INFO.I1,
    pathRefreshBound: 0,
    devicesKnown: [...new Set([...DEVICES, ...BACKLOG_KEYS])],
  });
  let at = 4;
  for (const n of ["B", "C", "D"])
    commit(w, n, {
      pathless: true,
      adds: keys(n)
        .slice(0, 7 - (n === "D") * 1)
        .map((k) => [k, at++]),
    });
  commit(w, "D", { pathless: true, adds: [["D8", at++]] });
  return w;
}
/** E-3 and the exit (§5.5): C leaves at a path-less head; the next commit is the honouring path commit; C held `next` of
 *  that head and cannot derive the path commit's epoch. */
export function pathlessExitScenario() {
  const w = createSession({
    tag: "pathless-exit",
    creator: "A",
    nonce: 37,
    admins: ["A"],
    members: ["A", "B", "C"],
    info: INFO.I1,
    pathRefreshBound: 24,
  });
  commit(w, "A", { pathless: true, adds: [["D", 3]] }); // 1
  gone(w, 1, "C", [], 1);
  commit(w, "A", { removes: ["C"] }); // 2: the honouring path commit
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
      sincePath: t.sincePath,
      owed: 0,
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
    pathless: o.pathless === true,
    head: { epochId: head.id, treeHash: tr.treeHash(tree), next: hex(rnd(`tree-secrets/${w.tag}/forged-next`)) },
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
      ...kemRecOf(n),
    })),
    admins: o.admins ? sortedUas(o.admins) : head.record.admins,
    info: null,
    uaRecordOf,
    accepted: () => true,
    keyOf: (x) =>
      x % 2 === 0 ? h.kems.get(`${tree.nodes[x].ua}/${tree.nodes[x].keyId}`).kemPk : h.nodeKey.get(x).kemPk,
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
    sessionId: o.sessionId ?? h.sessionId,
    treeId,
    epochId,
    nextEpoch: o.nextEpoch ?? (typeof named === "number" ? named : 0) + 1,
    members: o.unsorted ? members.map(uaOf).sort().reverse() : members.map(uaOf).sort(),
    admin: uaOf(admin),
    nonce,
  };
  const { treeId: _, ...kept } = record;
  const sig = o.signBy
    ? o.signBy(sc.purpose, sc.typed("PqChatTreeRemove", record))
    : sign(admin, "PqChatTreeRemove", record);
  return { record: kept, sig };
}
/** A leave by `who` on world `w`, kept under its head, naming epoch `named` (a number). */
function keptLeave(w, who, named, nonce) {
  const h = w.home;
  const record = { sessionId: h.sessionId, treeId: h.treeId, epochId: h.epochs[named].id, member: uaOf(who), nonce };
  const { treeId: _, ...kept } = record;
  return { record: kept, sig: sign(who, "PqChatTreeLeave", record) };
}

/** The lying reads of plan T11 (C25, C26, E-1, F-1, sc-F-3, sc-F-7, E-4): per row the world, the device, the views the endpoint
 *  replaces (by read name), the pin the device holds, and what replay and prepare give (null: accepted). `worlds` by name. */
export function lies(worlds) {
  const rows = [];
  const add = (name, world, device, overrides, expect, pin = null) =>
    rows.push({ name, world, device, overrides: owing(W(world), overrides), pin, expect });
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
    }); // R2-D-1 of the T4-T9 re-check: the head's removal hidden while the endpoint serves the true `treeOf` (its `owed` the
    // removed UA's leaf): the snapshot disagrees with the walk, a lying read, so a strict-majority `treeOf` covers the exits
    add(
      "the head's exit hidden under the true treeOf (R2-D-1)",
      "pin-exit",
      "A",
      { "removalCount(1)": 0, "treeOf()": tk.reader(w.home).treeOf() },
      { replay: "TreeHeadRoot", prepare: "TreeHeadRoot" },
    );
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
    // C-3: a walk from the pin at 17 numbers an exit's named epoch from verified records only: an `epochsOf` that lies
    // below the pin, and a removal (signed by the admin) naming the false id, are a lying read; from the cold tree too
    const pin = replayOf(w, "B").pin;
    const ids = tk.reader(w.home).epochsOf();
    const x = hex(rnd("tree-secrets/lies/below-pin"));
    const below = keptRemoval(w, "A", ["C"], x, 6, w.home.treeId, { nextEpoch: 17 });
    add(
      "an epochsOf that lies below the pin, an exit naming its false id (C-3)",
      "lag",
      "B",
      { "epochsOf()": ids.map((id, n) => (n === 16 ? x : id)), "removalCount(17)": 1, "removalAt(17,0)": below },
      { replay: "TreeReadCorrupted", prepare: "TreeReadCorrupted" },
      pin,
    );
    add(
      "a pinned walk with an exit 16 below the head (C-3, its control)",
      "lag",
      "B",
      { "removalCount(17)": 1, "removalAt(17,0)": at16 },
      { replay: null, prepare: null },
      pin,
    );
  }
  const lie = { replay: "TreeReadCorrupted", prepare: "TreeReadCorrupted" };
  {
    // C-1, F-2, B2-5: an epoch-0 head whose endpoint substitutes C's key consistently (kemKeyAt, treeLeaves, treeOf)
    const w = W("genesis");
    const [C, H] = [deviceOf("C"), deviceOf("H")];
    const hHash = hex(keccak_256(fromHex(H.kemPk)));
    const t = tr.coldTree(
      [deviceOf("A"), deviceOf("B"), C].map((d) => ({
        ua: d.ua,
        keyId: d.keyId,
        kemHash: d === C ? hHash : hex(keccak_256(fromHex(d.kemPk))),
      })),
    );
    const leaves = tk.reader(w.home).treeLeaves();
    leaves[2] = { ...leaves[2], kemHash: hHash };
    const th = tr.treeHash(t);
    const swap = {
      [`kemKeyAt(${C.ua},1)`]: { kemPk: H.kemPk, sig: kemRecOf("C").sig },
      "treeLeaves()": leaves,
      "treeOf()": { ...tk.reader(w.home).treeOf(), treeHash: th, genesisTreeHash: th },
    };
    add("an epoch-0 head with a consistent substituted member key (C-1)", "genesis", "A", swap, {
      replay: "TreeKemRecord",
      prepare: "TreeKemRecord",
    });
    // C's own signed key of version 3 served as its version 1: the record names the version, refused
    add(
      "a member key signed for another version (C-1)",
      "genesis",
      "A",
      { [`kemKeyAt(${C.ua},1)`]: kemRecOf("C3") },
      { replay: "TreeKemRecord", prepare: "TreeKemRecord" },
    );
    // an epochsOf whose first id is not the session's (C-5; at an epoch-0 head no record's parent checks it)
    add(
      "an epochsOf whose first id is not the session's (C-5)",
      "genesis",
      "A",
      {
        "epochsOf()": [hex(rnd("tree-secrets/lies/first"))],
      },
      lie,
    );
    // C-4: an epoch-0 snapshot whose leaf is not the cold tree's
    const gl = tk.reader(w.home).treeLeaves();
    add(
      "an epoch-0 snapshot with another leaf key (C-4)",
      "genesis",
      "A",
      {
        "treeLeaves()": gl.map((l, i) => (i === 2 ? { ...l, kemHash: hHash } : l)),
      },
      { replay: "TreeGenesisLeaves", prepare: "TreeGenesisLeaves" },
    );
    // a session record whose creator's signature does not verify (F-6)
    const s0 = tk.reader(w.home).sessionOf();
    add(
      "a session record with another record's signature (F-6)",
      "genesis",
      "A",
      {
        "sessionOf()": { record: s0.record, sig: sign("A", "PqChatSession", { ...s0.record, nonce: 99 }) },
      },
      lie,
    );
    // a session record of groupMode 0 its creator signed (C-5: the walk reads tree sessions only)
    const m0 = { ...s0.record, groupMode: 0 };
    add(
      "a session record of groupMode 0 (C-5)",
      "genesis",
      "A",
      { "sessionOf()": { record: m0, sig: sign("A", "PqChatSession", m0) } },
      {
        replay: "PqChatModeEntry",
        prepare: "PqChatModeEntry",
      },
    );
    // a session record its creator signed with 4,125 B of sealedInfo (C-5, B-5: bounded as a commit's)
    const big = { ...s0.record, sealedInfo: hex(new Uint8Array(4125)) };
    add(
      "a session record with 4,125 B of sealedInfo (C-5)",
      "genesis",
      "A",
      {
        "sessionOf()": { record: big, sig: sign("A", "PqChatSession", big) },
      },
      lie,
    );
    // a session record listing C's key twice, each version signed by C (C-5: one key one leaf)
    const twice = {
      ...s0.record,
      members: [...s0.record.members, { ua: C.ua, keyId: 2, via: Z32 }],
    };
    const dup = ua.kemRecordDigest({ ua: C.ua, version: 2, kemPk: C.kemPk });
    add(
      "a session record with one key at two leaves (C-5)",
      "genesis",
      "A",
      {
        "sessionOf()": { record: twice, sig: sign("A", "PqChatSession", twice) },
        [`kemKeyAt(${C.ua},2)`]: { kemPk: C.kemPk, sig: hex(pqSign(personOf("C").secretKey, ua.KEM_TAG, dup)) },
      },
      lie,
    );
  }
  {
    // F-1: N's removal by its enabled slot 1 after the update is accepted; by its disabled slot 0, a lying read
    const w = W("msig-updated");
    const N = keylessOf("N");
    const by = (slots, nonce) => keptRemoval(w, "N", ["C"], 3, nonce, w.home.treeId, { signBy: N.signBy(slots) });
    add(
      "a removal by an updated msig's enabled slot (F-1)",
      "msig-updated",
      "A",
      { "removalCount(3)": 1, "removalAt(3,0)": by([1], 7) },
      {
        replay: null,
        prepare: null,
      },
    );
    add(
      "a removal by an updated msig's disabled slot (F-1)",
      "msig-updated",
      "A",
      { "removalCount(3)": 1, "removalAt(3,0)": by([0], 8) },
      lie,
    );
    add(
      "a removal by an msig's first quorum after its update (F-1)",
      "msig-updated",
      "A",
      {
        "removalCount(3)": 1,
        "removalAt(3,0)": by([0, 1], 9),
      },
      lie,
    );
    // CTR-UA-74 step 6: a true version-0 record of N served after its version-1 one: a decrease, a lying read
    add(
      "a removal at version 0 after one at version 1 (CTR-UA-74 step 6)",
      "msig-updated",
      "A",
      {
        "removalCount(3)": 1,
        "removalAt(3,0)": keptRemoval(w, "N", ["C"], 3, 10, w.home.treeId, { signBy: N.signV0 }),
      },
      lie,
    );
  }
  {
    // CTR-UA-74 (F-1b): the tags of N's kept removals in msig-history: removalAt(1,0) at version 0 by slots 0 and 1, removalAt(2,0)
    // at version 1 by slot 2. Any other tag than the one each was accepted under: a lying read (the tag is not signed)
    const w = W("msig-history");
    const r = (n) => tk.reader(w.home).removalAt(n, 0);
    const tagged = (n, tag) => ({ [`removalAt(${n},0)`]: { ...r(n), sig: { ...r(n).sig, signature: tag } } });
    const v = (x) => hex(ua.versionTag(x));
    add("a version-0 record tagged with a later version (CTR-UA-74)", "msig-history", "A", tagged(1, v(1)), lie);
    add("a version-1 record tagged with an earlier version (CTR-UA-74)", "msig-history", "A", tagged(2, "0x"), lie);
    add("a tag naming a version never stored (CTR-UA-74)", "msig-history", "A", tagged(2, v(2)), lie);
    add("a tag of 8 zero bytes (CTR-UA-74)", "msig-history", "A", tagged(1, `0x${"00".repeat(8)}`), lie);
    add("a tag of 7 bytes (CTR-UA-74)", "msig-history", "A", tagged(2, `0x${"00".repeat(6)}01`), lie);
    add("a tag of 9 bytes (CTR-UA-74)", "msig-history", "A", tagged(2, `0x${"00".repeat(8)}01`), lie);
    // step 6 against the pin: A's pin of the head holds N at version 1; a true version-0 removal of B kept under the head names a
    // version below it
    const pin = replayOf(w, "A").pin;
    const below = keptRemoval(w, "N", ["B"], 3, 3, w.home.treeId, { signBy: keylessOf("N").signV0 });
    add(
      "a version-0 record after the pin saw version 1 (CTR-UA-74 step 6)",
      "msig-history",
      "A",
      { "removalCount(3)": 1, "removalAt(3,0)": below },
      lie,
      pin,
    );
    // a pin whose versions differ from the walk's (as its gone register, C-5): a walk from the cold tree refuses it
    add(
      "a pin whose msig versions differ (CTR-UA-74 step 6)",
      "msig-history",
      "A",
      {},
      { replay: "TreeReadCorrupted", prepare: null },
      { ...pin, msigVersions: pin.msigVersions.map(([u, v]) => [u, v + 1]) },
    );
  }
  {
    // B2-6, C21: the leaves owed at one head fit one commit: B, C and D owe 24, refused; B and C owe 16, accepted
    const w = W("backlog");
    add(
      "exits that owe more leaves than one commit removes (C21, B2-6)",
      "backlog",
      "A",
      {
        "removalCount(0)": 1,
        "removalAt(0,0)": keptRemoval(w, "A", ["B", "C", "D"], 0, 5),
      },
      lie,
    );
    add(
      "exits that owe 16 leaves (C21, the control)",
      "backlog",
      "A",
      {
        "removalCount(0)": 1,
        "removalAt(0,0)": keptRemoval(w, "A", ["B", "C"], 0, 5),
      },
      { replay: null, prepare: null },
    );
  }
  {
    const w = W("small");
    // B2-6: one UA exits twice under one head (its leave and a removal naming it; neither order lands)
    add(
      "a UA that exits twice under one head (B2-6)",
      "small",
      "A",
      {
        "leaveCount(1)": 1,
        "leaveAt(1,0)": keptLeave(w, "C", 1, 5),
        "removalCount(1)": 1,
        "removalAt(1,0)": keptRemoval(w, "A", ["C"], 1, 6),
      },
      lie,
    );
    // C24: the only admin that holds a leaf removes itself while B and C keep theirs
    add(
      "the last admin with a leaf removed while members stay (C24, B2-6)",
      "small",
      "B",
      {
        "removalCount(1)": 1,
        "removalAt(1,0)": keptRemoval(w, "A", ["A"], 1, 5),
      },
      lie,
    );
    // M17 of the round's runner: a leave (no nextEpoch to catch it) naming an epoch that is not the home's
    const far = {
      sessionId: w.home.sessionId,
      treeId: w.home.treeId,
      epochId: hex(rnd("tree-secrets/lies/losing-epoch")),
    };
    const farLeave = { ...far, member: uaOf("C"), nonce: 5 };
    const { treeId: _f, ...farKept } = farLeave;
    add(
      "a leave naming an epoch that is not the home's",
      "small",
      "A",
      {
        "leaveCount(1)": 1,
        "leaveAt(1,0)": { record: farKept, sig: sign("C", "PqChatTreeLeave", farLeave) },
      },
      lie,
    );
    // C-5: the exit's sessionId, a removal of no UA
    add(
      "a removal of another sessionId (C-5)",
      "small",
      "A",
      {
        "removalCount(1)": 1,
        "removalAt(1,0)": keptRemoval(w, "A", ["C"], 1, 5, w.home.treeId, {
          sessionId: hex(rnd("tree-secrets/lies/sid")),
        }),
      },
      lie,
    );
    add(
      "a removal that names no UA (C-5)",
      "small",
      "A",
      { "removalCount(1)": 1, "removalAt(1,0)": keptRemoval(w, "A", [], 1, 5) },
      lie,
    );
    // C-5: a commit whose signed epoch is not its number; one with an empty sealedInfo
    const f1 = forgedCommit(w, "B", w.home.tree, { edit: (r) => ({ ...r, epoch: 5 }) });
    add("a commit whose signed epoch is not its number (C-5)", "small", "C", served(w, f1.built, f1.sig), lie);
    const f2 = forgedCommit(w, "B", w.home.tree, { edit: (r) => ({ ...r, sealedInfo: "0x" }) });
    add("a commit with an empty sealedInfo (C-5)", "small", "C", served(w, f2.built, f2.sig), lie);
    // C-5: epochsOf whose epoch 0 is not the session; the snapshot's treeId, used, node list, genesisTreeHash
    const rd = tk.reader(w.home);
    const t = rd.treeOf();
    const root = { replay: "TreeHeadRoot", prepare: "TreeHeadRoot" };
    add(
      "a snapshot of another treeId (C-5)",
      "small",
      "A",
      { "treeOf()": { ...t, treeId: hex(rnd("tree-secrets/lies/tid")) } },
      root,
    );
    add(
      "a snapshot whose used is not the walk's (C-5)",
      "small",
      "A",
      { "treeOf()": { ...t, used: t.used + 1 } },
      root,
    );
    add(
      "a snapshot with another genesisTreeHash (C-5)",
      "small",
      "A",
      {
        "treeOf()": { ...t, genesisTreeHash: hex(rnd("tree-secrets/lies/genesis")) },
      },
      root,
    );
    add(
      "a node list one entry longer (C-5)",
      "small",
      "A",
      { "treeNodes()": [...rd.treeNodes(), { hash: Z32, keyHash: Z32, epoch: 0 }] },
      root,
    );
    // C-6: served values of a wrong shape and an exit count above EXITS_MAX: lying reads, never a TypeError
    add("an exit count of 545 (C-6)", "small", "A", { "leaveCount(1)": 545 }, lie);
    add("an exit count that is a string (C-6)", "small", "A", { "leaveCount(1)": "1" }, lie);
    add("a commit record that is null (C-6)", "small", "A", { "commitOf(1)": null }, lie);
    add("a node list that is null (C-6)", "small", "A", { "treeNodes()": null }, lie);
    add(
      "a removal whose members are not a list (C-6)",
      "small",
      "A",
      {
        "removalCount(1)": 1,
        "removalAt(1,0)": {
          ...keptRemoval(w, "A", ["C"], 1, 5),
          record: { ...keptRemoval(w, "A", ["C"], 1, 5).record, members: "0x00" },
        },
      },
      lie,
    );
    // F-6, C-5: a stored pin whose tree differs from the walk's; one whose gone register differs
    const pin = replayOf(w, "A").pin;
    const tree = JSON.parse(JSON.stringify(pin.tree));
    tree.nodes[4] = { ...tree.nodes[4], kemHash: hex(keccak_256(fromHex(deviceOf("H").kemPk))) };
    add(
      "a pin whose tree differs (F-6)",
      "small",
      "A",
      {},
      { replay: "TreeReadCorrupted", prepare: "TreeHeadRoot" },
      {
        ...pin,
        tree,
      },
    );
    add(
      "a pin whose gone register differs (C-5)",
      "small",
      "A",
      {},
      { replay: "TreeReadCorrupted", prepare: null },
      {
        ...pin,
        gone: [[uaOf("H"), 1, 0]],
      },
    );
    // C-4: the refusals by name, each from one lying read or pin: a pin above the head, a pin of another record there, a
    // leaf's period past the head
    add(
      "a pin above the head (C-4)",
      "small",
      "A",
      {},
      { replay: "TreeCheckpoint", prepare: "TreeCheckpoint" },
      {
        ...pin,
        epoch: pin.epoch + 1,
      },
    );
    add(
      "a pin of another record at its number (C-4)",
      "small",
      "A",
      {},
      { replay: "TreeConflict", prepare: "TreeConflict" },
      {
        ...pin,
        hash: hex(rnd("tree-secrets/lies/pin-hash")),
      },
    );
    const lv = rd.treeLeaves();
    add(
      "a leaf whose joinEpoch is past the head (C-4)",
      "small",
      "B",
      {
        "treeLeaves()": lv.map((l, i) => (i === 1 ? { ...l, joinEpoch: 5 } : l)),
      },
      { replay: "TreePeriod", prepare: null },
    );
  }
  {
    // the fix check's C-4, R-1 (2026-11-26; CTR-UA-74 step 6 with step 5): in msig-nested X signed through N at N's version 1 (applied at 1); X's removal of
    // B kept under the head through N's first quorum (slots 0 and 1, N's tag empty) verifies at N's version 0 alone, but N's
    // version went back along the chain (X's own tag did not move): a lying read, from the cold tree and from A's pin (which
    // holds N's version). Twin: the same removal through N at version 1 (slot 2) is accepted.
    const w = W("msig-nested");
    const X = keylessOf("X");
    const via = (slots, version, nonce) =>
      keptRemoval(w, "X", ["B"], 3, nonce, w.home.treeId, { signBy: X.signVia(slots, version) });
    add(
      "a removal through an inner msig at its later version (fix check R-1)",
      "msig-nested",
      "A",
      { "removalCount(3)": 1, "removalAt(3,0)": via([2], 1, 5) },
      { replay: null, prepare: null },
    );
    add(
      "an inner msig's empty tag after its later version was seen (fix check R-1, CTR-UA-74 step 6)",
      "msig-nested",
      "A",
      { "removalCount(3)": 1, "removalAt(3,0)": via([0, 1], 0, 6) },
      lie,
    );
    const pin = replayOf(w, "A").pin;
    add(
      "an inner msig's empty tag after the pin saw its later version (fix check R-1, CTR-UA-74 step 6)",
      "msig-nested",
      "A",
      { "removalCount(3)": 1, "removalAt(3,0)": via([0, 1], 0, 7) },
      lie,
      pin,
    );
  }
  {
    // the path-less delta §5.1, C25: each condition a path-less record breaks is a lying read for the walk (§6.1)
    const both = { replay: "TreeReadCorrupted", prepare: "TreeReadCorrupted" };
    const w = W("pathless");
    const n = w.home.epochs.length;
    const pl = (name, o) => {
      const f = forgedCommit(w, "A", o.tree ?? w.home.tree, { pathless: true, adds: [["H", 8]], ...o });
      add(`a path-less record ${name}`, "pathless", "C", { ...served(w, f.built, f.sig), ...(o.more ?? {}) }, both);
    };
    pl("with a Remove (R19)", { removes: ["C"] });
    pl("that changes the admins (R19)", { admins: ["A", "B"] });
    pl("with a node key (C42)", {
      edit: (r) => ({ ...r, nodeKeyHashes: [hex(rnd("tree-secrets/lies/pathless-key"))] }),
    });
    pl("with no Add (C42)", { edit: (r) => ({ ...r, adds: [], wrapHashes: [], leaves: 8 }) });
    // the owed exit: B removed at the head, then a path-less record on it
    pl("on a head that owes an exit (§5.5)", {
      more: { [`removalCount(${n - 1})`]: 1, [`removalAt(${n - 1},0)`]: keptRemoval(w, "A", ["B"], n - 1, 7) },
    });
    // the bound (R18): N = 2 and sincePath 1 at the head; two more leaves cross it (built on a tree without the bound)
    const wb = W("pathless-bound");
    const free = tr.treeFromJson({ ...tr.treeJson(wb.home.tree), pathBound: 0 });
    const f = forgedCommit(wb, "A", free, {
      pathless: true,
      adds: [
        ["F", 5],
        ["G", 6],
      ],
    });
    add("a path-less record over the bound (R18)", "pathless-bound", "B", served(wb, f.built, f.sig), both);
    // the snapshot's counter (C44): `treeOf` serving another `sincePath` than the walk's is refused, as any other field
    const t0 = tk.reader(w.home).treeOf();
    add(
      "a treeOf whose sincePath is not the walk's (C44)",
      "pathless",
      "C",
      { "treeOf()": { ...t0, sincePath: t0.sincePath + 1 } },
      {
        replay: "TreeHeadRoot",
        prepare: "TreeHeadRoot",
      },
    );
    const g = forgedCommit(wb, "A", free, { pathless: true, adds: [["F", 5]] });
    add("a path-less record at the bound (control)", "pathless-bound", "B", served(wb, g.built, g.sig), {
      replay: null,
      prepare: null,
    });
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
      return structuredClone(overrides[read]);
    };
  }
  return out;
}

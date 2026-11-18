// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The PQZ three-key model on the client (spec 2026-11-13 pqz-three-keys; CLI-SGN-50, -51, CTR-PQZ-40): the scoped key seeds, the
// opening KEM seed and key against pqz-ffi's KAT (smartcontracts/vectors/pqz/opening.json), the leg seed, the sealed opening's
// round trip and every one-change refusal giving the one outcome `null`. UNAUDITED.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { hex, fromHex } from "../src/bytes.js";
import { pqzKeySeed } from "../src/pq.js";
import {
  pqzTokenKeySeedWithoutOpening,
  openKemSeed,
  openKemKey,
  legSeedOfKeyHash,
  openingCoins,
  sealOpening,
  openOpening,
  pqzOpeningMemoHash,
  pqzKeyHandle,
  pqzLayout,
  pqzMarks,
  pqzOpeningAad,
  pqzEntryHash,
  pqzEntriesHash,
  pqzOpeningBlobOf,
  pqzScopedKeyMessages,
  pqzScopedKeyDigest,
  pqzScopedKeyRecordDigest,
  SKIP,
} from "../src/pqzopen.js";
import { seedFromWords } from "../src/seed.js";
import { concatBytes } from "../src/bytes.js";
import { pqzOwnTag } from "../src/evm.js";

const ROOT = new URL("../../../", import.meta.url);
const K = JSON.parse(readFileSync(new URL("smartcontracts/vectors/pqz/opening.json", ROOT), "utf8"));
const h0 = (x) => (x.startsWith("0x") ? x : `0x${x}`);
const SEED = fromHex(h0(K.bip39_seed));
const CU = ["0x" + "c1".repeat(32), "0x" + "c2".repeat(32)];
const TOK = ["0x" + "a1".repeat(20), "0x" + "a2".repeat(20)];

test("opening KEM seed and key (K3-6b) = pqz-ffi, both classes, every KAT row", () => {
  assert.ok(K.openKemSeeds.length >= 8);
  for (const r of K.openKemSeeds) {
    const s = openKemSeed(SEED, {
      ua: h0(r.ua),
      chainUid: h0(r.chainUid),
      token: r.token ? h0(r.token) : undefined,
      version: r.version,
    });
    assert.equal(hex(s), h0(r.openKemSeed), JSON.stringify([r.chainUid, r.token, r.version]));
    assert.equal(hex(keccak_256(openKemKey(s).kemPk)), h0(r.kemPk_keccak));
  }
});

test("leg seed (K3-4) = pqz-ffi; recipient and key inside", () => {
  for (const r of K.rows)
    assert.equal(hex(legSeedOfKeyHash(h0(r.seed_enc), h0(r.toUA), h0(r.pk_t_keccak))), h0(r.seed_leg));
  const r = K.rows[0];
  const other = "0x" + "22".repeat(32);
  assert.notEqual(hex(legSeedOfKeyHash(h0(r.seed_enc), other, h0(r.pk_t_keccak))), h0(r.seed_leg), "another recipient");
  assert.notEqual(
    hex(legSeedOfKeyHash(h0(r.seed_enc), h0(r.toUA), "0x" + "00".repeat(32))),
    h0(r.seed_leg),
    "another key",
  );
});

const L = pqzLayout(2304, 46, 4096);

test("scoped PQZ seeds (K3-2): three classes, two chains, two tokens, versions 0 and 1 pairwise distinct; registry unchanged", () => {
  // the seeds live in the handle; its commitment keccak256(seed32) stands for them (Fable P1-1)
  const at = { account: 0, index: 0, ua: "0x" + "11".repeat(32), layout: L };
  const all = [hex(keccak_256(pqzKeySeed(SEED, 0, 0, 0))), hex(keccak_256(pqzKeySeed(SEED, 0, 0, 1)))];
  for (const chainUid of CU) {
    for (const version of [0, 1]) {
      all.push(pqzKeyHandle(SEED, { ...at, chainUid, version }).seedCommitment());
      for (const token of TOK) all.push(pqzKeyHandle(SEED, { ...at, chainUid, token, version }).seedCommitment());
    }
  }
  assert.equal(new Set(all).size, all.length);
  // pq_kat.json's rows: the handle (class 2, class 3) and the one raw export (class 3 of a token without the opening)
  const k = JSON.parse(readFileSync(new URL("smartcontracts/vectors/ua/pq_kat.json", ROOT), "utf8"));
  const seed = seedFromWords(k.mnemonic);
  for (const r of k.pqzScopedSeeds) {
    const h = pqzKeyHandle(seed, { ...at, chainUid: r.chainUid, token: r.token, version: r.version });
    assert.equal(h.seedCommitment(), hex(keccak_256(fromHex(r.seed32))), r.keyClass);
    if (r.token)
      assert.equal(
        hex(pqzTokenKeySeedWithoutOpening(seed, { ...at, chainUid: r.chainUid, token: r.token, version: r.version })),
        r.seed32,
      );
  }
});

const fixture = () => {
  const ok = openKemSeed(SEED, { ua: "0x" + "11".repeat(32), chainUid: CU[0], version: 0 });
  const key = openKemKey(ok);
  const seedLeg = fromHex("0x" + "5e".repeat(32));
  const aad = fromHex("0x" + "aa".repeat(32 + 20 + 32 + 8 + 32));
  return { key, seedLeg, aad, o: sealOpening({ seedLeg, role: 0, kemPk: key.kemPk, aad }) };
};

test("the sealed opening (K3-6): deterministic, 1,648 bytes, opens to seed_leg; roles and keys give other coins", () => {
  const { key, seedLeg, aad, o } = fixture();
  assert.equal(o.bytes.length, 1648);
  assert.equal(hex(sealOpening({ seedLeg, role: 0, kemPk: key.kemPk, aad }).bytes), hex(o.bytes), "deterministic");
  assert.equal(
    hex(openOpening({ opening: o.bytes, kemPk: key.kemPk, dk: key.dk, x25519Secret: key.x25519Secret, aad })),
    hex(seedLeg),
  );
  assert.notEqual(hex(openingCoins(seedLeg, 0, key.kemPk)), hex(openingCoins(seedLeg, 1, key.kemPk)), "role");
  const k2 = openKemKey(openKemSeed(SEED, { ua: "0x" + "11".repeat(32), chainUid: CU[0], version: 1 }));
  assert.notEqual(hex(openingCoins(seedLeg, 0, key.kemPk)), hex(openingCoins(seedLeg, 0, k2.kemPk)), "key");
});

test("every one-change refusal is the one outcome null (CLI-SGN-51)", () => {
  const { key, aad, o } = fixture();
  const open = (opening, x = {}) =>
    openOpening({ opening, kemPk: key.kemPk, dk: key.dk, x25519Secret: key.x25519Secret, aad, ...x });
  const flip = (i) => {
    const b = o.bytes.slice();
    b[i] ^= 1;
    return b;
  };
  assert.equal(open(flip(10)), null, "mlkemCt bit");
  assert.equal(open(flip(1568 + 3)), null, "x25519Eph bit");
  assert.equal(open(flip(1600 + 47)), null, "tag bit");
  assert.equal(open(flip(1600)), null, "sealedSeed bit");
  const aad2 = aad.slice();
  aad2[0] ^= 1;
  assert.equal(open(o.bytes, { aad: aad2 }), null, "another aad (token, ua, version or ciphertext)");
  const k2 = openKemKey(openKemSeed(SEED, { ua: "0x" + "11".repeat(32), chainUid: CU[1], version: 0 }));
  assert.equal(
    open(o.bytes, { dk: k2.dk, x25519Secret: k2.x25519Secret, kemPk: k2.kemPk }),
    null,
    "another chain's key",
  );
  const low = o.bytes.slice();
  low.fill(0, 1568, 1600);
  assert.equal(open(low), null, "low-order X25519 point");
  assert.equal(open(o.bytes.subarray(0, 1647)), null, "short");
  assert.ok(open(o.bytes) !== null, "control");
});

test("memoHash covers the openings (CTR-PQZ-40): keccak256(memo ‖ ownTag ‖ keccak256(O_t ‖ [O_a]))", () => {
  const { o } = fixture();
  const tag = "0x" + "7a".repeat(32);
  const a = hex(pqzOpeningMemoHash("0x", tag, [o.bytes]));
  assert.equal(a, hex(keccak_256(new Uint8Array([...fromHex(tag), ...keccak_256(o.bytes)]))));
  const b = o.bytes.slice();
  b[0] ^= 1;
  assert.notEqual(hex(pqzOpeningMemoHash("0x", tag, [b])), a, "a swapped opening moves the word");
});

// ------------------------------------------------------------------ pqz3k_kat.json (Fable P2-2; forge PqzClientRows checks it)

test("client rows: handle commitments, ownTag over u_f, h(i) / entriesHash, scoped record messages, the opening blob", async () => {
  const k = JSON.parse(readFileSync(new URL("smartcontracts/vectors/ua/pqz3k_kat.json", ROOT), "utf8"));
  const m = await import("../src/pqzopen.js");
  assert.ok(!("pqzScopedKeySeed" in m), "no raw export of a scoped seed with the opening");
  const seed = seedFromWords(k.mnemonic);
  const at = { chainUid: k.chainUid, ua: k.ua, layout: k.layout };
  for (const r of k.handles)
    assert.equal(pqzKeyHandle(seed, { ...at, token: r.token, version: r.version }).seedCommitment(), r.seedCommitment);
  for (const r of k.ownTagOpening) {
    const h = pqzKeyHandle(seed, {
      ...at,
      layout: { ...k.layout, kMax: 4096 },
      token: r.keyClass === "offchain-token" ? r.token : undefined,
      version: r.version,
    });
    // T21 O5 (b): the own part through the debit entry, its counter the account's (`lastDebit − 1`)
    const deb = (puf, lastDebit = r.sendCounter + 1) => ({
      token: r.token,
      lastDebit,
      own: { pu: puf, pvf: r.pvf, ownTag: r.ownTag },
      window: [],
      shieldIn: 0,
    });
    assert.equal(
      h.withSecretDebit(deb(r.puf), (s) => s.length),
      32,
      "control: the own part alone",
    );
    assert.throws(() => h.withSecretDebit(deb(r.puf, r.sendCounter + 2), () => 0), /ownTag/, "the counter off by one");
    const other = pqzKeyHandle(seed, {
      ...at,
      layout: { ...k.layout, kMax: 4096 },
      token: r.keyClass === "offchain-token" ? r.token : undefined,
      version: 1,
    });
    assert.throws(() => other.withSecretDebit(deb(r.puf), () => 0), /ownTag/, "a foreign key's tag");
    const p = fromHex(r.puf);
    p[7] ^= 1;
    assert.throws(() => h.withSecretDebit(deb(p), () => 0), /ownTag/, "u_f alone differs");
    assert.equal(h.secretLoads, 1);
    assert.equal(other.secretLoads, 0);
  }
  const hs = k.entries.rows.map((r) => {
    const x = pqzEntryHash(r.index, r.slot, r.code ? k.entries.code : undefined);
    assert.equal(hex(x), r.h, r.what);
    return x;
  });
  assert.equal(hex(pqzEntriesHash(hs)), k.entries.entriesHash);
  for (const r of k.scopedKeyRecords) {
    const x = pqzScopedKeyMessages(r.kind, r);
    assert.deepEqual([x.keyDigest, x.recordDigest, x.message, x.regMessage].map(hex), [
      r.keyDigest,
      r.recordDigest,
      r.message,
      r.regMessage,
    ]);
  }
  const b = pqzOpeningBlobOf(k.openingBlob.code, k.layout);
  assert.deepEqual(b.at, k.openingBlob.at);
  assert.deepEqual(b.kv, [0n, 2n]);
  assert.equal(hex(b.toUA), k.ua);
  assert.throws(() => pqzOpeningBlobOf(k.openingBlob.code.slice(0, -2), k.layout), /not an opening op 1 blob/);
});

// ------------------------------------------------------------------ the key handle (Fable P1-1, P2-1; spec §6, §14.1, §14.18)

const UA = "0x" + "11".repeat(32);
const at0 = { chainUid: CU[0], ua: UA, version: 0, layout: L };
const be8 = (v) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(v));
  return b;
};
const filled = (n, x) => new Uint8Array(n).fill(x);
// a credit's slot `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)` at an op 1 credit's offsets (16, 16 + P(u)) (the review's F1)
const slotAt = (uOff, vOff) =>
  "0x" +
  ((BigInt("0x5e" + "00".repeat(19)) << 96n) | (BigInt(uOff) << 80n) | (BigInt(vOff) << 64n) | 7n)
    .toString(16)
    .padStart(64, "0");
const SLOT = slotAt(16, 16 + L.pkp);
const MARKED = "0x" + (BigInt(SLOT) | SKIP).toString(16).padStart(64, "0");
const TRIV = "0x" + ((100n << 96n) | 9n).toString(16).padStart(64, "0");

/** An opening op 1 blob's code to `ua` at key version 0 on `token`, `O_t` sealed from `seedLeg` (`sealTo` the recipient's key,
 *  `junk` a random opening instead), with the auditor's `O_a` when `aud` = `{ ua, kemPk, kv }`. */
function blob({ h, token, seedLeg, junk = false, wrongSeed = null, aud = null, fill = 1, role = 0 }) {
  const pu = filled(L.pkp, fill),
    pvt = filled(L.vp, fill + 1),
    pva = aud ? filled(L.vp, fill + 2) : new Uint8Array(0);
  const aadT = pqzOpeningAad({ chainUid: CU[0], token, ua: UA, keyVersion: 0, pu, pv: pvt });
  const oT = junk
    ? filled(1648, 9)
    : sealOpening({ seedLeg: wrongSeed ?? seedLeg, role, kemPk: h.openKem, aad: aadT }).bytes;
  const oA = aud
    ? sealOpening({
        seedLeg,
        role: 1,
        kemPk: aud.kemPk,
        aad: pqzOpeningAad({ chainUid: CU[0], token, ua: aud.ua, keyVersion: aud.kv, pu, pv: pva }),
      }).bytes
    : new Uint8Array(0);
  const n = aud ? 2 : 1;
  return concatBytes(
    Uint8Array.of(0),
    filled(16, 3),
    pu,
    pvt,
    pva,
    fromHex(UA),
    filled(L.pkp, 4),
    filled(L.vp, 5),
    oT,
    oA,
    filled(32, 6),
    be8(0),
    aud ? be8(aud.kv) : new Uint8Array(0),
    Uint8Array.of(n),
  );
}

test("pqzKeyHandle: the planted probe never loads the secret; a mark lets the window prove; acceptance bound to handle and bytes", () => {
  for (const token of [undefined, TOK[0]]) {
    const h = pqzKeyHandle(SEED, { ...at0, token });
    const other = pqzKeyHandle(SEED, { ...at0, token, version: 1 });
    assert.deepEqual(
      Object.keys(h).sort(),
      [
        "check",
        "keygens",
        "kind",
        "openKem",
        "scope",
        "secretLoads",
        "seedCommitment",
        "version",
        "wipe",
        "withSecretDebit",
        "withSecretKeygen",
      ].sort(),
    );
    assert.ok(Object.isFrozen(h) && !("decrypt" in h) && !("open" in h), "no decrypt, no bare open");
    const seedLeg = filled(32, 0x5e);
    const tok = TOK[0];
    const reads1 = { block: 100, finalized: false, strictMajority: false };
    const credit = (i, code, x = {}) => ({ token: tok, index: i, slot: SLOT, code, reads: reads1, ...x });
    // positive control: an honest credit; the binding's check gets seed_leg and the handle's own aad
    const good = blob({ h, token: tok, seedLeg });
    let seen = null;
    const ok = h.check(credit(0, good), (s, inp) => {
      seen = { s, inp };
      return 42n;
    });
    assert.equal(ok.value, 42n);
    assert.equal(hex(seen.s), hex(seedLeg));
    assert.equal(ok.accepted.entryHash, hex(pqzEntryHash(0, SLOT, good)));
    assert.equal(ok.accepted.token, hex(fromHex(tok)), "the acceptance names the token (T21 L47)");
    // F1: the slot's offsets bound (control: SLOT above)
    for (const [u, vv, what] of [
      [17, 16 + L.pkp, "uOff + 1"],
      [16, 17 + L.pkp, "vOff + 1"],
      [16, 200, "vOff 200"],
    ]) {
      assert.throws(
        () => h.check(credit(0, good, { slot: slotAt(u, vv) }), () => 42n),
        /Input: the slot's offsets/,
        what,
      );
    }
    // the planted probe, three variants: one outcome (skip); the binding never runs on the first, refuses the other two
    const v1 = h.check(credit(1, blob({ h, token: tok, seedLeg, junk: true, fill: 7 })), () => {
      throw new Error("ran on junk");
    });
    const v2 = h.check(credit(1, blob({ h, token: tok, seedLeg, wrongSeed: filled(32, 0x77), fill: 7 })), (s) =>
      s[0] === 0x77 ? null : 1n,
    );
    const v3 = h.check(credit(1, blob({ h, token: tok, seedLeg, fill: 7 })), () => null); // crafted u*: Enc-expand disagrees
    // step 8: an opening that opens to the right seed_leg but under other coins (the auditor's role) is not the one K3-6 makes
    const v4 = h.check(credit(1, blob({ h, token: tok, seedLeg, role: 1, fill: 7 })), () => 1n);
    for (const v of [v1, v2, v3, v4]) assert.ok(v.skip && v.skip.index === 1n);
    const bad = blob({ h, token: tok, seedLeg, fill: 7 });
    const w = (slot1) => [
      { token: tok, index: 0, slot: SLOT, code: good, accepted: ok.accepted },
      { token: tok, index: 1, slot: slot1, code: bad },
      { token: tok, index: 2, slot: TRIV },
    ];
    const deb = (lastDebit, window, own, shieldIn = 0) => ({ token: tok, lastDebit, own, window, shieldIn });
    // the holder's own part of a debit at counter 4 (lastDebit 5), its tag by the handle's own key
    const own = { pu: filled(L.pkp, 0x0f), pvf: filled(L.vp, 0x0e) };
    own.ownTag = h.withSecretKeygen(
      (s) => pqzOwnTag({ seed32: s, chainUid: CU[0], token: tok, fromUA: UA, sendCounter: 4, ...own }).ownTag,
    );
    assert.throws(
      () => h.withSecretDebit(deb(5, w(SLOT), own), () => 0),
      /neither accepted/,
      "an unaccepted unmarked credit",
    );
    assert.equal(h.secretLoads, 0, "the secret was never loaded");
    assert.throws(() => pqzMarks([v1.skip]), /not a reason to mark/, "a single unfinalized read");
    assert.deepEqual(
      pqzMarks([v1, v2, v3].map((v) => ({ ...v.skip, reads: { block: 90, finalized: true, strictMajority: true } }))),
      [1n],
    );
    assert.equal(
      h.withSecretDebit(deb(5, w(MARKED), own), (s) => s.length),
      32,
      "marked: own part and window",
    );
    assert.equal(
      h.withSecretDebit(deb(5, [], own), (s) => s.length),
      32,
      "control: the own part alone",
    );
    assert.equal(
      h.withSecretDebit(deb(0, w(MARKED)), (s) => s.length),
      32,
      "control: a first debit, the window alone",
    );
    assert.equal(h.secretLoads, 3);
    // the own part's gates (T21 L43): no empty-window bypass; every field named
    assert.throws(() => h.withSecretDebit(deb(5, []), () => 0), /OwnRequired/, "lastDebit > 0, zero entries");
    assert.throws(() => h.withSecretDebit(deb(5, w(MARKED)), () => 0), /OwnRequired/, "lastDebit > 0, no own part");
    assert.throws(
      () => h.withSecretDebit(deb(0, w(MARKED), own), () => 0),
      /never debited/,
      "an own part at lastDebit 0",
    );
    assert.throws(() => h.withSecretDebit(deb(0, []), () => 0), /EmptyDebit/, "nothing gated");
    // owner 2026-11-16: a first debit of Trivial(shieldIn) alone passes; shieldIn is a named, required field
    assert.equal(
      h.withSecretDebit(deb(0, [], undefined, 7), (s) => s.length),
      32,
      "a shielded-in-only first debit",
    );
    assert.throws(
      () => h.withSecretDebit({ token: tok, lastDebit: 0, window: [] }, () => 0),
      /shieldIn: not an integer/,
      "a missing shieldIn",
    );
    // the window's order and count (the review's F2)
    assert.throws(
      () => h.withSecretDebit(deb(0, [w(MARKED)[0], w(MARKED)[0]]), () => 0),
      /strictly ascending/,
      "an accepted entry twice",
    );
    assert.throws(
      () => h.withSecretDebit(deb(0, [w(MARKED)[2], w(MARKED)[1]]), () => 0),
      /strictly ascending/,
      "indexes descending",
    );
    const many = (n) => Array.from({ length: n }, (_, i) => ({ token: tok, index: i, slot: TRIV }));
    assert.throws(
      () => h.withSecretDebit(deb(0, many(L.kMax - 1)), () => 0),
      /Window: more than kMax/,
      "kMax - 1 entries",
    );
    assert.equal(
      h.withSecretDebit(deb(0, many(L.kMax - 2)), (s) => s.length),
      32,
      "control: kMax - 2 entries",
    );
    assert.throws(
      () =>
        pqzKeyHandle(SEED, { ...at0, token, layout: pqzLayout(2304, 46) }).withSecretDebit(deb(0, many(1)), () => 0),
      /kMax/,
      "a layout without kMax",
    );
    assert.throws(
      () => h.withSecretDebit(deb(5, [], { ...own, pu: own.pu.subarray(1) }), () => 0),
      /Input: the own part's/,
      "a short P(u_f)",
    );
    assert.throws(() => h.withSecretDebit(deb(6, [], own), () => 0), /ownTag/, "the own part at another counter");
    assert.throws(
      () => h.withSecretDebit({ token: tok, lastDebit: 0, shieldIn: 0 }, () => 0),
      /the window: an array/,
      "a missing window",
    );
    assert.throws(
      () => h.withSecretDebit({ token: tok, window: w(MARKED) }, () => 0),
      /lastDebit: not an integer/,
      "a missing lastDebit",
    );
    assert.throws(() => h.withSecretDebit({ lastDebit: 0, window: w(MARKED) }, () => 0), /token/, "a missing token");
    // the window's tokens (T21 L47)
    assert.throws(
      () => h.withSecretDebit(deb(0, [{ ...w(MARKED)[2], token: TOK[1] }]), () => 0),
      /another token than the debit/,
      "a TRIVIAL entry of another token",
    );
    assert.throws(
      () => h.withSecretDebit(deb(0, [{ ...w(MARKED)[0], token: TOK[1] }]), () => 0),
      /another token than the debit/,
      "an accepted entry of another token",
    );
    if (!token) {
      // a class-2 key serves every token; its acceptance names the token it was checked for
      const g1 = blob({ h, token: TOK[1], seedLeg });
      const a1 = h.check(credit(0, g1, { token: TOK[1] }), () => 3n);
      assert.equal(a1.accepted.token, hex(fromHex(TOK[1])));
      const e = { token: tok, index: 0, slot: SLOT, code: g1, accepted: a1.accepted };
      assert.throws(
        () => h.withSecretDebit(deb(0, [e]), () => 0),
        /neither accepted/,
        "an acceptance of another token",
      );
      assert.equal(
        h.withSecretDebit({ token: TOK[1], lastDebit: 0, window: [{ ...e, token: TOK[1] }], shieldIn: 0 }, () => 7),
        7,
        "control: its own token",
      );
    } else {
      assert.throws(
        () => h.withSecretDebit({ ...deb(0, w(MARKED)), token: TOK[1] }, () => 0),
        /not this offchain-token handle's/,
        "a class-3 debit of another token",
      );
    }
    assert.equal(h.secretLoads, token ? 5 : 6, "no refusal loaded the secret");
    const o2 = pqzKeyHandle(
      SEED.map((x) => x ^ 1),
      { ...at0, token },
    );
    assert.throws(
      () => o2.withSecretDebit(deb(0, [w(SLOT)[0]]), () => 0),
      /neither accepted/,
      "another wallet's key, the same scope",
    );
    // Codex 1 / Fable F7: the acceptance is bound to the key and its derivation path (account 0 and 1: the same scope fields)
    for (const [x, what] of [
      [{ account: 1 }, "account 1"],
      [{ index: 1 }, "index 1"],
    ]) {
      const h1 = pqzKeyHandle(SEED, { ...at0, token, ...x });
      assert.throws(
        () => h1.withSecretDebit(deb(0, [w(SLOT)[0]]), () => 0),
        /neither accepted/,
        `${what} given account 0's acceptance`,
      );
      const own1 = h1.check(credit(0, blob({ h: h1, token: tok, seedLeg })), () => 1n);
      assert.equal(
        h1.withSecretDebit(
          deb(0, [{ ...w(SLOT)[0], code: blob({ h: h1, token: tok, seedLeg }), accepted: own1.accepted }]),
          () => 9,
        ),
        9,
        `control: ${what}'s own acceptance`,
      );
      assert.throws(
        () =>
          h.withSecretDebit(
            deb(0, [{ ...w(SLOT)[0], code: blob({ h: h1, token: tok, seedLeg }), accepted: own1.accepted }]),
            () => 0,
          ),
        /neither accepted/,
        `account 0 given ${what}'s acceptance`,
      );
    }
    assert.throws(
      () => other.withSecretDebit(deb(0, [w(SLOT)[0]]), () => 0),
      /neither accepted/,
      "another handle's acceptance",
    );
    assert.throws(
      () => h.withSecretDebit(deb(0, [{ ...w(SLOT)[0], index: 3 }]), () => 0),
      /neither accepted/,
      "another index",
    );
    assert.throws(
      () => h.withSecretDebit(deb(0, [{ ...w(SLOT)[0], code: bad }]), () => 0),
      /neither accepted/,
      "other bytes",
    );
    assert.throws(
      () => h.withSecretDebit(deb(0, [{ ...w(SLOT)[0], accepted: { ...ok.accepted } }]), () => 0),
      /neither accepted/,
      "a copied acceptance",
    );
    // not this handle's, or incomplete: refused before the check
    const never = () => {
      throw new Error("the check ran");
    };
    assert.throws(() => h.check(credit(0, good, { slot: TRIV }), never), /TRIVIAL/);
    assert.throws(() => h.check(credit(0, good.subarray(0, good.length - 1)), never), /not an opening op 1 blob/);
    const r = () => h.check(credit(0, good, { token: TOK[1] }), () => 1n);
    if (token) assert.throws(r, /not this offchain-token handle's/);
    else assert.ok(r().skip, "class 2 serves every token; the aad binds the token: another token is a skip");
    assert.equal(
      h.withSecretKeygen((s) => s.length),
      32,
    );
    assert.equal(h.keygens, 2);
    // U4h-4: after wipe the honest credit that was accepted above is refused locally, never a (markable) skip
    h.wipe();
    assert.throws(() => h.withSecretKeygen(() => 0), /wiped/);
    assert.throws(
      () => h.withSecretDebit(deb(0, w(MARKED)), () => 0),
      /KeyRevoked: this handle was wiped/,
      "a wiped handle refuses the debit",
    );
    // KeyRevoked before any other refusal (the review, P3; ua-rs: `live` first)
    assert.throws(() => h.withSecretDebit(deb(0, []), () => 0), /KeyRevoked/, "an empty debit");
    assert.throws(() => h.withSecretDebit({ ...deb(0, []), token: TOK[1] }, () => 0), /KeyRevoked/, "another token");
    assert.throws(() => h.withSecretDebit({ token: tok }, () => 0), /KeyRevoked/, "missing fields");
    assert.throws(() => h.check(credit(0, good, { slot: TRIV }), never), /KeyRevoked/, "a TRIVIAL credit");
    assert.throws(() => h.check(credit(0, good), never), /wiped/, "a wiped handle refuses the check");
  }
});

test("U2-2: opening.json rejects: a malformed opening opens to null, O_a under role 0's coins is not K3-6's, a malformed kemPk is refused", () => {
  const r1 = K.rows.find((r) => r.auditorOn);
  const reader = (ua) => openKemKey(openKemSeed(SEED, { ua, chainUid: CU[0], version: 0 }));
  const T = reader("0x" + "11".repeat(32));
  const A = reader("0x" + "a0".repeat(32));
  const open = (R, opening, aad) =>
    openOpening({ opening, kemPk: R.kemPk, dk: R.dk, x25519Secret: R.x25519Secret, aad });
  // controls: the honest openings open to seed_leg and are K3-6's
  assert.equal(hex(open(T, h0(r1.opening_t), h0(r1.aad_t))), h0(r1.seed_leg));
  assert.equal(hex(open(A, h0(r1.opening_a), h0(r1.aad_a))), h0(r1.seed_leg));
  assert.equal(
    hex(sealOpening({ seedLeg: fromHex(h0(r1.seed_leg)), role: 0, kemPk: T.kemPk, aad: h0(r1.aad_t) }).bytes),
    h0(r1.opening_t),
  );
  assert.ok(K.rejects.length >= 22);
  const seen = new Set();
  for (const x of K.rejects) {
    seen.add(x.field);
    assert.equal(x.recipient, "skip", x.case);
    if (x.field === "to.kemPk" || x.field === "auditor.kemPk") {
      const au = x.field === "auditor.kemPk";
      assert.equal(x.seal, "refused", x.case);
      assert.throws(
        () =>
          sealOpening({
            seedLeg: fromHex(h0(r1.seed_leg)),
            role: au ? 1 : 0,
            kemPk: h0(x.value),
            aad: h0(au ? r1.aad_a : r1.aad_t),
          }),
        undefined,
        x.case,
      );
      continue;
    }
    if (x.field === "chainUid" || x.field === "to.keyVersion") {
      // T21 L66b: the honest O_t under the edited credit's aad (the row's, pqz-ffi's) opens to nothing
      assert.notEqual(h0(x.aad), h0(r1.aad_t), x.case);
      assert.equal(open(T, h0(r1.opening_t), h0(x.aad)), null, x.case);
      assert.equal(x.open, "none", x.case);
      continue;
    }
    const to = x.field === "to.opening";
    assert.ok(to || x.field === "auditor.opening", x.field);
    const got = open(to ? T : A, h0(x.value), h0(to ? r1.aad_t : r1.aad_a));
    if (x.open === "none") {
      assert.equal(got, null, x.case);
    } else {
      // the auditor's Unreadable branch after its opening authenticates: opens to seed_leg, but is not K3-6's opening of role 1
      assert.equal(hex(got), h0(x.open), x.case);
      assert.equal(x.auditor, "unreadable", x.case);
      const k36 = hex(
        sealOpening({ seedLeg: got, role: to ? 0 : 1, kemPk: (to ? T : A).kemPk, aad: h0(to ? r1.aad_t : r1.aad_a) })
          .bytes,
      );
      assert.equal(k36, h0(to ? r1.opening_t : r1.opening_a));
      assert.notEqual(k36, h0(x.value), x.case);
    }
  }
  assert.deepEqual([...seen].sort(), [
    "auditor.kemPk",
    "auditor.opening",
    "chainUid",
    "to.kemPk",
    "to.keyVersion",
    "to.opening",
  ]);
  // T21 L66b: spec §14.19's named cases are rows of the shared corpus (both readers run them)
  for (const c of [
    "O_t low-order X25519 point",
    "O_t mlkemCt of another UA's key",
    "O_t the auditor's sealed seed",
    "O_t mlkemCt bit flipped",
    "aad of another chain",
    "aad of another key version",
    "auditor kemPk 100 bytes",
  ]) {
    assert.ok(
      K.rejects.some((x) => x.case === c),
      c,
    );
  }
});

test("U4h-3: malformed hex and out-of-range integers are refused, never changed; valid controls", () => {
  const r = K.rows[0];
  const ok = hex(legSeedOfKeyHash(h0(r.seed_enc), h0(r.toUA), h0(r.pk_t_keccak)));
  assert.equal(ok, h0(r.seed_leg), "control");
  assert.equal(
    hex(legSeedOfKeyHash(h0(r.seed_enc).toUpperCase().replace("0X", "0x"), h0(r.toUA), h0(r.pk_t_keccak))),
    ok,
    "upper-case hex",
  );
  assert.throws(
    () => legSeedOfKeyHash(h0(r.seed_enc) + "0", h0(r.toUA), h0(r.pk_t_keccak)),
    /seed_enc: not hex/,
    "one extra nibble",
  );
  assert.throws(
    () => legSeedOfKeyHash("0x" + "zz" + h0(r.seed_enc).slice(4), h0(r.toUA), h0(r.pk_t_keccak)),
    /seed_enc: not hex/,
    "a non-hex pair",
  );
  assert.throws(
    () => legSeedOfKeyHash(h0(r.seed_enc).slice(0, -2), h0(r.toUA), h0(r.pk_t_keccak)),
    /seed_enc: 32 bytes/,
    "one byte short",
  );
  const at = { ua: "0x" + "11".repeat(32), chainUid: CU[0], version: 0, layout: L };
  const c0 = pqzKeyHandle(SEED, { ...at, account: 0 }).seedCommitment();
  assert.notEqual(
    pqzKeyHandle(SEED, { ...at, account: 0xffffffff }).seedCommitment(),
    c0,
    "control: the largest account",
  );
  for (const bad of [2 ** 32, -1, 1.5, NaN, "0"]) {
    assert.throws(() => pqzKeyHandle(SEED, { ...at, account: bad }), /account must be an integer/, `account ${bad}`);
    assert.throws(() => pqzKeyHandle(SEED, { ...at, index: bad }), /index must be an integer/, `index ${bad}`);
  }
  assert.equal(hex(pqzEntryHash(0, SLOT, "0x00")), hex(pqzEntryHash(0n, SLOT, "0x00")), "control: index 0");
  for (const bad of [-1, 1n << 256n])
    assert.throws(() => pqzEntryHash(bad, SLOT, "0x00"), /uint256/, `entry index ${bad}`);
  assert.throws(() => pqzEntryHash(0, SLOT, "0x0"), /code: not hex/, "an odd code");
  // T21 L65: an empty string, null, false or a padded number is refused, never read as 0 (or 7)
  const rec = {
    ua: "0x" + "11".repeat(32),
    keyClass: 2,
    chainUid: CU[0],
    token: "0x" + "00".repeat(20),
    version: 0,
    pqzKeyHash: "0x" + "22".repeat(32),
    pqzPopHash: "0x" + "33".repeat(32),
    openKemHash: "0x" + "44".repeat(32),
    validUntilBlock: "7",
  };
  assert.ok(pqzScopedKeyDigest(rec) && pqzScopedKeyRecordDigest(rec) && pqzKeyHandle(SEED, at), "control");
  assert.equal(hex(pqzEntryHash("7", SLOT, "0x00")), hex(pqzEntryHash(7n, SLOT, "0x00")), "control: decimal digits");
  for (const bad of ["", null, false, " 7 ", "+7", "07", "0x7", 1.5, undefined]) {
    const s = JSON.stringify(bad) ?? "undefined";
    assert.throws(() => pqzKeyHandle(SEED, { ...at, version: bad }), /version: not an integer/, `version ${s}`);
    assert.throws(() => pqzScopedKeyDigest({ ...rec, version: bad }), /version: not an integer/, `record version ${s}`);
    assert.throws(() => pqzScopedKeyDigest({ ...rec, keyClass: bad }), /keyClass: not an integer/, `keyClass ${s}`);
    assert.throws(
      () => pqzScopedKeyRecordDigest({ ...rec, validUntilBlock: bad }),
      /validUntilBlock: not an integer/,
      `validUntilBlock ${s}`,
    );
    assert.throws(() => pqzEntryHash(bad, SLOT, "0x00"), /entry index: not an integer/, `entry index ${s}`);
  }
  // T21 L79: each field's declared width (uint8 keyClass, uint64 version / validUntilBlock, uint64[] skip), its top value the
  // control
  const top = (bits) => (1n << BigInt(bits)) - 1n;
  assert.ok(pqzScopedKeyDigest({ ...rec, keyClass: 255, version: top(64) }), "control: uint8 / uint64 top");
  assert.ok(
    pqzScopedKeyRecordDigest({ ...rec, keyClass: top(8), version: top(64), validUntilBlock: top(64) }),
    "control: record tops",
  );
  for (const d of [pqzScopedKeyDigest, pqzScopedKeyRecordDigest]) {
    assert.throws(() => d({ ...rec, keyClass: 256 }), /keyClass: a uint8/, `${d.name} keyClass 256`);
    assert.throws(() => d({ ...rec, version: 1n << 64n }), /version: a uint64/, `${d.name} version 2^64`);
    assert.throws(() => d({ ...rec, version: -1n }), /version: a uint64/, `${d.name} version -1`);
  }
  assert.throws(
    () => pqzScopedKeyRecordDigest({ ...rec, validUntilBlock: 1n << 64n }),
    /validUntilBlock: a uint64/,
    "validUntilBlock 2^64",
  );
  const reads = { block: 90, finalized: true, strictMajority: true };
  assert.deepEqual(
    pqzMarks([
      { index: top(64), reads },
      { index: 0, reads },
    ]),
    [0n, top(64)],
    "control: skip 0 and 2^64 - 1",
  );
  for (const bad of [-1n, 1n << 64n])
    assert.throws(() => pqzMarks([{ index: bad, reads }]), /skip index: a uint64/, `skip ${bad}`);
});

test("P2-1: an audited credit checked against the auditor's key of another version is a skip that a single read cannot mark", () => {
  const h = pqzKeyHandle(SEED, at0);
  const audUA = "0x" + "33".repeat(32);
  const aud = (v) => openKemKey(openKemSeed(SEED, { ua: audUA, chainUid: CU[0], version: v })).kemPk;
  const code = blob({ h, token: TOK[0], seedLeg: filled(32, 0x5e), aud: { ua: audUA, kemPk: aud(0), kv: 0 } });
  const c = (kemPk, reads) => ({
    token: TOK[0],
    index: 4,
    slot: SLOT,
    code,
    auditor: { ua: audUA, pk: "0x", kemPk },
    reads,
  });
  const one = { block: 100, finalized: false, strictMajority: false };
  assert.equal(h.check(c(aud(0), one), () => 5n).value, 5n, "control: the auditor key of the leg's version");
  const s = h.check(c(aud(1), one), () => 5n);
  assert.ok(s.skip, "version 1's kemPk for a leg sealed to version 0");
  assert.throws(() => pqzMarks([s.skip]), /not a reason to mark/);
  assert.throws(
    () => h.check({ ...c(aud(0), one), auditor: undefined }, () => 5n),
    /without the auditor's keys/,
    "a missing read is an error, not a skip",
  );
});

test("the review (Codex 2): an acceptance keeps a copy of its token bytes; the caller overwriting its buffer moves nothing", () => {
  const h = pqzKeyHandle(SEED, at0); // class 2: serves every token
  const seedLeg = filled(32, 0x5e);
  const tA = fromHex(TOK[0]),
    tB = fromHex(TOK[1]);
  const code = blob({ h, token: TOK[0], seedLeg });
  const ok = h.check(
    { token: tA, index: 0, slot: SLOT, code, reads: { block: 1, finalized: true, strictMajority: true } },
    () => 1n,
  );
  const e = (t) => ({ token: t, index: 0, slot: SLOT, code, accepted: ok.accepted });
  const deb = (t) => ({ token: t, lastDebit: 0, window: [e(t)], shieldIn: 0 });
  assert.equal(
    h.withSecretDebit(deb(TOK[0]), () => 1),
    1,
    "control: token A",
  );
  assert.throws(() => h.withSecretDebit(deb(TOK[1]), () => 0), /neither accepted/, "token B");
  tA.set(tB); // the caller's buffer now holds token B
  assert.throws(() => h.withSecretDebit(deb(TOK[1]), () => 0), /neither accepted/, "token B after the buffer moved");
  assert.equal(
    h.withSecretDebit(deb(TOK[0]), () => 2),
    2,
    "token A still",
  );
});

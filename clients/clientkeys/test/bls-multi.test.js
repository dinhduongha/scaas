// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// bls12381-multi (0x0121, spec 2026-11-19-bls12381-multi) in clientkeys: key data (§2), the stored form, verify / verifyMinimal
// (§5), the PoP (§4), member parts and aggregation (§5.4), the builder; plan Tasks 1-3 and Review Focus 1-3. Signatures are made here
// with noble from fixed scalars. UNAUDITED.
import { test } from "node:test";
import assert from "node:assert/strict";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import * as ua from "../src/ua.js";
import { verify, kindVerify } from "../src/ua-verify.js";
import { deriveUAKey } from "../src/uakey.js";
import { keccak_256, concatBytes, hex } from "../src/bytes.js";
import {
  DST_MULTI_SIG,
  DST_MULTI_POP,
  parseBlsMulti,
  compressBlsMulti,
  expandBlsMulti,
  storedBlsMulti,
  blsMultiOk,
  minimalBlsMulti,
  negG2,
  g2Bytes,
  g1Bytes,
  indicesBitmap,
  popMessage,
  popMemberMessage,
  memberSign,
  memberPop,
  aggregatePop,
  aggregate,
  blsMultiAbi,
  buildKeyData,
} from "../src/bls-multi.js";

const { G1, G2 } = bls12_381;
const R = bls12_381.fields.Fr.ORDER;
const K = 0x0121;
const MSG = new Uint8Array(32).fill(7);
const pk = (sk) => G2.Point.BASE.multiply(((sk % R) + R) % R);
const cmp = (a, b) => {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
};
/** A group from points `[{ P, sk, w }]` sorted by key: `{ d, s }`, `s` the sks and weights in key-data order. */
function groupPoints(ms, t) {
  const rows = ms.map((m) => ({ key: g2Bytes(m.P), sk: m.sk, w: m.w })).sort((a, b) => cmp(a.key, b.key));
  const apk = ms.reduce((a, m) => a.add(m.P), G2.Point.ZERO);
  const u16 = (v) => Uint8Array.of(v >> 8, v & 0xff);
  const d = concatBytes(g2Bytes(apk), u16(t), u16(rows.length), ...rows.flatMap((r) => [r.key, u16(r.w)]));
  return { d, s: rows.map((r) => ({ sk: r.sk, w: r.w })) };
}
const group = (ms, t) =>
  groupPoints(
    ms.map(([sk, w]) => ({ P: pk(sk), sk, w })),
    t,
  );
const sks = (n) => Array.from({ length: n }, (_, i) => [1000n + 7n * BigInt(i), 1]);
const mmsg = (d, m) => keccak_256(concatBytes(ua.uaOf(K, d), m));
function signWith(d, s, m, signers, dst) {
  const H = G1.hashToCurve(mmsg(d, m), { DST: dst });
  const sigma = signers.reduce((a, i) => a.add(H.multiply(((s[i].sk % R) + R) % R)), G1.Point.ZERO);
  return concatBytes(g1Bytes(sigma), indicesBitmap(signers));
}
const sign = (d, s, m, signers) => signWith(d, s, m, signers, DST_MULTI_SIG);
const ok = (d, m, sig) => verify(K, hex(d), hex(m), hex(sig), false, false);
const okMin = (d, m, sig) => verify(K, hex(d), hex(m), hex(sig), false, true);
const refused = (d) =>
  assert.throws(
    () => ua.validateKeyData(K, d),
    (e) => e.code === "UAKeyData",
  );
const valid = (d) => assert.doesNotThrow(() => ua.validateKeyData(K, d));
const at = (s, sk) => s.findIndex((x) => x.sk === sk);

// --- Task 1 rows ---

test("keyDataValidRows", () => {
  for (const n of [2, 16, 64]) for (const t of [1, n]) valid(group(sks(n), t).d);
  const w = (ws) => ws.map((x, i) => [50n + BigInt(i), x]);
  valid(group(w([3, 1, 1]), 3).d);
  valid(group(w([5, 1]), 2).d); // a weight above t (R2-Q3)
  assert.equal(ua.keyHashOf(K, group(sks(2), 1).d), null, "no keyHash (Q5)");
  assert.ok(ua.isSigningKind(K) && ua.isMemberKind(K) && ua.hasSurplusForm(K));
  assert.ok(!ua.hasSurplusForm(0x0106) && !ua.hasSurplusForm(0x0120));
});

/** A G2 point on the curve outside the subgroup. */
function offSubgroup() {
  const { Fp2 } = bls12_381.fields;
  const b = Fp2.create({ c0: 4n, c1: 4n });
  for (let i = 1n; ; i++) {
    const x = Fp2.create({ c0: i, c1: 1n });
    const y2 = Fp2.add(Fp2.mul(Fp2.sqr(x), x), b);
    let y;
    try {
      y = Fp2.sqrt(y2);
    } catch {
      continue;
    }
    if (!y || !Fp2.eql(Fp2.sqr(y), y2)) continue;
    const P = G2.Point.fromAffine({ x, y });
    if (!P.isTorsionFree()) return P;
  }
}

test("keyDataRefusals", () => {
  const { d } = group(sks(3), 2);
  valid(d);
  const set16 = (x, o, v) => x.set(Uint8Array.of(v >> 8, v & 0xff), o);
  const key = (i) => 260 + 258 * i;
  let x = Uint8Array.from(group(sks(2), 1).d.subarray(0, 260 + 258));
  set16(x, 258, 1);
  refused(x); // n = 1
  refused(group(sks(65), 1).d); // n = 65
  x = Uint8Array.from(d);
  set16(x, 256, 0);
  refused(x); // t = 0
  x = Uint8Array.from(d);
  set16(x, 256, 4);
  refused(x); // t = Σw + 1
  x = Uint8Array.from(d);
  set16(x, 256, 3);
  valid(x); // t = Σw
  x = Uint8Array.from(d);
  set16(x, key(1) + 256, 0);
  refused(x); // weight 0
  for (const len of [d.length - 1, d.length + 1, 0, 259]) {
    x = new Uint8Array(len);
    x.set(d.subarray(0, Math.min(len, d.length)));
    refused(x);
  }
  x = Uint8Array.from(d);
  x.set(d.subarray(key(1), key(2)), key(0));
  x.set(d.subarray(key(0), key(1)), key(1));
  refused(x); // unsorted
  const p9 = pk(9n);
  refused(
    groupPoints(
      [
        { P: p9, sk: 9n, w: 1 },
        { P: p9, sk: 9n, w: 1 },
        { P: pk(3n), sk: 3n, w: 1 },
      ],
      1,
    ).d,
  ); // duplicate
  x = Uint8Array.from(d);
  x[key(1) + 255] ^= 1;
  refused(x); // off curve
  refused(
    groupPoints(
      [
        { P: offSubgroup(), sk: 1n, w: 1 },
        { P: pk(3n), sk: 3n, w: 1 },
      ],
      1,
    ).d,
  ); // outside the subgroup
  refused(
    groupPoints(
      [
        { P: G2.Point.ZERO, sk: 0n, w: 1 },
        { P: pk(3n), sk: 3n, w: 1 },
      ],
      1,
    ).d,
  ); // a key at infinity
  x = Uint8Array.from(d);
  x[key(2)] = 1;
  refused(x); // top bytes
  x = Uint8Array.from(d);
  x.fill(0xff, key(2) + 16, key(2) + 64);
  refused(x); // limb ≥ p
  x = Uint8Array.from(d);
  x.set(g2Bytes(pk(77n)), 0);
  refused(x); // apk ≠ the sum
  const c = groupPoints(
    [
      { P: pk(5n), sk: 5n, w: 1 },
      { P: pk(-5n), sk: -5n, w: 1 },
    ],
    1,
  ).d;
  assert.ok(c.subarray(0, 256).every((b) => b === 0));
  refused(c); // apk at infinity
});

test("compressExpandRoundTrip", () => {
  for (const n of [2, 5, 64]) {
    const { d } = group(sks(n), 1);
    const s = compressBlsMulti(d);
    assert.equal(s.length, 196 + 194 * n);
    assert.deepEqual(expandBlsMulti(s), d);
    const p = storedBlsMulti(d);
    assert.equal(p.length, 228 + 194 * n);
    assert.equal(hex(p.subarray(0, 32)), hex(ua.uaOf(K, d)));
  }
  const { d } = group(sks(2), 1);
  const x = Uint8Array.from(d);
  x[260 + 258 + 64] = 1;
  assert.throws(() => compressBlsMulti(x));
});

test("weightSumWide", () => {
  const { d, s } = group(
    [
      [11n, 65535],
      [12n, 65535],
    ],
    65535,
  );
  valid(d);
  const kd = parseBlsMulti(d);
  for (const one of [0, 1]) {
    assert.ok(ok(d, MSG, sign(d, s, MSG, [one])));
    assert.ok(okMin(d, MSG, sign(d, s, MSG, [one])));
    assert.ok(minimalBlsMulti(kd, [one]));
  }
  const both = sign(d, s, MSG, [0, 1]);
  assert.ok(ok(d, MSG, both));
  assert.ok(!okMin(d, MSG, both));
  assert.ok(!minimalBlsMulti(kd, [0, 1]));
});

test("negationZeroComponent", () => {
  assert.deepEqual(negG2(new Uint8Array(256)), new Uint8Array(256));
  const p = pk(3n);
  const e = g2Bytes(p);
  assert.deepEqual(negG2(e), g2Bytes(p.negate()));
  const z = Uint8Array.from(e);
  z.fill(0, 128, 192);
  const n = negG2(z);
  assert.ok(n.subarray(128, 192).every((b) => b === 0));
  assert.deepEqual(n.subarray(0, 128), e.subarray(0, 128));
  assert.deepEqual(n.subarray(192), g2Bytes(p.negate()).subarray(192));
});

test("subtractCancellingPair", () => {
  const a = 41n;
  const ms = [
    { P: pk(a), sk: a, w: 1 },
    { P: pk(-a), sk: -a, w: 1 },
    ...[0n, 1n, 2n, 3n].map((i) => ({ P: pk(60n + i), sk: 60n + i, w: 1 })),
  ];
  const { d, s } = groupPoints(ms, 4);
  valid(d);
  const signers = [0, 1, 2, 3, 4, 5].filter((i) => s[i].sk !== a && s[i].sk !== -a);
  assert.equal(signers.length, 4);
  const sig = sign(d, s, MSG, signers);
  assert.ok(ok(d, MSG, sig));
  assert.ok(okMin(d, MSG, sig));
});

test("f12CancellingPairDocumented", () => {
  const [a, c] = [41n, 43n];
  const { d, s } = groupPoints(
    [
      { P: pk(a), sk: a, w: 1 },
      { P: pk(-a), sk: -a, w: 1 },
      { P: pk(c), sk: c, w: 1 },
    ],
    3,
  );
  valid(d);
  const sig = sign(d, s, MSG, [at(s, c)]);
  sig.set(indicesBitmap([0, 1, 2]), 128);
  assert.ok(ok(d, MSG, sig));
});

test("verifyPaths", () => {
  const { d, s } = group(sks(5), 3);
  const by = (set) => sign(d, s, MSG, set);
  assert.ok(ok(d, MSG, by([0, 2, 4])) && okMin(d, MSG, by([0, 2, 4])), "k = t");
  assert.ok(ok(d, MSG, by([0, 1, 2, 3, 4])) && !okMin(d, MSG, by([0, 1, 2, 3, 4])), "k = n");
  assert.ok(!ok(d, MSG, by([0, 2])), "weight t − 1");
  let x = by([0, 2, 4]);
  x.fill(0, 128);
  assert.ok(!ok(d, MSG, x), "signers 0");
  x = by([0, 2, 4]);
  x[159] |= 1 << 5;
  assert.ok(!ok(d, MSG, x), "a bit ≥ n");
  x = by([0, 2, 4]);
  x.fill(0, 0, 128);
  assert.ok(!ok(d, MSG, x), "σ at infinity");
  x = by([0, 2, 4]);
  assert.ok(!ok(d, MSG, x.subarray(0, 159)) && !ok(d, MSG, concatBytes(x, Uint8Array.of(0))), "159 / 161");
  x = by([0, 2, 4]);
  x[159] |= 2;
  assert.ok(!ok(d, MSG, x), "one bit added");
  x = by([0, 2, 4]);
  x[159] &= ~1;
  assert.ok(!ok(d, MSG, x), "one bit cleared");
  assert.ok(!ok(d, new Uint8Array(32).fill(8), by([0, 2, 4])), "another message");
  const e = Uint8Array.from(d);
  e[260 + 258 * 2 + 200] ^= 1;
  assert.ok(!ok(e, MSG, by([0, 2, 4])), "a stored-key byte flipped");
});

test("apkPathBoundary", () => {
  // Review Focus 3: 2k = n + 1 (add) and 2k = n + 2 (subtract)
  for (const [n, ks] of [
    [5, [3, 4]],
    [64, [32, 33]],
  ]) {
    const { d, s } = group(sks(n), 1);
    for (const k of ks) {
      const set = Array.from({ length: k }, (_, i) => i);
      const sig = sign(d, s, MSG, set);
      assert.ok(ok(d, MSG, sig), `n ${n} k ${k}`);
      const other = [...set.slice(1), k].sort((a, b) => a - b);
      const x = Uint8Array.from(sig);
      x.set(indicesBitmap(other), 128);
      assert.ok(!ok(d, MSG, x), `n ${n} k ${k} other set`);
    }
  }
});

test("minimalRows", () => {
  const w = (ws) => ws.map((x, i) => [90n + BigInt(i), x]);
  let { d, s } = group(w([3, 1, 1]), 3);
  const heavy = s.findIndex((x) => x.w === 3);
  const light = [0, 1, 2].filter((i) => i !== heavy);
  assert.ok(okMin(d, MSG, sign(d, s, MSG, [heavy])));
  assert.ok(!ok(d, MSG, sign(d, s, MSG, light)));
  const two = [heavy, light[0]].sort((a, b) => a - b);
  assert.ok(ok(d, MSG, sign(d, s, MSG, two)) && !okMin(d, MSG, sign(d, s, MSG, two)));
  assert.ok(!minimalBlsMulti(parseBlsMulti(d), two));
  ({ d, s } = group(w([3, 3, 1]), 5)); // the min over S, not over all members
  const set = [0, 1, 2].filter((i) => s[i].w === 3);
  assert.ok(okMin(d, MSG, sign(d, s, MSG, set)));
});

test("dstsSeparate", () => {
  const a = 123n;
  const { d, s } = group(
    [
      [a, 1],
      [124n, 1],
    ],
    1,
  );
  const ia = at(s, a);
  const x = mmsg(d, MSG);
  const partial = g1Bytes(G1.hashToCurve(x, { DST: DST_MULTI_SIG }).multiply(a));
  assert.ok(!verify(0x0106, hex(g2Bytes(pk(a))), hex(x), hex(partial)));
  assert.ok(ok(d, MSG, concatBytes(partial, indicesBitmap([ia]))), "positive control");
  const single = g1Bytes(G1.hashToCurve(x, { DST: "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_" }).multiply(a));
  assert.ok(verify(0x0106, hex(g2Bytes(pk(a))), hex(x), hex(single)), "positive control");
  assert.ok(!ok(d, MSG, concatBytes(single, indicesBitmap([ia]))));
  assert.ok(!ok(d, MSG, signWith(d, s, MSG, [ia], DST_MULTI_POP)));
  assert.equal(DST_MULTI_SIG.length, 53);
  assert.notEqual(DST_MULTI_SIG, DST_MULTI_POP);
});

test("crossGroup", () => {
  const [a, b, c] = [201n, 202n, 203n];
  const g1 = group(
    [
      [a, 1],
      [b, 1],
    ],
    2,
  );
  const g2 = group(
    [
      [a, 1],
      [b, 1],
      [c, 1],
    ],
    2,
  );
  const sig1 = sign(g1.d, g1.s, MSG, [0, 1]);
  assert.ok(ok(g1.d, MSG, sig1));
  const ab = [0, 1, 2].filter((i) => g2.s[i].sk !== c);
  const x = Uint8Array.from(sig1);
  x.set(indicesBitmap(ab), 128);
  assert.ok(!ok(g2.d, MSG, x));
  assert.ok(ok(g2.d, MSG, sign(g2.d, g2.s, MSG, ab)));
});

test("kindVerify passes minimal and pop through", () => {
  const { d, s } = group(sks(3), 2);
  const all = sign(d, s, MSG, [0, 1, 2]);
  assert.ok(kindVerify(K, d, MSG, all, false) && !kindVerify(K, d, MSG, all, false, true));
  assert.ok(blsMultiOk(d, MSG, all) && !blsMultiOk(d, MSG, all, true));
});

// --- Task 2 rows ---

const popParts = (d, s) => s.map((x, i) => [i, memberPop(x.sk, d)]);
const popOk = (d, pop) => verify(K, hex(d), hex(popMessage(d)), hex(pop), true);
const hPop = (d, i) =>
  G1.hashToCurve(popMemberMessage(popMessage(d), d.subarray(260 + 258 * i, 516 + 258 * i)), { DST: DST_MULTI_POP });
const throwsCode = (f, code, index) =>
  assert.throws(f, (e) => e.code === code && (index === undefined || e.index === index));

test("popPositiveN_2_16_64", () => {
  for (const n of [2, 16, 64]) {
    const { d, s } = group(sks(n), 1);
    assert.ok(popOk(d, aggregatePop(d, popParts(d, s))), `n ${n}`);
  }
});

test("popMissingMemberFails", () => {
  const { d, s } = group(sks(3), 2);
  const parts = popParts(d, s);
  assert.ok(popOk(d, aggregatePop(d, parts)));
  throwsCode(() => aggregatePop(d, parts.slice(0, 2)), "Missing", 2);
  assert.ok(!popOk(d, g1Bytes(hPop(d, 0).multiply(s[0].sk).add(hPop(d, 1).multiply(s[1].sk)))));
});

test("popRogueSharedMessage", () => {
  const [a, x] = [31n, 32n];
  const pkH = pk(a);
  const pkM = G2.Point.BASE.multiply(x).subtract(pkH);
  const { d } = groupPoints(
    [
      { P: pkH, sk: a, w: 1 },
      { P: pkM, sk: 0n, w: 1 },
    ],
    1,
  );
  valid(d);
  const H = G1.hashToCurve(popMessage(d), { DST: DST_MULTI_POP });
  const pop = H.multiply(x);
  const { Fp12 } = bls12_381.fields;
  assert.ok(
    Fp12.eql(bls12_381.pairing(pop, G2.Point.BASE), bls12_381.pairing(H, pkH.add(pkM))),
    "passes a shared-message check",
  );
  assert.ok(!popOk(d, g1Bytes(pop)));
});

test("popSplitRogue", () => {
  const x = 77n;
  const P = G2.hashToCurve(new TextEncoder().encode("split"), { DST: "TEST-H2G2" });
  const Q = G2.Point.BASE.multiply(x).subtract(P);
  const { d } = groupPoints(
    [
      { P, sk: 0n, w: 1 },
      { P: Q, sk: 0n, w: 1 },
    ],
    1,
  );
  valid(d);
  const hm = G1.hashToCurve(popMessage(d), { DST: DST_MULTI_POP });
  for (const c of [
    hPop(d, 0).multiply(x),
    hPop(d, 1).multiply(x),
    hPop(d, 0).add(hPop(d, 1)).multiply(x),
    hm.multiply(x),
  ])
    assert.ok(!popOk(d, g1Bytes(c)));
});

test("popTwoRogues", () => {
  const [a, x, y] = [5n, 6n, 7n];
  const pkH = pk(a);
  const { d, s } = groupPoints(
    [
      { P: pkH, sk: a, w: 1 },
      { P: G2.Point.BASE.multiply(x).subtract(pkH), sk: x, w: 1 },
      { P: G2.Point.BASE.multiply(y).add(pkH), sk: y, w: 1 },
    ],
    1,
  );
  valid(d);
  const [i1, i2] = [at(s, x), at(s, y)];
  const hm = G1.hashToCurve(popMessage(d), { DST: DST_MULTI_POP });
  for (const c of [
    hPop(d, i1).multiply(x).add(hPop(d, i2).multiply(y)),
    hm.multiply(x + y),
    hPop(d, i1)
      .add(hPop(d, i2))
      .multiply(x + y),
  ])
    assert.ok(!popOk(d, g1Bytes(c)));
});

test("popOtherThresholdFails", () => {
  const m = sks(3);
  const g2 = group(m, 2);
  const pop = aggregatePop(g2.d, popParts(g2.d, g2.s));
  assert.ok(popOk(g2.d, pop));
  assert.ok(!popOk(group(m, 1).d, pop));
  const w = m.map((x, i) => (i === 0 ? [x[0], 2] : x));
  assert.ok(!popOk(group(w, 2).d, pop));
});

test("popIdentityFails", () => {
  assert.ok(!popOk(group(sks(2), 1).d, new Uint8Array(128)));
});

test("memberPopRefusesUnlistedKey", () => {
  const { d, s } = group(sks(2), 1);
  assert.doesNotThrow(() => memberPop(s[0].sk, d));
  throwsCode(() => memberPop(9999n, d), "NotMember");
  throwsCode(() => memberSign(9999n, d, MSG), "NotMember");
});

test("memberPopForOtherGroupNamed", () => {
  const m = sks(2);
  const g1 = group(m, 2);
  const g2 = group(m, 1);
  const parts = popParts(g2.d, g2.s);
  assert.doesNotThrow(() => aggregatePop(g2.d, parts));
  parts[0] = [0, memberPop(g1.s[0].sk, g1.d)];
  throwsCode(() => aggregatePop(g2.d, parts), "BadPartial", 0);
});

test("aggregatePopNamesBadPart", () => {
  const { d, s } = group(sks(4), 2);
  const parts = popParts(d, s);
  parts[2] = [2, parts[1][1]];
  throwsCode(() => aggregatePop(d, parts), "BadPartial", 2);
  const dup = popParts(d, s);
  dup[3] = [1, dup[3][1]];
  throwsCode(() => aggregatePop(d, dup), "Index", 1);
});

const partials = (d, s, set) => set.map((i) => [i, memberSign(s[i].sk, d, MSG)]);

test("aggregateDefaultMinimal", () => {
  const { d, s } = group(sks(4), 2);
  const a = aggregate(d, MSG, partials(d, s, [0, 1, 2, 3]));
  assert.equal(a.signers.length, 2);
  assert.ok(okMin(d, MSG, blsMultiAbi(a)));
  const all = aggregate(d, MSG, partials(d, s, [0, 1, 2, 3]), { surplus: true });
  assert.deepEqual(all.signers, [0, 1, 2, 3]);
  assert.ok(ok(d, MSG, blsMultiAbi(all)) && !okMin(d, MSG, blsMultiAbi(all)));
});

test("aggregateNamesBadPartial", () => {
  const { d, s } = group(sks(3), 2);
  const p = partials(d, s, [0, 1, 2]);
  p[0] = [0, p[1][1]];
  const a = aggregate(d, MSG, p);
  assert.deepEqual([a.dropped, a.signers], [[0], [1, 2]]);
  throwsCode(() => aggregate(d, MSG, p.slice(0, 2)), "BadPartial", 0);
  throwsCode(() => aggregate(d, MSG, partials(d, s, [1])), "BelowThreshold");
});

test("aggregateDuplicateIndexRefused", () => {
  const { d, s } = group(sks(3), 2);
  throwsCode(() => aggregate(d, MSG, partials(d, s, [1, 1])), "Index", 1);
  const p = partials(d, s, [0, 1]);
  p[1] = [3, p[1][1]];
  throwsCode(() => aggregate(d, MSG, p), "Index", 3);
});

test("aggregateDropsAndStillSigns", () => {
  const { d, s } = group(sks(5), 3);
  const p = partials(d, s, [0, 1, 2, 3]);
  p[1] = [1, new Uint8Array(128)];
  const a = aggregate(d, MSG, p);
  assert.deepEqual([a.dropped, a.signers], [[1], [0, 2, 3]]);
  assert.ok(okMin(d, MSG, blsMultiAbi(a)));
});

test("aggregateMinimalDropsSurplus", () => {
  const { d, s } = group(
    [3, 1, 1].map((w, i) => [90n + BigInt(i), w]),
    3,
  );
  const heavy = s.findIndex((x) => x.w === 3);
  const a = aggregate(d, MSG, partials(d, s, [0, 1, 2]));
  assert.deepEqual(a.signers, [heavy]);
  assert.ok(okMin(d, MSG, blsMultiAbi(a)));
  throwsCode(
    () =>
      aggregate(
        d,
        MSG,
        partials(
          d,
          s,
          [0, 1, 2].filter((i) => i !== heavy),
        ),
      ),
    "BelowThreshold",
  );
});

test("builderOrderAndIndexMap", () => {
  const keys = [0n, 1n, 2n, 3n].map((i) => g2Bytes(pk(300n + i)));
  const sorted = keys.map((key, i) => ({ key, weight: i + 1 })).sort((a, b) => cmp(a.key, b.key));
  const reversed = [...sorted].reverse();
  const a = buildKeyData(sorted, 5);
  const b = buildKeyData(reversed, 5);
  assert.deepEqual(a.keyData, b.keyData);
  assert.deepEqual(a.indexMap, [0, 1, 2, 3]);
  assert.deepEqual(b.indexMap, [3, 2, 1, 0]);
  reversed.forEach((m, i) => {
    const o = 260 + 258 * b.indexMap[i];
    assert.deepEqual(b.keyData.subarray(o, o + 256), m.key);
    assert.equal((b.keyData[o + 256] << 8) | b.keyData[o + 257], m.weight, "weights travel with keys");
  });
  const u = buildKeyData(
    keys.map((key) => ({ key })),
    2,
  );
  assert.ok(
    parseBlsMulti(u.keyData).members.every((m) => m.weight === 1),
    "weight defaults to 1",
  );
  assert.throws(() => buildKeyData(sorted.slice(0, 1), 1));
});

test("derive0x0121Path", () => {
  const seed = new Uint8Array(64).fill(3);
  const a = deriveUAKey(seed, { kind: K, account: 0 });
  const b = deriveUAKey(seed, { kind: K, account: 1 });
  const single = deriveUAKey(seed, { kind: 0x0106, account: 0 });
  assert.equal(a.keyData.length, 256);
  assert.equal(a.path, "m/12381/0/0/289");
  assert.notEqual(hex(a.keyData), hex(single.keyData));
  assert.equal(a.ua, null, "a member has no UA of its own");
  assert.throws(() => deriveUAKey(seed, { kind: K, account: 0, index: 1 }));
  const { keyData: d, indexMap } = buildKeyData([{ key: a.keyData }, { key: b.keyData }], 2);
  const agg = aggregate(d, MSG, [
    [indexMap[0], a.signBlsMulti(d, MSG)],
    [indexMap[1], b.signBlsMulti(d, MSG)],
  ]);
  assert.ok(okMin(d, MSG, blsMultiAbi(agg)));
  const pop = aggregatePop(d, [
    [indexMap[0], a.signBlsMultiPop(d)],
    [indexMap[1], b.signBlsMultiPop(d)],
  ]);
  assert.ok(popOk(d, pop));
  assert.throws(() => a.signUA(ua.purposeTag("metatx"), new Uint8Array(32)));
  assert.throws(() => single.signBlsMulti(d, MSG));
});

test("registrationArgs: registerBlsMulti typed key", () => {
  const { d } = group(sks(3), 2);
  const r = ua.registrationArgs({ kind: K, keyData: d, pop: new Uint8Array(128) });
  assert.equal(r.entry, "registerBlsMulti");
  assert.equal(r.args.key.threshold, 2);
  assert.equal(r.args.key.members.length, 3);
  assert.equal(r.args.key.aggKey, hex(d.subarray(0, 256)));
});

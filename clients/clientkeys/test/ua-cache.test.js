// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The ML-DSA expanded-key cache's part transactions (CTR-UA-23, NODE-JOB-29; owner 2026-11-15): `cacheExpandedKey(kind, pk, part)`
// calldata from the named fields, the part count per kind against mldsa_cache.json's rows (generated from @noble/post-quantum
// only), refusals by the registry's error names, and the cache-then-register order. UNAUDITED.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as ua from "../src/ua.js";
import { fromHex, hex } from "../src/bytes.js";
import { dir } from "./ua-vectors-dir.js";

const rows = JSON.parse(readFileSync(new URL("mldsa_cache.json", dir))).levels;
const KIND = { mldsa44: 0x0130, mldsa65: 0x0131, mldsa87: 0x0134 };
const word = (b, i) => BigInt(hex(b.subarray(4 + 32 * i, 36 + 32 * i)));

test("every row of mldsa_cache.json: one call per part, calldata cacheExpandedKey(uint16,bytes,uint256)", () => {
  for (const [name, level] of Object.entries(rows)) {
    for (const key of level.keys) {
      const calls = ua.mldsaCacheCalls(KIND[name], key.pk);
      assert.equal(calls.length, key.parts_sha256.length, name);
      assert.equal(ua.mldsaCacheParts(KIND[name]), key.parts_sha256.length, name);
      calls.forEach((c, part) => {
        assert.deepEqual(c.args, { kind: KIND[name], pk: key.pk, part: String(part) });
        const d = fromHex(c.data);
        assert.equal(hex(d.subarray(0, 4)), "0x8b738873", 'cast sig "cacheExpandedKey(uint16,bytes,uint256)"');
        const pk = fromHex(key.pk);
        assert.deepEqual(
          [word(d, 0), word(d, 1), word(d, 2), word(d, 3)],
          [BigInt(KIND[name]), 96n, BigInt(part), BigInt(pk.length)],
        );
        assert.equal(hex(d.subarray(132, 132 + pk.length)), key.pk);
        assert.equal(d.length, 132 + Math.ceil(pk.length / 32) * 32);
      });
    }
  }
});

test("refusals by the registry error names, beside each kind boundary", () => {
  const code = (f) => {
    try {
      f();
    } catch (e) {
      return e.code;
    }
    return "none";
  };
  for (const [kind, len, parts] of [
    [0x0130, 1312, 1],
    [0x0131, 1952, 2],
    [0x0134, 2592, 3],
  ]) {
    const pk = new Uint8Array(len).fill(7);
    assert.equal(
      code(() => ua.cacheExpandedKeyCall(kind, pk, parts - 1)),
      "none",
    );
    assert.equal(
      code(() => ua.cacheExpandedKeyCall(kind, pk, parts)),
      "UAKeyCache",
    );
    assert.equal(
      code(() => ua.cacheExpandedKeyCall(kind, pk, -1)),
      "UAKeyCache",
    );
    // T21 L65: a malformed part is refused, never read as part 0 (control: part 0 as a decimal string)
    assert.equal(
      code(() => ua.cacheExpandedKeyCall(kind, pk, "0")),
      "none",
    );
    for (const bad of ["", null, false, " 0 ", undefined, []])
      assert.equal(
        code(() => ua.cacheExpandedKeyCall(kind, pk, bad)),
        "UAKeyCache",
        String(bad),
      );
    for (const bad of ["", null, false])
      assert.equal(
        code(() => ua.cacheExpandedKeyCall(bad, pk, 0)),
        "UAKeyCache",
        `kind ${bad}`,
      );
    assert.equal(
      code(() => ua.cacheExpandedKeyCall(kind, pk.subarray(1), 0)),
      "UAKeyData",
    );
    assert.equal(
      code(() => ua.cacheExpandedKeyCall(kind, new Uint8Array(len + 1), 0)),
      "UAKeyData",
    );
  }
  for (const kind of [0x0132, 0x0133, 0x0135, 0x0101, 0x0120]) {
    assert.equal(ua.mldsaCacheParts(kind), 0);
    assert.equal(
      code(() => ua.cacheExpandedKeyCall(kind, new Uint8Array(1952), 0)),
      "UAKeyCache",
    );
    assert.equal(
      code(() => ua.mldsaCacheCalls(kind, new Uint8Array(1952))),
      "UAKeyCache",
    );
  }
});

test("cache then register: the parts in order, then the registration; another kind registers alone", () => {
  const key = rows.mldsa87.keys[0];
  const order = ua.cacheThenRegister({ kind: 0x0134, keyData: key.pk, pop: "0x01" });
  assert.deepEqual(
    order.map((c) => [c.entry, c.args.part]),
    [
      ["cacheExpandedKey", "0"],
      ["cacheExpandedKey", "1"],
      ["cacheExpandedKey", "2"],
      ["register", undefined],
    ],
  );
  assert.deepEqual(order[3].args, ua.registrationArgs({ kind: 0x0134, keyData: key.pk, pop: "0x01" }).args);
  const ed = ua.cacheThenRegister({ kind: 0x0102, keyData: new Uint8Array(32).fill(1), pop: "0x01" });
  assert.deepEqual(
    ed.map((c) => c.entry),
    ["register"],
  );
});

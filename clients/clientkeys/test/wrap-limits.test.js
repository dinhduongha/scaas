// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Group 3l (wrap limits spec 2026-11-10 §2.1, §7, §9): the decay rows of smartcontracts/vectors/wraplimits/wraplimits.json (its
// generator, replayed by forge on the contract) recomputed with the wallet's preview, and the wrap-limit errors decoded.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { hex, keccak_256, utf8ToBytes } from "../src/bytes.js";
import {
  wrapCredit,
  wrapDebit,
  wrapEntitlement,
  wrapLimitError,
  WRAP_LIMIT_ERRORS,
  supplyCapError,
  SUPPLY_CAP_ERRORS,
} from "../src/evm.js";

const V = JSON.parse(
  readFileSync(new URL("../../../smartcontracts/vectors/wraplimits/wraplimits.json", import.meta.url), "utf8"),
);

test("wraplimits.json: the preview equals every row after every step", () => {
  assert.equal(V.rows.length, 8);
  for (const r of V.rows) {
    const unit = 10n ** BigInt(r.unitExp);
    let t = BigInt(r.t0);
    let line = { base: 0n, startMin: 0n };
    r.steps.forEach((s, k) => {
      const x = BigInt(s.value);
      if (s.op === "warp") t += x;
      else if (s.op === "wrap") line = wrapCredit(line, x / unit, r.decayDays, t / 60n);
      else line = wrapDebit(line, (x + unit - 1n) / unit, r.decayDays, t / 60n);
      const a = r.after[k];
      assert.equal(line.base, BigInt(a.base), `${r.name} ${k}`);
      assert.equal(line.startMin, BigInt(a.startMin), `${r.name} ${k}`);
      assert.equal(wrapEntitlement(line, r.decayDays, t / 60n) * unit, BigInt(a.entitlement), `${r.name} ${k}`);
    });
  }
});

test("the wrap-limit errors decode by selector; five are liftable", () => {
  assert.equal(Object.keys(WRAP_LIMIT_ERRORS).length, 7);
  assert.equal(Object.values(WRAP_LIMIT_ERRORS).filter((e) => e.liftable).length, 5);
  const sel = Object.entries(WRAP_LIMIT_ERRORS).find(([, e]) => e.name === "UnwrapAboveNetWrapped")[0];
  const w = (x) => BigInt(x).toString(16).padStart(64, "0");
  const data = sel + w("0x5ca00000000000000000000000000000000000c3") + "ab".repeat(32) + w(501) + w(500);
  const e = wrapLimitError(data);
  assert.deepEqual([e.name, e.liftable], ["UnwrapAboveNetWrapped", true]);
  assert.deepEqual(e.args, {
    underlying: "0x5ca00000000000000000000000000000000000c3",
    account: "0x" + "ab".repeat(32),
    amount: "501",
    entitlement: "500",
  });
  assert.equal(wrapLimitError(sel + w(1)), null, "a short payload");
  assert.equal(wrapLimitError("0xdeadbeef"), null);
  assert.equal(
    wrapLimitError(Object.keys(WRAP_LIMIT_ERRORS).find((k) => WRAP_LIMIT_ERRORS[k].name === "WrapSubjectZero"))
      .liftable,
    false,
  );
});

// Round 3zc (CTR-GOV-30, spec 2026-11-13-burner-wrap-caps.md §3.6, §4): the supply-cap errors decode by selector; six are liftable (a
// wrap or mint above a cap, a setter's floor at its apply), the two shape refusals are not.
test("the supply-cap errors decode by selector; six are liftable", () => {
  assert.equal(Object.keys(SUPPLY_CAP_ERRORS).length, 8);
  assert.deepEqual(
    Object.values(SUPPLY_CAP_ERRORS)
      .filter((e) => !e.liftable)
      .map((e) => e.name),
    ["MaxSupplyInvalid", "MaxWrapSupplyInvalid"],
  );
  const sel = Object.entries(SUPPLY_CAP_ERRORS).find(([, e]) => e.name === "MaxWrapSupplyExceeded")[0];
  assert.equal(sel, hex(keccak_256(utf8ToBytes("MaxWrapSupplyExceeded(uint256,uint256)")).subarray(0, 4)));
  const w = (x) => BigInt(x).toString(16).padStart(64, "0");
  const e = supplyCapError(sel + w(1001) + w(1000));
  assert.deepEqual(
    [e.name, e.liftable, e.args],
    ["MaxWrapSupplyExceeded", true, { totalWrapped: "1001", maxWrapSupply: "1000" }],
  );
  assert.equal(supplyCapError(sel + w(1)), null, "a short payload");
  assert.equal(supplyCapError(Object.keys(WRAP_LIMIT_ERRORS)[0] + w(1) + w(2)), null, "a wrap-limit error is not one");
  const inv = Object.keys(SUPPLY_CAP_ERRORS).find((k) => SUPPLY_CAP_ERRORS[k].name === "MaxWrapSupplyInvalid");
  assert.deepEqual([supplyCapError(inv).name, supplyCapError(inv).liftable], ["MaxWrapSupplyInvalid", false]);
});

// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-mtx-merge T34 (regulated-kinds spec §3.1, §3.3, §3.6, §5, §7): smartcontracts/vectors/governance/regulated_kat.json
// (written by forge, test/as/RegulatedKat.t.sol, from a real kind-8 token and the canonical ComplianceRegistry) against
// src/regulated.js: every `recordId`, every row of the `R` truth table, every freeze transition T1-T9, every relaxation
// `commit`. Each section counted, so a row the walk skips fails here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as reg from '../src/regulated.js';

const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/governance/regulated_kat.json', import.meta.url)));

test('regulated_kat.json: the constants are this module\'s', () => {
  const c = V.constants;
  assert.deepEqual([c.uaPool, c.shieldPool], [reg.UA_POOL_ID, reg.SHIELD_POOL_ID]);
  assert.deepEqual([c.freezeSpan, c.episodeSpan, c.freezeCooldown].map(BigInt), [reg.FREEZE_SPAN, reg.EPISODE_SPAN, reg.FREEZE_COOLDOWN]);
  assert.equal(BigInt(c.eligibleContract), reg.ELIGIBLE_CONTRACT);
  assert.deepEqual(c.actions, { ...reg.ACTION });
  assert.deepEqual([c.controls.freeze, c.controls.allowlist, c.controls.denylist, c.controls.record, c.controls.kyc],
    [reg.C_FREEZE, reg.C_ALLOW, reg.C_DENY, reg.C_RECORD, reg.C_KYC]);
  assert.deepEqual([c.listFlags.allowed, c.listFlags.denied], [reg.ALLOWED, reg.DENIED]);
});

test('recordId = keccak256(abi.encode(orderId, subject, beneficiary)): every row, and none binds fewer than the three', () => {
  assert.ok(V.recordId.length >= 3);
  for (const r of V.recordId) assert.equal(reg.recordId(r.orderId, r.subject, r.beneficiary), r.recordId, r.name);
  const ids = new Set(V.recordId.map((r) => r.recordId));
  assert.equal(ids.size, V.recordId.length, 'distinct inputs, distinct ids');
});

test('the R truth table: canReceive (ok, reason) of every row under KYC (round 3s, both masks); each mask alone, ' +
  'ELIGIBLE_CONTRACT on each side, lapsed, validUntil == now, a disabled KYC provider', () => {
  let n = 0;
  const seen = new Set();
  for (const r of V.receiver) {
    const controls = r.kyc ? reg.C_KYC : 0;
    assert.deepEqual(reg.canReceive({ ...r, controls }), { ok: r.ok, reason: r.reason }, r.name);
    seen.add(`${r.kyc}/${r.requiredFlags !== '0'}/${r.deniedFlags !== '0'}`);
    n++;
  }
  assert.equal(n, V.receiver.length);
  assert.deepEqual([...seen].sort(), ['false/false/false', 'true/false/true', 'true/true/false', 'true/true/true']);
  const has = (f) => V.receiver.some(f);
  const req = (r) => r.kyc && r.requiredFlags !== '0';
  const den = (r) => r.kyc && r.deniedFlags !== '0';
  assert.ok(has((r) => req(r) && (BigInt(r.flags) & 8n) && r.ok), 'ELIGIBLE_CONTRACT satisfies requiredFlags');
  assert.ok(has((r) => den(r) && (BigInt(r.flags) & 8n) && !r.ok && r.reason === 4), 'ELIGIBLE_CONTRACT never deniedFlags');
  assert.ok(has((r) => r.validUntil === r.now && r.ok && req(r)), 'validUntil == now passes');
  assert.ok(has((r) => !r.kycProviderEnabled && r.reason === 3), 'a disabled KYC provider');
  assert.ok(has((r) => r.reason === 2), 'lapsed');
});

test('the lists (round 3s): listed(controls, listFlags) of every row, reasons 5 and 6, the allow list first', () => {
  const reasons = new Set();
  for (const r of V.lists) {
    assert.deepEqual(reg.listed(r.controls, r.listFlags), { ok: r.ok, reason: r.reason }, r.name);
    reasons.add(r.reason);
  }
  assert.equal(V.lists.length, 16);
  assert.deepEqual([...reasons].sort(), [0, 5, 6]);
});

test('enableable (spec 5.5): every row, one term failing at a time', () => {
  for (const r of V.enableable) {
    assert.equal(reg.enableable(r), BigInt(r.enableable), r.name);
  }
  assert.ok(V.enableable.length >= 9);
});

test('the freeze transitions T1-T9: every row reproduced, its state after or its error, and F after', () => {
  const rules = new Set();
  for (const r of V.freeze) {
    rules.add(r.rule);
    const ctx = { now: r.now, controls: r.controls, token: r.token, record: r.record };
    let state = r.before;
    if (r.call) {
      const got = reg.freezeStep(r.before, r.call, ctx);
      if (r.error) {
        assert.deepEqual(got, { error: { sig: r.error.sig, args: r.error.args } }, r.name);
        continue;
      }
      assert.deepEqual(got, { after: r.after }, r.name);
      state = got.after;
    } else {
      assert.deepEqual(r.after, r.before, `${r.name}: no call writes nothing`);
      assert.equal(reg.frozen(r.before, r.controlsBefore, r.nowBefore), r.frozenBefore, `${r.name}: before`);
    }
    assert.equal(reg.frozen(state, r.controls, r.now), r.frozen, r.name);
  }
  assert.deepEqual([...rules].sort(), ['T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'T8', 'T9']);
});

test('the relaxation commit of each action: keccak256(abi.encode(action, bit, account, argsHash)), SET over the terms', () => {
  const actions = new Set();
  for (const r of V.commit) {
    actions.add(r.action);
    assert.equal(reg.relaxCommit(r.action, r.bit, r.account, r.terms), r.commit, r.name);
  }
  assert.deepEqual([...actions].sort(), [1, 2, 3, 4, 5]);
  // the action is bound: the same key under another action is another commit
  const r = V.commit.find((x) => x.action === reg.ACTION.REVOKE);
  assert.notEqual(reg.relaxCommit(reg.ACTION.RENOUNCE, r.bit, r.account), r.commit);
  assert.throws(() => reg.relaxCommit(reg.ACTION.SET, 5, r.account), /SET/);
});

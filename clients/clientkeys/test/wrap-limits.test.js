// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Group 3l (wrap limits spec 2026-11-10 §2.1, §7, §9): the decay rows of smartcontracts/vectors/wraplimits/wraplimits.json (its
// generator, replayed by forge on the contract) recomputed with the wallet's preview, and the wrap-limit errors decoded.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { wrapCredit, wrapDebit, wrapEntitlement, wrapLimitError, WRAP_LIMIT_ERRORS } from '../src/evm.js';

const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/wraplimits/wraplimits.json', import.meta.url), 'utf8'));

test('wraplimits.json: the preview equals every row after every step', () => {
  assert.equal(V.rows.length, 8);
  for (const r of V.rows) {
    const unit = 10n ** BigInt(r.unitExp);
    let t = BigInt(r.t0);
    let line = { base: 0n, startMin: 0n };
    r.steps.forEach((s, k) => {
      const x = BigInt(s.value);
      if (s.op === 'warp') t += x;
      else if (s.op === 'wrap') line = wrapCredit(line, x / unit, r.decayDays, t / 60n);
      else line = wrapDebit(line, (x + unit - 1n) / unit, r.decayDays, t / 60n);
      const a = r.after[k];
      assert.equal(line.base, BigInt(a.base), `${r.name} ${k}`);
      assert.equal(line.startMin, BigInt(a.startMin), `${r.name} ${k}`);
      assert.equal(wrapEntitlement(line, r.decayDays, t / 60n) * unit, BigInt(a.entitlement), `${r.name} ${k}`);
    });
  }
});

test('the wrap-limit errors decode by selector; five are liftable', () => {
  assert.equal(Object.keys(WRAP_LIMIT_ERRORS).length, 7);
  assert.equal(Object.values(WRAP_LIMIT_ERRORS).filter((e) => e.liftable).length, 5);
  const sel = Object.entries(WRAP_LIMIT_ERRORS).find(([, e]) => e.name === 'UnwrapAboveNetWrapped')[0];
  const w = (x) => BigInt(x).toString(16).padStart(64, '0');
  const data = sel + w('0x5ca00000000000000000000000000000000000c3') + 'ab'.repeat(32) + w(501) + w(500);
  const e = wrapLimitError(data);
  assert.deepEqual([e.name, e.liftable], ['UnwrapAboveNetWrapped', true]);
  assert.deepEqual(e.args, { underlying: '0x5ca00000000000000000000000000000000000c3', account: '0x' + 'ab'.repeat(32), amount: '501',
    entitlement: '500' });
  assert.equal(wrapLimitError(sel + w(1)), null, 'a short payload');
  assert.equal(wrapLimitError('0xdeadbeef'), null);
  assert.equal(wrapLimitError(Object.keys(WRAP_LIMIT_ERRORS).find((k) => WRAP_LIMIT_ERRORS[k].name === 'WrapSubjectZero')).liftable, false);
});

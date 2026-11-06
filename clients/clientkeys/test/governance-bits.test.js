// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// governance T14: smartcontracts/vectors/governance/governance_bits.json (written by forge, GovBitsVector.t.sol) against
// evm.GOVERNANCE_BITS, every row both ways; each row carries its sentences.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as evm from '../src/evm.js';

const FILE = new URL('../../../smartcontracts/vectors/governance/governance_bits.json', import.meta.url);

test('governance_bits.json: every row equals GOVERNANCE_BITS, none missing, each with its sentences', () => {
  const v = JSON.parse(readFileSync(FILE, 'utf8'));
  assert.equal(v.bits.length, evm.GOVERNANCE_BITS.length);
  for (const [i, row] of v.bits.entries()) {
    assert.deepEqual({ bit: row.bit, name: row.name, type: row.type }, { ...evm.GOVERNANCE_BITS[i] }, `bit ${i}`);
    assert.ok(Object.values(row.sentences).length > 0 && Object.values(row.sentences).every((s) => s.length > 0), `bit ${i}`);
  }
  assert.deepEqual(Object.keys(v.bits[1].sentences), ['plain', 'hybrid', 'hybridBrackets'], 'bit 1: plain and hybrid');
  assert.deepEqual(Object.keys(v.bits[5].sentences), ['public', 'confidential'], 'bit 5: one per class of kind');
  for (const k of ['delegable', 'leg', 'grantDelay']) assert.ok(v.sentences[k], k);
});

// ua-mtx-merge T34 (regulated-kinds spec §7; CTR-GOV-17, CTR-GOV-20): the regulated rows name their kinds (bit 8 not on the
// confidential 10-13) and their holder rule (contract-only with an `msig` UA counting, RK-1; bit 22 any holder); the
// confidential decoy-fee sentence; bit 22 `OPERATOR_TRANSFER`; bit 23 `TAX` (any holder, T39) is the last row.
test('governance_bits.json: the regulated rows carry their kinds and holder rule; bit 22; the decoy-fee sentence', () => {
  const v = JSON.parse(readFileSync(FILE, 'utf8'));
  const all = [8, 9, 10, 11, 12, 13];
  const want = { 5: [all, 'contractOrMsig'], 6: [all, 'contractOrMsig'], 7: [all, 'contractOrMsig'], 8: [[8, 9], undefined],
    9: [all, undefined], 10: [all, 'contractOrMsig'], 21: [all, 'contractOrMsig'], 22: [all, 'any'], 23: [all, 'any'] };
  for (const row of v.bits) {
    const w = want[row.bit];
    assert.deepEqual([row.kinds, row.holder], w ?? [undefined, undefined], `bit ${row.bit}`);
  }
  assert.equal(v.bits.at(-1).bit, 23, 'bit 23 TAX (pay-meta-tax spec §6.1) is the last row');
  assert.equal(v.bits[22].name, 'OPERATOR_TRANSFER');
  assert.equal(v.bits[23].name, 'TAX');
  for (const k of ['msig', 'decoyFee', 'decoyFeeWhen']) assert.ok(v.sentences[k], k);
});

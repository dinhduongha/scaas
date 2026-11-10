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
// confidential decoy-fee sentence; bit 22 `OPERATOR_TRANSFER`; bit 23 `TAX` (any holder, T39); bit 24 `PQZ_PROOF` (3h T61) last.
test('governance_bits.json: the regulated rows carry their kinds and holder rule; bit 22; the decoy-fee sentence', () => {
  const v = JSON.parse(readFileSync(FILE, 'utf8'));
  const all = [8, 9, 10, 11, 12, 13];
  const want = { 5: [all, 'contractOrMsig'], 6: [all, 'contractOrMsig'], 7: [all, 'contractOrMsig'], 8: [[8, 9], undefined],
    9: [all, undefined], 10: [all, 'contractOrMsig'], 21: [all, 'contractOrMsig'], 22: [all, 'any'], 23: [all, 'any'],
    24: [[4, 5, 12, 13], 'any'], 25: [[1, 3, 5, 9, 11, 13], undefined], 26: [[1, 3, 5, 9, 11, 13], 'any'],
    27: [[1, 3, 5, 9, 11, 13], 'any'] };
  for (const row of v.bits) {
    const w = want[row.bit];
    assert.deepEqual([row.kinds, row.holder], w ?? [undefined, undefined], `bit ${row.bit}`);
  }
  // group 3h T61: bit 24 `PQZ_PROOF` (PQZ proof path spec §5: the PQZ kinds 4, 5, 12, 13, any holder); group 3l: bits 25-27
  // (the hybrids of the wrapped kinds; 25 a capability, 26 and 27 any holder), 27 the last row
  assert.equal(v.bits.at(-1).bit, 27, 'bit 27 REDEEMER is the last row');
  assert.deepEqual(v.bits.slice(25).map((r) => r.name), ['WRAP_LIMIT', 'WRAP_LIST', 'REDEEMER']);
  assert.equal(v.bits[24].name, 'PQZ_PROOF');
  assert.equal(v.bits[22].name, 'OPERATOR_TRANSFER');
  assert.equal(v.bits[23].name, 'TAX');
  for (const k of ['msig', 'decoyFee', 'decoyFeeWhen']) assert.ok(v.sentences[k], k);
});

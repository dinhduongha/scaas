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

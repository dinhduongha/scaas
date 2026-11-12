// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Round 3t (CTR-PQZ-36, verifier fee spec §12): `pqzFeeWord` against every row of smartcontracts/vectors/pqz/verifier_fee.json
// (written from real token ops by test/pqz/PqzVerifierFeeVectors.t.sol), the payouts' arithmetic, the direct binding words,
// the `pqzVerifyConfig` decode, and `UASetVerifierFee` against GovernanceRouterBase.sol. UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as evm from '../src/evm.js';
import { hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';

const ROOT = new URL('../../../', import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');
const VF = JSON.parse(read('smartcontracts/vectors/pqz/verifier_fee.json'));
const BEN = '0x' + '11'.repeat(32);
const word = (x) => BigInt(x).toString(16).padStart(64, '0');

test('pqzFeeWord = header word 256 of every row; the payouts txFee·s, vf·s, d·s; dPool = dTotalShielded·s', () => {
  assert.equal(VF.rows.length, VF.rowCount);
  assert.equal(VF.rowCount, 108);
  for (const r of VF.rows) {
    const w = evm.pqzFeeWord({ confidentialFee: r.confidentialFee, beneficiaryUA: r.beneficiary ? BEN : undefined,
      verifierFee: r.verifierFee, legs: r.legs, decoyFee: r.decoyFee });
    assert.equal(w, BigInt(r.feeWord), `${r.form} ben ${r.beneficiary} vf ${r.verifierFee}`);
    const s = BigInt(r.shieldScale);
    assert.equal(BigInt(r.payVerifier), BigInt(r.verifierFee) * s, 'the verifier');
    assert.equal(BigInt(r.payBeneficiary), (r.beneficiary ? BigInt(r.confidentialFee) : 0n) * s, 'the beneficiary: txFee only');
    assert.equal(BigInt(r.payPerLeg), BigInt(r.decoyFee) * s, 'each leg');
    assert.equal(BigInt(r.dTotalShielded), w + BigInt(r.amount), 'totalShielded falls by fee + amount');
    assert.equal(BigInt(r.dPool), BigInt(r.dTotalShielded) * s, 'the pool');
  }
  // a beneficiary-less debit pays vf (+ M·d) only; the word is refused at 2^64
  assert.equal(evm.pqzFeeWord({ confidentialFee: 3, verifierFee: 2, legs: 2, decoyFee: 1 }), 4n);
  assert.throws(() => evm.pqzFeeWord({ confidentialFee: 2n ** 63n, beneficiaryUA: BEN, verifierFee: 2n ** 63n }), /2\^64/);
});

test('the direct binding word 544: TAG_DIRECT_MODE_VF folds vf on OFFCHAIN, PRECOMPILE keeps TAG_DIRECT_MODE', () => {
  assert.equal(VF.tagDirectModeVf, hex(keccak_256(utf8ToBytes('SCAAS-PQZ-DIRECT-MODE-VF-V1'))));
  assert.equal(VF.tagDirectMode, hex(keccak_256(utf8ToBytes('SCAAS-PQZ-DIRECT-MODE-V1'))));
  assert.equal(VF.binding.length, 8);
  for (const b of VF.binding) {
    const off = b.pqzVerifyMode === 'OFFCHAIN';
    const enc = (off ? VF.tagDirectModeVf.slice(2) : VF.tagDirectMode.slice(2)) + word(b.modeByte) + (off ? word(b.verifierFee) : '');
    const want = hex(keccak_256(fromHex('0x' + enc)));
    assert.equal(b.op1Word544, want, `op 1 ${b.pqzVerifyMode} ${b.mode} ${b.verifierFee}`);
    assert.equal(b.op7Word544, want, `op 7 ${b.pqzVerifyMode} ${b.mode} ${b.verifierFee}`);
  }
});

test('decodePqzVerifyConfig: the eleven words, the four fee fields appended', () => {
  const words = [1, 0xabc, 1, 2, 0, 0, 86400, 3, 10, 7, 1800000000].map(word).join('');
  const c = evm.decodePqzVerifyConfig('0x' + words);
  assert.deepEqual([c.pqzVerifyMode, c.fixed, c.pqzVerifierEpoch], [1, true, 2]);
  assert.deepEqual([c.verifierFee, c.verifierFeeMax, c.verifierFeePending, c.verifierFeeEta], [3n, 10n, 7n, 1800000000n]);
  assert.throws(() => evm.decodePqzVerifyConfig('0x' + words.slice(0, 64 * 7)), /11 words/);
});

test('UASetVerifierFee: the router type string, typehash and entry as GovernanceRouterBase.sol / GovernanceRouter.sol', () => {
  const op = evm.TYPED_OPS.UASetVerifierFee;
  const src = read('smartcontracts/evm/src/governance/GovernanceRouterBase.sol');
  assert.ok(src.includes(`"${op.typeString}"`), 'the type string');
  // CTR-GOV-28: + `bytes32 chainUid` (was 0xffa3baec15773742773872cec5ac6e8000b668a4576324f215b5e663818dd14d)
  assert.equal(op.typehash, '0x5f8c20d2f3af20d59df1aa1fe75e52fc9b95a15483b98b268246963ff7b4076e');
  assert.equal(op.entry, 'mtxSetVerifierFee');
  assert.ok(read('smartcontracts/evm/src/governance/GovernanceRouter.sol').includes('function mtxSetVerifierFee('));
});

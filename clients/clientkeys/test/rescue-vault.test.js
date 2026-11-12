// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// CTR-GOV-25 Change (RescueVault): the rotation digest equals the contract's for the KAT row written by forge
// (smartcontracts/evm/test/governance/RescueVault.t.sol, WRITE_RESCUE_VAULT=true).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import * as evm from '../src/evm.js';
import { hex } from '../src/bytes.js';

const KAT = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/governance/rescue_vault_kat.json', import.meta.url), 'utf8'));

test('rescue_vault_kat.json: rotation typehash and digest', () => {
  const td = evm.rescueVaultRotateTypedData({ vault: KAT.vault, seq: KAT.seq, newOwner: KAT.newOwner });
  assert.equal(hex(keccak_256(utf8ToBytes(evm.encodeType(td.types, 'Rotate')))), KAT.rotateTypehash);
  assert.equal(hex(evm.hashTypedData(td)), KAT.digest);
  const other = evm.rescueVaultRotateTypedData({ vault: KAT.vault, seq: KAT.seq + 1, newOwner: KAT.newOwner }); // negative
  assert.notEqual(hex(evm.hashTypedData(other)), KAT.digest);
});

test('rescueVaultRotateTypedData refuses seq 0, seq above uint64 and the zero owner', () => {
  const ok = { vault: KAT.vault, seq: 1, newOwner: KAT.newOwner };
  assert.throws(() => evm.rescueVaultRotateTypedData({ ...ok, seq: 0 }), /seq/);
  assert.throws(() => evm.rescueVaultRotateTypedData({ ...ok, seq: 1n << 64n }), /seq/);
  assert.throws(() => evm.rescueVaultRotateTypedData({ ...ok, newOwner: '0x' + '00'.repeat(20) }), /newOwner/);
  evm.rescueVaultRotateTypedData(ok);
});

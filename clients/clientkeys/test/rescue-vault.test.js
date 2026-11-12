// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// CTR-GOV-25 Change (RescueVault): both admin digests equal the contract's for the KAT rows written by forge
// (smartcontracts/evm/test/governance/RescueVault.t.sol, WRITE_RESCUE_VAULT=true).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import * as evm from '../src/evm.js';
import { hex } from '../src/bytes.js';

const KAT = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/governance/rescue_vault_kat.json', import.meta.url), 'utf8'));
const typehash = (td) => hex(keccak_256(utf8ToBytes(evm.encodeType(td.types, td.primaryType))));

test('rescue_vault_kat.json: setRescuer typehash and digest', () => {
  const r = KAT.setRescuer;
  const td = evm.rescueVaultSetRescuerTypedData({ vault: KAT.vault, seq: r.seq, newRescuer: r.newRescuer });
  assert.equal(typehash(td), KAT.setRescuerTypehash);
  assert.equal(hex(evm.hashTypedData(td)), r.digest);
  const other = evm.rescueVaultSetRescuerTypedData({ vault: KAT.vault, seq: r.seq + 1, newRescuer: r.newRescuer }); // negative
  assert.notEqual(hex(evm.hashTypedData(other)), r.digest);
});

test('rescue_vault_kat.json: rotateAdmin typehash and digest', () => {
  const a = KAT.rotateAdmin;
  const td = evm.rescueVaultRotateAdminTypedData({ vault: KAT.vault, seq: a.seq, newAdmin: a.newAdmin });
  assert.equal(typehash(td), KAT.rotateAdminTypehash);
  assert.equal(hex(evm.hashTypedData(td)), a.digest);
  const other = evm.rescueVaultRotateAdminTypedData({ vault: KAT.vault, seq: a.seq - 1, newAdmin: a.newAdmin }); // negative
  assert.notEqual(hex(evm.hashTypedData(other)), a.digest);
});

test('rescue vault builders refuse seq 0, seq above uint64, a zero rescuer and a non-native admin', () => {
  const r = { vault: KAT.vault, seq: 1, newRescuer: KAT.setRescuer.newRescuer };
  assert.throws(() => evm.rescueVaultSetRescuerTypedData({ ...r, seq: 0 }), /seq/);
  assert.throws(() => evm.rescueVaultSetRescuerTypedData({ ...r, seq: 1n << 64n }), /seq/);
  assert.throws(() => evm.rescueVaultSetRescuerTypedData({ ...r, newRescuer: '0x' + '00'.repeat(20) }), /newRescuer/);
  evm.rescueVaultSetRescuerTypedData(r);
  const a = { vault: KAT.vault, seq: 1, newAdmin: KAT.rotateAdmin.newAdmin };
  assert.throws(() => evm.rescueVaultRotateAdminTypedData({ ...a, newAdmin: '0x' + '00'.repeat(32) }), /native/);
  assert.throws(() => evm.rescueVaultRotateAdminTypedData({ ...a, newAdmin: '0x01' + KAT.rotateAdmin.newAdmin.slice(4) }), /native/);
  assert.throws(() => evm.rescueVaultRotateAdminTypedData({ ...a, newAdmin: KAT.setRescuer.newRescuer }), /bytes32/);
  evm.rescueVaultRotateAdminTypedData(a);
});

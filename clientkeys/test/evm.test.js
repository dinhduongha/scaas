import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  hashTypedData, secpSubjectKey, accountSalt, predictAccount, accountSignature, merkleBatch, processProof,
  batchLeaf, evmAddress,
} from '../src/evm.js';
import { abiEncode, hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';

const vectors = new URL('../../smartcontracts/test/vectors/', import.meta.url);
const read = (f) => JSON.parse(readFileSync(new URL(f, vectors)));

test('EIP-712 digest of the typed data Odoo issues = MetaTx KAT (MetaTxKat.t.sol)', () => {
  const k = read('metatx_kat.json');
  const td = {
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
      MetaTransaction: ['from:address', 'to:address', 'value:uint256', 'data:bytes', 'batch:uint256', 'nonce:uint256',
        'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256', 'feeRecipient:address']
        .map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] })),
    },
    primaryType: 'MetaTransaction',
    domain: { name: k.domain_name, version: k.domain_version, chainId: Number(k.chain_id), verifyingContract: k.verifying_contract },
    // mode 1: relayer bound, feeRecipient canonical-zeroed (as dms_blockchain/lib/eip712.typed_data does).
    message: { from: k.from, to: k.to, value: k.value, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until,
      mode: Number(k.mode), relayer: k.relayer, fee: k.fee, feeRecipient: '0x' + '00'.repeat(20) },
  };
  assert.equal(hex(hashTypedData(td)), k.digest);
});

test('OwnerCall typed data (as Odoo issues it) hashes to the digest pinned in SubjectAccount.t.sol', () => {
  const td = {
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
      OwnerCall: [{ name: 'data', type: 'bytes' }, { name: 'nonce', type: 'uint256' }, { name: 'validUntil', type: 'uint256' }],
    },
    primaryType: 'OwnerCall',
    domain: { name: 'Bamboo SubjectAccount', version: '1', chainId: 31337, verifyingContract: '0x' + '00'.repeat(18) + 'acc0' },
    message: { data: '0x1234', nonce: '3', validUntil: '1800000000' },
  };
  assert.equal(hex(hashTypedData(td)), '0x24bb1dae4c38217e81cff2a57e2c7b461830c462e83cf6184e0d4714cf625610');
});

test('passkey keyId = keccak(abi.encode(SubjectKey)) as cast computes it', async () => {
  const { passkeySubjectKey, keyId } = await import('../src/evm.js');
  const key = passkeySubjectKey({
    x: fromHex('6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296'),
    y: fromHex('4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5'),
    rpId: 'pay.example.com', origin: 'https://pay.example.com' });
  assert.equal(hex(keyId(key)), '0xe01e0b8f122754973202cd330eb728c9d9b19f4f31bbe7e33d012e745be6f631');
});

test('SubjectAccount CREATE2: salt and clone address match the forge-pinned vector', () => {
  const v = read('subject_account_create2.json');
  const addr = evmAddress(secp256k1.getPublicKey(fromHex(v.seedPrivateKey.slice(2).padStart(64, '0')), false));
  const salt = accountSalt(secpSubjectKey(addr), v.guardian);
  assert.equal(hex(salt), v.salt);
  assert.equal(predictAccount(v.implementation, salt, v.factory), v.account);
});

test('ABI encodings match `cast abi-encode` (foundry 1.3.5)', () => {
  // cast abi-encode "f(uint256,bytes32[],bytes)" 3 "[0x11..11,0x22..22]" 0xdeadbeef
  assert.equal(hex(accountSignature(3, ['0x' + '11'.repeat(32), '0x' + '22'.repeat(32)], fromHex('deadbeef'))),
    '0x' + '0'.repeat(63) + '3' + '0'.repeat(62) + '60' + '0'.repeat(62) + 'c0' + '0'.repeat(63) + '2'
    + '11'.repeat(32) + '22'.repeat(32) + '0'.repeat(63) + '4' + 'deadbeef' + '0'.repeat(56));
  // cast abi-encode "f(bytes,bytes,bytes32,bytes32)" 0x0102 0x7b7d 0x..01 0x..02
  assert.equal(hex(abiEncode(['bytes', 'bytes', 'bytes32', 'bytes32'],
    [fromHex('0102'), fromHex('7b7d'), '0x' + '00'.repeat(31) + '01', '0x' + '00'.repeat(31) + '02'])),
    '0x' + '0'.repeat(62) + '80' + '0'.repeat(62) + 'c0' + '0'.repeat(63) + '1' + '0'.repeat(63) + '2'
    + '0'.repeat(63) + '2' + '0102' + '0'.repeat(60) + '0'.repeat(63) + '2' + '7b7d' + '0'.repeat(60));
});

test('Merkle batch: every digest proves to the root; foreign digest does not', () => {
  for (let n = 2; n <= 9; n++) {
    const d = Array.from({ length: n }, (_, i) => keccak_256(utf8ToBytes(`op${i}`)));
    const { root, proofs } = merkleBatch(d);
    d.forEach((x, i) => assert.equal(hex(processProof(proofs[i], batchLeaf(x))), hex(root), `n=${n} i=${i}`));
    assert.notEqual(hex(processProof(proofs[0], batchLeaf(keccak_256(utf8ToBytes('x'))))), hex(root));
  }
  assert.throws(() => merkleBatch([new Uint8Array(32)]), /at least two/);
});

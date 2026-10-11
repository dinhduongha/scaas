import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  hashTypedData, secpSubjectKey, accountSalt, predictAccount, accountSignature, merkleBatch, processProof,
  batchLeaf, evmAddress, passkeySubjectKey, addKeyCalldata, ownerCallTypedData, checkOwnerCall, checkPayment,
  keyProofMessage, metaTxTypedData,
} from '../src/evm.js';
import { abiEncode, hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';

const vectors = new URL('../../../smartcontracts/evm/test/vectors/', import.meta.url);
const read = (f) => JSON.parse(readFileSync(new URL(f, vectors)));

test('EIP-712 digest of the typed data Odoo issues = MetaTx KAT (MetaTxKat.t.sol)', () => {
  const k = read('metatx_v1_kat.json');
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

test('SmartKeyAccount owner call = forge KAT (AccountKat.t.sol, smart_key_account_kat.json)', () => {
  const k = read('smart_key_account_kat.json');
  assert.equal(hex(addKeyCalldata(secpSubjectKey('0x' + '77'.repeat(20)))), k.data);
  const td = ownerCallTypedData({ account: k.verifying_contract, chainId: Number(k.chain_id), chainUid: k.salt,
    data: k.data, nonce: k.nonce, validUntil: k.valid_until });
  assert.equal(hex(hashTypedData(td)), k.digest);
  assert.equal(hex(checkOwnerCall(td, { account: k.verifying_contract, chainId: 7622, chainUid: k.salt,
    newKey: secpSubjectKey('0x' + '77'.repeat(20)), now: 1_800_000_000 })), k.digest);
  // the account encoding of the seed key's ECDSA signature (key index 0, no batch proof)
  const sig = fromHex(k.signature).subarray(160, 225);
  assert.equal(hex(accountSignature(0, [], sig)), k.signature);
  const r = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact').addRecoveryBit(sig[64] - 27);
  assert.equal(evmAddress(r.recoverPublicKey(fromHex(k.digest)).toBytes(false)), k.signer_key);
});

test('MandateWallet pay and revoke = forge KATs (mandate_pay_kat.json, mandate_revoke_kat.json)', () => {
  for (const f of ['mandate_pay_kat.json', 'mandate_revoke_kat.json']) {
    const k = read(f);
    const td = metaTxTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: Number(k.chain_id),
      chainUid: k.salt, message: { from: k.from, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until } });
    assert.equal(hex(hashTypedData(td)), k.digest, f);
  }
  // the derived lanes: keccak256("scaas.mandate.pay" ‖ entryRef), keccak256("scaas.mandate.revoke" ‖ token ‖ uint64 epoch)
  const pay = read('mandate_pay_kat.json');
  const ref = fromHex(pay.data).subarray(100, 132);
  assert.equal(BigInt(hex(keccak_256(new Uint8Array([...utf8ToBytes('scaas.mandate.pay'), ...ref])))), BigInt(pay.batch));
  const rev = read('mandate_revoke_kat.json');
  const token = fromHex(rev.data).subarray(16, 36);
  const epoch = new Uint8Array(8); epoch[7] = 1;
  assert.equal(BigInt(hex(keccak_256(new Uint8Array([...utf8ToBytes('scaas.mandate.revoke'), ...token, ...epoch])))),
    BigInt(rev.batch));
});

test('passkey keyId = keccak(abi.encode(SubjectKey)) as cast computes it', async () => {
  const { passkeySubjectKey, keyId } = await import('../src/evm.js');
  const key = passkeySubjectKey({
    x: fromHex('6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296'),
    y: fromHex('4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5'),
    rpId: 'pay.example.com', origin: 'https://pay.example.com' });
  assert.equal(hex(keyId(key)), '0xe01e0b8f122754973202cd330eb728c9d9b19f4f31bbe7e33d012e745be6f631');
});

test('SmartKeyAccount CREATE2: salt and clone address match the forge-pinned vector', () => {
  const v = read('smart_key_account_create2.json');
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

// ------------------------------------------------------------------ review S4-M2: no blind signing

const ACCOUNT = '0x' + 'ac'.repeat(20);
const NOW = 1_800_000_000;
const NEW_KEY = secpSubjectKey('0x' + '77'.repeat(20));

const UID = '0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464';   // chain 7622 (chain-uids.json)

/** The account's owner call as a server issues it: a `MetaTransaction` in the salted `SCaaS SmartKeyAccount` domain. */
function serverOwnerCall(data, { account = ACCOUNT, chainId = 7622, salt = UID, nonce = '2', validUntil = String(NOW + 600),
  ...over } = {}) {
  const td = metaTxTypedData({ name: 'SCaaS SmartKeyAccount', contract: account, chainId, chainUid: salt,
    message: { from: account, data, nonce, validUntil, ...over } });
  td.message.nonce = nonce;
  return td;
}

test('owner call: the client signs only addKey(the key it just made) as its own account, on its chain', () => {
  const want = { account: ACCOUNT, chainId: 7622, chainUid: UID, newKey: NEW_KEY, now: NOW };
  const td = serverOwnerCall(addKeyCalldata(NEW_KEY));
  assert.equal(hex(checkOwnerCall(td, want)), hex(hashTypedData(td)));
  assert.equal(hex(hashTypedData(ownerCallTypedData({ account: ACCOUNT, chainId: 7622, chainUid: UID,
    data: addKeyCalldata(NEW_KEY), nonce: '2', validUntil: String(NOW + 600) }))), hex(hashTypedData(td)));
  // addKey(abi.encode(key)): selector of addKey((uint8,bytes32,bytes32,bytes32,bytes32)) + 5 words.
  assert.equal(hex(addKeyCalldata(NEW_KEY).subarray(0, 4)),
    hex(keccak_256(utf8ToBytes('addKey((uint8,bytes32,bytes32,bytes32,bytes32))')).subarray(0, 4)));
  const drain = concatSel('execute(address,uint256,bytes)');
  const unsalted = serverOwnerCall(addKeyCalldata(NEW_KEY));
  unsalted.types = { ...unsalted.types, EIP712Domain: unsalted.types.EIP712Domain.slice(0, 4) };
  delete unsalted.domain.salt;
  const oldShape = serverOwnerCall(addKeyCalldata(NEW_KEY));
  oldShape.domain.name = 'SCaaS SubjectAccount';
  const refused = [
    serverOwnerCall(drain),                                                      // any other call
    serverOwnerCall(addKeyCalldata(secpSubjectKey('0x' + '66'.repeat(20)))),     // someone else's key
    serverOwnerCall(addKeyCalldata(NEW_KEY), { account: '0x' + 'bd'.repeat(20) }),
    serverOwnerCall(addKeyCalldata(NEW_KEY), { from: '0x' + 'bd'.repeat(20) }),  // signed as another party
    serverOwnerCall(addKeyCalldata(NEW_KEY), { chainId: 1 }),
    serverOwnerCall(addKeyCalldata(NEW_KEY), { salt: '0x' + '11'.repeat(32) }),  // another chain_uid
    unsalted,                                                                    // no salt (CLI-SGN-33)
    oldShape,                                                                    // the built domain name
    serverOwnerCall(addKeyCalldata(NEW_KEY), { batch: '1' }),
    serverOwnerCall(addKeyCalldata(NEW_KEY), { mode: 1, relayer: '0x' + '02'.repeat(20) }),
    serverOwnerCall(addKeyCalldata(NEW_KEY), { fee: '1' }),
    serverOwnerCall(addKeyCalldata(NEW_KEY), { validUntil: String(NOW - 1) }),
    serverOwnerCall(addKeyCalldata(NEW_KEY), { validUntil: String(NOW + 7200) }),
    serverOwnerCall(addKeyCalldata(NEW_KEY), { nonce: '-1' }),
    { ...serverOwnerCall(addKeyCalldata(NEW_KEY)), primaryType: 'OwnerCall' },
  ];
  const extra = serverOwnerCall(addKeyCalldata(NEW_KEY));
  extra.types = { ...extra.types, MetaTransaction: [...extra.types.MetaTransaction, { name: 'value', type: 'uint256' }] };
  extra.message.value = '1';
  refused.push(extra);
  for (const [i, bad] of refused.entries()) assert.throws(() => checkOwnerCall(bad, want), /Refusing to sign/, `case ${i}`);
  assert.throws(() => checkOwnerCall(td, { ...want, chainUid: '0x' + '11'.repeat(32) }), /Refusing to sign/);
  // A passkey key is rebuilt from the server's rpId/origin and the coordinates the device returned.
  const pk = passkeySubjectKey({ x: new Uint8Array(32).fill(1), y: new Uint8Array(32).fill(2), rpId: 'pay.example.com',
    origin: 'https://pay.example.com' });
  checkOwnerCall(serverOwnerCall(addKeyCalldata(pk)), { ...want, newKey: pk });
});

function concatSel(sig) {
  return new Uint8Array([...keccak_256(utf8ToBytes(sig)).subarray(0, 4), ...new Uint8Array(96)]);
}

/** MetaTransaction exactly as Odoo `eip712.typed_data` issues it for a pay. */
function odooPayment(over = {}, dom = {}) {
  const k = read('metatx_v1_kat.json');
  return {
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
      MetaTransaction: ['from:address', 'to:address', 'value:uint256', 'data:bytes', 'batch:uint256', 'nonce:uint256',
        'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256', 'feeRecipient:address']
        .map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] })),
    },
    primaryType: 'MetaTransaction',
    domain: { name: 'SCaaS MetaToken', version: '1', chainId: 31337, verifyingContract: k.verifying_contract, ...dom },
    message: { from: ACCOUNT, to: '0x' + '5e'.repeat(20), value: '125000500000', data: hex(concatPay()), batch: '7',
      nonce: '0', validUntil: String(NOW + 300), mode: 1, relayer: '0x' + '02'.repeat(20), fee: '0',
      feeRecipient: '0x' + '00'.repeat(20), ...over },
  };
}

function concatPay() {
  return new Uint8Array([...keccak_256(utf8ToBytes('pay(bytes32)')).subarray(0, 4), ...new Uint8Array(32).fill(9)]);
}

test('payment: the client signs only a pay of the amount it showed, from its own account, on its chain', () => {
  const intent = { account: ACCOUNT, chainId: 31337, amount: 125000.5, decimals: 6, now: NOW };
  const td = odooPayment();
  const ok = checkPayment(td, intent);
  assert.equal(hex(ok.digest), hex(hashTypedData(td)));
  assert.equal(ok.payee, '0x' + '5e'.repeat(20));
  checkPayment(odooPayment({ value: '125000000000' }), { ...intent, amount: 125000 });
  checkPayment(odooPayment({ mode: 0, relayer: '0x' + '00'.repeat(20) }), intent);
  const refused = [
    serverOwnerCall(addKeyCalldata(NEW_KEY)),                     // an owner call disguised as a payment
    odooPayment({ value: '125000500001' }),                       // more than shown
    odooPayment({ from: '0x' + 'bd'.repeat(20) }),
    odooPayment({ data: hex(concatSel('trade(address,uint256,address)')) }),
    odooPayment({ data: '0x' }),
    odooPayment({ fee: '1' }),
    odooPayment({ validUntil: String(NOW - 1) }),
    odooPayment({ validUntil: String(NOW + 8 * 86400) }),
    odooPayment({}, { chainId: 1 }),
    odooPayment({}, { verifyingContract: ACCOUNT }),
  ];
  for (const [i, bad] of refused.entries()) assert.throws(() => checkPayment(bad, intent), /Refusing to sign/, `case ${i}`);
  assert.throws(() => checkPayment(td, { ...intent, amount: 1e21 }), /Refusing to sign/);
});

const KEY_PROOF_ZERO = '0xfa7987471ecf88572865d4f53880fda17e67fadcae78beb98eb39504833f66de';

test('key proof message = keccak256("scaas-subject-key-proof-v1" ‖ challenge) (pinned with Odoo)', () => {
  assert.equal(hex(keyProofMessage(new Uint8Array(32))), KEY_PROOF_ZERO);
});

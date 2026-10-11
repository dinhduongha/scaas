import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  hashTypedData, hashStruct, secpSubjectKey, accountSalt, predictAccount, accountSignature, merkleBatch, processProof,
  batchLeaf, evmAddress, passkeySubjectKey, addKeyCalldata, ownerCallTypedData, checkOwnerCall, checkPayment,
  keyProofMessage, metaTxTypedData, metaTransferTypedData, checkCall, tradeOrderTypedData, orderCancelTypedData,
  checkTradeOrder,
} from '../src/evm.js';
import { abiEncode, hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';

const vectors = new URL('../../../smartcontracts/evm/test/vectors/', import.meta.url);
const read = (f) => JSON.parse(readFileSync(new URL(f, vectors)));

test('MetaTransfer payment = forge KAT (TokenKat.t.sol, metatransfer_kat.json)', () => {
  const k = read('metatransfer_kat.json');   // mode 35: relayer and fee recipient bound, FIXED fee
  const td = metaTransferTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: k.chain_id, chainUid: k.salt,
    message: { from: k.from, to: k.to, value: k.value, entryRef: k.entry_ref, batch: k.batch, nonce: k.nonce,
      validUntil: k.valid_until, mode: Number(k.mode), relayer: k.relayer, fee: k.fee, feeRecipient: k.fee_recipient } });
  assert.equal(hex(hashTypedData(td)), k.digest);
  const unbound = metaTransferTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: k.chain_id,
    chainUid: k.salt, message: { ...td.message, mode: 0x20 } });
  assert.equal(unbound.message.feeRecipient, '0x' + '00'.repeat(20), 'unbound fields are hashed as 0');
});

/** `abi.encode(TradeOrder)` (13 static words) as forge wrote it into the KATs. */
function decodeOrder(abi) {
  const w = (i) => fromHex(abi).subarray(32 * i, 32 * i + 32);
  const addr = (i) => hex(w(i).subarray(12));
  const num = (i) => BigInt(hex(w(i))).toString();
  return { from: addr(0), receiveToken: addr(1), amount: num(2), receiveAmount: num(3), minFill: num(4), fee: num(5),
    relayer: addr(6), dex: addr(7), destination: addr(8), flags: Number(num(9)), batch: num(10), nonce: num(11),
    validUntil: num(12) };
}

test('TradeOrder, CancelOrder, InvalidateNonces in the token domain = forge KAT (TradeKat.t.sol, trade_kat.json)', () => {
  const k = read('trade_kat.json');
  const o = decodeOrder(k.order_abi);
  const td = tradeOrderTypedData({ token: k.verifying_contract, chainId: 7622, chainUid: k.salt, order: o });
  assert.equal(hex(hashTypedData(td)), k.order_hash);
  const at = { contract: k.verifying_contract, chainId: 7622, chainUid: k.salt };
  assert.equal(hex(hashTypedData(orderCancelTypedData({ ...at, orderHash: k.order_hash }))), k.cancel_digest);
  assert.equal(hex(hashTypedData(orderCancelTypedData({ ...at, invalidate: { from: o.from, batch: 7, minNonce: 43 } }))),
    k.invalidate_digest);
});

test('DexOrder (nested TradeOrder) and the DEX cancels in the DEX domain = forge KAT (DexKat.t.sol, dex_order_kat.json)', () => {
  const k = read('dex_order_kat.json');
  const o = decodeOrder(k.maker_order_abi);
  const td = tradeOrderTypedData({ dex: k.dex, sellToken: k.outside_token, chainId: 7622, chainUid: k.salt, order: o });
  assert.equal(hex(hashStruct(td.types, 'DexOrder', td.message)), k.dex_order_struct_hash);
  assert.equal(hex(hashTypedData(td)), k.dex_order_hash);
  const at = { name: 'SCaaS Dex', contract: k.dex, chainId: 7622, chainUid: k.salt };
  assert.equal(hex(hashTypedData(orderCancelTypedData({ ...at, orderHash: k.dex_order_hash }))), k.cancel_digest);
  assert.equal(hex(hashTypedData(orderCancelTypedData({ ...at, invalidate: { from: o.from, batch: 1, minNonce: 5 } }))),
    k.invalidate_digest);
  const t = decodeOrder(k.taker_order_abi);
  assert.equal(hex(hashTypedData(tradeOrderTypedData({ token: k.token, chainId: 7622, chainUid: k.salt, order: t }))),
    k.taker_order_hash);
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
  // payUnderMandate(token, payee, amount, entryRef, epoch): the pay names the mandate epoch (1 here), so a revoke voids it
  assert.equal(hex(fromHex(pay.data).subarray(0, 4)),
    hex(keccak_256(utf8ToBytes('payUnderMandate(address,address,uint256,bytes32,uint64)')).subarray(0, 4)));
  assert.equal(BigInt(hex(fromHex(pay.data).subarray(132, 164))), 1n);
  assert.equal(BigInt(hex(keccak_256(new Uint8Array([...utf8ToBytes('scaas.mandate.pay'), ...ref])))), BigInt(pay.batch));
  const rev = read('mandate_revoke_kat.json');
  const token = fromHex(rev.data).subarray(16, 36);
  const epoch = new Uint8Array(8); epoch[7] = 1;
  assert.equal(BigInt(hex(keccak_256(new Uint8Array([...utf8ToBytes('scaas.mandate.revoke'), ...token, ...epoch])))),
    BigInt(rev.batch));
});

test('metaTxTypedData zeroes relayer / feeRecipient by mode, as the contract hashes them = metatx_kat.json', () => {
  const k = read('metatx_kat.json');   // mode 1: relayer bound, feeRecipient 0xFEE given but not bound
  const msg = { from: k.from, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until, mode: Number(k.mode),
    relayer: k.relayer, fee: k.fee, feeRecipient: k.fee_recipient };
  const td = metaTxTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: k.chain_id, chainUid: k.salt,
    message: msg });
  assert.equal(hex(hashTypedData(td)), k.digest);
  assert.equal(td.message.feeRecipient, '0x' + '00'.repeat(20));
  assert.equal(td.message.relayer, k.relayer);
  const unbound = metaTxTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: k.chain_id,
    chainUid: k.salt, message: { ...msg, mode: 0 } });
  assert.equal(unbound.message.relayer, '0x' + '00'.repeat(20));
  const both = metaTxTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: k.chain_id,
    chainUid: k.salt, message: { ...msg, mode: 3 } });
  assert.equal(both.message.feeRecipient, k.fee_recipient);
});

test('metaTxTypedData keeps chainId exact (number, decimal or hex string, BigInt) and needs a 32-byte chainUid', () => {
  const k = read('mandate_pay_kat.json');
  const td = (chainId, chainUid = k.salt) => metaTxTypedData({ name: k.domain_name, contract: k.verifying_contract,
    chainId, chainUid, message: { from: k.from, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until } });
  for (const id of [7622, '7622', '0x1dc6', 7622n]) assert.equal(hex(hashTypedData(td(id))), k.digest, String(id));
  assert.equal(hex(hashTypedData(td(k.chain_id, fromHex(k.salt)))), k.digest);
  const big = (1n << 60n) + 1n;
  assert.equal(td(big).domain.chainId, '1152921504606846977');
  assert.equal(hex(hashTypedData(td(big))), hex(hashTypedData(td('1152921504606846977'))));
  assert.notEqual(hex(hashTypedData(td(big))), hex(hashTypedData(td(Number(big)))));
  for (const bad of [null, '', '0x', '0x' + '11'.repeat(31), '0x' + '11'.repeat(33), '11'.repeat(32),
    new Uint8Array(31)]) {
    assert.throws(() => td(7622, bad), /Refusing to sign: the chain_uid is not 32 bytes/, String(bad));
  }
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
  // single fields the server might slip in (set after the builder, which would zero the unbound ones)
  const field = (f) => { const x = serverOwnerCall(addKeyCalldata(NEW_KEY)); f(x); return x; };
  refused.push(
    field((x) => { x.message.feeRecipient = '0x' + '0f'.repeat(20); }),
    field((x) => { x.message.relayer = '0x' + '02'.repeat(20); }),             // relayer with mode 0
    field((x) => { x.domain.verifyingContract = '0x' + 'bd'.repeat(20); }),
    field((x) => { x.domain.version = '2'; }),
  );
  for (const [i, bad] of refused.entries()) {
    assert.throws(() => checkOwnerCall(bad, want), /Refusing to sign: this is not the key change|deadline|nonce|malformed/,
      `case ${i}`);
  }
  assert.throws(() => checkOwnerCall(td, { ...want, chainUid: '0x' + '11'.repeat(32) }), /Refusing to sign/);
  // a signer whose own chainUid is short or missing refuses rather than signing a garbage digest
  for (const chainUid of [undefined, '0x', '0x' + '24'.repeat(31)]) {
    assert.throws(() => checkOwnerCall(td, { ...want, chainUid }), /Refusing to sign: the chain_uid is not 32 bytes/);
  }
  // the deadline bounds: now is too late, now + maxWindow is the last accepted
  assert.throws(() => checkOwnerCall(serverOwnerCall(addKeyCalldata(NEW_KEY), { validUntil: String(NOW) }), want),
    /Refusing to sign: the signing deadline is not near/);
  checkOwnerCall(serverOwnerCall(addKeyCalldata(NEW_KEY), { validUntil: String(NOW + 3600) }), want);
  assert.throws(() => checkOwnerCall(serverOwnerCall(addKeyCalldata(NEW_KEY), { validUntil: String(NOW + 3601) }), want),
    /Refusing to sign: the signing deadline is not near/);
  // typed data that does not hash is refused as such, never signed as some digest
  const noTypes = serverOwnerCall(addKeyCalldata(NEW_KEY));
  delete noTypes.types;
  assert.throws(() => checkOwnerCall(noTypes, want), /Refusing to sign: malformed typed data/);
  // A passkey key is rebuilt from the server's rpId/origin and the coordinates the device returned.
  const pk = passkeySubjectKey({ x: new Uint8Array(32).fill(1), y: new Uint8Array(32).fill(2), rpId: 'pay.example.com',
    origin: 'https://pay.example.com' });
  checkOwnerCall(serverOwnerCall(addKeyCalldata(pk)), { ...want, newKey: pk });
});

function concatSel(sig) {
  return new Uint8Array([...keccak_256(utf8ToBytes(sig)).subarray(0, 4), ...new Uint8Array(96)]);
}

const TOKEN = '0x' + 'cd'.repeat(20);
const REF = '0x' + '09'.repeat(32);

/** A payment `MetaTransfer` as a server issues it, in the token's salted domain. */
function serverPayment(over = {}, dom = {}) {
  const td = metaTransferTypedData({ contract: TOKEN, chainId: 7622, chainUid: UID, message: { from: ACCOUNT,
    to: '0x' + '5e'.repeat(20), value: '125000500000', entryRef: REF, batch: '7', nonce: '0', validUntil: String(NOW + 300),
    mode: 1, relayer: '0x' + '02'.repeat(20), ...over } });
  td.domain = { ...td.domain, ...dom };
  return td;
}

test('payment: the client signs only a MetaTransfer of the amount it showed, from its account, on its chain', () => {
  const intent = { account: ACCOUNT, chainId: 7622, chainUid: UID, amount: 125000.5, decimals: 6, now: NOW };
  const td = serverPayment();
  const ok = checkPayment(td, intent);
  assert.equal(hex(ok.digest), hex(hashTypedData(td)));
  assert.equal(ok.payee, '0x' + '5e'.repeat(20));
  assert.equal(ok.entryRef, REF);
  checkPayment(serverPayment({ value: '125000000000' }), { ...intent, amount: 125000 });
  checkPayment(serverPayment({ mode: 0, relayer: '0x' + '00'.repeat(20) }), intent);
  checkPayment(td, { ...intent, entryRef: REF, expectedToken: TOKEN });
  assert.throws(() => checkPayment(td, { ...intent, expectedToken: '0x' + 'ce'.repeat(20) }), /wrong token/, 'CLI-SGN-08');
  const unsalted = serverPayment();
  unsalted.types = { ...unsalted.types, EIP712Domain: unsalted.types.EIP712Domain.slice(0, 4) };
  delete unsalted.domain.salt;
  const v1 = { ...serverPayment(), primaryType: 'MetaTransaction' };
  const refused = [
    serverPayment({ value: '125000500001' }),                       // more than shown
    serverPayment({ from: '0x' + 'bd'.repeat(20) }),
    serverPayment({ entryRef: '0x' + '00'.repeat(32) }),             // a plain transfer, not a payment
    serverPayment({ fee: '1', mode: 0x21 }),
    serverPayment({ validUntil: String(NOW - 1) }),
    serverPayment({ validUntil: String(NOW + 8 * 86400) }),
    serverPayment({}, { chainId: '1' }),
    serverPayment({}, { verifyingContract: ACCOUNT }),
    serverPayment({}, { salt: '0x' + '11'.repeat(32) }),             // another chain_uid (CLI-SGN-33)
    unsalted,
    v1,                                                              // the v1 struct
  ];
  for (const [i, bad] of refused.entries()) assert.throws(() => checkPayment(bad, intent), /Refusing to sign/, `case ${i}`);
  assert.throws(() => checkPayment(td, { ...intent, entryRef: '0x' + '08'.repeat(32) }), /reference differs/);
  assert.throws(() => checkPayment(td, { ...intent, amount: 1e21 }), /Refusing to sign/);
  // an owner call disguised as a payment, on the payment's own chain: its struct is a MetaTransaction
  assert.throws(() => checkPayment(serverOwnerCall(addKeyCalldata(NEW_KEY)), intent), /Refusing to sign: this is not a payment/);
});

test('self-call: decoded against the published allowlist; transfers, payments and approvals are never calls', () => {
  const k = read('metatx_kat.json');   // cancelNonce(42), relayer bound
  const allowlist = [{ selector: '0xcfdd7aea', name: 'cancelNonce', feeClass: 1 }];
  const want = { account: k.from, chainId: 7622, chainUid: k.salt, allowlist, now: 1_800_000_000 };
  const call = (over = {}) => metaTxTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: 7622,
    chainUid: k.salt, message: { from: k.from, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until,
      mode: Number(k.mode), relayer: k.relayer, ...over } });
  const ok = checkCall(call(), want);
  assert.equal(hex(ok.digest), k.digest);
  assert.equal(ok.name, 'cancelNonce');
  const word = (n) => n.toString(16).padStart(64, '0');
  for (const [i, data] of [
    '0x12345678' + word(1),                                          // not on the allowlist
    '0xa9059cbb' + word(1) + word(2),                                // transfer
    '0x095ea7b3' + word(1) + word(2),                                // approve
    '0x23b872dd' + word(1) + word(2) + word(3),                      // transferFrom
    '0x',
  ].entries()) {
    assert.throws(() => checkCall(call({ data }), { ...want, allowlist: [...allowlist,
      { selector: '0xa9059cbb', name: 'transfer', feeClass: 2 }, { selector: '0x095ea7b3', name: 'approve', feeClass: 1 }] }),
    /Refusing to sign/, `case ${i}`);
  }
  assert.throws(() => checkCall(call({ mode: 0x11 }), want), /percentage fee/);
  assert.throws(() => checkCall(call(), { ...want, chainUid: '0x' + '11'.repeat(32) }), /unexpected call fields/);
  assert.throws(() => checkCall(call({ from: ACCOUNT }), want), /not from your account/);
});

test('trade order: only a DEX on the pinned list, a wrap only into a pinned wrapper (CLI-SGN-35, CLI-SGN-36)', () => {
  const DEX = '0x' + 'de'.repeat(20);
  const WRAPPER = '0x' + 'aa'.repeat(20);
  const order = { from: ACCOUNT, receiveToken: '0x' + 'bb'.repeat(20), amount: '1000', receiveAmount: '2000', minFill: '0',
    fee: '3000', relayer: '0x' + '02'.repeat(20), dex: DEX, destination: '0x' + '00'.repeat(20), flags: 0, batch: '1',
    nonce: '1', validUntil: String(NOW + 600) };
  const want = { account: ACCOUNT, chainId: 7622, chainUid: UID, dexes: [DEX], wrappers: [WRAPPER], now: NOW };
  const td = (o, outside) => outside
    ? tradeOrderTypedData({ dex: o.dex, sellToken: '0x' + '0c'.repeat(20), chainId: 7622, chainUid: UID, order: o })
    : tradeOrderTypedData({ token: TOKEN, chainId: 7622, chainUid: UID, order: o });
  const ok = checkTradeOrder(td(order), want);
  assert.deepEqual(ok.warnings, []);
  assert.equal(ok.minFill, 500n, 'a minFill below half is shown as half');
  assert.equal(hex(ok.digest), hex(hashTypedData(td(order))));
  checkTradeOrder(td(order, true), want);
  assert.deepEqual(checkTradeOrder(td({ ...order, destination: '0x' + '77'.repeat(20) }), want).warnings,
    ['someone else receives the proceeds']);
  // a wrap by signature: dex = receiveToken = the wrapper, all or nothing
  checkTradeOrder(td({ ...order, dex: WRAPPER, receiveToken: WRAPPER, minFill: '1000' }), want);
  const refused = [
    td({ ...order, dex: '0x' + 'ee'.repeat(20) }),                   // unlisted DEX
    td({ ...order, dex: WRAPPER, receiveToken: WRAPPER }),           // a wrap that is not all or nothing
    td({ ...order, dex: WRAPPER, minFill: '1000' }),                 // a wrap paying out something else
    td({ ...order, fee: '10001' }),
    td({ ...order, flags: 2 }),                                      // ESCROW without IOC
    td({ ...order, flags: 8 }),
    td({ ...order, minFill: '1001' }),
    td({ ...order, from: '0x' + 'bd'.repeat(20) }),
    td({ ...order, validUntil: String(NOW - 1) }),
  ];
  const wrongDex = td(order, true);
  wrongDex.domain = { ...wrongDex.domain, verifyingContract: '0x' + 'ee'.repeat(20) };
  refused.push(wrongDex);                                            // a DexOrder signed for another DEX
  for (const [i, bad] of refused.entries()) assert.throws(() => checkTradeOrder(bad, want), /Refusing to sign/, `case ${i}`);
});

const KEY_PROOF_ZERO = '0xfa7987471ecf88572865d4f53880fda17e67fadcae78beb98eb39504833f66de';

test('key proof message = keccak256("scaas-subject-key-proof-v1" ‖ challenge) (pinned with Odoo)', () => {
  assert.equal(hex(keyProofMessage(new Uint8Array(32))), KEY_PROOF_ZERO);
});

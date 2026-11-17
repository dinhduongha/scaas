import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  hashTypedData, hashStruct, erc7739TypedData, erc7739Signature, secpSubjectKey, accountSalt, predictAccount, accountSignature, merkleBatch, processProof,
  batchLeaf, evmAddress, passkeySubjectKey, addKeyCall, addKeyTypedData, executeTypedData, checkOwnerCall, checkPayment,
  keyProofMessage, metaTxTypedData, uaMetaTxTypedData, uaMetaTransferTypedData, checkCall, tradeOrderTypedData, uaTradeOrderTypedData, padId,
  cancelUAOrderTypedData, cancelDexOrderTypedData, invalidateNoncesTypedData, uaInvalidateNoncesTypedData, checkTradeOrder, bidMinFill,
  bidMinBase, checkCancel, payLane, uaPayeeFeeTypedData, wrapToUACall, unwrapToUACall, payWithFeeToUACalldata, checkPayeeFee,
  uaPayUnderMandateTypedData, uaPayUnderMandateCalldata, uaDelegateRevokeTypedData, uaDelegateRevokeCalldata, mtxExecuteCalldata,
  mtxExecuteTransferCalldata, TYPED_OPS, metaPayId,
} from '../src/evm.js';
import { abiEncode, hex, fromHex, keccak_256, utf8ToBytes, concatBytes } from '../src/bytes.js';

const vectors = new URL('../../../smartcontracts/evm/test/vectors/', import.meta.url);
const read = (f) => JSON.parse(readFileSync(new URL(f, vectors)));
// ua-mtx-merge T2: the token's KATs of the address `MetaTransaction` / `MetaTransfer` moved to the legacy place; the files
// of the same name hold the UA structs. T11: the clients build the UA ones; the address `MetaTransaction` stays for
// `executeMetaTransaction` (R3) and `SmartKeyAccount`, so its KAT is read from the legacy place.
const legacyKat = (f) => read(`legacy/ua-mtx-merge/${f}`);
// What `SmartKeyAccount`'s generic `mtxExecute` hashes: its owner call as a `MetaTransaction` over `addKey(key)`. ua-mtx-merge
// T11: built here from `metaTxTypedData`, as legacy/typed-signing/evm-pre-named.js did (that file imports the retired
// `metaTransferTypedData` and no longer loads; it stays as it is, legacy).
const ownerCallTypedData = ({ account, chainId, chainUid, data, nonce, validUntil }) => metaTxTypedData({ name: 'SCaaS SmartKeyAccount',
  contract: account, chainId, chainUid, message: { from: account, data, nonce, validUntil } });
const kTransfer = (k) => uaMetaTransferTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: k.chain_id, chainUid: k.salt,
  message: { from: k.from, to: k.to, value: k.value, entryRef: k.entry_ref, batch: k.batch, nonce: k.nonce,
    validUntil: k.valid_until, mode: Number(k.mode), relayer: k.relayer, fee: k.fee, feeRecipient: k.fee_recipient } });

test('UAMetaTransfer payment = forge KAT (TokenKat.t.sol, metatransfer_kat.json); mtxExecuteTransfer calldata with UASig', () => {
  const k = read('metatransfer_kat.json');   // mode 35: relayer and fee recipient bound, FIXED fee; an EOA's padded id
  const td = kTransfer(k);
  assert.equal(hex(hashTypedData(td)), k.digest);
  assert.equal(hex(hashStruct(td.types, 'UAMetaTransfer', td.message)), k.struct_hash);
  assert.equal(hex(keccak_256(utf8ToBytes(`UAMetaTransfer(${td.types.UAMetaTransfer.map((f) => `${f.type} ${f.name}`).join(',')})`))), k.type_hash);
  assert.equal(hex(mtxExecuteTransferCalldata(td, k.signature)), k.calldata);
  const unbound = uaMetaTransferTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: k.chain_id,
    chainUid: k.salt, message: { ...td.message, mode: 0x20 } });
  assert.equal(unbound.message.feeRecipient, '0x' + '00'.repeat(20), 'unbound fields are hashed as 0');
});

test('UAMetaTransaction = forge KAT (metatx_kat.json): a non-zero unbound feeRecipient is hashed as 0; mtxExecute with UASig', () => {
  const k = read('metatx_kat.json');   // mode 1: relayer bound, feeRecipient 0xFEE given but not bound
  assert.notEqual(BigInt(k.fee_recipient), 0n);
  const td = uaMetaTxTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: k.chain_id, chainUid: k.salt,
    message: { from: k.from, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until, mode: Number(k.mode),
      relayer: k.relayer, fee: k.fee, feeRecipient: k.fee_recipient } });
  assert.equal(td.message.feeRecipient, '0x' + '00'.repeat(20));
  assert.equal(hex(hashTypedData(td)), k.digest);
  assert.equal(hex(hashStruct(td.types, 'UAMetaTransaction', td.message)), k.struct_hash);
  // the KAT's calldata carries the relayer's unbound 0xFEE (the contract hashes it as 0, pays `msg.sender`); the client's
  // carries the canonical 0: the two differ in that one word only, and both run under the same signature
  assert.equal(hex(mtxExecuteCalldata({ ...td, message: { ...td.message, feeRecipient: k.fee_recipient } }, k.signature)), k.calldata);
  const mine = mtxExecuteCalldata(td, k.signature);
  const theirs = fromHex(k.calldata);
  const words = [];
  for (let i = 4; i < theirs.length; i += 32) if (hex(mine.subarray(i, i + 32)) !== hex(theirs.subarray(i, i + 32))) words.push((i - 4) / 32);
  assert.deepEqual(words, [10], 'm.feeRecipient: word 2 (m) + 8');
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

// ua-mtx-merge T6 / T11 (R12): the token's address `TradeOrder` side, its KAT (test/vectors/legacy/ua-mtx-merge/trade_kat.json)
// and its builders are legacy; the token signs `UATradeOrder` (uatrade_kat.json, ua-trade.test.js).
test('the token\'s address TradeOrder is refused by name; DexOrder stays for an outside token', () => {
  const k = legacyKat('trade_kat.json');
  assert.throws(() => tradeOrderTypedData({ token: k.verifying_contract, chainId: 7622, chainUid: k.salt, order: decodeOrder(k.order_abi) }),
    /Refusing to sign: a SCaaS sell token takes a UATradeOrder/);
});

test('DexOrder (nested TradeOrder) and the DEX cancels in the DEX domain = forge KAT (DexKat.t.sol, dex_order_kat.json)', () => {
  const k = read('dex_order_kat.json');
  const o = decodeOrder(k.maker_order_abi);
  const td = tradeOrderTypedData({ dex: k.dex, sellToken: k.outside_token, chainId: 7622, chainUid: k.salt, order: o });
  assert.equal(hex(hashStruct(td.types, 'DexOrder', td.message)), k.dex_order_struct_hash);
  assert.equal(hex(hashTypedData(td)), k.dex_order_hash);
  const at = { name: 'SCaaS Dex', contract: k.dex, chainId: 7622, chainUid: k.salt };
  assert.equal(hex(hashTypedData(cancelDexOrderTypedData({ ...at, message: { order: { sellToken: k.outside_token, order: o } } }))), k.cancel_digest);
  assert.equal(hex(hashTypedData(invalidateNoncesTypedData({ ...at, from: o.from, batch: 1, minNonce: 5 }))), k.invalidate_digest);
  // ua-mtx-merge T6 (R12): the SCaaS taker's leg is its `UATradeOrder` (the address zero-padded, the same 13 words)
  const t = decodeOrder(k.taker_order_abi);
  const ut = { ...t, from: padId(t.from), destination: padId(t.destination) };
  assert.equal(hex(hashTypedData(uaTradeOrderTypedData({ token: k.token, chainId: 7622, chainUid: k.salt, order: ut }))),
    k.taker_order_hash);
});

test('SmartKeyAccount owner call = forge KAT (AccountKat.t.sol, smart_key_account_kat.json)', () => {
  const k = read('smart_key_account_kat.json');
  assert.equal(hex(addKeyCall(secpSubjectKey('0x' + '77'.repeat(20)))), k.data);
  const td = ownerCallTypedData({ account: k.verifying_contract, chainId: Number(k.chain_id), chainUid: k.salt,
    data: k.data, nonce: k.nonce, validUntil: k.valid_until });
  assert.equal(hex(hashTypedData(td)), k.digest);
  assert.equal(hex(hashTypedData(ownerCallTypedData({ account: k.verifying_contract, chainId: 7622, chainUid: k.salt,
    data: addKeyCall(secpSubjectKey('0x' + '77'.repeat(20))), nonce: k.nonce, validUntil: k.valid_until }))), k.digest);
  // the account encoding of the seed key's ECDSA signature (key index 0, no batch proof)
  const sig = fromHex(k.signature).subarray(160, 225);
  assert.equal(hex(accountSignature(0, [], sig)), k.signature);
  const r = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact').addRecoveryBit(sig[64] - 27);
  assert.equal(evmAddress(r.recoverPublicKey(fromHex(k.digest)).toBytes(false)), k.signer_key);
});

// B P3-2 (CTR-ACC-02, owner 2026-11-12: ERC-7739 only): the nested `TypedDataSign` a wallet key signs and the signature
// suffix, against the forge KAT (AccountKat.t.sol, erc7739_kat.json): implicit mode (a token's `UAMetaTransfer` for a
// `SmartKeyAccount`) and explicit mode (`Order` nesting `Asset` for a `MandateWallet`).
test('erc7739TypedData / erc7739Signature = forge KAT (erc7739_kat.json)', () => {
  const k = read('erc7739_kat.json');
  const chainId = Number(k.chain_id);
  const s = k.smart_key_account;
  const td = uaMetaTransferTypedData({ name: s.app_name, contract: s.app_contract, chainId, chainUid: k.salt,
    message: { from: s.from, to: s.to, value: s.value, entryRef: s.entry_ref, batch: s.batch, validUntil: s.valid_until } });
  assert.equal(hex(hashTypedData(td)), hex(keccak_256(concatBytes(new Uint8Array([0x19, 1]), fromHex(s.app_separator),
    fromHex(s.contents)))), 'the app hash is 0x1901 ‖ separator ‖ contents');
  const nested = erc7739TypedData(td, { wallet: 'SmartKeyAccount', address: s.wallet, chainId, chainUid: k.salt });
  assert.equal(hex(hashTypedData(nested)), s.digest);
  const sig = fromHex(s.signature);
  const blob = sig.subarray(0, sig.length - 66 - ((sig[sig.length - 2] << 8) | sig[sig.length - 1]));
  assert.equal(blob.length, 256, 'abi.encode(0, [], 65-byte ECDSA)');
  assert.equal(hex(erc7739Signature(blob, td)), s.signature);
  const ecdsa = blob.subarray(160, 225);
  const r = secp256k1.Signature.fromBytes(ecdsa.subarray(0, 64), 'compact').addRecoveryBit(ecdsa[64] - 27);
  assert.equal(evmAddress(r.recoverPublicKey(fromHex(s.digest)).toBytes(false)), s.signer_key);
  assert.notEqual(hex(hashTypedData(erc7739TypedData(td, { wallet: 'SmartKeyAccount', address: '0x' + '33'.repeat(20), chainId,
    chainUid: k.salt }))), s.digest, 'bound to the wallet');

  const m = k.mandate_wallet;
  const order = {
    types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' },
      { name: 'verifyingContract', type: 'address' }], Order: [{ name: 'give', type: 'Asset' }, { name: 'nonce', type: 'uint256' }],
    Asset: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }] },
    primaryType: 'Order',
    domain: { name: m.app_name, version: m.app_version, chainId, verifyingContract: m.app_contract },
    message: { give: { token: m.token, amount: m.amount }, nonce: m.nonce },
  };
  const n2 = erc7739TypedData(order, { wallet: 'MandateWallet', address: m.wallet, chainId, chainUid: k.salt });
  assert.equal(hex(hashTypedData(n2)), m.digest);
  const msig = fromHex(m.signature);
  assert.equal(hex(erc7739Signature(msig.subarray(0, 65), order)), m.signature, 'explicit mode: contentsType ‖ Order');
  assert.ok(new TextDecoder().decode(msig.subarray(65 + 64, msig.length - 2)).endsWith(')Order'));
  assert.throws(() => erc7739TypedData(td, { wallet: 'NormalToken', address: s.wallet, chainId, chainUid: k.salt }), /no ERC-7739/);
  const w = { wallet: 'MandateWallet', address: m.wallet, chainId, chainUid: k.salt };
  for (const bad of ['', 'order', 'Or der', 'Or,der', 'Or(der', 'Or)der', 'Or\0der']) {
    assert.throws(() => erc7739TypedData({ ...order, primaryType: bad }, w), /refuses the contents name/, JSON.stringify(bad));
  }
});

// ua-mtx-merge T3b / T11 (Q6, MD-11): the wallet's one signed entry per op over `UA<Op>`; the flat builders' KATs
// (mandate_pay_kat.json, mandate_revoke_kat.json) are legacy.
test('mandate_kat.json equals the builders (pay and delegate revoke): UAPayUnderMandate, UADelegateRevoke, UASig calldata', () => {
  const kat = read('mandate_kat.json');
  const build = { pay: [uaPayUnderMandateTypedData, uaPayUnderMandateCalldata, ['token', 'payee', 'amount', 'entryRef', 'epoch']],
    revoke: [uaDelegateRevokeTypedData, uaDelegateRevokeCalldata, ['token', 'epoch']] };
  for (const [row, [typed, calldata, own]] of Object.entries(build)) {
    const k = kat[row];
    const types = own.map((n) => TYPED_OPS[row === 'pay' ? 'UAPayUnderMandate' : 'UADelegateRevoke'].fields.find((f) => f.name === n).type);
    const words = fromHex(k.args);
    const args = Object.fromEntries(own.map((n, i) => {
      const w = words.subarray(32 * i, 32 * i + 32);
      return [n, types[i] === 'address' ? hex(w.subarray(12)) : types[i] === 'bytes32' ? hex(w) : BigInt(hex(w)).toString()];
    }));
    assert.equal(hex(abiEncode(types, own.map((n) => args[n]))), k.args, row);
    const td = typed({ contract: kat.verifying_contract, chainId: kat.chain_id, chainUid: kat.salt, message: { from: k.from, ...args,
      batch: k.batch, nonce: k.nonce, validUntil: k.valid_until, mode: Number(k.mode), relayer: k.relayer, fee: k.fee, feeRecipient: k.fee_recipient } });
    assert.equal(td.domain.name, kat.domain_name);
    assert.equal(hex(hashStruct(td.types, 'EIP712Domain', td.domain)), kat.domain_separator, row);
    assert.equal(TYPED_OPS[td.primaryType].typeString, k.type_string, row);
    assert.equal(TYPED_OPS[td.primaryType].typehash, k.type_hash, row);
    assert.equal(hex(hashStruct(td.types, td.primaryType, td.message)), k.struct_hash, row);
    assert.equal(hex(hashTypedData(td)), k.digest, row);
    // pay-meta-tax T37 / T41: the pay takes its `PayMeta` last, unsigned; the signed `entryRef` is its commitment
    const meta = row === 'pay' ? { salt: k.meta_salt, payNo: k.meta_pay_no, save: k.meta_save, schema: Number(k.meta_schema),
      body: k.meta_body } : undefined;
    if (meta) assert.equal(metaPayId(meta), args.entryRef, 'the entryRef commits to the PayMeta');
    assert.equal(hex(calldata(td, k.signature, meta && { meta })), k.calldata, row);
    const r = secp256k1.Signature.fromBytes(fromHex(k.signature).subarray(0, 64), 'compact').addRecoveryBit(fromHex(k.signature)[64] - 27);
    assert.equal(evmAddress(r.recoverPublicKey(fromHex(k.digest)).toBytes(false)).toLowerCase(), kat.signer.toLowerCase(), row);
    assert.equal(k.from, padId(kat.signer).toLowerCase(), `${row}: the owner's address zero-padded`);
  }
  // the derived lanes: keccak256("scaas.mandate.pay" ‖ entryRef), keccak256("scaas.mandate.revoke" ‖ token ‖ uint64 epoch)
  const ref = fromHex(kat.pay.args).subarray(96, 128);
  assert.equal(BigInt(hex(fromHex(kat.pay.args).subarray(128, 160))), 1n, 'the pay names the mandate epoch (1), so a revoke voids it');
  assert.equal(BigInt(hex(keccak_256(new Uint8Array([...utf8ToBytes('scaas.mandate.pay'), ...ref])))), BigInt(kat.pay.batch));
  const token = fromHex(kat.revoke.args).subarray(12, 32);
  const epoch = new Uint8Array(8); epoch[7] = 1;
  assert.equal(BigInt(hex(keccak_256(new Uint8Array([...utf8ToBytes('scaas.mandate.revoke'), ...token, ...epoch])))),
    BigInt(kat.revoke.batch));
});

test('metaTxTypedData zeroes relayer / feeRecipient by mode, as the contract hashes them = metatx_kat.json', () => {
  const k = legacyKat('metatx_kat.json');   // mode 1: relayer bound, feeRecipient 0xFEE given but not bound
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
  const k = legacyKat('metatx_kat.json');   // the address MetaTransaction of executeMetaTransaction (R3)
  const td = (chainId, chainUid = k.salt) => metaTxTypedData({ name: k.domain_name, contract: k.verifying_contract,
    chainId, chainUid, message: { from: k.from, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until,
      mode: Number(k.mode), relayer: k.relayer, fee: k.fee, feeRecipient: k.fee_recipient } });
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

/** The account's owner call as a server issues it: an `AddKey` in the salted `SCaaS SmartKeyAccount` domain. */
function serverOwnerCall(key, { account = ACCOUNT, chainId = 7622, salt = UID, nonce = '2', validUntil = String(NOW + 600),
  ...over } = {}) {
  const [kind, x, y, rpIdHash, originHash] = key;
  const td = addKeyTypedData({ contract: account, chainId, chainUid: salt,
    message: { from: account, kind, x, y, rpIdHash, originHash, validUntil, ...over } });
  td.message.nonce = nonce;
  return td;
}

test('owner call: the client signs only AddKey(the key it just made) as its own account, on its chain', () => {
  const want = { account: ACCOUNT, chainId: 7622, chainUid: UID, newKey: NEW_KEY, now: NOW };
  const td = serverOwnerCall(NEW_KEY);
  assert.equal(td.primaryType, 'AddKey');
  assert.equal(hex(checkOwnerCall(td, want)), hex(hashTypedData(td)));
  // addKey(abi.encode(key)): selector of addKey((uint8,bytes32,bytes32,bytes32,bytes32)) + 5 words.
  assert.equal(hex(addKeyCall(NEW_KEY).subarray(0, 4)),
    hex(keccak_256(utf8ToBytes('addKey((uint8,bytes32,bytes32,bytes32,bytes32))')).subarray(0, 4)));
  const drain = executeTypedData({ contract: ACCOUNT, chainId: 7622, chainUid: UID, name: 'SCaaS SmartKeyAccount',
    message: { from: ACCOUNT, target: ATK, value: 1, validUntil: String(NOW + 600) } });
  const unsalted = serverOwnerCall(NEW_KEY);
  unsalted.types = { ...unsalted.types, EIP712Domain: unsalted.types.EIP712Domain.slice(0, 4) };
  delete unsalted.domain.salt;
  const oldShape = serverOwnerCall(NEW_KEY);
  oldShape.domain.name = 'SCaaS SubjectAccount';
  const refused = [
    drain,                                                       // any other op
    serverOwnerCall(secpSubjectKey('0x' + '66'.repeat(20))),     // someone else's key
    serverOwnerCall(NEW_KEY, { account: '0x' + 'bd'.repeat(20) }),
    serverOwnerCall(NEW_KEY, { from: '0x' + 'bd'.repeat(20) }),  // signed as another party
    serverOwnerCall(NEW_KEY, { chainId: 1 }),
    serverOwnerCall(NEW_KEY, { salt: '0x' + '11'.repeat(32) }),  // another chain_uid
    unsalted,                                                    // no salt (CLI-SGN-33)
    oldShape,                                                    // the built domain name
    serverOwnerCall(NEW_KEY, { batch: '1' }),
    serverOwnerCall(NEW_KEY, { mode: 1, relayer: '0x' + '02'.repeat(20) }),
    serverOwnerCall(NEW_KEY, { fee: '1' }),
    serverOwnerCall(NEW_KEY, { validUntil: String(NOW - 1) }),
    serverOwnerCall(NEW_KEY, { validUntil: String(NOW + 7200) }),
    serverOwnerCall(NEW_KEY, { nonce: '-1' }),
    { ...serverOwnerCall(NEW_KEY), primaryType: 'OwnerCall' },
  ];
  const extra = serverOwnerCall(NEW_KEY);
  extra.types = { ...extra.types, AddKey: [...extra.types.AddKey, { name: 'value', type: 'uint256' }] };
  extra.message.value = '1';
  refused.push(extra);
  // single fields the server might slip in (set after the builder, which would zero the unbound ones)
  const field = (f) => { const x = serverOwnerCall(NEW_KEY); f(x); return x; };
  refused.push(
    field((x) => { x.message.feeRecipient = '0x' + '0f'.repeat(20); }),
    field((x) => { x.message.relayer = '0x' + '02'.repeat(20); }),             // relayer with mode 0
    field((x) => { x.domain.verifyingContract = '0x' + 'bd'.repeat(20); }),
    field((x) => { x.domain.version = '2'; }),
  );
  for (const [i, bad] of refused.entries()) {
    assert.throws(() => checkOwnerCall(bad, want),
      /Refusing to sign: this is not the operation|contract you chose|not signed in the domain|deadline|nonce|malformed/, `case ${i}`);
  }
  assert.throws(() => checkOwnerCall(td, { ...want, chainUid: '0x' + '11'.repeat(32) }), /Refusing to sign/);
  // a signer whose own chainUid is short or missing refuses rather than signing a garbage digest
  for (const chainUid of [undefined, '0x', '0x' + '24'.repeat(31)]) {
    assert.throws(() => checkOwnerCall(td, { ...want, chainUid }), /Refusing to sign: the chain_uid is not 32 bytes/);
  }
  // the deadline bounds: now is too late, now + maxWindow is the last accepted
  assert.throws(() => checkOwnerCall(serverOwnerCall(NEW_KEY, { validUntil: String(NOW) }), want),
    /Refusing to sign: the signing deadline is not near/);
  checkOwnerCall(serverOwnerCall(NEW_KEY, { validUntil: String(NOW + 3600) }), want);
  assert.throws(() => checkOwnerCall(serverOwnerCall(NEW_KEY, { validUntil: String(NOW + 3601) }), want),
    /Refusing to sign: the signing deadline is not near/);
  // typed data that does not hash is refused as such, never signed as some digest
  const noTypes = serverOwnerCall(NEW_KEY);
  delete noTypes.types;
  assert.throws(() => checkOwnerCall(noTypes, want), /Refusing to sign: malformed typed data/);
  // A passkey key is rebuilt from the server's rpId/origin and the coordinates the device returned.
  const pk = passkeySubjectKey({ x: new Uint8Array(32).fill(1), y: new Uint8Array(32).fill(2), rpId: 'pay.example.com',
    origin: 'https://pay.example.com' });
  checkOwnerCall(serverOwnerCall(pk), { ...want, newKey: pk });
});

const TOKEN = '0x' + 'cd'.repeat(20);
const REF = '0x' + '09'.repeat(32);
const ATK = '0x' + 'ee'.repeat(20);
const PAYEE = '0x' + '5e'.repeat(20);
const word = (n) => BigInt(n).toString(16).padStart(64, '0');
// ua-mtx-merge T11 (R20, R46): a payment is the token's `UAMetaTransfer` between ids; an EOA's id is its address zero-padded
const ACCOUNT_ID = padId(ACCOUNT);
const PAYEE_ID = padId(PAYEE);
const ATK_ID = padId(ATK);

/** A payment `UAMetaTransfer` as a server issues it, in the token's salted domain, on the request's lane with nonce 0. */
function serverPayment(over = {}, dom = {}, tok = TOKEN) {
  const td = uaMetaTransferTypedData({ contract: tok, chainId: 7622, chainUid: UID, message: { from: ACCOUNT_ID, to: PAYEE_ID,
    value: '125000500000', entryRef: REF, batch: payLane(REF), nonce: '0', validUntil: String(NOW + 300), mode: 1,
    relayer: '0x' + '02'.repeat(20), ...over } });
  td.domain = { ...td.domain, ...dom };
  return td;
}

test('payment lane = payLane(entryRef) of the forge KAT; the KAT payment passes with its fee named', () => {
  const k = read('metatransfer_kat.json');   // mode 35: FIXED fee 100000 to 0xFEE, relayer 0xbEEF bound
  assert.equal(payLane(k.entry_ref).toString(), k.batch);
  const td = kTransfer(k);
  const want = { account: k.from, chainId: 7622, chainUid: k.salt, amount: '100', decimals: 6, payee: k.to,
    entryRef: k.entry_ref, expectedToken: k.verifying_contract, maxFee: '100000', feeRecipient: k.fee_recipient,
    relayer: k.relayer, now: NOW };
  const ok = checkPayment(td, want);
  assert.equal(hex(ok.digest), k.digest);
  assert.deepEqual([ok.feeMode, ok.fee, ok.feeRecipient, ok.relayer], [2, 100000n, k.fee_recipient, k.relayer]);
  assert.throws(() => checkPayment(td, { ...want, maxFee: '99999' }), /the fee is above your limit/);
  assert.throws(() => checkPayment(td, { ...want, feeRecipient: ATK }), /an address you did not name/);
  assert.throws(() => checkPayment(td, { ...want, feeRecipient: undefined }), /an address you did not name/);
  assert.throws(() => checkPayment(td, { ...want, relayer: ATK }), /bound to another relayer/);
});

test('payment: only the payment the user was shown (payee, token, reference, amount, lane, fee), CLI-SGN-05/08', () => {
  const intent = { account: ACCOUNT_ID, chainId: 7622, chainUid: UID, amount: 125000.5, decimals: 6, payee: PAYEE_ID, entryRef: REF,
    expectedToken: TOKEN, now: NOW };
  const td = serverPayment();
  const ok = checkPayment(td, intent);
  assert.equal(hex(ok.digest), hex(hashTypedData(td)));
  assert.deepEqual([ok.payee, ok.entryRef, ok.token, ok.fee, ok.feeMode], [PAYEE_ID, REF, TOKEN, 0n, 0]);
  checkPayment(serverPayment({ value: '125000000000' }), { ...intent, amount: 125000 });
  checkPayment(serverPayment({ mode: 0, relayer: '0x' + '00'.repeat(20) }), intent);
  assert.equal(checkPayment(serverPayment({ mode: 0x20, fee: '1' }), { ...intent, maxFee: 1 }).fee, 1n);
  // PERCENT: ⌊value × rate / 10^6⌋ against the limit
  const pct = serverPayment({ mode: 0x10, fee: '10000' });
  assert.equal(checkPayment(pct, { ...intent, maxFee: '1250005000' }).fee, 1250005000n);
  assert.throws(() => checkPayment(pct, { ...intent, maxFee: '1250004999' }), /the fee is above your limit/);
  const cases = [
    [serverPayment({ to: ATK_ID }), /the payee differs/],                            // hostile probe: payee swap
    [serverPayment({ batch: '8', nonce: '5' }), /signed once, on its request lane/],   // pay twice on a fresh lane
    [serverPayment({ batch: '8' }), /signed once/],
    [serverPayment({ nonce: '5' }), /signed once/],
    [serverPayment({}, {}, ATK), /wrong token/],                                      // CLI-SGN-08
    [serverPayment({}, { verifyingContract: ACCOUNT }), /wrong token/],
    [serverPayment({ entryRef: '0x' + '07'.repeat(32) }), /reference differs/],
    [serverPayment({ value: '125000500001' }), /amount differs/],                    // more than shown
    [serverPayment({ fee: '1', mode: 1 }), /a fee with fee mode NONE/],
    [serverPayment({ fee: '0', mode: 0x22, feeRecipient: ATK }), /an address you did not name/],
    [serverPayment({ fee: '1', mode: 0x20 }), /the fee is above your limit/],
    [serverPayment({ fee: '10001', mode: 0x10 }), /a percentage fee/],
    [serverPayment({ mode: 0x30 }), /unexpected fee mode/],
    [serverPayment({ mode: 0x04 }), /unexpected fee mode/],
    [serverPayment({ mode: '0x1' }), /the fee mode is not a number/],
    [serverPayment({ from: padId('0x' + 'bd'.repeat(20)) }), /unexpected payment fields/],
    [serverPayment({ validUntil: String(NOW) }), /deadline/],
    [serverPayment({ validUntil: String(NOW + 86401) }), /deadline/],
    [serverPayment({}, { chainId: '1' }), /unexpected payment fields/],
    [serverPayment({}, { salt: '0x' + '11'.repeat(32) }), /unexpected payment fields/],  // another chain_uid (CLI-SGN-33)
    [{ ...serverPayment(), primaryType: 'MetaTransaction' }, /this is not a payment/],    // the v1 struct
    [{ ...serverPayment(), primaryType: 'MetaTransfer' }, /this is not a payment/],       // the address struct (R46, legacy)
    [serverOwnerCall(NEW_KEY), /this is not a payment/],
  ];
  const unsalted = serverPayment();
  unsalted.types = { ...unsalted.types, EIP712Domain: unsalted.types.EIP712Domain.slice(0, 4) };
  delete unsalted.domain.salt;
  cases.push([unsalted, /unexpected payment fields/]);
  for (const [i, [bad, why]] of cases.entries()) assert.throws(() => checkPayment(bad, intent), why, `case ${i}`);
  checkPayment(serverPayment({ validUntil: String(NOW + 86400) }), intent);
  // the ids are the client's: an address where an id is signed is refused, never padded behind the user's back
  assert.throws(() => checkPayment(td, { ...intent, account: ACCOUNT }), /Refusing to sign/);
  // the pins are required: a caller that forgets one gets a refusal, never an unpinned signature
  for (const f of ['payee', 'entryRef', 'expectedToken', 'amount']) {
    assert.throws(() => checkPayment(td, { ...intent, [f]: undefined }), /are required/, f);
  }
  assert.throws(() => checkPayment(serverPayment({ value: '0' }), { ...intent, amount: 0 }), /amount differs/);
  const zero = '0x' + '00'.repeat(32);
  assert.throws(() => checkPayment(serverPayment({ entryRef: zero }), { ...intent, entryRef: zero }), /this is not a payment/);
  assert.throws(() => checkPayment(td, { ...intent, amount: 1e21 }), /Refusing to sign/);
});

test('self-call: exactly the call the client built, on its contract, with the fee the user allows (CLI-SGN-34)', () => {
  const k = legacyKat('metatx_kat.json');   // cancelNonce(42), relayer bound, fee mode NONE
  const allowlist = [{ selector: '0xcfdd7aea', name: 'cancelNonce', feeClass: 1 }];
  const want = { account: k.from, chainId: 7622, chainUid: k.salt, allowlist, call: { contract: k.verifying_contract, data: k.data },
    now: NOW };
  const call = (over = {}, contract = k.verifying_contract) => metaTxTypedData({ name: k.domain_name, contract, chainId: 7622,
    chainUid: k.salt, message: { from: k.from, data: k.data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until,
      mode: Number(k.mode), relayer: k.relayer, ...over } });
  const ok = checkCall(call(), want);
  assert.equal(hex(ok.digest), k.digest);
  assert.deepEqual([ok.name, ok.selector, ok.fee, ok.feeMode, ok.relayer], ['cancelNonce', '0xcfdd7aea', 0n, 0, k.relayer]);
  checkCall(call(), { ...want, call: { ...want.call, data: fromHex(k.data) } });   // calldata as bytes
  const big = '1000000000000000000000000';
  assert.equal(checkCall(call({ mode: 0x21, fee: big }), { ...want, maxFee: big }).fee, BigInt(big));
  const cases = [
    [call({ mode: 0x23, fee: big, feeRecipient: ATK }), /the fee is above your limit/],   // hostile probe: fee to attacker
    [call({ mode: 0x21, fee: big }), /the fee is above your limit/],
    [call({ fee: '1' }), /a fee with fee mode NONE/],
    [call({ mode: 0x11, fee: '1' }), /a percentage fee/],                                 // PERCENT on an ABSOLUTE selector
    [call({}, ATK), /not on the contract you chose/],
    [call({}, k.from), /not on the contract you chose/],                                  // the account itself
    [call({ data: '0xcfdd7aea' + word(43) }), /not the call you asked for/],
    [call({ data: k.data + word(1) }), /not the call you asked for/],                     // trailing words
    [call({ validUntil: String(NOW + 7200) }), /deadline/],
    [call({ from: ACCOUNT }), /unexpected call fields/],
  ];
  for (const [i, [bad, why]] of cases.entries()) assert.throws(() => checkCall(bad, want), why, `case ${i}`);
  assert.throws(() => checkCall(call(), { ...want, chainUid: '0x' + '11'.repeat(32) }), /unexpected call fields/);
  assert.throws(() => checkCall(call(), { ...want, relayer: ATK }), /bound to another relayer/);
  assert.throws(() => checkCall(call({ mode: 0x23, fee: big, feeRecipient: ATK }), { ...want, maxFee: big }),
    /an address you did not name/);
  assert.throws(() => checkCall(call(), { ...want, call: undefined }), /not on the contract you chose/);
  assert.throws(() => checkCall({ ...call(), primaryType: 'MetaTransfer' }, want), /this is not a contract call/);
  // calldata the client itself built is still decoded: transfers, payments and approvals are never calls
  const never = { ...want, allowlist: [...allowlist, { selector: '0xa9059cbb', name: 'transfer', feeClass: 2 },
    { selector: '0x095ea7b3', name: 'approve', feeClass: 1 }] };
  for (const [i, [data, why]] of [
    ['0x12345678' + word(1), /not on the contract's allowlist/],
    ['0x', /not on the contract's allowlist/],
    ['0xa9059cbb' + word(1) + word(2), /never signed as a call/],
    ['0x095ea7b3' + word(1) + word(2), /never signed as a call/],
    ['0x23b872dd' + word(1) + word(2) + word(3), /never signed as a call/],
    [hex(keccak_256(utf8ToBytes('pay(bytes32)')).subarray(0, 4)) + word(1), /never signed as a call/],
    [hex(keccak_256(utf8ToBytes('payWithFee(address,uint256,uint8,uint256,address,bytes32)')).subarray(0, 4)) + word(1),
      /never signed as a call/],
  ].entries()) {
    assert.throws(() => checkCall(call({ data }), { ...never, call: { ...want.call, data } }), why, `selector ${i}`);
  }
  // PERCENT on an AMOUNT selector: the basis is argument `amountArg` of the call
  const UNWRAP = hex(keccak_256(utf8ToBytes('unwrap(address,uint256,address,uint256)')).subarray(0, 4));
  const unwrap = UNWRAP + '00'.repeat(12) + 'aa'.repeat(20) + word(1_000_000) + word(0) + word(0);
  const pct = { ...want, allowlist: [{ selector: UNWRAP, name: 'unwrap', feeClass: 2, amountArg: 1 }],
    call: { ...want.call, data: unwrap } };
  const td = call({ data: unwrap, mode: 0x10, fee: '10000' });
  assert.equal(checkCall(td, { ...pct, maxFee: 10000 }).fee, 10000n);
  assert.throws(() => checkCall(td, { ...pct, maxFee: 9999 }), /the fee is above your limit/);
});

test('trade order: exactly the order the client built, on a pinned DEX or wrapper (CLI-SGN-35, CLI-SGN-36)', () => {
  const DEX = '0x' + 'de'.repeat(20);
  const DEX2 = '0x' + 'df'.repeat(20);
  const WRAPPER = '0x' + 'aa'.repeat(20);
  const OUT = '0x' + '0c'.repeat(20);
  // ua-mtx-merge T11 (R12): a SCaaS sell token's order is a `UATradeOrder` (ids); an outside token's a `DexOrder` (addresses)
  const ZID = '0x' + '00'.repeat(32);
  const mine = { receiveToken: '0x' + 'bb'.repeat(20), amount: '1000', receiveAmount: '2000', minFill: '0', fee: '3000',
    relayer: '0x' + '02'.repeat(20), dex: DEX, destination: ZID, flags: 0, batch: '1' };
  const server = (o = {}, { outside = false, sellToken, dom = {} } = {}) => {
    const order = { ...mine, ...(outside ? { from: ACCOUNT, destination: '0x' + '00'.repeat(20) } : { from: ACCOUNT_ID }), nonce: '1',
      validUntil: String(NOW + 600), ...o };
    const td = outside
      ? tradeOrderTypedData({ dex: order.dex, sellToken: sellToken || OUT, chainId: 7622, chainUid: UID, order })
      : uaTradeOrderTypedData({ token: sellToken || TOKEN, chainId: 7622, chainUid: UID, order });
    td.domain = { ...td.domain, ...dom };
    return td;
  };
  const want = { account: ACCOUNT_ID, chainId: 7622, chainUid: UID, order: mine, sellToken: TOKEN, dexes: [DEX, DEX2], now: NOW };
  const ok = checkTradeOrder(server(), want);
  assert.deepEqual(ok.warnings, []);
  assert.equal(ok.minFill, 0n, 'the signed minFill (no protocol floor, CTR-DEX-14)');
  assert.equal(hex(ok.digest), hex(hashTypedData(server())));
  const odd = { ...mine, amount: '1001' };
  assert.equal(checkTradeOrder(server(odd), { ...want, order: odd }).minFill, 0n);
  const some = { ...mine, minFill: '300' };
  assert.equal(checkTradeOrder(server(some), { ...want, order: some }).minFill, 300n);
  checkTradeOrder(server(), { ...want, order: { ...mine, validUntil: String(NOW + 600) } });
  const outsideMine = { ...mine, destination: '0x' + '00'.repeat(20) };
  const outsideWant = { ...want, account: ACCOUNT, order: outsideMine, outside: true, sellToken: OUT };
  checkTradeOrder(server({}, { outside: true }), outsideWant);
  assert.throws(() => checkTradeOrder(server(), { ...want, ua: false }), /a SCaaS sell token takes a UATradeOrder/);
  const away = { ...mine, destination: '0x' + '77'.repeat(32) };
  assert.deepEqual(checkTradeOrder(server(away), { ...want, order: away }).warnings, ['someone else receives the proceeds']);
  const open = { ...mine, relayer: '0x' + '00'.repeat(20) };
  assert.deepEqual(checkTradeOrder(server(open), { ...want, order: open }).warnings,
    ['any submitter may settle this order and earn the relayer share']);
  const escrow = { ...mine, flags: 3 };
  checkTradeOrder(server(escrow), { ...want, order: escrow });
  // C6-5: the chain refuses a nonce >= 2^128 (no lane floor can reach it)
  const big = server({ nonce: String(2n ** 128n) });
  assert.throws(() => checkTradeOrder(big, want), /nonce/);
  checkTradeOrder(server({ nonce: String(2n ** 128n - 1n) }), want);
  // a hostile server changes one field of the order the client built: refused (hostile probe cases included)
  const NOT = /this is not the trade order you asked for/;
  const changed = [
    server({ receiveAmount: '1' }), server({ receiveToken: ATK }), server({ amount: '1000000000' }),
    server({}, { sellToken: ATK }), server({ relayer: ATK }), server({ flags: 3 }), server({ flags: 4 }),
    server({ fee: '3001' }), server({ batch: '2' }), server({ minFill: '1' }), server({ dex: DEX2 }),
    server({ destination: ATK_ID }), server({ from: padId('0x' + 'bd'.repeat(20)) }), server({}, { dom: { salt: '0x' + '11'.repeat(32) } }),
    server({}, { outside: true }),                                       // a DexOrder where the client built a UATradeOrder
  ];
  for (const [i, bad] of changed.entries()) assert.throws(() => checkTradeOrder(bad, want), NOT, `changed ${i}`);
  assert.throws(() => checkTradeOrder(server({ validUntil: String(NOW + 601) }),
    { ...want, order: { ...mine, validUntil: String(NOW + 600) } }), NOT);
  for (const [i, bad] of [
    server({}, { outside: true, dom: { verifyingContract: ATK } }),       // a DexOrder signed for another DEX
    server({}, { outside: true, sellToken: ATK }),
    server(),
  ].entries()) assert.throws(() => checkTradeOrder(bad, outsideWant), NOT, `outside ${i}`);
  // the order the client built must itself be sane
  for (const [i, [o, why, extra]] of [
    [{ dex: '0x' + 'ee'.repeat(20) }, /DEX that is not on your chain profile/],
    [{ dex: WRAPPER, minFill: '1000' }, /DEX that is not on your chain profile/],    // not on the DEX list
    [{ dex: DEX, receiveToken: DEX }, /a wrap by signature is a WrapOrder/],         // the chain hashes it as one
    [{ dex: WRAPPER, receiveToken: WRAPPER, minFill: '1000', destination: '0x' + '00'.repeat(20) }, /a wrap by signature is a WrapOrder/,
      { outside: true, sellToken: OUT, account: ACCOUNT }],
    [{ fee: '10001' }, /the fee is above 1 %/],
    [{ flags: 2 }, /unknown order flags/],                                           // ESCROW without IOC
    [{ flags: 8 }, /unknown order flags/],
    [{ flags: 3, destination: '0x' + '00'.repeat(20) }, /unknown order flags/, { outside: true, sellToken: OUT, account: ACCOUNT }], // ESCROW outside (BadFlags)
    [{ flags: 'x' }, /the flags is not a number/],
    [{ minFill: '1001' }, /the amounts are malformed/],
    [{ amount: '0' }, /the amounts are malformed/],
    [{ receiveAmount: '0' }, /the amounts are malformed/],
    [{ validUntil: String(NOW) }, /deadline/],
    [{ validUntil: String(NOW + 30 * 86400 + 1) }, /deadline/],
  ].entries()) {
    const x = extra || {};
    const o2 = { ...mine, ...o };
    assert.throws(() => checkTradeOrder(server(o2, x), { ...want, ...x, order: o2 }), why, `shape ${i}`);
  }
  checkTradeOrder(server({ validUntil: String(NOW + 30 * 86400) }), want);
});

test('cancel: only the order the user holds or the lane the user chose, from the account, in the order\'s domain', () => {
  const order = cancelUAOrderTypedData({ name: 'SCaaS MetaToken', contract: TOKEN, chainId: 7622, chainUid: UID, message: { order: { from: ACCOUNT_ID,
    receiveToken: ATK, amount: 1000, receiveAmount: 2000, dex: '0x' + 'de'.repeat(20), nonce: 5, validUntil: NOW + 600 } } }).message.order;
  const want = { account: ACCOUNT_ID, chainId: 7622, chainUid: UID, contract: TOKEN, order, ua: true };
  const at = { name: 'SCaaS MetaToken', contract: TOKEN, chainId: 7622, chainUid: UID };
  const td = cancelUAOrderTypedData({ ...at, message: { order } });
  assert.equal(hex(checkCancel(td, want)), hex(hashTypedData(td)));
  const inv = { batch: 7, minNonce: 43 };
  const tdInv = uaInvalidateNoncesTypedData({ ...at, ...inv, from: ACCOUNT_ID });
  assert.equal(hex(checkCancel(tdInv, { ...want, order: undefined, invalidate: inv })), hex(hashTypedData(tdInv)));
  const short = cancelUAOrderTypedData({ ...at, message: { order } });
  short.message.order.nonce = '6';
  for (const [i, bad] of [
    cancelUAOrderTypedData({ ...at, message: { order: { ...order, nonce: 6 } } }),   // another order
    cancelUAOrderTypedData({ ...at, contract: ATK, message: { order } }),
    uaInvalidateNoncesTypedData({ ...at, ...inv, from: ATK_ID }),
    short,
    { ...td, primaryType: 'CancelOrder' },                                          // the token's address cancel (legacy)
  ].entries()) assert.throws(() => checkCancel(bad, want), /Refusing to sign/, `case ${i}`);
  assert.throws(() => checkCancel(td, { ...want, order: { ...order, from: ATK_ID } }), /not your order/);
  assert.throws(() => checkCancel(td, { ...want, order: undefined }), /not your order/);
  assert.throws(() => checkCancel(uaInvalidateNoncesTypedData({ ...at, ...inv, minNonce: 44, from: ACCOUNT_ID }),
    { ...want, order: undefined, invalidate: inv }), /not the cancel you asked for/);
  assert.throws(() => checkCancel(uaInvalidateNoncesTypedData({ ...at, ...inv, from: ATK_ID }),
    { ...want, order: undefined, invalidate: inv }), /not the cancel you asked for/);
  // the DEX's own lanes (an outside token's orders) keep the address `InvalidateNonces`
  const dex = { name: 'SCaaS Dex', contract: '0x' + 'de'.repeat(20), chainId: 7622, chainUid: UID };
  const dexInv = invalidateNoncesTypedData({ ...dex, ...inv, from: ACCOUNT });
  assert.equal(hex(checkCancel(dexInv, { account: ACCOUNT, chainId: 7622, chainUid: UID, contract: dex.contract, invalidate: inv })),
    hex(hashTypedData(dexInv)));
});

test('checkCancel: the UA invalidation resolves its builder', () => {
  const id = '0x' + 'ac'.repeat(32);
  const inv = { batch: 7, minNonce: 43 };
  const at = { contract: TOKEN, chainId: 7622, chainUid: UID };
  const td = uaInvalidateNoncesTypedData({ ...at, ...inv, from: id });
  assert.equal(hex(checkCancel(td, { account: id, ...at, invalidate: inv, ua: true })), hex(hashTypedData(td)));
});

const KEY_PROOF_ZERO = '0xfa7987471ecf88572865d4f53880fda17e67fadcae78beb98eb39504833f66de';

test('key proof message = keccak256("scaas-subject-key-proof-v1" ‖ challenge) (pinned with Odoo)', () => {
  assert.equal(hex(keyProofMessage(new Uint8Array(32))), KEY_PROOF_ZERO);
});

test('UA-5a: UAPayeeFee typed data and the receivers\' calldata (`cast calldata`, foundry 1.3.5); checkCall', () => {
  // test/v2/PayeeFee.t.sol test_payeeFeeDigestIsPinned: the typehash and the salted domain of the token
  const fields = (td) => td.types[td.primaryType].map((f) => `${f.type} ${f.name}`).join(',');
  const contract = '0x' + 'a1'.repeat(20);
  const ZERO_FEE_TO = '0x' + '00'.repeat(20);
  const chainUid = '0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464';
  const paymentDigest = hex(keccak_256(utf8ToBytes('payment')));
  const td = uaPayeeFeeTypedData({ name: 'SCaaS MetaToken', contract, chainId: 7622, chainUid, message: {
    payment: { from: padId(contract), to: padId(contract), value: 1, entryRef: paymentDigest, batch: 0, nonce: 0, validUntil: 1, mode: 1,
      relayer: contract, fee: 0, feeRecipient: ZERO_FEE_TO },
    fee: 3000000, feeRecipient: '0x0000000000000000000000000000000000000fee', validUntil: 1800000060 } });
  const typehash = '0x8a3955a6c3529266f588d56c7bfd28bdd0b5ad194fc9ca4428e159686a16c7ca';
  assert.equal(hex(keccak_256(utf8ToBytes(`UAPayeeFee(${fields(td)})UAMetaTransfer(${td.types.UAMetaTransfer.map((f) => `${f.type} ${f.name}`).join(',')})`))), typehash);
  const ds = hashStruct(td.types, 'EIP712Domain', td.domain);
  const sh = keccak_256(abiEncode(['bytes32', 'bytes32', 'uint256', 'address', 'uint256'],
    [typehash, hex(hashStruct(td.types, 'UAMetaTransfer', td.message.payment)), 3000000n,
      '0x0000000000000000000000000000000000000fee', 1800000060n]));
  assert.equal(hex(hashTypedData(td)), hex(keccak_256(new Uint8Array([0x19, 0x01, ...ds, ...sh]))));
  // cast calldata "wrapToUA(address,uint256,bytes32)" 0x5ca0…b1 1000000 0xabab…ab (likewise below)
  const U = '0x5ca00000000000000000000000000000000000b1';
  const TO = '0x' + 'ab'.repeat(32);
  const W = (n) => n.toString(16).padStart(64, '0');
  assert.equal(hex(wrapToUACall(U, 1000000n, TO)), '0x1b0237ad' + W(BigInt(U)) + W(1000000n) + 'ab'.repeat(32));
  assert.equal(hex(unwrapToUACall(U, 1000000n, TO, 990000n)),
    '0xe4a9f766' + W(BigInt(U)) + W(1000000n) + 'ab'.repeat(32) + W(990000n));
  // pay-meta-tax T41: `PayMeta` last; the entryRef its commitment (a salt-only meta here)
  const META = { salt: '0x' + '5a'.repeat(32) };
  const REF = metaPayId(META);
  const pw = hex(payWithFeeToUACalldata(TO, 100000000n, 2, 100000n, '0x0000000000000000000000000000000000000fee', REF, META));
  assert.equal(pw.slice(0, 10), hex(keccak_256(utf8ToBytes(
    'payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32,(bytes32,bytes32,bool,uint16,bytes))')).subarray(0, 4)));
  assert.equal(pw.slice(10, 10 + 64 * 7), 'ab'.repeat(32) + W(100000000n) + W(2n) + W(100000n) + W(0xfeen) + REF.slice(2) + W(224n));
  assert.equal(pw.slice(10 + 64 * 7, 10 + 64 * 8), '5a'.repeat(32), 'the tuple starts with the salt');
  // checkCall decodes the two allowlisted receivers; payWithFeeToUA is never signed as a call (as payWithFee)
  const k = legacyKat('metatx_kat.json');
  const allowlist = [{ selector: '0x1b0237ad', name: 'wrapToUA', feeClass: 1 },
    { selector: '0xe4a9f766', name: 'unwrapToUA', feeClass: 2, amountArg: 1 },
    { selector: '0x18c3a777', name: 'payWithFeeToUA', feeClass: 1 }];
  const run = (data, over = {}) => {
    const t = metaTxTypedData({ name: k.domain_name, contract: k.verifying_contract, chainId: 7622, chainUid: k.salt,
      message: { from: k.from, data, batch: k.batch, nonce: k.nonce, validUntil: k.valid_until, mode: 1, relayer: k.relayer,
        ...over } });
    return checkCall(t, { account: k.from, chainId: 7622, chainUid: k.salt, allowlist, maxFee: 10000,
      call: { contract: k.verifying_contract, data }, now: NOW });
  };
  assert.equal(run(hex(wrapToUACall(U, 1000000n, TO))).name, 'wrapToUA');
  const unwrap = hex(unwrapToUACall(U, 1000000n, TO, 0n));
  assert.equal(run(unwrap, { mode: 0x11, fee: '10000' }).fee, 10000n);   // PERCENT on wrapped (argument 1): 1 %
  assert.throws(() => run(hex(wrapToUACall(U, 1000000n, TO)), { mode: 0x11, fee: '1' }), /a percentage fee/);
  assert.throws(() => run(hex(payWithFeeToUACalldata(TO, 1n, 0, 0n, '0x' + '00'.repeat(20), REF, META))), /never signed as a call/);
});

test('payee fee: the payee co-signs UAPayeeFee nesting only the payment it expects, within its own bounds', () => {
  const FEE_TO = '0x' + '0f'.repeat(20);
  const payment = serverPayment();   // mode 1 (relayer bound), fee NONE, lane payLane(REF), nonce 0: CTR-MTX-06's shape
  const pd = hex(hashTypedData(payment));
  const rf = (over = {}, dom = {}, pay = {}) => {
    const t = uaPayeeFeeTypedData({ name: 'SCaaS MetaToken', contract: TOKEN, chainId: 7622, chainUid: UID, message: { payment: { ...payment.message, ...pay },
      fee: '3000000', feeRecipient: FEE_TO, validUntil: String(NOW + 60), ...over } });
    t.domain = { ...t.domain, ...dom };
    return t;
  };
  const want = { payee: PAYEE_ID, chainId: 7622, chainUid: UID, amount: '125000.5', decimals: 6, entryRef: REF,
    expectedToken: TOKEN, maxFee: '3000000', feeRecipient: FEE_TO, now: NOW };
  const ok = checkPayeeFee(rf(), want);
  assert.equal(hex(ok.digest), hex(hashTypedData(rf())));
  assert.deepEqual([hex(ok.paymentDigest), ok.payer, ok.fee, ok.feeRecipient], [pd, ACCOUNT_ID, 3000000n, FEE_TO]);
  const no = (td, w, why) => assert.throws(() => checkPayeeFee(td, { ...want, ...w }), why);
  // the payee's own bounds on fee / feeRecipient / deadline
  no(rf(), { maxFee: '2999999' }, /the fee is above your limit/);
  no(rf(), { maxFee: undefined }, /the fee is above your limit/);
  no(rf({ feeRecipient: ATK }), {}, /an address you did not name/);
  no(rf(), { feeRecipient: undefined }, /required/);
  no(rf({ fee: '0' }), {}, /no fee/);
  no(rf({ validUntil: String(NOW + 86401) }), {}, /deadline is not near/);
  no(rf({ validUntil: String(NOW) }), {}, /deadline is not near/);
  // the nested payment against the one the payee expects
  no(rf({}, {}, { to: ATK_ID }), {}, /does not pay you/);
  no(rf(), { amount: '125000.4' }, /the amount differs/);
  no(rf({ fee: '125000500001' }), { maxFee: '999999999999' }, /more than the payment/);
  no(rf(), { entryRef: '0x' + '0a'.repeat(32) }, /reference differs/);
  no(rf({}, {}, { nonce: '1' }), {}, /on its request lane/);
  no(rf({}, {}, { mode: 0x21, fee: '1' }), {}, /payee fee shape/);
  no(rf({}, {}, { mode: 0, relayer: '0x' + '00'.repeat(20) }), {}, /payee fee shape/);
  no(rf({}, { verifyingContract: ATK }), {}, /wrong token/);
  no(rf({}, { salt: '0x' + '11'.repeat(32) }), {}, /unexpected payee fee fields/);
  no({ ...rf(), primaryType: 'MetaTransfer' }, {}, /not a payee fee/);
  no({ ...rf(), primaryType: 'ReceiverFee' }, {}, /not a payee fee/);   // the address struct (legacy)
  no({ ...rf(), primaryType: 'UAReceiverFee' }, {}, /not a payee fee/); // the name before the payee-fee rename (legacy)
});

test('a bid\'s minFill from a base minimum and back (CLI-SGN-35)', () => {
  assert.equal(bidMinFill(10n, 1000n, 2000n), 5n);
  assert.equal(bidMinFill(7n, 1000n, 3000n), 3n, 'ceil(7000 / 3000)');
  assert.equal(bidMinBase(5n, 1000n, 2000n), 10n);
  assert.equal(bidMinBase(3n, 1000n, 3000n), 9n);
  assert.equal(bidMinFill(0n, 1000n, 2000n), 0n);
  assert.equal(bidMinBase(7n, 1000n, 3001n), 22n, 'ceil(21007 / 1000), floor is 21');
  assert.equal(bidMinBase(1n, 3000n, 1000n), 1n, 'ceil(1000 / 3000), floor is 0');
  for (const [x, a, r] of [[7n, 1000n, 3000n], [13n, 999n, 70n]]) {
    assert.ok(bidMinBase(bidMinFill(x, a, r), a, r) >= x, 'a round trip never lowers the minimum');
  }
  assert.throws(() => bidMinFill(1n, 0n, 2000n), /malformed/);
  assert.throws(() => bidMinFill(1n, 1000n, 0n), /malformed/);
  assert.throws(() => bidMinBase(1n, 0n, 2000n), /malformed/);
});

test('a base minimum that needs more than the bid\'s amount is refused', () => {
  assert.equal(bidMinFill(2000n, 1000n, 2000n), 1000n);
  assert.throws(() => bidMinFill(2001n, 1000n, 2000n), /more than the bid/);
});

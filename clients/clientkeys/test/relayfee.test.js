// CTR-MTX-27 (metatx split T18): a token fee for a fee-less call through `RelayFeeRouter`. `relayref.json` is written by
// forge (test/metatx/RelayFeeRouter.t.sol `test_relayRefVectors`) against the router itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { relayRef, payLane, buildRelayFee, metaTxTypedData, uaMetaTxTypedData, hashTypedData, padId, mtxExecuteCalldata,
  uaUnwrapTypedData, uaUnwrapCalldata, TYPED_OPS } from '../src/evm.js';
import { hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';

const R = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/metatx/relayref.json', import.meta.url)));
const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
const word = (b, i) => hex(b.subarray(4 + 32 * i, 4 + 32 * (i + 1)));

const TOKEN = '0x' + '7a'.repeat(20);
const ROUTER = '0x' + 'a0'.repeat(20);
const EXECUTOR = '0x' + 'e0'.repeat(20);
const TARGET = '0x' + 'c0'.repeat(20);
const PAYER = '0x' + '11'.repeat(20);
const SIGNER = '0x' + '44'.repeat(20);
const UID = '0x' + 'c1'.repeat(32);
const NOW = 1_800_000_000;
// ua-mtx-merge T11 (R21): the payment is `UARelayFee` between ids, the router's `relay(…, bytes32 from, bytes32 payee, …, UASig)`
const base = { token: TOKEN, chainId: 7622, chainUid: UID, router: ROUTER, executor: EXECUTOR, target: TARGET,
  from: padId(PAYER), amount: 25n, batch: 7, nonce: 2, validUntil: NOW + 300 }; // pay-meta-tax O4: the payer's own lane
const RELAY = `relay(address,bytes,address,bytes32,bytes32,uint256,uint256,uint256,uint256,${'(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])'})`;
const inner = (mode, relayer) => metaTxTypedData({ name: 'SCaaS TestRegistry', contract: TARGET, chainId: 7622,
  chainUid: UID, message: { from: SIGNER, data: '0x12345678', nonce: 4, validUntil: NOW + 300, mode, relayer } });

test('relayRef matches the contract vector', () => {
  assert.equal(R.length, 3);
  for (const r of R) {
    assert.equal(relayRef(r.chainId, r.target, r.callData), r.ref, r.name);
    assert.equal(payLane(r.ref), BigInt(r.payLane), r.name);
  }
  assert.notEqual(relayRef(1, R[0].target, R[0].callData), R[0].ref, 'the chain id is in ref');
});

test('buildRelayFee: open mode by default, one prompt with both intents, the router-bound payment', () => {
  const plan = buildRelayFee({ ...base, inner: inner(1, '0x' + '00'.repeat(20)) });
  // the inner envelope binds its relayer to the executor (the router never calls a target itself)
  assert.equal(plan.call.message.relayer, EXECUTOR);
  assert.equal(plan.call.message.mode, 1);
  assert.deepEqual(plan.prompt.call, { target: TARGET, op: 'MetaTransaction', message: plan.call.message, from: SIGNER, relayer: EXECUTOR });
  assert.deepEqual(plan.prompt.payment, { token: TOKEN, amount: 25n, payee: null, open: true });
  const callData = '0xdeadbeef';
  const p = plan.payment(callData);
  assert.equal(p.ref, relayRef(7622, TARGET, callData));
  assert.equal(p.lane, 7n, 'the payer\'s lane, not payLane(ref)');
  assert.equal(p.nonce, 2n);
  const m = p.typedData.message;
  assert.equal(p.typedData.primaryType, 'UARelayFee');
  assert.deepEqual([m.from, m.target, m.callDataHash, m.payee, m.value, m.batch, m.nonce, m.validUntil, m.relayer],
    [padId(PAYER), TARGET, hex(keccak_256(fromHex(callData))), padId(ROUTER), '25', '7', '2', String(NOW + 300), ROUTER]);
  assert.equal(hex(p.digest), hex(hashTypedData(p.typedData)));
  const cd = p.calldata(new Uint8Array(65));
  assert.equal(hex(cd.subarray(0, 4)), sel(RELAY));
  assert.equal(word(cd, 0), '0x' + '00'.repeat(12) + TARGET.slice(2));
  assert.equal(word(cd, 2), '0x' + '00'.repeat(12) + TOKEN.slice(2));
  assert.equal(word(cd, 3), padId(PAYER), 'from, an id');
  assert.equal(word(cd, 4), padId(ROUTER), 'payee: open mode, pad(router)');
});

test('buildRelayFee: an open inner envelope stays open; a bound payee; a derived payer', () => {
  const open = buildRelayFee({ ...base, inner: inner(0, '0x' + '00'.repeat(20)) });
  assert.equal(open.call.message.relayer, '0x' + '00'.repeat(20));
  const PAYEE = padId('0x' + '55'.repeat(20));
  const bound = buildRelayFee({ ...base, payee: PAYEE }).payment('0x');
  assert.equal(bound.typedData.message.payee, PAYEE);
  const derived = buildRelayFee({ ...base, from: '0x' + 'ab'.repeat(32) });
  assert.equal(derived.call, null);
  const u = derived.payment('0x01');
  assert.equal(u.typedData.primaryType, 'UARelayFee');
  assert.equal(u.typedData.message.payee, padId(ROUTER), 'open mode: payee = pad(router)');
  assert.equal(hex(u.calldata(new Uint8Array(2)).subarray(0, 4)), sel(RELAY));
  // an address where an id is signed is refused, never padded behind the user's back; the old router entry is gone
  assert.throws(() => buildRelayFee({ ...base, from: PAYER }).payment('0x'), /Refusing to sign/);
  assert.notEqual(sel(RELAY), sel(`uaRelay(address,bytes,address,bytes32,bytes32,uint256,uint256,${'(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])'})`));
});

test('mtxExecuteCalldata on a token: the UAMetaTransaction and a UASig (spec §2.3: one name, the struct by kind)', () => {
  const td = uaMetaTxTypedData({ contract: TARGET, chainId: 7622, chainUid: UID, message: { from: padId(SIGNER), data: '0x12345678',
    nonce: 4, validUntil: NOW + 300, mode: 1, relayer: EXECUTOR } });
  const cd = mtxExecuteCalldata(td, new Uint8Array(65).fill(9));
  assert.equal(hex(cd.subarray(0, 4)), sel(`mtxExecute((bytes32,bytes,uint256,uint256,uint256,uint32,address,uint256,address),${'(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])'})`));
  assert.equal(word(cd, 2), padId(SIGNER));
  assert.throws(() => mtxExecuteCalldata({ ...td, primaryType: 'UAMetaTransfer' }, new Uint8Array(65)), /Refusing to sign/);
});

test('mtxExecuteCalldata: the signed call the payment commits to', () => {
  const plan = buildRelayFee({ ...base, inner: inner(1, EXECUTOR) });
  const sig = new Uint8Array(65).fill(9);
  const cd = mtxExecuteCalldata(plan.call, sig);
  assert.equal(hex(cd.subarray(0, 4)),
    sel('mtxExecute((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)'));
  const w = (i) => BigInt(word(cd, i));
  assert.deepEqual([w(0), w(1)], [64n, 64n + 32n * 11n], 'm at 0x40; m = 9 head words + data (len, 1 word)');
  assert.equal(word(cd, 2), '0x' + '00'.repeat(12) + SIGNER.slice(2));
  assert.deepEqual([w(3), w(5), w(7)], [288n, 4n, 1n], 'data offset, nonce, mode');
  assert.equal(word(cd, 8), '0x' + '00'.repeat(12) + EXECUTOR.slice(2), 'relayer = executor');
  assert.deepEqual([w(11), hex(cd.subarray(4 + 32 * 12, 4 + 32 * 12 + 4))], [4n, '0x12345678']);
  assert.equal(w(13), 65n, 'signature length');
  assert.equal(cd.length, 4 + 32 * 17);
  assert.equal(plan.payment(cd).ref, relayRef(7622, TARGET, cd));
});

test('a named entry as the relayed call: fee 0, relayer bound to the executor; the payment commits to its calldata', () => {
  const td = uaUnwrapTypedData({ name: 'SCaaS MetaToken', contract: TARGET, chainId: 7622, chainUid: UID, message: { from: padId(SIGNER), wrapped: 7,
    recipient: SIGNER, validUntil: NOW + 300, mode: 1 } });
  const plan = buildRelayFee({ ...base, inner: td });
  assert.equal(plan.call.message.relayer, EXECUTOR);
  assert.deepEqual([plan.prompt.call.op, plan.prompt.call.relayer], ['UAUnwrap', EXECUTOR]);
  const cd = uaUnwrapCalldata(plan.call, new Uint8Array(65));
  assert.equal(hex(cd.subarray(0, 4)), sel(TYPED_OPS.UAUnwrap.call(plan.call, new Uint8Array(65)).abi));
  assert.ok(TYPED_OPS.UAUnwrap.call(plan.call, new Uint8Array(65)).abi.startsWith('mtxUnwrap('));
  const p = plan.payment(cd);
  assert.equal(p.typedData.message.callDataHash, hex(keccak_256(cd)));
  assert.equal(p.ref, relayRef(7622, TARGET, cd));
});

test('buildRelayFee refuses to pay the executor, an inner envelope bound elsewhere or on another contract', () => {
  assert.throws(() => buildRelayFee({ ...base, payee: padId(EXECUTOR) }), /executor/);
  assert.throws(() => buildRelayFee({ ...base, target: EXECUTOR }), /executor/);
  assert.throws(() => buildRelayFee({ ...base, inner: inner(1, '0x' + '99'.repeat(20)) }), /another relayer/);
  assert.throws(() => buildRelayFee({ ...base, target: TOKEN, inner: inner(1, EXECUTOR) }), /not on the target/);
});

test('buildRelayFee refuses an inner call on another chain or outliving its payment, a zero or token payee', () => {
  const ok = inner(1, EXECUTOR);
  assert.throws(() => buildRelayFee({ ...base, inner: { ...ok, domain: { ...ok.domain, chainId: '1' } } }), /another chain/);
  assert.throws(() => buildRelayFee({ ...base, inner: { ...ok, domain: { ...ok.domain, salt: '0x' + 'c2'.repeat(32) } } }),
    /another chain/);
  assert.throws(() => buildRelayFee({ ...base, validUntil: NOW + 299, inner: ok }), /outlives/);
  assert.equal(buildRelayFee({ ...base, validUntil: NOW + 300, inner: ok }).call.message.relayer, EXECUTOR);
  assert.throws(() => buildRelayFee({ ...base, payee: '0x' + '00'.repeat(32) }), /zero address/);
  assert.throws(() => buildRelayFee({ ...base, payee: padId(TOKEN) }), /token itself/);
});

test('buildRelayFee: the lane and nonce are the payer\'s and required (T38 / T41, O4)', () => {
  const { batch, nonce, ...noLane } = base;
  assert.throws(() => buildRelayFee(noLane), /lane is required/);
  assert.throws(() => buildRelayFee({ ...noLane, batch: 1 }), /nonce is required/);
  assert.equal(TYPED_OPS.UARelayFee.typeString, 'UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,'
    + 'uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)');
  assert.equal(TYPED_OPS.UARelayFee.typehash, '0x220269b9987739caf1274adfea8055b107d8e0a4b237683de5b13ae493e43ea5', 'RelayFeeRouter.t.sol pin');
});

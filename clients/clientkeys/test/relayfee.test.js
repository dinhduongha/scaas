// CTR-MTX-27 (metatx split T18): a token fee for a fee-less call through `MtxRelayFee`. `relayref.json` is written by
// forge (test/metatx/MtxRelayFee.t.sol `test_relayRefVectors`) against the router itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { relayRef, payLane, buildRelayFee, metaTxTypedData, hashTypedData, padId, mtxExecuteCalldata } from '../src/evm.js';
import { hex, keccak_256, utf8ToBytes } from '../src/bytes.js';

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
const base = { token: TOKEN, chainId: 7622, chainUid: UID, router: ROUTER, executor: EXECUTOR, target: TARGET,
  from: PAYER, amount: 25n, validUntil: NOW + 300 };
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
  assert.deepEqual(plan.prompt.call, { target: TARGET, data: '0x12345678', from: SIGNER, relayer: EXECUTOR });
  assert.deepEqual(plan.prompt.payment, { token: TOKEN, amount: 25n, payee: null, open: true });
  const callData = '0xdeadbeef';
  const p = plan.payment(callData);
  assert.equal(p.ref, relayRef(7622, TARGET, callData));
  assert.equal(p.lane, payLane(p.ref));
  const m = p.typedData.message;
  assert.equal(p.typedData.primaryType, 'MetaTransfer');
  assert.deepEqual([m.from, m.to, m.value, m.entryRef, m.batch, m.nonce, m.mode, m.relayer, m.fee],
    [PAYER, ROUTER, '25', p.ref, String(p.lane), '0', 1, ROUTER, '0']);
  assert.equal(hex(p.digest), hex(hashTypedData(p.typedData)));
  const cd = p.calldata(new Uint8Array(65));
  assert.equal(hex(cd.subarray(0, 4)), sel('relay(address,bytes,address,(address,address,uint256,bytes32,uint256,uint256,'
    + 'uint256,uint32,address,uint256,address),bytes)'));
  assert.equal(word(cd, 0), '0x' + '00'.repeat(12) + TARGET.slice(2));
  assert.equal(word(cd, 2), '0x' + '00'.repeat(12) + TOKEN.slice(2));
  assert.equal(word(cd, 6), p.ref, 't.entryRef');
});

test('buildRelayFee: an open inner envelope stays open; a bound payee; the UA path', () => {
  const open = buildRelayFee({ ...base, inner: inner(0, '0x' + '00'.repeat(20)) });
  assert.equal(open.call.message.relayer, '0x' + '00'.repeat(20));
  const PAYEE = '0x' + '55'.repeat(20);
  const bound = buildRelayFee({ ...base, payee: PAYEE }).payment('0x');
  assert.equal(bound.typedData.message.to, PAYEE);
  const ua = buildRelayFee({ ...base, from: padId(PAYER), ua: true });
  assert.equal(ua.call, null);
  const u = ua.payment('0x01');
  assert.equal(u.typedData.primaryType, 'UAMetaTransfer');
  assert.equal(u.typedData.message.to, padId(ROUTER), 'open mode on the UA path: to = pad(router)');
  assert.equal(hex(u.calldata(new Uint8Array(2)).subarray(0, 4)), sel('uaRelay(address,bytes,address,(bytes32,bytes32,'
    + 'uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address),bytes)'));
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

test('buildRelayFee refuses to pay the executor, an inner envelope bound elsewhere or on another contract', () => {
  assert.throws(() => buildRelayFee({ ...base, payee: EXECUTOR }), /executor/);
  assert.throws(() => buildRelayFee({ ...base, from: padId(PAYER), ua: true, payee: padId(EXECUTOR) }), /executor/);
  assert.throws(() => buildRelayFee({ ...base, target: EXECUTOR }), /executor/);
  assert.throws(() => buildRelayFee({ ...base, inner: inner(1, '0x' + '99'.repeat(20)) }), /another relayer/);
  assert.throws(() => buildRelayFee({ ...base, target: TOKEN, inner: inner(1, EXECUTOR) }), /not on the target/);
});

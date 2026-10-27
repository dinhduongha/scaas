// CTR-MTX-26 (metatx split T18): the payment id commits to its metadata. `paymeta.json` is written by forge
// (test/metatx/PayMeta.t.sol) and read by every family; clientkeys rebuilds every row and the pay-meta envelopes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  metaPayId, payLane, encodeMeta, decodeMeta, buildMtxPayMeta, buildUaPayMeta, checkPayMeta, hashTypedData,
  metaTransferTypedData, padId,
} from '../src/evm.js';
import { hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';

const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/metatx/paymeta.json', import.meta.url)));
const R = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/metatx/relayref.json', import.meta.url)));
const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
const row = (name) => V.find((r) => r.name === name);

const TOKEN = '0x' + '7a'.repeat(20);
const PAYER = '0x' + '11'.repeat(20);
const PAYEE = '0x' + '22'.repeat(20);
const LANE = '0x' + '33'.repeat(20);
const UID = '0x' + 'c1'.repeat(32);
const NOW = 1_800_000_000;
const base = { token: TOKEN, chainId: 7622, chainUid: UID, from: PAYER, to: PAYEE, amount: 1000n, validUntil: NOW + 600,
  mode: 1, relayer: LANE };

test('paymeta vectors', () => {
  assert.equal(V.length, 6);
  for (const r of V) {
    assert.equal(metaPayId(r.salt, r.meta), r.payId, r.name);
    assert.equal(payLane(r.payId), BigInt(r.payLane), r.name);
    const d = decodeMeta(r.meta);
    assert.equal(d.schema, r.schema, r.name);
    assert.equal(hex(encodeMeta(d.schema, d.body)), r.meta, `${r.name}: canonical envelope`);
  }
  assert.deepEqual(decodeMeta(row('note_utf8').meta).shown, { note: 'Hóa đơn 2026-0042 — cảm ơn' });
  assert.deepEqual(decodeMeta(row('empty_body').meta).shown, { note: '' });
  assert.deepEqual(decodeMeta(row('structured_reference').meta).shown,
    { creditorRef: 'RF18539007547034', invoiceNo: 'INV-2026-0042', dueDate: 1830297600n });
  const bound = decodeMeta(row('bound_call').meta).shown;
  const call = R.find((x) => x.name === 'cancel_nonce_7');
  assert.deepEqual(bound, { chainId: 7622n, target: '0x' + '00'.repeat(29) + 'c0ffee', callHash: call.callHash },
    'schema 3 commits to the relay-fee vector call');
  assert.deepEqual(decodeMeta(row('encrypted_illustrative').meta).shown, { encrypted: 96 });
});

test('decodeMeta refuses a non-canonical envelope or an unknown schema', () => {
  const m = fromHex(row('note_utf8').meta);
  const longer = new Uint8Array([...m, 0]);
  assert.throws(() => decodeMeta(longer), /Refusing to sign/);
  const offset = m.slice(); offset[63] = 0x60;
  assert.throws(() => decodeMeta(offset), /Refusing to sign/);
  assert.throws(() => decodeMeta(encodeMeta(9, new Uint8Array(0))), /unknown metadata schema/);
  assert.throws(() => decodeMeta(encodeMeta(1, new Uint8Array([0xff, 0xfe]))), /UTF-8/);
});

test('refuses a payId that does not commit to meta', () => {
  const r = row('note_utf8');
  const other = row('empty_body').payId;
  assert.throws(() => buildMtxPayMeta({ ...base, salt: r.salt, meta: r.meta, entryRef: other }), /does not commit/);
  assert.throws(() => buildUaPayMeta({ ...base, from: padId(PAYER), to: padId(PAYEE), salt: r.salt, meta: r.meta,
    entryRef: other }), /does not commit/);
  // server typed data whose entryRef is another payId (a different meta, or the same meta with another salt)
  const td = metaTransferTypedData({ contract: TOKEN, chainId: 7622, chainUid: UID, message: { from: PAYER, to: PAYEE,
    value: 1000n, entryRef: other, batch: payLane(other), nonce: 0, validUntil: NOW + 600, mode: 1, relayer: LANE } });
  const opts = { account: PAYER, chainId: 7622, chainUid: UID, amount: '1000', decimals: 0, payee: PAYEE,
    expectedToken: TOKEN, now: NOW, salt: r.salt, meta: r.meta };
  assert.throws(() => checkPayMeta(td, opts), /does not commit/);
  assert.throws(() => checkPayMeta(td, { ...opts, salt: row('empty_body').salt }), /does not commit/);
});

test('mtxPayMeta: the payment is mtxPay with payId = metaPayId(salt, meta), lane payLane, nonce 0', () => {
  const r = row('structured_reference');
  const p = buildMtxPayMeta({ ...base, salt: r.salt, meta: r.meta, entryRef: r.payId });
  assert.equal(p.payId, r.payId);
  assert.equal(p.lane, BigInt(r.payLane));
  assert.equal(p.typedData.primaryType, 'MetaTransfer');
  assert.equal(p.typedData.message.entryRef, r.payId);
  assert.equal(p.typedData.message.batch, String(BigInt(r.payLane)));
  assert.equal(p.typedData.message.nonce, '0');
  assert.equal(p.typedData.message.relayer, LANE);
  assert.equal(hex(p.digest), hex(hashTypedData(p.typedData)));
  assert.equal(p.shown.invoiceNo, 'INV-2026-0042');
  const sig = new Uint8Array(65).fill(7);
  const cd = p.calldata(sig);
  assert.equal(hex(cd.subarray(0, 4)),
    sel('mtxPayMeta(address,address,uint256,bytes32,bytes,uint256,uint32,address,uint256,address,bytes)'));
  assert.equal(hex(cd.subarray(4 + 32 * 3, 4 + 32 * 4)), r.salt, 'salt is the 4th argument');
  // the off-chain variant: plain mtxPay with the same payId, the same digest; meta stays with the payee
  const off = buildMtxPayMeta({ ...base, salt: r.salt, meta: r.meta, onChain: false });
  assert.equal(hex(off.digest), hex(p.digest));
  const ocd = off.calldata(sig);
  assert.equal(hex(ocd.subarray(0, 4)),
    sel('mtxPay(address,address,uint256,bytes32,uint256,uint32,address,uint256,address,bytes)'));
  assert.equal(hex(ocd.subarray(4 + 32 * 3, 4 + 32 * 4)), r.payId);
});

test('uaPayMeta: UAMetaTransfer between ids, uaPayMeta / uaPay calldata', () => {
  const r = row('note_utf8');
  const p = buildUaPayMeta({ ...base, from: padId(PAYER), to: padId(PAYEE), salt: r.salt, meta: r.meta });
  assert.equal(p.typedData.primaryType, 'UAMetaTransfer');
  assert.equal(p.typedData.message.from, padId(PAYER));
  assert.equal(p.typedData.message.entryRef, r.payId);
  assert.equal(p.typedData.message.batch, String(BigInt(r.payLane)));
  const cd = p.calldata(new Uint8Array(3));
  assert.equal(hex(cd.subarray(0, 4)),
    sel('uaPayMeta(bytes32,bytes32,uint256,bytes32,bytes,uint256,uint32,address,uint256,address,bytes)'));
  const off = buildUaPayMeta({ ...base, from: padId(PAYER), to: padId(PAYEE), salt: r.salt, meta: r.meta, onChain: false });
  assert.equal(hex(off.calldata(new Uint8Array(3)).subarray(0, 4)),
    sel('uaPay(bytes32,bytes32,uint256,bytes32,uint256,uint32,address,uint256,address,bytes)'));
});

test('checkPayMeta: server typed data for the committed payId passes and returns the decoded meta', () => {
  const r = row('note_utf8');
  const td = metaTransferTypedData({ contract: TOKEN, chainId: 7622, chainUid: UID, message: { from: PAYER, to: PAYEE,
    value: 1000n, entryRef: r.payId, batch: payLane(r.payId), nonce: 0, validUntil: NOW + 600, mode: 1, relayer: LANE } });
  const got = checkPayMeta(td, { account: PAYER, chainId: 7622, chainUid: UID, amount: '1000', decimals: 0, payee: PAYEE,
    expectedToken: TOKEN, now: NOW, salt: r.salt, meta: r.meta });
  assert.equal(got.entryRef, r.payId);
  assert.equal(got.schema, 1);
  assert.deepEqual(got.shown, { note: 'Hóa đơn 2026-0042 — cảm ơn' });
  assert.equal(hex(got.digest), hex(hashTypedData(td)));
});

// CTR-MTX-26 (pay-meta-tax spec §3, T41; plan T83, owner 2026-11-09): `PayMeta {salt, payNo, save, schema, body}`, the last
// parameter of every pay entry, and its commitment under `scaas.pay.meta.v3`; `payNo` 32 bytes (recommended a right-aligned
// UUIDv7). `paymeta.json` and `payrecords.json` are written by forge (test/metatx/PayMeta.t.sol, PayRecords.t.sol); clientkeys
// rebuilds every row, the bodies from named fields, and the pay entries' calldata. The non-EVM families read the old file
// (vectors/metatx/legacy/ua-mtx-merge/paymeta.json, `metaPayIdV1`) until their round.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  metaPayId, metaPayIdV1, payMeta, payNoFromUuid, payNoToUuid, encodeMetaBody, decodeMetaBody, payMetaWarning, buildPay, buildPayReceiverFee,
  checkPayMeta, hashTypedData, uaMetaTransferTypedData, padId, payLane, payWithFeeToUACalldata,
} from '../src/evm.js';
import { hex, fromHex, keccak_256, utf8ToBytes, abiEncode } from '../src/bytes.js';

const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/metatx/paymeta.json', import.meta.url)));
const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
const row = (name) => V.find((r) => r.name === name);
const metaOf = (r) => ({ salt: r.salt, payNo: r.payNo, save: r.save, schema: r.schema, body: r.body });
const R = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/metatx/payrecords.json', import.meta.url)));

const TOKEN = '0x' + '7a'.repeat(20);
const PAYER = '0x' + '11'.repeat(20);
const PAYEE = '0x' + '22'.repeat(20);
const LANE = '0x' + '33'.repeat(20);
const FEE_TO = '0x' + '44'.repeat(20);
const UID = '0x' + 'c1'.repeat(32);
const NOW = 1_800_000_000;
const base = { token: TOKEN, chainId: 7622, chainUid: UID, from: padId(PAYER), to: padId(PAYEE), amount: 1000n, validUntil: NOW + 600,
  mode: 1, relayer: LANE };
const SIG = '(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])';
const PM = '(bytes32,bytes32,bool,uint16,bytes)';
const UMT = '(bytes32,bytes32,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)';

test('paymeta.json v3: every accepted row is metaPayId(PayMeta); save without a payNo refused; save and the tag committed', () => {
  assert.equal(V.length, 9);
  for (const r of V) {
    if (!r.accepted) {
      assert.throws(() => metaPayId(metaOf(r)), /save needs a payment number/, r.name);
      continue;
    }
    assert.equal(metaPayId(metaOf(r)), r.payId, r.name);
    assert.equal(decodeMetaBody(r.schema, r.body) !== null, true);
    if (r.payNoUuid) {
      assert.equal(payNoFromUuid(r.payNoUuid), r.payNo, `${r.name}: the UUIDv7 right-aligned`);
      assert.equal(payNoToUuid(r.payNo), r.payNoUuid, `${r.name}: shown as its UUID`);
    }
  }
  const v2 = row('payno_uuidv7');
  assert.notEqual(v2.v2TagPayId, v2.payId);
  assert.equal(hex(keccak_256(new Uint8Array([...utf8ToBytes('scaas.pay.meta.v2'), ...fromHex(v2.salt),
    ...keccak_256(abiEncode(['bytes32', 'bool', 'uint16', 'bytes'], [v2.payNo, false, 0, '0x']))]))), v2.v2TagPayId, 'C1: the v2 tag');
  const saved = row('payno_uuidv7_save');
  assert.equal(metaPayId({ ...metaOf(saved), save: false }), saved.saveOffPayId, 'save off: another commitment');
  assert.notEqual(saved.saveOffPayId, saved.payId);
  assert.equal(payNoToUuid(row('payno_any32_save').payNo), null, 'a 32-byte id that is no UUID: shown as hex');
  assert.equal(payNoToUuid(row('salt_only').payNo), null, '0: none');
});

test('payNoFromUuid / payNoToUuid: UUIDv7 only, right-aligned, any case in', () => {
  const u = '019a6e3c-5f00-7a3b-8c4d-5e6f708192a3';
  assert.equal(payNoFromUuid(u.toUpperCase()), '0x' + '00'.repeat(16) + u.replaceAll('-', ''));
  assert.throws(() => payNoFromUuid('019a6e3c-5f00-4a3b-8c4d-5e6f708192a3'), /not a UUIDv7/, 'version 4');
  assert.throws(() => payNoFromUuid('019a6e3c-5f00-7a3b-cc4d-5e6f708192a3'), /not a UUIDv7/, 'variant 110');
  assert.throws(() => payNoFromUuid('019a6e3c5f007a3b8c4d5e6f708192a3'), /not a UUIDv7/, 'no hyphens');
  assert.throws(() => payNoFromUuid('INV-2026-0042'), /not a UUIDv7/);
  assert.equal(payNoToUuid('0x' + '01'.repeat(32)), null, 'the high 16 bytes set');
  assert.equal(payNoToUuid('0x' + '00'.repeat(16) + '019a6e3c5f004a3b8c4d5e6f708192a3'), null, 'version 4: hex');
});

test('payrecords.json: the row an ERP reads by eth_call (paymentCount, paymentsOf pages) and the slots', () => {
  assert.equal(R.payNo, payNoFromUuid(R.payNoUuid));
  const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
  assert.equal(R.paymentCount.calldata, sel('paymentCount(bytes32)') + R.payNo.slice(2));
  assert.equal(R.paymentsOfAll.calldata, hex(new Uint8Array([...fromHex(sel('paymentsOf(bytes32,uint256,uint256)')),
    ...abiEncode(['bytes32', 'uint256', 'uint256'], [R.payNo, 0n, 10n])])));
  const recs = (r) => R.records.slice(r[0], r[1]).map((x) => [x.to, BigInt(x.amount), BigInt(x.blockNumber)]);
  assert.equal(R.paymentsOfAll.returndata, hex(abiEncode(['(bytes32,uint192,uint64)[]'], [recs([0, 2])])));
  assert.equal(R.paymentsOfSecond.returndata, hex(abiEncode(['(bytes32,uint192,uint64)[]'], [recs([1, 2])])));
  assert.equal(R.paymentsOfPastEnd.returndata, hex(abiEncode(['(bytes32,uint192,uint64)[]'], [[]])));
  assert.equal(R.paymentCount.returndata, hex(abiEncode(['uint256'], [2n])));
  const root = BigInt(hex(keccak_256(abiEncode(['uint256'], [BigInt(hex(keccak_256(utf8ToBytes('scaas.pay.records')))) - 1n])))) & ~0xffn;
  assert.equal(BigInt(R.root), root, 'ERC-7201 of scaas.pay.records');
  const len = hex(keccak_256(abiEncode(['bytes32', 'uint256'], [R.payNo, root])));
  assert.equal(R.lengthSlot, len);
  const data = BigInt(hex(keccak_256(fromHex(len))));
  R.records.forEach((x, i) => assert.deepEqual(x.slots.map(BigInt), [data + 2n * BigInt(i), data + 2n * BigInt(i) + 1n]));
});

test('the bodies from named fields: each schema equals the forge row', () => {
  assert.deepEqual(decodeMetaBody(1, row('note_utf8').body), { note: 'Hóa đơn 2026-0042 — cảm ơn' });
  assert.equal(hex(encodeMetaBody(1, { note: 'Hóa đơn 2026-0042 — cảm ơn' })), row('note_utf8').body);
  const sr = { creditorRef: 'RF18539007547034', dueDate: 1830297600n };
  assert.deepEqual(decodeMetaBody(2, row('structured_reference').body), sr);
  assert.equal(hex(encodeMetaBody(2, sr)), row('structured_reference').body, 'schema 2: (string creditorRef, uint64 dueDate), no invoiceNo');
  const bc = decodeMetaBody(3, row('bound_call').body);
  assert.equal(bc.chainId, 7622n);
  assert.equal(hex(encodeMetaBody(3, bc)), row('bound_call').body);
  assert.deepEqual(decodeMetaBody(4, row('encrypted_illustrative').body), { encrypted: 96 });
  assert.equal(hex(encodeMetaBody(4, { ciphertext: row('encrypted_illustrative').body })), row('encrypted_illustrative').body);
  const named = payMeta({ salt: row('structured_reference').salt, payNo: payNoFromUuid('019a6e3c-5f00-7a3b-8c4d-5e6f708192a3'),
    save: true, schema: 2, fields: sr });
  assert.equal(metaPayId(named), row('structured_reference').payId, 'built from fields, the same commitment');
  assert.deepEqual(decodeMetaBody(9, '0x0102'), { opaque: 2 }, 'an unknown schema is opaque data, never facts');
});

test('PayMeta shape refuses before signing; payNo is 32 bytes, never text', () => {
  const s = row('salt_only').salt;
  assert.throws(() => payMeta({ salt: '0x' + '00'.repeat(32) }), /salt is 0/);
  assert.throws(() => payMeta({ salt: s, schema: 0, body: '0x01' }), /schema 0 iff/);
  assert.throws(() => payMeta({ salt: s, schema: 1, body: '0x' }), /schema 0 iff/);
  assert.throws(() => encodeMetaBody(1, { note: '' }), /non-empty/);
  assert.throws(() => payMeta({ salt: s, payNo: 'INV-2026-0042' }), /32 bytes/, 'a text payNo (v2) is refused');
  assert.throws(() => payMeta({ salt: s, payNo: '0x' + '01'.repeat(31) }), /32 bytes/);
  assert.throws(() => payMeta({ salt: s, save: true }), /save needs a payment number/);
  assert.throws(() => payMeta({ salt: s, payNo: '0x' + '01'.repeat(32), save: 'true' }), /true or false/);
  assert.equal(payMeta({ salt: s }).payNo, '0x' + '00'.repeat(32), '0 = none by default');
  assert.equal(payMeta({ salt: s }).save, false);
  const fresh = payMeta({});
  assert.match(fresh.salt, /^0x[0-9a-f]{64}$/);
  assert.notEqual(BigInt(fresh.salt), 0n, 'a CSPRNG salt when none is given');
});

test('the clear-metadata warning: once per payee per session, none for schema 0 or 4 without a payNo', () => {
  const session = new Set();
  const clear = metaOf(row('structured_reference'));
  assert.match(payMetaWarning(clear, padId(PAYEE), session), /in clear/);
  assert.equal(payMetaWarning(clear, padId(PAYEE), session), null, 'once per payee');
  assert.match(payMetaWarning(metaOf(row('note_utf8')), padId(PAYER), session), /in clear/, 'another payee');
  assert.equal(payMetaWarning({ ...metaOf(row('encrypted_illustrative')), payNo: '0x' + '00'.repeat(32) }, padId(LANE), new Set()),
    null, 'schema 4 without a payNo');
  assert.match(payMetaWarning(metaOf(row('encrypted_illustrative')), padId(LANE), new Set()), /in clear/, 'schema 4 with a payNo');
  assert.equal(payMetaWarning(metaOf(row('salt_only')), padId(LANE), new Set()), null);
  assert.match(payMetaWarning(metaOf(row('payno_uuidv7')), padId(LANE), new Set()), /in clear/);
});

test('buildPay: mtxPay(t, UASig, PayMeta) with entryRef = metaPayId(meta); any lane, the request lane by default', () => {
  const r = row('structured_reference');
  const p = buildPay({ ...base, meta: metaOf(r), entryRef: r.payId });
  assert.equal(p.payId, r.payId);
  assert.equal(p.typedData.primaryType, 'UAMetaTransfer');
  assert.equal(p.typedData.message.entryRef, r.payId);
  assert.equal(p.typedData.message.batch, String(payLane(r.payId)));
  assert.equal(hex(p.digest), hex(hashTypedData(p.typedData)));
  assert.equal(p.shown.payNo, r.payNo);
  assert.equal(p.shown.payNoUuid, '019a6e3c-5f00-7a3b-8c4d-5e6f708192a3');
  assert.equal(p.shown.save, true);
  assert.equal(p.shown.creditorRef, 'RF18539007547034');
  const cd = p.calldata(new Uint8Array(65).fill(7));
  assert.equal(hex(cd.subarray(0, 4)), sel(`mtxPay(${UMT},${SIG},${PM})`));
  const free = buildPay({ ...base, meta: metaOf(r), batch: 7, nonce: 3 });
  assert.equal(free.typedData.message.batch, '7', 'O3: a free lane');
  assert.equal(free.typedData.message.nonce, '3');
  assert.throws(() => buildPay({ ...base, meta: metaOf(r), entryRef: row('note_utf8').payId }), /does not commit/);
  assert.throws(() => buildPay({ ...base, meta: { salt: r.salt, save: true } }), /save needs/, 'refused before signing');
  assert.throws(() => buildPay({ ...base }), /payment metadata is required/, 'never empty (O11)');
});

test('a digest with a non-zero unbound relayer / feeRecipient is the canonical one (MetaTxLib.canon)', () => {
  const r = row('salt_only');
  const unbound = buildPay({ ...base, mode: 0, relayer: '0x' + 'de'.repeat(20), feeRecipient: '0x' + 'be'.repeat(20), meta: metaOf(r) });
  const zero = buildPay({ ...base, mode: 0, relayer: '0x' + '00'.repeat(20), meta: metaOf(r) });
  assert.equal(hex(unbound.digest), hex(zero.digest));
});

test('buildPayReceiverFee: the payer\'s mode-1 payment, the payee\'s UAReceiverFee, PayMeta last', () => {
  const r = row('note_utf8');
  const p = buildPayReceiverFee({ ...base, meta: metaOf(r), fee: 30n, feeRecipient: FEE_TO, rfValidUntil: NOW + 60 });
  assert.equal(p.typedData.primaryType, 'UAReceiverFee');
  assert.equal(p.typedData.message.payment.entryRef, r.payId);
  const cd = p.calldata(new Uint8Array(65).fill(1), new Uint8Array(65).fill(2));
  assert.equal(hex(cd.subarray(0, 4)), sel(`mtxPayReceiverFee(${UMT},${SIG},uint256,address,uint256,${SIG},${PM})`));
});

test('payWithFeeToUA carries PayMeta; checkPayMeta refuses a server entryRef over another meta', () => {
  const r = row('payno_uuidv7');
  const cd = payWithFeeToUACalldata(padId(PAYEE), 5, 0, 0, '0x' + '00'.repeat(20), r.payId, metaOf(r));
  assert.equal(hex(cd.subarray(0, 4)), sel(`payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32,${PM})`));
  assert.throws(() => payWithFeeToUACalldata(padId(PAYEE), 5, 0, 0, '0x' + '00'.repeat(20), row('salt_only').payId, metaOf(r)),
    /does not commit/);
  const other = row('salt_only').payId;
  const td = uaMetaTransferTypedData({ contract: TOKEN, chainId: 7622, chainUid: UID, message: { from: padId(PAYER), to: padId(PAYEE),
    value: 1000n, entryRef: other, batch: payLane(other), nonce: 0, validUntil: NOW + 600, mode: 1, relayer: LANE } });
  const opts = { account: padId(PAYER), chainId: 7622, chainUid: UID, amount: '1000', decimals: 0, payee: padId(PAYEE),
    expectedToken: TOKEN, now: NOW, meta: metaOf(r) };
  assert.throws(() => checkPayMeta(td, opts), /does not commit/);
  const ok = uaMetaTransferTypedData({ contract: TOKEN, chainId: 7622, chainUid: UID, message: { ...td.message, entryRef: r.payId,
    batch: payLane(r.payId) } });
  assert.equal(checkPayMeta(ok, opts).payId, r.payId);
});

test('metaPayIdV1 stays for the non-EVM families: the legacy file still matches it', () => {
  const L = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/metatx/legacy/ua-mtx-merge/paymeta.json', import.meta.url)));
  for (const r of L) assert.equal(metaPayIdV1(r.salt, r.meta), r.payId, r.name);
});

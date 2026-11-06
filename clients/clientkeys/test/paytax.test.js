// pay-meta-tax spec §5 (T41): `paytax.json` (written by forge, test/as/Tax.t.sol) against clientkeys: the PERCENT floor at
// every rate and amount row, the AMOUNT and refused rows, and the `UAPayWithTax` digest with a non-zero unbound relayer /
// feeRecipient; `buildPayWithTax` on `mtxPayWithTax(t, taxMode, tax, UASig, PayMeta)`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { percentTax, buildPayWithTax, hashStruct, hashTypedData, uaPayWithTaxTypedData, TYPED_OPS, padId } from '../src/evm.js';
import { hex, keccak_256, utf8ToBytes } from '../src/bytes.js';

const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/metatx/paytax.json', import.meta.url)));
const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));

test('paytax.json: PERCENT is the floor at the rate (2^255 included); refused rows refused by buildPayWithTax', () => {
  const rows = V.filter((r) => r.taxMode !== undefined && r.name.startsWith('percent') || r.name.startsWith('amount') || r.name.startsWith('mode'));
  assert.equal(V.length, 25);
  for (const r of rows) {
    const [amount, tax] = [BigInt(r.amount), BigInt(r.tax)];
    if (r.taxMode === 1 && r.refused === '') assert.equal(percentTax(amount, r.ratePpm), tax, r.name);
    const pay = { token: '0x' + '7a'.repeat(20), chainId: 7622, chainUid: '0x' + 'c1'.repeat(32), from: padId('0x' + '11'.repeat(20)),
      to: padId('0x' + '22'.repeat(20)), amount, validUntil: 1800000600, meta: { salt: '0x' + '5a'.repeat(32) } };
    const build = () => buildPayWithTax({ ...pay, taxMode: r.taxMode, tax, ratePpm: r.ratePpm });
    if (r.refused) assert.throws(build, /Refusing to sign/, r.name);
    else assert.equal(build().typedData.message.tax, String(tax), r.name);
  }
  const half = V.find((r) => r.name === 'percent_floor_not_half_up');
  assert.equal(half.tax, '100', '100.5 floors to 100');
});

test('the UAPayWithTax digest row: canonical payment hash, struct hash, digest in its fixed domain', () => {
  const r = V.find((x) => x.name === 'digest_unbound_relayer_fee_recipient');
  assert.notEqual(r.relayer, '0x' + '00'.repeat(20), 'a non-zero unbound relayer in the input');
  assert.equal(TYPED_OPS.UAPayWithTax.typehash, r.typehash);
  const payment = { from: r.from, to: r.to, value: r.value, entryRef: r.entryRef, batch: r.batch, nonce: r.nonce, validUntil: r.validUntil,
    mode: r.mode, relayer: r.relayer, fee: r.fee, feeRecipient: r.feeRecipient };
  const td = uaPayWithTaxTypedData({ name: r.domain.name, contract: r.domain.verifyingContract, chainId: r.domain.chainId,
    chainUid: r.domain.salt, message: { payment, taxMode: r.taxMode, tax: r.tax } });
  assert.equal(hex(hashStruct(td.types, 'UAMetaTransfer', td.message.payment)), r.paymentHash);
  assert.equal(hex(hashStruct(td.types, 'UAPayWithTax', td.message)), r.structHash);
  assert.equal(hex(hashTypedData(td)), r.digest);
});

test('buildPayWithTax: mtxPayWithTax(t, uint8, uint256, UASig, PayMeta); the rate check; tax <= amount', () => {
  const pay = { token: '0x' + '7a'.repeat(20), chainId: 7622, chainUid: '0x' + 'c1'.repeat(32), from: padId('0x' + '11'.repeat(20)),
    to: padId('0x' + '22'.repeat(20)), amount: 1000n, validUntil: 1800000600, meta: { salt: '0x' + '5a'.repeat(32), payNo: 'INV-1' },
    batch: 4, nonce: 9 };
  const p = buildPayWithTax({ ...pay, taxMode: 1, tax: 100, ratePpm: 100000, taxRecipient: padId('0x' + '7a0'.padStart(40, '0')) });
  assert.equal(p.typedData.primaryType, 'UAPayWithTax');
  assert.equal(p.typedData.message.payment.batch, '4', 'the payer\'s own lane');
  assert.equal(p.shown.payNo, 'INV-1');
  const cd = p.calldata(new Uint8Array(65).fill(9));
  assert.equal(hex(cd.subarray(0, 4)), sel('mtxPayWithTax((bytes32,bytes32,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,'
    + 'address),uint8,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]),(bytes32,string,uint16,bytes))'));
  assert.throws(() => buildPayWithTax({ ...pay, taxMode: 1, tax: 101, ratePpm: 100000 }), /rate/);
  assert.throws(() => buildPayWithTax({ ...pay, taxMode: 2, tax: 1001 }), /more than the payment/);
  assert.throws(() => buildPayWithTax({ ...pay, taxMode: 0, tax: 0 }), /tax mode/);
});

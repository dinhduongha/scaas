// smartcontracts/vectors/ua/liquidity_kat.json (spec 2026-11-10-dex-liquidity.md §12): each row's typed data hashes to its
// `h`, `liquidityOrderTypedData` rebuilds it from the row's order, the native rows recover the signer, the p256 row verifies
// with noble over sha256(uaMessage(p256, trade, h)); `checkLiquidityOrder` accepts the rows and refuses each shape it names.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as ua from '../src/ua.js';
import { hex, fromHex, keccak_256, concatBytes } from '../src/bytes.js';
import { hashTypedData, hashStruct, liquidityOrderTypedData, checkLiquidityOrder, checkLiquiditySettled, padId } from '../src/evm.js';
import { dir } from './ua-vectors-dir.js';

const V = JSON.parse(readFileSync(new URL('liquidity_kat.json', dir)));
const at = { chainId: V.chainId, chainUid: V.chainUid };
const now = 1_800_000_000;

const recover = (sig, digest) => {
  const s = fromHex(sig);
  const rec = secp256k1.Signature.fromBytes(s.subarray(0, 64), 'compact').addRecoveryBit(s[64] - 27);
  return padId(hex(keccak_256(rec.recoverPublicKey(fromHex(digest)).toBytes(false).subarray(1)).subarray(12)));
};

test('typehashes and the domain separator', () => {
  const td = V.rows[0].typedData;
  assert.equal(hex(keccak_256(new TextEncoder().encode('LiquidityToken(address token,uint256 amount)'))), V.liquidityTokenTypeHash);
  assert.equal(hex(hashStruct(td.types, 'EIP712Domain', td.domain)), V.rows[0].domainSeparator);
});

test('every row: typed data, rebuild, hashes, signature', () => {
  for (const r of V.rows) {
    assert.equal(hex(hashTypedData(r.typedData)), r.h, r.name);
    assert.equal(hex(hashStruct(r.typedData.types, 'LiquidityOrder', r.typedData.message)), r.hashOrder, r.name);
    assert.equal(hex(hashTypedData(liquidityOrderTypedData({ dex: V.dex, ...at, order: r.order }))), r.h, r.name);
    if (r.auth.keyData === '0x') assert.equal(recover(r.auth.signature, r.h), r.signer, r.name);
    else {
      const m = ua.uaMessage(0x0101, ua.purposeTag('trade'), fromHex(r.h));
      assert.ok(p256.verify(fromHex(r.auth.signature), sha256(m), concatBytes(Uint8Array.of(4), fromHex(r.auth.keyData)),
        { prehash: false, lowS: true }), r.name);
    }
  }
});

test('a zero-extended negative tick gives another digest', () => {
  const r = V.rows.find((x) => x.name === 'v4_mint_negative_tick');
  const td = liquidityOrderTypedData({ dex: V.dex, ...at, order: { ...r.order, tickLower: 2 ** 24 - 600 } });
  assert.throws(() => hashTypedData(td)); // out of the int24 range: refused, never zero-extended
});

const opts = (r, extra = {}) => ({ account: r.order.from, ...at, order: { ...r.order }, dexes: [V.dex], liquidityDexes: [V.dex],
  readers: { '0x7070000000000000000000000000000000000707': ['0x4e4e0000000000000000000000000000000004e4'] },
  scaasTokens: [V.tokenA, V.tokenB], now, ...extra });

test('checkLiquidityOrder accepts the rows and refuses each shape', () => {
  for (const r of V.rows) {
    if (r.name === 'eight_inputs') continue; // its tokens are not on the profile: a structural row only
    const got = checkLiquidityOrder(r.typedData, opts(r));
    assert.equal(hex(got.digest), r.h, r.name);
    assert.equal(got.display.givesWholePosition, r.name === 'v4_withdraw_whole', r.name);
  }
  const add = V.rows[0];
  const refusesWith = (o, re) => assert.throws(() => checkLiquidityOrder(add.typedData, o), re);
  refusesWith(opts(add, { liquidityDexes: [] }), /not liquidity-capable/);
  refusesWith(opts(add, { dexes: [] }), /not on your chain profile/);
  refusesWith(opts(add, { routerWrap: true }), /RelayFeeRouter/);
  refusesWith({ ...opts(add), order: { ...add.order, fee: '10001' } }, /above 1 %/);
  refusesWith({ ...opts(add), order: { ...add.order, inputs: [add.order.inputs[0], add.order.inputs[0]] } }, /repeated/);
  refusesWith({ ...opts(add), order: { ...add.order, recipient: padId(V.lp) } }, /plan token/);
  refusesWith({ ...opts(add), order: { ...add.order, inputs: Array(9).fill(add.order.inputs[0]) } }, /eight/);
  const whole = V.rows.find((x) => x.name === 'v4_withdraw_whole');
  assert.throws(() => checkLiquidityOrder(whole.typedData, opts(whole, { partial: true })), /receive the position back/);
  const derived = V.rows.find((x) => x.name === 'derived_p256');
  assert.throws(() => checkLiquidityOrder(derived.typedData, { ...opts(derived), order: { ...derived.order,
    inputs: [{ token: '0x9999999999999999999999999999999999999999', amount: '1' }] } }), /derived UA gives only SCaaS/);
  assert.throws(() => checkLiquidityOrder(add.typedData, { ...opts(add), order: { ...add.order,
    recipient: derived.order.from } }), /derived recipient/);
});

test('LiquiditySettled: a refund above its pull is valid', () => {
  const o = V.rows[0].order;
  assert.ok(checkLiquiditySettled(o, { pulled: ['100000', '100000'], refunded: ['250000', '0'], received: ['98703'] }));
  assert.throws(() => checkLiquiditySettled(o, { pulled: ['100001', '0'], refunded: ['0', '0'], received: ['98703'] }), /above its maximum/);
});

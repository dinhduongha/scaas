// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Service pull (spec 2026-11-09-service-pull §10, proposed CTR-MTX-32): `servicepull.json` is written by its Python generator
// (smartcontracts/vectors/metatx/gen_servicepull.py) and landed by forge (test/metatx/ServicePullVectors.t.sol) on the
// reference service and a real token. The builder must reproduce every row byte for byte, and refuse what §3.1 / §10 refuse.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildServicePull, buildRelayFee, hashTypedData, uaMetaTransferTypedData } from '../src/evm.js';
import { hex } from '../src/bytes.js';

const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/metatx/servicepull.json', import.meta.url)));

const args = (r) => ({ token: r.token.address, chainId: r.chainId, chainUid: r.token.salt, entry: r.entry, op: r.typedData,
  from: r.t.from, amount: r.t.value, batch: r.t.batch, nonce: r.t.nonce, validUntil: r.t.validUntil });

test('every row: entryRef, the transfer digest, the selector and the calldata', () => {
  assert.equal(V.rows.length, 3);
  for (const r of V.rows) {
    const b = buildServicePull(args(r));
    assert.equal(b.entryRef, r.entryRef, r.name);
    assert.equal(hex(b.digest), r.transferDigest, r.name);
    assert.equal(b.selector, r.selector, r.name);
    if (r.serviceAccepts) assert.equal(hex(b.calldata(r.auth.signature)), r.calldata, r.name);
    assert.equal(b.typedData.message.to, r.t.to, r.name);
    assert.equal(b.typedData.message.relayer.toLowerCase(), r.service.address, r.name);
    assert.equal(b.typedData.message.feeRecipient, '0x' + '00'.repeat(20), r.name);
  }
});

test('the unbound feeRecipient row: the digest zeroes it; a client that forgets canon gets another digest', () => {
  const r = V.rows.find((x) => x.name === 'deposit_unbound_fee_recipient');
  const td = uaMetaTransferTypedData({ contract: r.token.address, chainId: r.chainId, chainUid: r.token.salt, message: r.t });
  assert.equal(hex(hashTypedData(td)), r.transferDigest);
  const forgot = { ...td, message: { ...td.message, feeRecipient: r.t.feeRecipient } };
  assert.equal(hex(hashTypedData(forgot)), r.transferDigestUncanon);
  assert.notEqual(r.transferDigestUncanon, r.transferDigest);
});

test('the relay-fee wrap: F = T on the pull\'s lane at nonce + 1, open mode, the router\'s relay calldata', () => {
  for (const r of V.rows.filter((x) => x.relayFee)) {
    const f = r.relayFee;
    const p = buildRelayFee({ token: f.feeToken, chainId: r.chainId, chainUid: r.token.salt, router: f.router,
      executor: f.executor, target: r.service.address, from: r.t.from, amount: f.value, batch: f.batch,
      nonce: BigInt(r.t.nonce) + 1n, validUntil: f.validUntil }).payment(r.calldata);
    assert.equal(p.ref, f.relayRef, r.name);
    assert.equal(hex(p.digest), f.digest, r.name);
    assert.equal(hex(p.calldata(f.signature)), f.relayCalldata, r.name);
  }
});

test('refusals: another payer, another chain, a zero amount, a nested or an array field, too many fields, a missing field', () => {
  const r = V.rows[0];
  const ok = args(r);
  const refused = (o, why) => assert.throws(() => buildServicePull(o), new RegExp(why));
  refused({ ...ok, from: '0x' + '11'.repeat(32) }, 'not the payer');
  refused({ ...ok, chainId: 1 }, 'another chain');
  refused({ ...ok, amount: '0' }, 'zero');
  refused({ ...ok, entry: 'deposit(x)' }, 'not a function name');
  const td = r.typedData;
  const withField = (f, v) => ({ ...td, types: { ...td.types, [td.primaryType]: [...td.types[td.primaryType], f] },
    message: { ...td.message, [f.name]: v } });
  refused({ ...ok, op: withField({ name: 'xs', type: 'uint256[]' }, []) }, 'not atomic');
  refused({ ...ok, op: withField({ name: 'n', type: 'int256' }, '1') }, 'not atomic');
  refused({ ...ok, op: { ...withField({ name: 'inner', type: 'Inner' }, {}), types: { ...withField({ name: 'inner', type: 'Inner' }, {}).types,
    Inner: [{ name: 'a', type: 'uint256' }] } } }, 'nests a struct');
  let big = td;
  for (let i = 0; i < 13; ++i) big = { ...big, types: { ...big.types, [td.primaryType]: [...big.types[td.primaryType], { name: `f${i}`, type: 'uint8' }] },
    message: { ...big.message, [`f${i}`]: '0' } };
  assert.equal(big.types[td.primaryType].length, 17);
  refused({ ...ok, op: big }, 'more than 16');
  const missing = { ...td, message: { ...td.message } };
  delete missing.message.salt;
  refused({ ...ok, op: missing }, 'not its type');
  const swapped = { ...td, types: { ...td.types, [td.primaryType]: [...td.types[td.primaryType]].reverse() } };
  refused({ ...ok, op: swapped }, 'bytes32 payer');
  // the control: the unchanged row is built
  assert.equal(buildServicePull(ok).entryRef, r.entryRef);
});

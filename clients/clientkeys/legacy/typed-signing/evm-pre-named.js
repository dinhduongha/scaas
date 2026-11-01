// typed-signing C1: what src/evm.js built before the named typed entries, verbatim, for what the chain still verifies until
// C5 / C6: `ReceiverFee(bytes32 paymentDigest,…)`, `CancelOrder(bytes32 orderHash)`, the account's owner call as a
// `MetaTransaction`, the relay fee as a `MetaTransfer`. scripts/ua-sig-vectors.mjs and the forge KAT tests load it until
// then, so metatx3.json and uatrade_kat.json keep the structs the contracts hash. Not exported, not bundled.
import { keccak_256, concatBytes, utf8ToBytes, fromHex, hex, abiEncode, bytes32 } from '../../src/bytes.js';
import {
  ADD_KEY_SELECTOR, hashTypedData, metaTransferTypedData, metaTxTypedData, padId, payLane, relayRef, uaInvalidateNoncesTypedData,
  uaMetaTransferTypedData,
} from '../../src/evm.js';

const ZERO_ADDRESS = '0x' + '00'.repeat(20);
const ZERO_ID = '0x' + '00'.repeat(32);
const DOMAIN_TYPE = [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
  { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }];
const SALTED_DOMAIN_TYPE = [...DOMAIN_TYPE, { name: 'salt', type: 'bytes32' }];
const fields = (list) => list.map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] }));
const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
const abiCall = (sig, types, values) => concatBytes(fromHex(sel(sig)), abiEncode(types, values));
const asBytes = (v) => (v instanceof Uint8Array ? v : fromHex(v));
const refuse = (why) => { throw new Error(`Refusing to sign: ${why}.`); };
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();

function uint(v, what) {
  const s = String(v ?? '');
  if (!/^[0-9]+$/.test(s)) refuse(`${what} is not a number`);
  return BigInt(s);
}

function digestOf(td) {
  try { return hashTypedData(td); } catch { return refuse('malformed typed data'); }
}

function deadline(validUntil, now, max) {
  const until = uint(validUntil, 'the deadline');
  if (!(until > BigInt(now) && until <= BigInt(now) + BigInt(max))) refuse('the signing deadline is not near');
  return until;
}

function toBase(amount, decimals) {
  const s = String(amount);
  const m = /^([0-9]+)(?:\.([0-9]+))?$/.exec(s);
  if (!m || (m[2] || '').length > decimals) refuse(`cannot read the amount ${s}`);
  return BigInt(m[1] + (m[2] || '').padEnd(decimals, '0'));
}

function salted({ name, contract, chainId, chainUid }) {
  const salt = chainUid instanceof Uint8Array ? hex(chainUid) : String(chainUid);
  if (!/^0x[0-9a-fA-F]{64}$/.test(salt)) refuse('the chain_uid is not 32 bytes');
  return { name, version: '1', chainId: String(chainId), verifyingContract: contract, salt: salt.toLowerCase() };
}

export function addKeyCalldata(key) {
  return concatBytes(ADD_KEY_SELECTOR, abiEncode(['(uint8,bytes32,bytes32,bytes32,bytes32)'], [key]));
}

/** The account's own call (CTR-ACC-10): `MetaTransaction{from: account, data, batch: 0, nonce, validUntil}` in the
 *  domain `SCaaS SmartKeyAccount`, exactly what `mtxExecuteAsOwner(data, nonce, validUntil, sig)` builds. */
export function ownerCallTypedData({ account, chainId, chainUid, data, nonce, validUntil }) {
  return metaTxTypedData({ name: 'SCaaS SmartKeyAccount', contract: account, chainId, chainUid,
    message: { from: account, data, nonce, validUntil } });
}

/** The server's owner call must be exactly `addKey(newKey)` signed by `account` itself on lane 0, on `chainId` and the
 *  signer's own pinned `chainUid` (a missing or different salt is refused, CLI-SGN-33); nonce and a near deadline come
 *  from the server. Returns the digest to sign, or throws (CLI-SGN-05). */
export function checkOwnerCall(td, { account, chainId, chainUid, newKey, now = Math.floor(Date.now() / 1000), maxWindow = 3600 }) {
  const m = (td && td.message) || {};
  const nonce = uint(m.nonce, 'the nonce');
  const until = deadline(m.validUntil, now, maxWindow);
  const mine = digestOf(ownerCallTypedData({ account, chainId, chainUid, data: addKeyCalldata(newKey), nonce, validUntil: until }));
  if (hex(digestOf(td)) !== hex(mine)) refuse('this is not the key change you asked for');
  return mine;
}

// The payee's co-signature of receiver-pays (CTR-MTX-05/06), over the payer's payment digest: `MetaTransfer`'s on the
// address path (`mtxPayReceiverFee`), `UAMetaTransfer`'s on the UA path (`uaPayReceiverFee`). A native payee signs its
// digest; a derived one `ua_msg(kind, receiver-fee, digest)` through the registry.
const RECEIVER_FEE_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, ReceiverFee: fields(['paymentDigest:bytes32', 'fee:uint256',
  'feeRecipient:address', 'validUntil:uint256']) };

/** A token's `ReceiverFee(paymentDigest, fee, feeRecipient, validUntil)` in its salted domain (both paths). */
export function receiverFeeTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, paymentDigest, fee,
  feeRecipient, validUntil }) {
  return { types: RECEIVER_FEE_TYPES, primaryType: 'ReceiverFee', domain: salted({ name, contract, chainId, chainUid }),
    message: { paymentDigest: hex(bytes32(paymentDigest)), fee: String(fee), feeRecipient, validUntil: String(validUntil) } };
}

/** The payee's side of receiver-pays (CTR-MTX-05/06), both paths: `td` is the `ReceiverFee` to co-sign, `payment` the
 *  payer's `MetaTransfer` (`mtxPayReceiverFee`) or `UAMetaTransfer` (`uaPayReceiverFee`; `payee` then a 32-byte id,
 *  `padId` for a native one) it rides on. The payment must be the one the payee expects, as `checkPayment` checks it for
 *  the payer: to `payee`, `amount` (× 10^`decimals`) with the request's `entryRef` on lane `payLane(entryRef)` nonce 0,
 *  the contract's shape (fee NONE, relayer bound: mode 1), in `expectedToken`'s domain salted with `chainUid`; its digest
 *  is recomputed here and must be `paymentDigest`. The fee is the payee's own: non-zero, at most the amount and
 *  `maxFee` (default 0), to the `feeRecipient` it named, with a near deadline. The server supplies only the payment's
 *  `from` / `validUntil` / `relayer` and the fee's `validUntil`. Returns {digest, paymentDigest, payer, fee, feeRecipient}. */
export function checkReceiverFee(td, { payee, chainId, chainUid, amount, decimals, entryRef, expectedToken, payment,
  maxFee = 0, feeRecipient, now = Math.floor(Date.now() / 1000), maxWindow = 86400 }) {
  if (!td || td.primaryType !== 'ReceiverFee') refuse('this is not a receiver fee');
  if ([payee, amount, entryRef, expectedToken, feeRecipient].some((v) => v == null)) {
    refuse('the payee, amount, reference, token and fee recipient are required');
  }
  const ua = payment && payment.primaryType === 'UAMetaTransfer';
  if (!payment || !(ua || payment.primaryType === 'MetaTransfer')) refuse('the fee is not on a payment');
  const p = payment.message || {};
  const pdom = payment.domain || {};
  if (!same(pdom.verifyingContract, expectedToken) || !same((td.domain || {}).verifyingContract, expectedToken)) refuse('wrong token');
  if (!same(p.to, payee)) refuse('the payment does not pay you');
  const value = toBase(amount, decimals);
  if (uint(p.value, 'the amount') !== value || value === 0n) refuse('the amount differs from what you were shown');
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(entryRef)) || BigInt(entryRef) === 0n) refuse('this is not a payment');
  if (!same(p.entryRef, entryRef)) refuse('the payment reference differs from the request');
  const batch = payLane(entryRef);
  if (uint(p.batch, 'the lane') !== batch || uint(p.nonce, 'the nonce') !== 0n) refuse('a payment is signed once, on its request lane');
  if (uint(p.mode, 'the fee mode') !== 1n || uint(p.fee, 'the payer fee') !== 0n) refuse('the payment is not in the receiver-pays shape');
  const build = ua ? uaMetaTransferTypedData : metaTransferTypedData;
  const paymentDigest = digestOf(build({ name: pdom.name, contract: expectedToken, chainId, chainUid,
    message: { ...p, to: payee, value, entryRef, batch, nonce: 0 } }));
  if (hex(digestOf(payment)) !== hex(paymentDigest)) refuse('unexpected payment fields');
  const m = td.message || {};
  if (!same(m.paymentDigest, hex(paymentDigest))) refuse('the fee is not on the payment you expect');
  const fee = uint(m.fee, 'the fee');
  if (fee === 0n) refuse('no fee to co-sign');
  if (fee > value) refuse('the fee is more than the payment');
  if (fee > uint(maxFee, 'your fee limit')) refuse('the fee is above your limit');
  if (!same(m.feeRecipient, feeRecipient)) refuse('the fee goes to an address you did not name');
  const validUntil = deadline(m.validUntil, now, maxWindow);
  const digest = digestOf(receiverFeeTypedData({ name: (td.domain || {}).name, contract: expectedToken, chainId, chainUid,
    paymentDigest, fee, feeRecipient, validUntil }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected receiver fee fields');
  return { digest, paymentDigest, payer: p.from, fee, feeRecipient };
}

const TRANSFER_TUPLE = (id) => `(${id},${id},uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)`;

/** A relay-fee job (CTR-MTX-27) on `router` (`MtxRelayFee`, executor `executor`): `inner` (optional) is the call's own
 *  `MetaTransaction` typed data on `target`; a relayer it binds (`MODE_RESTRICT_RELAYER`) is set to the executor (left
 *  open otherwise; bound to anything else: refused). Open mode by default (`payee` unset: the payment goes to the router,
 *  which pays whoever submits); `payee` binds it (never the executor). `ua`: the payer `from` and `payee` are 32-byte ids.
 *  Returns {call (the inner typed data to sign first, or null), prompt {call, payment}: both intents for one review,
 *  payment(callData) → {ref, lane, typedData, digest, calldata(sig)}}: `callData` is the call with its own signature
 *  (`mtxExecuteCalldata`); the payment is `{from, to, value: amount, entryRef: ref, batch: payLane(ref), nonce: 0,
 *  validUntil, mode: RESTRICT_RELAYER, relayer: router, fee: 0}`, `calldata` is `relay(…)` / `uaRelay(…)`. */
export function buildRelayFee({ name = 'SCaaS MetaToken', token, chainId, chainUid, router, executor, target, inner, from,
  amount, payee, validUntil, ua = false }) {
  if (same(target, executor) || same(target, router)) refuse('a relay never targets the router or its executor');
  const idOf = (a) => (ua ? padId(a) : a);
  const open = payee == null;
  const to = open ? idOf(router) : payee;
  if (same(to, idOf(executor)) || same(to, executor)) refuse('never pay the executor');
  if (same(to, ZERO_ADDRESS) || same(to, ZERO_ID)) refuse('the payee is the zero address');
  if (same(to, token) || same(to, padId(token))) refuse('the payee is the token itself');
  let call = null;
  let bound = 0n;
  if (inner) {
    const m = inner.message || {};
    const d = inner.domain || {};
    if (!same(d.verifyingContract, target)) refuse('the call is not on the target');
    const uid = chainUid instanceof Uint8Array ? hex(chainUid) : String(chainUid);
    if (uint(d.chainId, 'the call\'s chain id') !== BigInt(chainId) || !same(d.salt, uid)) refuse('the call is for another chain');
    if (uint(m.validUntil, 'the call\'s deadline') > uint(validUntil, 'the deadline')) refuse('the call outlives its payment');
    bound = BigInt(m.mode ?? 0) & 1n;
    if (bound && !same(m.relayer, ZERO_ADDRESS) && !same(m.relayer, executor)) refuse('the call is bound to another relayer');
    call = { ...inner, message: { ...m, relayer: bound ? executor : m.relayer } };
  }
  const prompt = {
    call: call ? { target, data: call.message.data, from: call.message.from, relayer: bound ? executor : null }
      : { target },
    payment: { token, amount: BigInt(amount), payee: open ? null : to, open },
  };
  const payment = (callData) => {
    const ref = relayRef(chainId, target, callData);
    const lane = payLane(ref);
    const typedData = (ua ? uaMetaTransferTypedData : metaTransferTypedData)({ name, contract: token, chainId, chainUid,
      message: { from, to, value: amount, entryRef: ref, batch: lane, nonce: 0, validUntil, mode: 1, relayer: router, fee: 0 } });
    const t = typedData.message;
    const tuple = [t.from, t.to, t.value, t.entryRef, t.batch, t.nonce, t.validUntil, t.mode, t.relayer, t.fee, t.feeRecipient];
    const T = TRANSFER_TUPLE(ua ? 'bytes32' : 'address');
    const calldata = (sig) => abiCall(`${ua ? 'uaRelay' : 'relay'}(address,bytes,address,${T},bytes)`,
      ['address', 'bytes', 'address', T, 'bytes'], [target, asBytes(callData), token, tuple, asBytes(sig)]);
    return { ref, lane, typedData, digest: digestOf(typedData), calldata };
  };
  return { call, prompt, payment };
}

/** `CancelOrder(orderHash)` or `InvalidateNonces(from, batch, minNonce)` in the domain that holds the order (the sell
 *  token, or the DEX for an outside token). */
export function orderCancelTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, orderHash, invalidate }) {
  const domain = salted({ name, contract, chainId, chainUid });
  if (invalidate) {
    return { types: { EIP712Domain: SALTED_DOMAIN_TYPE, InvalidateNonces: fields(['from:address', 'batch:uint256', 'minNonce:uint256']) },
      primaryType: 'InvalidateNonces', domain,
      message: { from: invalidate.from, batch: String(invalidate.batch), minNonce: String(invalidate.minNonce) } };
  }
  return { types: { EIP712Domain: SALTED_DOMAIN_TYPE, CancelOrder: fields(['orderHash:bytes32']) }, primaryType: 'CancelOrder',
    domain, message: { orderHash } };
}

/** A cancel the user chose: `CancelOrder(orderHash)` of the client's own stored order, or `InvalidateNonces(account,
 *  batch, minNonce)`, in the domain that holds the order (`contract`: the sell token, or the DEX). `ua`: the account is
 *  a 32-byte id and the invalidation is `UAInvalidateNonces` (CTR-DEX-25). Returns the digest. */
export function checkCancel(td, { account, chainId, chainUid, contract, orderHash, invalidate, ua = false }) {
  const d = (td && td.domain) || {};
  const mine = digestOf(ua && invalidate
    ? uaInvalidateNoncesTypedData({ name: d.name, contract, chainId, chainUid, ...invalidate, from: account })
    : orderCancelTypedData({ name: d.name, contract, chainId, chainUid, orderHash,
      invalidate: invalidate && { ...invalidate, from: account } }));
  if (hex(digestOf(td)) !== hex(mine)) refuse('this is not the cancel you asked for');
  return mine;
}

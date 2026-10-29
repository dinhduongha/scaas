// NEAR client (near-algorand T18, spec §6): MetaOp v1 = "scaas.metaop.v1" ‖ Borsh(MetaOp); the key signs NEP-413 over
// the digest text. Layouts follow scaas-node/src/adapters/near.rs and smartcontracts/near/vectors/near-vectors.json.
import { sha256, concatBytes, utf8ToBytes, hex, fromHex } from './bytes.js';
import { derToRS } from './webauthn.js';
import {
  LABEL, PayMetaMismatch, NativeToUa, b32, le, lane32, signText, relayRef, checkPayMeta,
  passkeyAssertion as assertion,
} from './metaop.js';

export { PayMetaMismatch, NativeToUa, signText, relayRef };

const bstr = (s) => { const b = utf8ToBytes(s); return concatBytes(le(b.length, 4), b); };
const holder = (h) => ('Near' in h ? concatBytes(Uint8Array.of(0), bstr(h.Near)) : concatBytes(Uint8Array.of(1), b32(h.Ua, 'UA id')));

/** `"scaas.metaop.v1" ‖ Borsh(MetaOp)`; `op` is a vectors `fields` object (hex strings, decimal amount, holders `{Near}`/`{Ua}`). */
export function encodeMetaOp(op) {
  return concatBytes(LABEL, b32(op.network, 'network'), bstr(op.contract), Uint8Array.of(op.op), holder(op.from), holder(op.to),
    op.relayer == null ? Uint8Array.of(0) : concatBytes(Uint8Array.of(1), bstr(op.relayer)), le(op.amount, 16),
    b32(op.pay_ref, 'pay_ref'), b32(op.lane, 'lane'), le(op.nonce, 8), le(op.valid_until, 8), b32(op.extra, 'extra'));
}
export const digest = (op) => sha256(encodeMetaOp(op));

/** NEP-413 hash: sha256(tag 2^31+413 LE ‖ Borsh{message, nonce[32], recipient, callbackUrl: None}). */
export function nep413Hash(text, recipient, nonce) {
  return sha256(concatBytes(fromHex('0x9d010080'), bstr(text), b32(nonce, 'nonce'), bstr(recipient), Uint8Array.of(0)));
}

export const passkeyAssertion = (d, cred) => assertion(d, cred, derToRS);

/** Relay-fee `ref` target form: `u8 len ‖ account id`. Router call: `len8 target ‖ len8 method ‖ args`; wrapper: `len8 entry ‖ args`. */
export const targetBytes = (id) => concatBytes(Uint8Array.of(utf8ToBytes(id).length), utf8ToBytes(id));
export const routerCall = (target, method, args) => concatBytes(targetBytes(target), targetBytes(method), args);
export const wrapperCall = (entry, args) => concatBytes(targetBytes(entry), args);

/** 64 lower-case hex = an implicit account, id = its 32 bytes; any other valid account id (named, ETH-implicit) = sha256(id). */
export function nativeId(accountId) {
  const sep = (c) => '-_.'.includes(c);
  const a = accountId;
  if (!/^[a-z0-9._-]{2,64}$/.test(a) || sep(a[0]) || sep(a[a.length - 1]) || /[-_.]{2}/.test(a)) {
    throw new Error(`not a NEAR account id: ${JSON.stringify(a)}`);
  }
  return /^[0-9a-f]{64}$/.test(a) ? fromHex(a) : sha256(utf8ToBytes(a));
}

/**
 * Open-mode relay-fee payment (CTR-MTX-27): the payer pays the router (or the wrapper token) and one prompt shows the call
 * AND the fee payment. `entry` = `{route:'router', router, target, method, args, salt}` or `{route:'wrapper', entry, args, salt}`;
 * `payOp` = the payment's fields without pay_ref / lane / extra / to / relayer (these are derived).
 */
export function buildRelayFee(entry, payOp) {
  const wrapper = entry.route === 'wrapper';
  const payee = wrapper ? payOp.contract : entry.router;
  const call = wrapper ? wrapperCall(entry.entry, entry.args) : routerCall(entry.target, entry.method, entry.args);
  const tgt = wrapper ? targetBytes(payOp.contract) : targetBytes(entry.target);
  const ref = relayRef(payOp.network, tgt, call, entry.salt);
  const op = { ...payOp, op: 0, pay_ref: hex(ref), lane: lane32(hex(ref)), extra: entry.salt, to: { Near: payee }, relayer: payee };
  const d = digest(op);
  return {
    op, ref: hex(ref), digest: d, text: signText(d),
    prompt: {
      call: { target: wrapper ? payOp.contract : entry.target, method: wrapper ? entry.entry : entry.method, data: hex(call) },
      payment: { token: payOp.contract, amount: BigInt(payOp.amount), payee: null, open: true },
    },
  };
}

/** Pay with a metadata envelope: `pay_ref == metaPayId(salt, meta)` or PayMetaMismatch. The entry is `mtx_pay_meta`. */
export function buildPayMeta(op, salt, meta) {
  checkPayMeta(op, salt, meta);
  return { op, entry: 'mtx_pay_meta', salt, meta, digest: digest(op), text: signText(digest(op)) };
}

/** A native NEAR transfer cannot target a UA id (NET-ALL-21: UA holders exist only inside the SCaaS token). */
export function send(op, { native = false } = {}) {
  if (native && 'Ua' in op.to) throw new NativeToUa('a native send cannot go to a UA id (NET-ALL-21): pay the token instead');
  return { op, digest: digest(op), text: signText(digest(op)) };
}

/** A key op is per token contract: one op for every held token (each its own digest and nonce). Codes 6-12 are key ops. */
export function keyOpFanOut(keyOp, tokens) {
  if (!(keyOp.op >= 6 && keyOp.op <= 12)) throw new Error('not a key op (add/remove key, origin, guardian, recovery)');
  if (!tokens.length) throw new Error('no token held');
  return tokens.map((t) => ({ ...keyOp, contract: t }));
}

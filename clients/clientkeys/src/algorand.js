// Algorand client (near-algorand T18, spec §6): MetaOp v1 = "scaas.metaop.v1" ‖ the 291-byte ARC-4 static tuple; the key
// signs "MX" ‖ text. Layouts follow scaas-node/src/adapters/algorand.rs and smartcontracts/algorand/vectors/algorand-vectors.json.
import { sha256, concatBytes, utf8ToBytes, hex, fromHex } from './bytes.js';
import { sha512_256 } from '@noble/hashes/sha2.js';
import { base32nopad } from '@scure/base';
import { derToRS } from './webauthn.js';
import {
  LABEL, PayMetaMismatch, NativeToUa, b32, be, lane32, signText, relayRef, checkPayMeta, needNonce0, passkeyAssertion as assertion,
} from './metaop.js';

export { PayMetaMismatch, NativeToUa, signText, relayRef };

const holder = (h) => concatBytes(Uint8Array.of(h.kind), b32(h.id, 'holder id'));

/** `op` is a vectors `fields` object: hex 32-byte ids, holders `{kind: 0 address | 1 UA id, id}`, relayer zero = any. */
export function encodeMetaOp(op) {
  return concatBytes(LABEL, b32(op.network, 'network'), b32(op.contract, 'contract'), Uint8Array.of(op.op), holder(op.from),
    holder(op.to), b32(op.relayer, 'relayer'), be(op.amount, 16), b32(op.pay_ref, 'pay_ref'), b32(op.lane, 'lane'),
    be(op.nonce, 8), be(op.valid_until, 8), b32(op.extra, 'extra'));
}
export const digest = (op) => sha256(encodeMetaOp(op));

/** ed25519verify_bare payload: "MX" ‖ text. */
export const signBytes = (text) => concatBytes(utf8ToBytes('MX'), utf8ToBytes(text));

export const passkeyAssertion = (d, cred) => assertion(d, cred, derToRS);

const checksum = (key) => sha512_256(key).subarray(28);
export const keyToAddress = (key) => base32nopad.encode(concatBytes(b32(key, 'key'), checksum(key)));
export function addressToKey(addr) {
  if (!/^[A-Z2-7]{58}$/.test(addr)) throw new Error(`not an Algorand address: ${JSON.stringify(addr)}`);
  const raw = base32nopad.decode(addr);
  const key = raw.subarray(0, 32);
  if (hex(raw.subarray(32)) !== hex(checksum(key))) throw new Error('Algorand address checksum');
  return key;
}
/** `sha512_256("appID" ‖ u64 BE app id)`. */
export const appAddress = (id) => sha512_256(concatBytes(utf8ToBytes('appID'), be(id, 8)));

/** Router call: `target app id (u64 BE) ‖ u8 n ‖ (u16 BE len ‖ arg)×n`, arg 0 = the ARC-4 selector. */
export const routerCall = (app, args) =>
  concatBytes(be(app, 8), Uint8Array.of(args.length), ...args.map((a) => concatBytes(be(a.length, 2), a)));

/**
 * Open-mode relay-fee payment: pays the router; one prompt shows the call and the fee. `entry` = `{router (key hex),
 * targetApp, args (bytes[], arg 0 the selector), salt}`; `payOp` = the payment fields without pay_ref / lane / extra / to / relayer.
 */
export function buildRelayFee(entry, payOp) {
  needNonce0(payOp);
  if (payOp.contractApp === undefined) throw new Error('payOp.contractApp (the token app id) is required for the prompt');
  const call = routerCall(entry.targetApp, entry.args);
  const ref = hex(relayRef(payOp.network, appAddress(entry.targetApp), call, entry.salt));
  const op = { ...payOp, op: 0, pay_ref: ref, lane: lane32(ref), extra: entry.salt, to: { kind: 0, id: entry.router }, relayer: entry.router };
  const d = digest(op);
  return {
    op, ref, digest: d, text: signText(d),
    prompt: {
      call: { target: entry.targetApp, data: hex(call) },
      payment: { token: payOp.contractApp, amount: BigInt(payOp.amount), payee: null, open: true },
    },
  };
}

export function buildPayMeta(op, salt, meta) {
  checkPayMeta(op, salt, meta);
  return { op, entry: 'mtx_pay_meta', salt, meta, digest: digest(op), text: signText(digest(op)) };
}

/** A native ALGO transfer cannot target a UA id (NET-ALL-21). */
export function send(op, { native = false } = {}) {
  if (native && op.to.kind === 1) throw new NativeToUa('a native send cannot go to a UA id (NET-ALL-21): pay the token instead');
  return { op, digest: digest(op), text: signText(digest(op)) };
}

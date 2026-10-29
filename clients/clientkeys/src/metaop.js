// Shared by the NEAR and Algorand clients (near-algorand T18): the scaas.metaop.v1 envelope parts both families use.
import { keccak_256, concatBytes, utf8ToBytes, hex, fromHex, b64url } from './bytes.js';
import { metaPayId, payLane } from './evm.js';

export const LABEL = utf8ToBytes('scaas.metaop.v1');

export class PayMetaMismatch extends Error { constructor(m) { super(m); this.name = 'PayMetaMismatch'; } }
export class NativeToUa extends Error { constructor(m) { super(m); this.name = 'NativeToUa'; } }

const u = (x) => (typeof x === 'string' ? fromHex(x) : x);
export const b32 = (x, what) => {
  const b = u(x);
  if (b.length !== 32) throw new Error(`${what} is 32 bytes`);
  return b;
};
export const be = (v, n) => { const o = new Uint8Array(n); let x = BigInt(v); for (let i = n - 1; i >= 0; i--, x >>= 8n) o[i] = Number(x & 255n); if (x) throw new Error('integer overflow'); return o; };
export const le = (v, n) => be(v, n).reverse();
export const lane32 = (ref) => '0x' + payLane(ref).toString(16).padStart(64, '0');

/** The text the key signs: `scaas.metaop.v1:` ‖ lower hex digest (both families; NEP-413 message / `MX` payload). */
export const signText = (d) => `scaas.metaop.v1:${hex(u(d)).slice(2)}`;

/** `keccak256("scaas.relayfee" ‖ network ‖ target ‖ keccak256(call) ‖ salt)` (CTR-MTX-27; target bytes are family forms). */
export function relayRef(network, target, call, salt) {
  return keccak_256(concatBytes(utf8ToBytes('scaas.relayfee'), b32(network, 'network'), u(target), keccak_256(u(call)), b32(salt, 'salt')));
}

/** The node requires nonce 0 on pay-meta and relay-fee payments (their lane is derived from the ref). */
export function needNonce0(op) {
  if (Number(op.nonce) !== 0) throw new Error('nonce must be 0 for this payment (the lane is payLane(pay_ref))');
}

/** CTR-MTX-26: the op's pay_ref must be metaPayId(salt, meta) and its lane payLane(pay_ref). */
export function checkPayMeta(op, salt, meta) {
  needNonce0(op);
  const id = metaPayId(salt, meta);
  if (hex(u(op.pay_ref)) !== id) throw new PayMetaMismatch('pay_ref does not commit to the metadata (metaPayId(salt, meta))');
  if (hex(u(op.lane)) !== lane32(id)) throw new PayMetaMismatch('lane is not payLane(pay_ref)');
}

/** WebAuthn: the authenticator signs `challenge = digest`; the chains take low-s r‖s (a high-s signature is refused). The
 *  returned clientDataJSON must be valid UTF-8, type webauthn.get, challenge b64url(digest). */
export async function passkeyAssertion(digest, cred, derToRS) {
  const a = await cred.get(digest);
  let cdj;
  try { cdj = new TextDecoder('utf-8', { fatal: true }).decode(a.clientDataJSON); } catch { throw new Error('clientDataJSON is not UTF-8 encoded'); }
  let c;
  try { c = JSON.parse(cdj); } catch { throw new Error('clientDataJSON is not JSON'); }
  if (c.type !== 'webauthn.get') throw new Error('clientDataJSON type is not webauthn.get');
  if (c.challenge !== b64url(u(digest))) throw new Error('clientDataJSON challenge is not the operation digest');
  const { r, s } = derToRS(a.signature);
  return { authenticatorData: a.authenticatorData, clientDataJSON: cdj, signature: concatBytes(r, s) };
}

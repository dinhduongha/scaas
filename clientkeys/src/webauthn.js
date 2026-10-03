// WebAuthn (passkey) helpers for SubjectAccount (R31). Nothing secret: the private key never
// leaves the authenticator; we only shape options and re-encode what it returns.
import { abiEncode, fromHex } from './bytes.js';

// P-256 group order.
export const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const SPKI_P256_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

export function passkeySupported(win = globalThis) {
  return Boolean(win.PublicKeyCredential && win.navigator && win.navigator.credentials);
}

/** `navigator.credentials.create` options: ES256 only, discoverable, user verification required. */
export function creationOptions({ rpId, rpName, userId, userName, challenge, prf = true }) {
  return {
    publicKey: {
      rp: { id: rpId, name: rpName || rpId },
      user: { id: userId, name: userName, displayName: userName },
      challenge,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      ...(prf ? { extensions: { prf: {} } } : {}),
    },
  };
}

/** `navigator.credentials.get` options: challenge = the 32-byte digest (or batch root). */
export function requestOptions({ rpId, challenge, credentialIds = [], prfSalt }) {
  if (challenge.length !== 32) throw new Error('challenge must be the 32-byte operation digest');
  return {
    publicKey: {
      rpId,
      challenge,
      allowCredentials: credentialIds.map((id) => ({ type: 'public-key', id })),
      userVerification: 'required',
      ...(prfSalt ? { extensions: { prf: { eval: { first: prfSalt } } } } : {}),
    },
  };
}

/** (x, y) of a P-256 key from `AuthenticatorAttestationResponse.getPublicKey()` (SPKI DER). */
export function publicKeyFromSpki(spki) {
  const prefix = fromHex(SPKI_P256_PREFIX);
  if (spki.length !== 91 || !prefix.every((b, i) => spki[i] === b) || spki[26] !== 4) {
    throw new Error('not an uncompressed P-256 SPKI public key');
  }
  return { x: spki.slice(27, 59), y: spki.slice(59, 91) };
}

function toBig(b) {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

function to32(v) {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

/**
 * WebAuthn returns an ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` and authenticators do NOT
 * enforce low-s. The contract (OZ P256) rejects s > n/2, so normalise s := n − s (still valid,
 * review S5). Strict DER: short lengths only, minimal integers.
 */
export function derToRS(der) {
  const fail = () => { throw new Error('malformed DER ECDSA signature'); };
  if (der[0] !== 0x30 || der[1] !== der.length - 2) fail();
  let i = 2;
  const int = () => {
    if (der[i] !== 0x02) fail();
    const len = der[i + 1];
    if (len < 1 || len > 33 || i + 2 + len > der.length) fail();
    const v = der.subarray(i + 2, i + 2 + len);
    if (v[0] & 0x80 || (len > 1 && v[0] === 0 && !(v[1] & 0x80))) fail();
    i += 2 + len;
    return toBig(v);
  };
  const r = int();
  let s = int();
  if (i !== der.length || r === 0n || s === 0n || r >= P256_N || s >= P256_N) fail();
  const highS = s > P256_N / 2n;
  if (highS) s = P256_N - s;
  return { r: to32(r), s: to32(s), highS };
}

/** Inner payload for a P-256 key: `abi.encode(authenticatorData, clientDataJSON, r, s)`. */
export function encodeAssertion({ authenticatorData, clientDataJSON, signature }) {
  const { r, s } = derToRS(signature);
  return abiEncode(['bytes', 'bytes', 'bytes32', 'bytes32'], [authenticatorData, clientDataJSON, r, s]);
}

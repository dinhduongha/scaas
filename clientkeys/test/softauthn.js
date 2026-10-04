// Software authenticator for tests (and the forge vector script): a real P-256 key in WebCrypto,
// authenticatorData and clientDataJSON built byte for byte per WebAuthn L3 (§6.1, §5.8.1.1), and the
// signature returned as ASN.1 DER exactly like `AuthenticatorAssertionResponse.signature`.
import { sha256, utf8ToBytes, concatBytes, b64url } from '../src/bytes.js';

function derInt(b) {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  const v = b.subarray(i);
  return v[0] & 0x80 ? concatBytes(new Uint8Array([2, v.length + 1, 0]), v) : concatBytes(new Uint8Array([2, v.length]), v);
}

export function p1363ToDer(sig) {
  const body = concatBytes(derInt(sig.subarray(0, 32)), derInt(sig.subarray(32)));
  return concatBytes(new Uint8Array([0x30, body.length]), body);
}

export async function softAuthenticator({ rpId, origin, jwk }) {
  const algo = { name: 'ECDSA', namedCurve: 'P-256' };
  const { d: _d, ...pub } = jwk || {};
  const pair = jwk
    ? { privateKey: await crypto.subtle.importKey('jwk', jwk, algo, true, ['sign']),
        publicKey: await crypto.subtle.importKey('jwk', pub, algo, true, ['verify']) }
    : await crypto.subtle.generateKey(algo, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  return {
    spki,
    rpId,
    origin,
    async get(challenge, { flags = 0x05, counter = 0, tail = ',"crossOrigin":false}' } = {}) {
      const authenticatorData = concatBytes(sha256(utf8ToBytes(rpId)), new Uint8Array([flags]),
        new Uint8Array([counter >>> 24, (counter >>> 16) & 255, (counter >>> 8) & 255, counter & 255]));
      const clientDataJSON = utf8ToBytes(
        `{"type":"webauthn.get","challenge":"${b64url(challenge)}","origin":"${origin}"${tail}`);
      // WebCrypto ECDSA hashes with SHA-256: the signature is over sha256(authData ‖ sha256(clientDataJSON)).
      const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey,
        concatBytes(authenticatorData, sha256(clientDataJSON))));
      return { authenticatorData, clientDataJSON, signature: p1363ToDer(raw) };
    },
  };
}

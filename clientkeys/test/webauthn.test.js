import { test } from 'node:test';
import assert from 'node:assert/strict';
import { p256 } from '@noble/curves/nist.js';
import {
  derToRS, publicKeyFromSpki, encodeAssertion, creationOptions, requestOptions, passkeySupported, P256_N,
} from '../src/webauthn.js';
import { sha256, concatBytes, bytesToHex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';
import { softAuthenticator, p1363ToDer } from './softauthn.js';

const RP = 'pay.example.com';
const ORIGIN = 'https://pay.example.com';

function big(b) { return BigInt('0x' + bytesToHex(b)); }

test('DER decode, low-s normalisation and strictness', () => {
  const r = fromHex('00'.repeat(31) + '05');
  const sHigh = fromHex((P256_N - 7n).toString(16).padStart(64, '0'));
  const out = derToRS(p1363ToDer(concatBytes(r, sHigh)));
  assert.equal(big(out.r), 5n);
  assert.equal(big(out.s), 7n);
  assert.ok(out.highS);
  const low = derToRS(p1363ToDer(concatBytes(r, fromHex('00'.repeat(31) + '07'))));
  assert.equal(big(low.s), 7n);
  assert.equal(low.highS, false);
  // Non-minimal integer, trailing junk, wrong tag, zero: all refused.
  assert.throws(() => derToRS(fromHex('3008020200050202000700')), /malformed/);
  assert.throws(() => derToRS(fromHex('300602010502010700')), /malformed/);
  assert.throws(() => derToRS(fromHex('310602010502010')), /./);
  assert.throws(() => derToRS(fromHex('3006020100020107')), /malformed/);
});

test('options builders: ES256, user verification required, challenge = 32-byte digest, PRF opt-in', () => {
  const c = creationOptions({ rpId: RP, userId: new Uint8Array([1]), userName: 'outlet', challenge: new Uint8Array(32) });
  assert.deepEqual(c.publicKey.pubKeyCredParams, [{ type: 'public-key', alg: -7 }]);
  assert.equal(c.publicKey.authenticatorSelection.userVerification, 'required');
  assert.deepEqual(c.publicKey.extensions, { prf: {} });
  const g = requestOptions({ rpId: RP, challenge: new Uint8Array(32), credentialIds: [new Uint8Array([9])], prfSalt: new Uint8Array(32) });
  assert.equal(g.publicKey.userVerification, 'required');
  assert.equal(g.publicKey.allowCredentials[0].id[0], 9);
  assert.ok(g.publicKey.extensions.prf.eval.first);
  assert.throws(() => requestOptions({ rpId: RP, challenge: new Uint8Array(31) }), /32-byte/);
  assert.equal(passkeySupported({}), false);
  assert.equal(passkeySupported({ PublicKeyCredential: class {}, navigator: { credentials: {} } }), true);
});

test('software authenticator: SPKI → (x,y), assertion verifies over sha256(authData ‖ sha256(cdj)) after low-s', async () => {
  const auth = await softAuthenticator({ rpId: RP, origin: ORIGIN });
  const { x, y } = publicKeyFromSpki(auth.spki);
  const digest = keccak_256(utf8ToBytes('op'));
  let sawHigh = false;
  for (let i = 0; i < 24; i++) {
    const a = await auth.get(digest);
    assert.deepEqual([...a.authenticatorData.subarray(0, 32)], [...sha256(utf8ToBytes(RP))]);
    const { r, s, highS } = derToRS(a.signature);
    sawHigh ||= highS;
    assert.ok(big(s) <= P256_N / 2n);
    const h = sha256(concatBytes(a.authenticatorData, sha256(a.clientDataJSON)));
    assert.ok(p256.verify(concatBytes(r, s), h, concatBytes(new Uint8Array([4]), x, y), { prehash: false }));
    const enc = encodeAssertion(a);
    assert.equal(enc.length % 32, 0);
  }
  assert.ok(sawHigh, 'WebCrypto produced at least one high-s signature in 24 tries');
  assert.throws(() => publicKeyFromSpki(auth.spki.subarray(1)), /SPKI/);
});

test('clientDataJSON shape is what SubjectAccount checks (RS4-2)', async () => {
  const auth = await softAuthenticator({ rpId: RP, origin: ORIGIN });
  const a = await auth.get(new Uint8Array(32).fill(0xab));
  assert.equal(new TextDecoder().decode(a.clientDataJSON),
    `{"type":"webauthn.get","challenge":"${'q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s'}","origin":"${ORIGIN}","crossOrigin":false}`);
});

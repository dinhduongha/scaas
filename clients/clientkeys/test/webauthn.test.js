import { test } from "node:test";
import assert from "node:assert/strict";
import { p256 } from "@noble/curves/nist.js";
import {
  derToRS,
  publicKeyFromSpki,
  encodeAssertion,
  creationOptions,
  requestOptions,
  passkeySupported,
  P256_N,
  WEBAUTHN_MAX_ASSERTION,
} from "../src/webauthn.js";
import { passkeyAssertion } from "../src/metaop.js";
import { WEBAUTHN_MAX_ASSERTION as UA_CAP } from "../src/uakey.js";
import { sha256, concatBytes, bytesToHex, fromHex, keccak_256, utf8ToBytes } from "../src/bytes.js";
import { softAuthenticator, p1363ToDer } from "./softauthn.js";

const RP = "pay.example.com";
const ORIGIN = "https://pay.example.com";

function big(b) {
  return BigInt("0x" + bytesToHex(b));
}

test("DER decode, low-s normalisation and strictness", () => {
  const r = fromHex("00".repeat(31) + "05");
  const sHigh = fromHex((P256_N - 7n).toString(16).padStart(64, "0"));
  const out = derToRS(p1363ToDer(concatBytes(r, sHigh)));
  assert.equal(big(out.r), 5n);
  assert.equal(big(out.s), 7n);
  assert.ok(out.highS);
  const low = derToRS(p1363ToDer(concatBytes(r, fromHex("00".repeat(31) + "07"))));
  assert.equal(big(low.s), 7n);
  assert.equal(low.highS, false);
  // Non-minimal integer, trailing junk, wrong tag, zero: all refused.
  assert.throws(() => derToRS(fromHex("3008020200050202000700")), /malformed/);
  assert.throws(() => derToRS(fromHex("300602010502010700")), /malformed/);
  assert.throws(() => derToRS(fromHex("310602010502010")), /./);
  assert.throws(() => derToRS(fromHex("3006020100020107")), /malformed/);
});

test("options builders: ES256, user verification required, challenge = 32-byte digest, PRF opt-in", () => {
  const c = creationOptions({ rpId: RP, userName: "outlet", challenge: new Uint8Array(32), excludeCredentialIds: [] });
  assert.deepEqual(c.publicKey.pubKeyCredParams, [{ type: "public-key", alg: -7 }]);
  assert.equal(c.publicKey.authenticatorSelection.userVerification, "required");
  assert.deepEqual(c.publicKey.extensions, { prf: {} });
  const g = requestOptions({
    rpId: RP,
    challenge: new Uint8Array(32),
    credentialIds: [new Uint8Array([9])],
    prfSalt: new Uint8Array(32),
  });
  assert.equal(g.publicKey.userVerification, "required");
  assert.equal(g.publicKey.allowCredentials[0].id[0], 9);
  assert.ok(g.publicKey.extensions.prf.eval.first);
  assert.throws(() => requestOptions({ rpId: RP, challenge: new Uint8Array(31) }), /32-byte/);
  assert.equal(passkeySupported({}), false);
  assert.equal(passkeySupported({ PublicKeyCredential: class {}, navigator: { credentials: {} } }), true);
});

test("software authenticator: SPKI → (x,y), assertion verifies over sha256(authData ‖ sha256(cdj)) after low-s", async () => {
  const auth = await softAuthenticator({ rpId: RP, origin: ORIGIN });
  const { x, y } = publicKeyFromSpki(auth.spki);
  const digest = keccak_256(utf8ToBytes("op"));
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
  assert.ok(sawHigh, "WebCrypto produced at least one high-s signature in 24 tries");
  assert.throws(() => publicKeyFromSpki(auth.spki.subarray(1)), /SPKI/);
});

test("clientDataJSON shape is what SmartKeyAccount checks (RS4-2)", async () => {
  const auth = await softAuthenticator({ rpId: RP, origin: ORIGIN });
  const a = await auth.get(new Uint8Array(32).fill(0xab));
  assert.equal(
    new TextDecoder().decode(a.clientDataJSON),
    `{"type":"webauthn.get","challenge":"${"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s"}","origin":"${ORIGIN}","crossOrigin":false}`,
  );
});

// Review S4-H1: a discoverable credential is stored per (rpId, user handle). One handle per
// partner made "add a passkey on this device" REPLACE the account's passkey in a synced keychain.
test("creationOptions: random 16-byte user handle per credential, account passkeys excluded", () => {
  const ex = [new Uint8Array([1, 2, 3]), "AQID"];
  const a = creationOptions({ rpId: RP, userName: "outlet", challenge: new Uint8Array(32), excludeCredentialIds: ex });
  const b = creationOptions({ rpId: RP, userName: "outlet", challenge: new Uint8Array(32), excludeCredentialIds: ex });
  assert.equal(a.publicKey.user.id.length, 16);
  assert.notEqual(bytesToHex(a.publicKey.user.id), bytesToHex(b.publicKey.user.id));
  assert.deepEqual(
    a.publicKey.excludeCredentials.map((c) => [c.type, bytesToHex(c.id)]),
    [
      ["public-key", "010203"],
      ["public-key", "010203"],
    ],
  );
  assert.equal(a.publicKey.authenticatorSelection.residentKey, "required");
  assert.throws(
    () => creationOptions({ rpId: RP, userName: "o", challenge: new Uint8Array(32) }),
    /excludeCredentialIds/,
  );
  assert.throws(
    () =>
      creationOptions({
        rpId: RP,
        userName: "o",
        challenge: new Uint8Array(32),
        userId: new Uint8Array(16),
        excludeCredentialIds: [],
      }),
    /user handle/,
  );
});

// Owner 2026-11-19, Q4: the G3 cap on the account passkey path (`encodeAssertion`, `SmartKeyAccount`) and the NEAR / Algorand
// path (`passkeyAssertion`): authenticatorData and clientDataJSON at most 1,024 bytes together; at the cap encoded (control), a
// byte above `WebAuthnTooLong`, nothing returned.
test("Q4: account and metaop passkey assertions capped at 1,024 bytes", async () => {
  assert.equal(WEBAUTHN_MAX_ASSERTION, 1024);
  assert.equal(UA_CAP, WEBAUTHN_MAX_ASSERTION, "one constant with uakey.js");
  const digest = new Uint8Array(32).fill(0xab);
  const authenticatorData = concatBytes(sha256(utf8ToBytes(RP)), new Uint8Array([5, 0, 0, 0, 0]));
  const prefix = `{"type":"webauthn.get","challenge":"${"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s"}","origin":"https://`;
  const cdj = (n) => utf8ToBytes(prefix + "a".repeat(n - authenticatorData.length - prefix.length - 2) + '"}');
  const signature = p1363ToDer(fromHex("00".repeat(31) + "05" + "00".repeat(31) + "07"));
  const at = cdj(1024),
    above = cdj(1025);
  assert.equal(authenticatorData.length + at.length, 1024);
  assert.equal(authenticatorData.length + above.length, 1025);
  const tooLong = (e) => e.code === "WebAuthnTooLong";
  assert.ok(encodeAssertion({ authenticatorData, clientDataJSON: at, signature }).length > 0, "control");
  assert.throws(() => encodeAssertion({ authenticatorData, clientDataJSON: above, signature }), tooLong);
  const cred = (clientDataJSON) => ({ get: async () => ({ authenticatorData, clientDataJSON, signature }) });
  const ok = await passkeyAssertion(digest, cred(at), derToRS);
  assert.equal(ok.clientDataJSON.length, at.length, "control");
  await assert.rejects(passkeyAssertion(digest, cred(above), derToRS), tooLong);
});

// PR A review, finding 5: an authenticator returns `ArrayBuffer`s, which have no `.length`; the cap reads their bytes (it
// summed `NaN` and passed): a 2,000-byte `ArrayBuffer` refused `WebAuthnTooLong`, one at the cap accepted, read as bytes;
// anything that is not bytes refused `WebAuthnAssertion`. On both paths (`encodeAssertion`, `passkeyAssertion`).
test("finding 5: ArrayBuffer assertions are capped by their bytes", async () => {
  const digest = new Uint8Array(32).fill(0xab);
  const ad = concatBytes(sha256(utf8ToBytes(RP)), new Uint8Array([5, 0, 0, 0, 0]));
  const prefix = `{"type":"webauthn.get","challenge":"${"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s"}","origin":"https://`;
  const cdj = (n) => utf8ToBytes(prefix + "a".repeat(n - ad.length - prefix.length - 2) + '"}');
  const signature = p1363ToDer(fromHex("00".repeat(31) + "05" + "00".repeat(31) + "07"));
  const buf = (b) => b.slice().buffer;
  const at = cdj(1024);
  const big = new Uint8Array(2000).fill(1);
  const code = (c) => (e) => e.code === c;
  const enc = (authenticatorData, clientDataJSON) => encodeAssertion({ authenticatorData, clientDataJSON, signature });
  const cred = (authenticatorData, clientDataJSON) => ({
    get: async () => ({ authenticatorData, clientDataJSON, signature }),
  });
  // control: at the cap, ArrayBuffers encode as their bytes do
  assert.equal(bytesToHex(enc(buf(ad), buf(at))), bytesToHex(enc(ad, at)));
  const ok = await passkeyAssertion(digest, cred(buf(ad), buf(at)), derToRS);
  assert.ok(ok.authenticatorData instanceof Uint8Array && bytesToHex(ok.authenticatorData) === bytesToHex(ad));
  // 2,000 bytes of ArrayBuffer, as authenticatorData or clientDataJSON
  assert.throws(() => enc(buf(big), at), code("WebAuthnTooLong"));
  assert.throws(() => enc(ad, buf(big)), code("WebAuthnTooLong"));
  await assert.rejects(passkeyAssertion(digest, cred(buf(big), at), derToRS), code("WebAuthnTooLong"));
  await assert.rejects(passkeyAssertion(digest, cred(ad, buf(big)), derToRS), code("WebAuthnTooLong"));
  // a DataView over the bytes reads its own window
  assert.throws(() => enc(new DataView(buf(big), 1), at), code("WebAuthnTooLong"));
  // not bytes: refused by name
  for (const x of [undefined, "0x00", [1, 2], { length: 1 }])
    assert.throws(() => enc(x, at), code("WebAuthnAssertion"), String(x));
  await assert.rejects(passkeyAssertion(digest, cred([1, 2], at), derToRS), code("WebAuthnAssertion"));
});

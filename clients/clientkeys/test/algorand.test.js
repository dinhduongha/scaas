// near-algorand T18: Algorand client side against smartcontracts/algorand/vectors/algorand-vectors.json (every row).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  encodeMetaOp, digest, signText, signBytes, relayRef, routerCall, buildPayMeta, buildRelayFee, addressToKey,
  keyToAddress, appAddress, send, passkeyAssertion, PayMetaMismatch, NativeToUa,
} from '../src/algorand.js';
import { hex, fromHex } from '../src/bytes.js';
import { payLane } from '../src/evm.js';
import { p1363ToDer } from './softauthn.js';

const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/algorand/vectors/algorand-vectors.json', import.meta.url)));
const P = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/metatx/paymeta.json', import.meta.url)));
const rows = V.metaops.vectors;
const row = (n) => rows.find((r) => r.name === n);
const lane = (ref) => '0x' + payLane(ref).toString(16).padStart(64, '0');

test('algorand vectors', () => {
  assert.equal(rows.length, 33);
  for (const r of rows) {
    assert.equal(hex(encodeMetaOp(r.fields)), r.encoding, r.name);
    assert.equal(hex(digest(r.fields)), r.digest, r.name);
    assert.equal(signText(digest(r.fields)), r.text, r.name);
    if (r.auth.kind === 'ed25519') {
      assert.equal(hex(signBytes(r.text)), r.auth.signBytes, r.name);
      assert.ok(ed25519.verify(fromHex(r.auth.sig), signBytes(r.text), fromHex(r.auth.key)), `${r.name}: signature`);
    }
  }
  assert.equal(hex(signBytes(V.signing.text)), V.signing.signBytes);
});

test('algorand addresses and app addresses', () => {
  for (const r of V.nativeIds.rows) {
    assert.equal(hex(addressToKey(r.address)), r.key, r.name);
    assert.equal(keyToAddress(fromHex(r.key)), r.address, r.name);
  }
  for (const [n, a] of Object.entries(V.apps)) assert.equal(hex(appAddress(a.id)), a.key, n);
  assert.throws(() => addressToKey(V.keys.alice.address.slice(0, 57) + 'A'), /checksum/);
  assert.throws(() => addressToKey('abc'), /address/);
});

test('algorand relay refs, lanes and router call', () => {
  assert.equal(V.relayRefs.length, 2);
  for (const r of V.relayRefs) {
    assert.equal(hex(relayRef(fromHex(V.network), fromHex(r.target), fromHex(r.call), fromHex(r.salt))), r.ref, r.name);
    assert.equal(lane(r.ref), r.lane, r.name);
    assert.equal(hex(routerCall(r.targetApp, r.args.map(fromHex))), r.call, r.name);
  }
});

test('algorand passkey assertion', async () => {
  const p = V.passkey;
  const cred = { async get(challenge) {
    assert.equal(hex(challenge), row('pay_ua_passkey').digest);
    return { authenticatorData: fromHex(p.authenticatorData), clientDataJSON: new TextEncoder().encode(p.clientDataJSON),
      signature: p1363ToDer(fromHex(p.sigHighS)) };
  } };
  const a = await passkeyAssertion(fromHex(row('pay_ua_passkey').digest), cred);
  assert.equal(hex(a.signature), p.sig);
});

test('refuses pay-meta mismatch', () => {
  const r = row('pay_meta_note_utf8'), m = P.find((x) => x.name === 'note_utf8');
  assert.equal(hex(buildPayMeta(r.fields, m.salt, m.meta).digest), r.digest);
  const other = P.find((x) => x.name === 'empty_body');
  assert.throws(() => buildPayMeta(r.fields, other.salt, other.meta), PayMetaMismatch);
});

test('relay fee prompt carries both intents', () => {
  const rf = V.relayRefs[0], pay = row('relay_fee_pay_router_short');
  const base = { ...pay.fields, pay_ref: undefined, lane: undefined, extra: undefined, to: undefined, relayer: undefined };
  const plan = buildRelayFee({ router: V.apps.router.key, targetApp: rf.targetApp, args: rf.args.map(fromHex),
    salt: rf.salt }, base);
  assert.equal(plan.ref, rf.ref);
  assert.equal(hex(plan.digest), pay.digest);
  assert.deepEqual(plan.prompt.call, { target: rf.targetApp, data: rf.call });
  assert.deepEqual(plan.prompt.payment, { token: pay.fields.contractApp, amount: 10n, payee: null, open: true });
});

test('pay-meta and relay-fee payments need nonce 0', () => {
  const r = row('pay_meta_note_utf8'), m = P.find((x) => x.name === 'note_utf8');
  assert.throws(() => buildPayMeta({ ...r.fields, nonce: 1 }, m.salt, m.meta), /nonce/);
  const rf = V.relayRefs[0], pay = row('relay_fee_pay_router_short');
  assert.throws(() => buildRelayFee({ router: V.apps.router.key, targetApp: rf.targetApp, args: rf.args.map(fromHex),
    salt: rf.salt }, { ...pay.fields, nonce: 2 }), /nonce/);
  assert.throws(() => buildRelayFee({ router: V.apps.router.key, targetApp: rf.targetApp, args: rf.args.map(fromHex),
    salt: rf.salt }, { ...pay.fields, contractApp: undefined }), /contractApp/);
});

test('passkeyAssertion refuses a wrong challenge', async () => {
  const p = V.passkey;
  const cred = { async get() {
    return { authenticatorData: fromHex(p.authenticatorData),
      clientDataJSON: new TextEncoder().encode(p.clientDataJSON.replace(p.challenge, 'AAAA')), signature: p1363ToDer(fromHex(p.sig)) };
  } };
  await assert.rejects(passkeyAssertion(fromHex(row('pay_ua_passkey').digest), cred), /challenge/);
});

test('refuses native send to a UA id', () => {
  const ua = row('pay_ua_secp256k1').fields;
  assert.throws(() => send({ ...ua, to: ua.from }, { native: true }), NativeToUa);
  assert.equal(hex(send(row('pay').fields, { native: true }).digest), row('pay').digest);
  assert.equal(hex(send(ua).digest), row('pay_ua_secp256k1').digest);
});

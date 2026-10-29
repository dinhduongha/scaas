// near-algorand T18: NEAR client side against smartcontracts/near/vectors/near-vectors.json (every row).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import {
  encodeMetaOp, digest, signText, nep413Hash, relayRef, routerCall, wrapperCall, targetBytes, buildPayMeta,
  buildRelayFee, nativeId, keyOpFanOut, send, passkeyAssertion, PayMetaMismatch, NativeToUa,
} from '../src/near.js';
import { hex, fromHex, sha256, b64url, concatBytes } from '../src/bytes.js';
import { payLane } from '../src/evm.js';
import { p1363ToDer } from './softauthn.js';

const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/near/vectors/near-vectors.json', import.meta.url)));
const P = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/metatx/paymeta.json', import.meta.url)));
const rows = V.metaops.vectors;
const row = (n) => rows.find((r) => r.name === n);
const lane = (ref) => '0x' + payLane(ref).toString(16).padStart(64, '0');

test('near vectors', () => {
  assert.equal(rows.length, 37);
  for (const r of rows) {
    const enc = encodeMetaOp(r.fields);
    assert.equal(hex(enc), r.encoding, r.name);
    assert.equal(hex(digest(r.fields)), r.digest, r.name);
    assert.equal(signText(digest(r.fields)), r.text, r.name);
    if (r.auth.kind === 'ed25519' && r.auth.nep413Hash) {
      const h = nep413Hash(r.text, r.auth.recipient, fromHex(r.auth.nonce));
      assert.equal(hex(h), r.auth.nep413Hash, r.name);
      assert.ok(ed25519.verify(fromHex(r.auth.sig), h, fromHex(r.auth.key)), `${r.name}: signature`);
    }
  }
  assert.equal(hex(nep413Hash(V.signing.message, V.signing.recipient, fromHex(V.signing.nonce))), V.signing.hash);
});

test('near relay refs, lanes and call forms', () => {
  assert.equal(V.relayRefs.length, 6);
  const net = fromHex(V.network);
  for (const r of V.relayRefs) {
    assert.equal(hex(targetBytes(r.target)), r.targetBytes, r.name);
    assert.equal(hex(relayRef(net, fromHex(r.targetBytes), fromHex(r.call), fromHex(r.salt))), r.ref, r.name);
    assert.equal(lane(r.ref), r.lane, r.name);
    if (r.kind === 'router') assert.equal(hex(routerCall(r.target, r.method, fromHex(r.args))), r.call, r.name);
    else if (r.name === 'wrapper_add_key_real') assert.equal(hex(wrapperCall(r.entry, fromHex(r.args))), r.call);
  }
});

test('near native ids', () => {
  for (const r of V.nativeIds.rows) assert.equal(hex(nativeId(r.accountId)), r.id, r.accountId);
  for (const r of V.nativeIds.invalid) assert.throws(() => nativeId(r.accountId), /not a NEAR account id/, r.accountId);
});

test('near passkey assertion: low-s normalised, challenge = digest', async () => {
  const p = V.passkey;
  const seen = [];
  const cred = { async get(challenge) {
    seen.push(hex(challenge));
    return { authenticatorData: fromHex(p.authenticatorData), clientDataJSON: new TextEncoder().encode(p.clientDataJSON),
      signature: p1363ToDer(fromHex(p.sigHighS)) };
  } };
  const d = row('pay_ua_passkey').digest;
  const a = await passkeyAssertion(fromHex(d), cred);
  assert.deepEqual(seen, [d]);
  assert.equal(hex(a.signature), p.sig);
  assert.equal(a.clientDataJSON, p.clientDataJSON);
  assert.equal(hex(a.authenticatorData), p.authenticatorData);
});

test('refuses pay-meta mismatch', () => {
  const r = row('pay_meta_note_utf8'), m = P.find((x) => x.name === 'note_utf8');
  const ok = buildPayMeta(r.fields, m.salt, m.meta);
  assert.equal(hex(ok.digest), r.digest);
  assert.equal(ok.entry, 'mtx_pay_meta');
  const other = P.find((x) => x.name === 'empty_body');
  assert.throws(() => buildPayMeta(r.fields, other.salt, other.meta), PayMetaMismatch);
  assert.throws(() => buildPayMeta(r.fields, m.salt, other.meta), PayMetaMismatch);
  assert.throws(() => buildPayMeta({ ...r.fields, lane: '0x' + '00'.repeat(32) }, m.salt, m.meta), PayMetaMismatch);
});

test('relay fee prompt carries both intents', () => {
  const rf = V.relayRefs.find((x) => x.name === 'router_short');
  const pay = row('relay_fee_pay_router_short');
  const base = { ...pay.fields, pay_ref: undefined, lane: undefined, extra: undefined, to: undefined, relayer: undefined };
  const plan = buildRelayFee({ route: 'router', router: V.accounts.router, target: rf.target, method: rf.method,
    args: fromHex(rf.args), salt: rf.salt }, base);
  assert.equal(plan.ref, rf.ref);
  assert.equal(hex(plan.digest), pay.digest);
  assert.deepEqual(plan.prompt.call, { target: rf.target, method: 'settle', data: rf.call });
  assert.deepEqual(plan.prompt.payment, { token: V.accounts.token, amount: 10n, payee: null, open: true });
  const wr = V.relayRefs.find((x) => x.name === 'wrapper_add_key_real');
  const wp = row('relay_fee_pay_wrapper_add_key_real');
  const w = buildRelayFee({ route: 'wrapper', entry: wr.entry, args: fromHex(wr.args), salt: wr.salt },
    { ...wp.fields, pay_ref: undefined, lane: undefined, extra: undefined, to: undefined, relayer: undefined });
  assert.equal(hex(w.digest), wp.digest);
  assert.equal(w.prompt.call.target, V.accounts.token);
  assert.equal(w.prompt.call.method, 'mtx_add_key');
});

test('refuses native send to a UA id', () => {
  const ua = row('pay_ua_secp256k1').fields;
  assert.throws(() => send({ ...ua, to: ua.from }, { native: true }), NativeToUa);
  assert.throws(() => send({ ...ua, to: ua.from }, { native: true }), /NET-ALL-21/);
  const ok = send(row('pay').fields, { native: true });
  assert.equal(hex(ok.digest), row('pay').digest);
  assert.equal(hex(send(ua).digest), row('pay_ua_secp256k1').digest, 'a token send to a UA id is the normal path');
});

test('near key op fans out to every held token, each at its own nonce', () => {
  const k = row('add_key_secp256k1').fields;
  const T = [V.accounts.token, V.accounts.tokenB];
  const ops = keyOpFanOut(k, T, { [T[0]]: 0, [T[1]]: 5 });
  assert.equal(ops.length, 2);
  assert.deepEqual(ops.map((o) => o.contract), T);
  assert.deepEqual(ops.map((o) => o.nonce), [0, 5]);
  assert.equal(hex(digest(ops[0])), row('add_key_secp256k1').digest);
  assert.notEqual(hex(digest(ops[1])), hex(digest(ops[0])));
  assert.throws(() => keyOpFanOut(k, T, { [T[0]]: 0 }), /nonce/);
  assert.throws(() => keyOpFanOut(row('pay').fields, [T[0]], { [T[0]]: 0 }), /key op/);
  assert.throws(() => keyOpFanOut(k, [], {}), /no token/);
});

test('pay-meta and relay-fee payments need nonce 0', () => {
  const r = row('pay_meta_note_utf8'), m = P.find((x) => x.name === 'note_utf8');
  assert.throws(() => buildPayMeta({ ...r.fields, nonce: 1 }, m.salt, m.meta), /nonce/);
  const rf = V.relayRefs.find((x) => x.name === 'router_short'), pay = row('relay_fee_pay_router_short');
  assert.throws(() => buildRelayFee({ route: 'router', router: V.accounts.router, target: rf.target, method: rf.method,
    args: fromHex(rf.args), salt: rf.salt }, { ...pay.fields, nonce: 2 }), /nonce/);
});

test('passkeyAssertion refuses a wrong challenge, type or invalid UTF-8', async () => {
  const p = V.passkey, d = fromHex(row('pay_ua_passkey').digest);
  const mk = (cdj) => ({ async get() {
    return { authenticatorData: fromHex(p.authenticatorData), clientDataJSON: cdj, signature: p1363ToDer(fromHex(p.sig)) };
  } });
  const enc = (s) => new TextEncoder().encode(s);
  await assert.rejects(passkeyAssertion(d, mk(enc(p.clientDataJSON.replace(p.challenge, 'AAAA')))), /challenge/);
  await assert.rejects(passkeyAssertion(d, mk(enc(p.clientDataJSON.replace('webauthn.get', 'webauthn.create')))), /type/);
  await assert.rejects(passkeyAssertion(d, mk(Uint8Array.of(0x7b, 0xff, 0x7d))), /UTF-8|encoded/);
});

test('passkeyAssertion output verifies as P-256 over authenticatorData || sha256(clientDataJSON)', async () => {
  const p = V.passkey, d = fromHex(row('pay_ua_passkey').digest);
  const cred = { async get() {
    return { authenticatorData: fromHex(p.authenticatorData), clientDataJSON: enc(p.clientDataJSON),
      signature: p1363ToDer(fromHex(p.sigHighS)) };
  } };
  const a = await passkeyAssertion(d, cred);
  const msg = concatBytes(a.authenticatorData, sha256(enc(a.clientDataJSON)));
  assert.ok(p256.verify(a.signature, msg, concatBytes(Uint8Array.of(4), fromHex(p.key)), { lowS: true }));
  assert.equal(JSON.parse(a.clientDataJSON).challenge, b64url(d));
});
function enc(s) { return new TextEncoder().encode(s); }

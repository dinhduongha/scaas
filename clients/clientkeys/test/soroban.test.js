// UA-Soroban T4 (spec §2, §10): src/soroban.js against the Soroban cross vector of the node adapter and token, and
// smartcontracts/soroban/vectors/ua-ops.json (the generator reproduces it; every digest is rebuilt from the args' XDR;
// every auth verifies under its kind with the verifiers of test/ua-verify.js); derived ids are URNs, never strkeys.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as ua from '../src/ua.js';
import * as sor from '../src/soroban.js';
import { sha256, concatBytes, hex } from '../src/bytes.js';
import { be } from '../src/metaop.js';
import { strkey } from '../src/seed.js';
import { uaOpsJson, OUT } from '../scripts/soroban-ua-ops-vectors.mjs';
import { B, sigOk, msigOk } from './ua-verify.js';

const h = (b) => hex(b).slice(2);

test('soroban op digest: the token cross vector reproduced', () => {
  const rs = readFileSync(new URL('../../../scaas-node/src/adapters/soroban.rs', import.meta.url), 'utf8');
  const PREIMAGE = /const PREIMAGE: &str = "([0-9a-f]+)";/.exec(rs)[1];
  const net = sor.networkId('Standalone Network ; February 2017');
  const contract = sor.addr('CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO');
  const args = [sor.addr('GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6'),
    sor.addr('GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6'), sor.i128(12_345),
    sor.bytesN(new Uint8Array(32).fill(0x11)), sor.u64(1_800_000_300)];
  // HashIdPreimage::SorobanAuthorization { network_id, nonce 42, expiration 1000, ContractFn(contract, "pay", args), [] }:
  // the XDR bodies are the ScVal encodings without their type word (and, for the args VecM, without the Option word).
  const pre = concatBytes(be(9, 4), net, be(42, 8), be(1000, 4), be(0, 4), sor.scvalXdr(contract).subarray(4),
    sor.scvalXdr(sor.sym('pay')).subarray(4), sor.scvalXdr(sor.vec(args)).subarray(8), be(0, 4));
  assert.equal(h(pre), PREIMAGE);
  assert.equal(h(sha256(pre)), '0a2127bfdc94f6062f0ec27f6db966ae719dafaca90bc537666eab606b901103');
  const d = sor.opDigest({ networkId: net, contract: 'CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO', fn: 'pay', args });
  assert.equal(h(d), '0bb4e9123b86f99303e03cfd8aacb1eecd3b8ccb10d572907e1228a715369b00'); // token VEC_DIGEST, ua-common
  // ScVal edges: i128 two's complement, Option, a struct's keys sorted, a Holder variant.
  assert.equal(h(sor.scvalXdr(sor.i128(-1))), `0000000a${'ff'.repeat(16)}`);
  assert.equal(h(sor.scvalXdr(sor.none())), '00000001');
  assert.equal(h(sor.scvalXdr(sor.struct({ b: sor.u32(2), a: sor.bool(true) }))),
    '000000110000000100000002' + '0000000f0000000161000000' + '0000000000000001' + '0000000f0000000162000000' + '0000000300000002');
  assert.equal(h(sor.scvalXdr(sor.holderUa(new Uint8Array(32).fill(7)))),
    `000000100000000100000002${'0000000f000000025561' + '0000'}0000000d00000020${'07'.repeat(32)}`);
  assert.throws(() => sor.u32(2 ** 32), RangeError);
  assert.throws(() => sor.addr('GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ7'), /strkey/);
});

const TEXT = readFileSync(OUT, 'utf8');
const V = JSON.parse(TEXT);

test('soroban ua-ops.json reproduced byte for byte', () => {
  assert.equal(uaOpsJson(), TEXT);
  assert.equal(V.network.networkId, hex(sor.networkId(V.network.passphrase)));
  assert.deepEqual(V.entries.map((e) => e.name), ['ua_transfer', 'ua_pay', 'ua_pay_meta', 'ua_burn', 'ua_cancel_nonce',
    'ua_order', 'ua_cancel', 'ua_relay', 'mtx_mandate_pay', 'mtx_set_mandate']);
  for (const e of V.entries) {
    assert.deepEqual(e.perKind.map((p) => p.kind), ['webauthn-p256', 'p256', 'ed25519', 'secp256k1', 'mldsa44', 'mldsa65', 'msig'], e.name);
  }
  // the e2e signer (SOR-D13) signs as the vectors do
  const e = V.entries.find((x) => x.name === 'ua_cancel_nonce');
  for (const [kind, index] of [['mldsa65', '2'], ['msig', '0'], ['webauthn-p256', '0']]) {
    const p = e.perKind.find((x) => x.kind === kind);
    const out = execFileSync(process.execPath, [fileURLToPath(new URL('../scripts/soroban-sign.mjs', import.meta.url)),
      kind, index, p.digest, e.purpose], { encoding: 'utf8' });
    const r = V.registrations.find((x) => x.ua === p.ua);
    assert.deepEqual(JSON.parse(out), { ua: p.ua, keyData: r.keyData, auth: p.auth }, kind);
  }
});

test('soroban ua-ops: every auth verifies under its kind', () => {
  const reg = (id) => V.registrations.find((r) => r.ua === id) ?? assert.fail(`no registration of ${id}`);
  const keyOf = (id) => reg(id).keyData;
  // registrations: portable pops (no network, no registry)
  for (const r of V.registrations) {
    assert.equal(hex(ua.uaOf(r.kind, B(r.keyData))), r.ua, r.name);
    const m = ua.holderPopMessage(r.kind, { ua: B(r.ua), keyData: B(r.keyData) });
    assert.ok(r.kind === 0x0120 ? msigOk(r, hex(m.memberDigest), r.pop, keyOf) : sigOk(r.kind, r.keyData, hex(m.message), r.pop), r.name);
  }
  for (const e of V.entries) {
    assert.equal(e.purposeTag, hex(ua.purposeTag(e.purpose)), e.name);
    for (const p of e.perKind) {
      const what = `${e.name} ${p.kind}`;
      const r = reg(p.ua);
      const d = sor.opDigest({ networkId: B(V.network.networkId), contract: e.contract, fn: e.fn,
        args: p.args.map((a) => ({ xdr: B(a.xdr) })) });
      assert.equal(hex(d), p.digest, what);
      const msg = ua.uaMessage(r.kind, B(e.purposeTag), d);
      assert.equal(hex(msg), p.uaMsg, what);
      assert.ok(r.kind === 0x0120 ? msigOk(r, hex(ua.memberDigest(B(r.ua), msg)), p.auth, keyOf) : sigOk(r.kind, r.keyData, p.uaMsg, p.auth), what);
      // the signature is bound to this digest: another entry's message fails
      const other = ua.uaMessage(r.kind, B(e.purposeTag), sha256(d));
      assert.equal(r.kind === 0x0120 ? msigOk(r, hex(ua.memberDigest(B(r.ua), other)), p.auth, keyOf) : sigOk(r.kind, r.keyData, hex(other), p.auth), false, what);
      // a UA argument is the signer's own id (from / ua / order.maker), never another's
      if (['ua_transfer', 'ua_pay', 'ua_pay_meta', 'ua_burn', 'ua_cancel_nonce', 'ua_relay'].includes(e.name)) {
        assert.equal(p.args[0].xdr, hex(sor.scvalXdr(sor.bytesN(B(p.ua)))), what);
      }
    }
  }
  // ua_relay: the inner ua_pay's pay_ref is the router's relay_ref, relayer = Some(router)
  const relay = V.entries.find((e) => e.name === 'ua_relay');
  for (const p of relay.perKind) {
    assert.equal(p.args.find((a) => a.name === 'pay_ref').xdr, hex(sor.scvalXdr(sor.bytesN(B(relay.relay.ref)))));
    assert.equal(p.args.find((a) => a.name === 'relayer').xdr, hex(sor.scvalXdr(sor.addr(V.contracts.router))));
  }
});

test('soroban URN: derived ids never as strkey; a native send to a URN is refused', () => {
  for (const r of V.registrations) {
    const urn = sor.uaUrn(r.kind, B(r.ua));
    assert.match(urn, /^urn:scaas:ua:v1:[a-z0-9-]+:[0-9a-f]{64}$/);
    assert.deepEqual(sor.parseRecipient(urn), { ua: B(r.ua), kind: r.kind });
    assert.throws(() => sor.assertNativeRecipient(urn), (e) => e instanceof ua.UAError && e.code === 'UaNotNative', r.name);
  }
  // native ids keep their strkeys; a native kind has no URN
  const g = 'GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6';
  assert.equal(sor.assertNativeRecipient(g), g);
  assert.equal(sor.assertNativeRecipient(V.contracts.token), V.contracts.token);
  assert.throws(() => sor.uaUrn(0x0011, sor.decodeStrkey(g).payload), (e) => e.code === 'UAKindNotDerived');
  assert.throws(() => sor.parseRecipient('urn:scaas:ua:v1:stellar-account:' + '11'.repeat(32)), (e) => e.code === 'UAKindNotDerived');
  assert.throws(() => sor.parseRecipient('0x' + '11'.repeat(32)), /strkey/);
  // the same 32 bytes as a strkey are a different (native) recipient: the URN is the only form a UA is shown in
  const id = B(V.registrations[0].ua);
  assert.deepEqual(sor.parseRecipient(strkey(6 << 3, id)), { addr: strkey(6 << 3, id) });
});

test('soroban URN: any-case urn:scaas:ua: prefix is a UA form, never a strkey (NET-SOR-17)', () => {
  const id = 'ab'.repeat(32);
  for (const t of [`URN:SCAAS:UA:v1:ed25519:${id}`, `Urn:Scaas:Ua:v1:ed25519:${id}`, `urn:scaas:ua:v1:ED25519:${id}`,
    `urn:scaas:ua:v1:ed25519:${id.toUpperCase()}`]) {
    assert.throws(() => sor.assertNativeRecipient(t), (e) => e instanceof ua.UAError && e.code === 'UaNotNative', t);
    assert.throws(() => sor.parseRecipient(t), (e) => e instanceof ua.UAError && e.code === 'UAIdFormat', t);
  }
});

test('soroban msig: a soroban-contract (C…) member is refused when building (S10, owner ruling 2026-10-31)', () => {
  const m = (kind, b) => ({ kind, id: new Uint8Array(32).fill(b), weight: 1 });
  assert.throws(() => sor.encodeMsig(1, [m(0x0102, 1), m(0x0012, 2)]), (e) => e instanceof ua.UAError && e.code === 'MemberUnknown');
  assert.deepEqual(sor.encodeMsig(1, [m(0x0011, 1), m(0x0102, 2)]), ua.encodeMsig(1, [m(0x0011, 1), m(0x0102, 2)]));
});

// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Set-auditor (spec 2026-11-17-set-auditor.md §5.2, §8; plan A7; CTR-GOV-31): the router's `UASetAuditorKey` and `UASetAuditorUA`
// (the struct signs `keccak256(newKey)` or the new UA, the epoch and the target's chain word; the new auditor's consent rides
// unsigned beside it, forwarded as given) and the new auditor's `AuditorConsent`, typed under the token's own domain, its PQZ
// signature under `PURPOSE_AUDITOR_CONSENT`. Type strings read from the contract sources; digests and calldata from
// smartcontracts/vectors/typed/typed_ops.json. UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as evm from '../src/evm.js';
import * as ua from '../src/ua.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes } from '../src/bytes.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const ROOT = new URL('../../../', import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT), 'utf8');
const V = JSON.parse(read('smartcontracts/vectors/typed/typed_ops.json'));
const k = (s) => hex(keccak_256(utf8ToBytes(s)));
const solString = (path, name) => {
  const m = new RegExp(`${name}\\s*=\\s*keccak256\\(\\s*"([^"]*)"\\s*\\)`).exec(read(path));
  assert.ok(m, `${name} in ${path}`);
  return m[1];
};
const ROUTER_BASE = 'smartcontracts/evm/src/governance/GovernanceRouterBase.sol';
const domainOf = (r, d) => ({ name: d.domain.name, contract: d.domain.verifyingContract, chainId: d.domain.chainId, chainUid: d.domain.salt });

test('the type strings are the contracts\'', () => {
  assert.equal(evm.TYPED_OPS.UASetAuditorKey.typeString, solString(ROUTER_BASE, 'UA_SET_AUDITOR_KEY'));
  assert.equal(evm.TYPED_OPS.UASetAuditorUA.typeString, solString(ROUTER_BASE, 'UA_SET_AUDITOR_UA'));
  assert.equal(evm.TYPED_OPS.AuditorConsent.typeString,
    solString('smartcontracts/evm/src/confidential/AuditorRules.sol', 'AUDITOR_CONSENT_TYPEHASH'));
  assert.equal(hex(ua.purposeTag('auditor-consent')), k('scaas.ua.purpose.auditor-consent.v1'));
  assert.equal(hex(ua.purposeTag('auditor-consent')), k(solString('smartcontracts/evm/src/ua/UAKinds.sol', 'PURPOSE_AUDITOR_CONSENT')));
});

test('UASetAuditorKey: newKey hashed into the struct, the proof forwarded beside it', () => {
  const r = V.ops.UASetAuditorKey;
  const d = r.domains.gov_router;
  const build = (m) => evm.OP_BUILDERS.uaSetAuditorKeyTypedData({ ...domainOf(r, d), message: m });
  assert.equal(hex(evm.hashTypedData(build(r.message))), d.digest, 'the row');
  assert.notEqual(hex(evm.hashTypedData(build({ ...r.message, newKey: '0x' + 'ab'.repeat(128) }))), d.digest, 'newKey is signed');
  assert.notEqual(hex(evm.hashTypedData(build({ ...r.message, epoch: 2 }))), d.digest, 'the epoch is signed');
  assert.ok(d.abi.startsWith('mtxSetAuditorKey('), d.abi);
  assert.ok(d.calldata.includes(d.extra.pop.slice(2)), 'the pop rides in the calldata');
  const op = evm.TYPED_OPS.UASetAuditorKey;
  assert.throws(() => op.call(build(r.message), d.signature, {}), /extra\.pop/);
});

test('UASetAuditorUA: the new UA in the struct, the consent forwarded beside it', () => {
  const r = V.ops.UASetAuditorUA;
  const d = r.domains.gov_router;
  const build = (m) => evm.OP_BUILDERS.uaSetAuditorUATypedData({ ...domainOf(r, d), message: m });
  assert.equal(hex(evm.hashTypedData(build(r.message))), d.digest);
  assert.notEqual(hex(evm.hashTypedData(build({ ...r.message, newAuditor: '0x' + '77'.repeat(32) }))), d.digest, 'the UA is signed');
  assert.ok(d.abi.startsWith('mtxSetAuditorUA('), d.abi);
  assert.ok(d.calldata.includes(d.extra.consent.signature.slice(2)), 'the consent rides in the calldata');
  assert.throws(() => evm.TYPED_OPS.UASetAuditorUA.call(build(r.message), d.signature, {}), /extra\.consent/);
});

test('AuditorConsent: typed under each confidential token domain, no entry of its own', () => {
  const r = V.ops.AuditorConsent;
  assert.deepEqual(Object.keys(r.domains).sort(), ['pqz', 'zether']);
  for (const [kind, d] of Object.entries(r.domains)) {
    const td = evm.OP_BUILDERS.auditorConsentTypedData({ ...domainOf(r, d), message: r.message });
    assert.equal(hex(evm.hashTypedData(td)), d.digest, kind);
    assert.equal(d.calldata, undefined, `${kind}: no entry`);
  }
});

test('AuditorConsent: the consent rows, a native and a derived signer, each over the consent naming its own UA', () => {
  const r = V.ops.AuditorConsent;
  const tag = ua.purposeTag('auditor-consent');
  const S = JSON.parse(read('smartcontracts/vectors/ua/structures.json')).contexts.A;
  const recover = (sig, h) => {
    const b = fromHex(sig);
    const pk = secp256k1.Signature.fromBytes(b.subarray(0, 64), 'compact').addRecoveryBit(b[64] - 27).recoverPublicKey(h)
      .toBytes(false).subarray(1);
    return hex(keccak_256(pk).subarray(12));
  };
  for (const [kind, d] of Object.entries(r.domains)) {
    const typed = (auditor) => hex(evm.hashTypedData(evm.OP_BUILDERS.auditorConsentTypedData({ ...domainOf(r, d),
      message: { ...r.message, auditor } })));
    const n = d.consent.native;
    assert.equal(n.digest, typed(n.ua), `${kind}: the native consent names its own id`);
    assert.equal(n.digest, d.digest, `${kind}: the row's own message`);
    assert.equal(hex(ua.uaAuthDigest({ generation: 1, ...S }, fromHex(n.ua), tag, fromHex(n.digest))), n.uaAuthDigest, kind);
    assert.equal('0x' + '00'.repeat(12) + recover(n.signature, fromHex(n.uaAuthDigest)).slice(2), n.ua, `${kind}: native signer`);
    const x = d.consent.derived;
    assert.equal(hex(ua.uaOf(x.kind, fromHex(x.keyData))), x.ua, kind);
    assert.equal(x.digest, typed(x.ua), `${kind}: the derived consent names its own UA`);
    assert.equal(hex(ua.uaMessage(x.kind, tag, fromHex(x.digest))), x.uaMessage, kind);
    assert.ok(secp256k1.verify(fromHex(x.signature).subarray(0, 64), fromHex(x.uaMessage), concatBytes(Uint8Array.of(4), fromHex(x.keyData)),
      { prehash: false }), `${kind}: derived signer`);
    assert.notEqual(x.digest, n.digest, 'two consents, two digests');
  }
});


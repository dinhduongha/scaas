// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-rs-sign T20c (owner 2026-11-08, CLI-SGN-29 Change): an imported native key registers its own derived kind, secp256k1
// (0x0108) for a secp256k1 secret, ed25519 (0x0102) for an ed25519 seed, and no other; read back from
// smartcontracts/vectors/ua/{keys,sign,seal}.json `imported` (scripts/ua-wallet-vectors.mjs). UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { dir } from './ua-vectors-dir.js';
import { hex, fromHex, utf8ToBytes } from '../src/bytes.js';
import * as ua from '../src/ua.js';
import * as evm from '../src/evm.js';
import * as seedjs from '../src/seed.js';
import { verify as kindVerify } from '../src/ua-verify.js';

// red first: every named test fails on its own before the code exists
const U = await import('../src/uakey.js').catch(() => ({}));
const KEM = await import('../src/kem.js').catch(() => ({}));
const SL = await import('../src/seal.js').catch(() => ({}));
const json = (f) => { try { return JSON.parse(readFileSync(new URL(f, dir), 'utf8')); } catch { return null; } };
const K = json('keys.json');
const S = json('sign.json');
const SE = json('seal.json');
const B = (h) => fromHex(h);
const codeOf = (f) => { try { f(); return null; } catch (e) { return e.code ?? e.message; } };
const codeOfAsync = async (f) => { try { await f(); return null; } catch (e) { return e.code ?? e.message; } };
const seeds = () => Object.fromEntries(K.mnemonics.map((m) => [m.id, B(m.seed)]));
const kemOf = (r) => KEM.kemKeyOf(U.deriveUAKey(seeds()[r.mnemonic], { kind: r.kind, account: r.account, index: r.index }), r.version);
const importedOf = (r) => U.importedUAKey({ network: r.network, secret: B(r.secret), kind: r.kind });

test('keys.json imported: the UA of an imported key per network, separate from its native id; every other kind refused', () => {
  assert.ok(K?.imported, 'keys.json imported');
  assert.equal(K.imported.rows.length, 9);
  for (const r of K.imported.rows) {
    const k = importedOf(r);
    assert.equal(k.kind, r.kind, r.network);
    assert.equal(r.kind, seedjs.NETWORKS[r.network].curve === 'ed25519' ? 0x0102 : 0x0108, r.network);
    assert.equal(hex(k.keyData), r.keyData, r.network);
    assert.equal(hex(k.ua), r.ua, r.network);
    assert.equal(hex(ua.deriveUA(r.kind, B(r.keyData))), r.ua, `${r.network}: keccak256(TAG(kind) ‖ key_data)`);
    const n = seedjs.importKey(r.network, B(r.secret));
    assert.equal(n.publicKey, r.native.publicKey, r.network);
    assert.equal(n.address ?? null, r.native.address, r.network);
    // the native id: a secp256k1 key's 20-byte address in the 32-byte space, an ed25519 key's public key
    const nativeId = n.curve === 'secp256k1' && n.address ? '0x' + '00'.repeat(12) + n.address.slice(2).toLowerCase() : '0x' + n.publicKey.replace(/^0x/, '');
    assert.notEqual(r.ua, nativeId, `${r.network}: a separate account`);
    assert.notEqual(BigInt(r.ua) >> 160n, 0n, `${r.network}: not in the native space`);
  }
  const eoa = K.imported.rows.find((r) => r.network === 'evm');
  const fromSeed = seedjs.deriveKey(seeds().bip39_test, 'evm', 0);
  assert.equal(hex(fromSeed.privateKey), eoa.secret, 'the evm row is the BIP-39 test mnemonic\'s EOA key 0');
  assert.equal(eoa.native.address, fromSeed.address);
  assert.equal(K.imported.refusals.length, 6);
  for (const x of K.imported.refusals) {
    const r = K.imported.rows.find((y) => y.network === x.network);
    assert.equal(codeOf(() => U.importedUAKey({ network: x.network, secret: B(r.secret), kind: x.kind })), x.error, x.reason);
  }
  // positive control: the same row with its own kind
  assert.ok(importedOf(K.imported.rows[0]).ua);
});

test('importedUAKey: no raw-digest call, no KEM key (KemHolder), 32-byte secrets only', () => {
  for (const r of K.imported.rows.filter((x) => ['evm', 'solana'].includes(x.network))) {
    const k = importedOf(r);
    assert.equal(k.signDigest, undefined, 'no raw-digest call on a UA key');
    assert.equal(codeOf(() => k.kemKey(0)), 'KemHolder', r.network);
    assert.equal(codeOf(() => U.importedUAKey({ network: r.network, secret: B(r.secret).subarray(0, 31), kind: r.kind })), 'Argument');
  }
  assert.equal(codeOf(() => U.importedUAKey({ network: 'evm', secret: new Uint8Array(32), kind: 0x0108 })), 'Argument', 'scalar 0');
  assert.equal(codeOf(() => U.importedUAKey({ network: 'near', secret: new Uint8Array(32).fill(1), kind: 0x0102 })), 'Argument');
});

test('sign.json imported: pop v2, a meta-transaction (unbound relayer / feeRecipient zeroed) and a member signature, byte-equal', () => {
  assert.ok(S?.imported, 'sign.json imported');
  assert.equal(S.imported.rows.length, 6);
  for (const r of S.imported.rows) {
    const k = importedOf(K.imported.rows.find((x) => x.network === r.network));
    let digest;
    if (r.what === 'pop') digest = ua.registrationDigest({ ua: k.ua, kind: k.kind });
    else if (r.what === 'metatx') {
      const td = evm.uaMetaTransferTypedData(r.input);
      digest = evm.hashTypedData(JSON.parse(JSON.stringify(td)));
      assert.notEqual(r.input.message.relayer, '0x' + '00'.repeat(20), 'the input names a non-zero relayer');
      assert.notEqual(hex(evm.hashTypedData({ ...JSON.parse(JSON.stringify(td)), message: r.input.message })), hex(digest),
        'the supplied value hashes elsewhere: the builder zeroed it');
    } else digest = ua.memberDigest(B(r.structureUa), B(r.structureUaMsg));
    assert.equal(hex(digest), r.digest, r.id);
    const msg = ua.uaMessage(k.kind, B(r.purposeTag), digest);
    assert.equal(hex(msg), r.uaMsg, r.id);
    const sig = r.what === 'member' ? k.signMember(B(r.structureUa), B(r.structureUaMsg)) : k.signUA(B(r.purposeTag), digest);
    assert.equal(hex(sig), r.signature, r.id);
    assert.ok(kindVerify(k.kind, hex(k.keyData), r.uaMsg, r.signature, r.what === 'pop'), r.id);
  }
});

test('sign.json imported separation: a native signature is no UA signature and a UA signature fails the native check', () => {
  assert.equal(S.imported.separation.length, 4);
  for (const r of S.imported.separation) {
    const row = K.imported.rows.find((x) => x.network === r.network);
    const k = importedOf(row);
    const n = seedjs.importKey(r.network, B(row.secret));
    const pub = B(n.publicKey);
    const nativeOk = (sig, d) => (n.curve === 'ed25519' ? ed25519.verify(B(sig), B(d), pub)
      : secp256k1.verify(B(sig).subarray(0, 64), B(d), pub, { prehash: false, lowS: true }));
    // the row's native signature is the key's over the operation's own digest (positive control), never a UA signature
    const nativeSig = r.op === 'typed' ? seedjs.signTyped(n, r.td) : r.op === 'tx' ? (() => {
      const t = seedjs.signTransaction(n, r.tx); return new Uint8Array([...t.r, ...t.s, 27 + t.yParity]); })()
      : seedjs.signKeyProof(n, utf8ToBytes(r.challenge));
    assert.equal(hex(nativeSig), r.nativeSignature, r.id);
    assert.ok(nativeOk(r.nativeSignature, r.digest), `${r.id}: native positive control`);
    assert.equal(kindVerify(k.kind, hex(k.keyData), r.uaMsg, r.nativeSignature, false), false, `${r.id}: native as UA refused`);
    // the UA signature over uaMessage(kind, metatx, digest): valid as a UA signature, refused by the native check
    assert.equal(hex(k.signUA(ua.purposeTag('metatx'), B(r.digest))), r.uaSignature, r.id);
    assert.ok(kindVerify(k.kind, hex(k.keyData), r.uaMsg, r.uaSignature, false), `${r.id}: UA positive control`);
    assert.equal(nativeOk(r.uaSignature, r.digest), false, `${r.id}: UA as native refused`);
  }
});

const restoreRow = async (r) => {
  const R = kemOf(r.opener.kem);
  return SL.restoreBackup(R, r.container, r.expect);
};

test('seal.json imported: a backup with its importedUas restores; one secret under two sources; refusals Argument', async () => {
  assert.ok(SE?.imported, 'seal.json imported');
  let ok = 0;
  for (const r of SE.imported) {
    if (r.error) {
      assert.equal(await codeOfAsync(() => restoreRow(r)), r.error, r.id);
      continue;
    }
    const { install, payload } = await restoreRow(r);
    assert.equal(install, true, r.id);
    assert.deepEqual(payload.manifest.importedUas, r.importedUas, r.id);
    assert.equal(hex(SL.encodeBackup(payload)), r.pt, `${r.id}: the payload writes back byte for byte`);
    ok++;
  }
  assert.equal(ok, 2);
  assert.equal(SE.imported.filter((r) => r.error).length, 5);
});

test('encodeBackup: importedUas after entries, written only when not empty; a present empty list is refused', () => {
  const entropy = new Uint8Array(16).fill(7);
  const entries = [{ kind: 258, account: 0, index: 0, ua: '0x' + '11'.repeat(32) }];
  const a = new TextDecoder().decode(SL.encodeBackup({ generation: 1, entropy, manifest: { entries, importedUas: [] } }));
  assert.ok(a.endsWith('"manifest":{"entries":[{"kind":258,"account":0,"index":0,"ua":"0x' + '11'.repeat(32) + '"}]}}'), a);
  const iu = [{ kind: 264, source: 'native-import:evm:0', ua: '0x' + '22'.repeat(32) }];
  const b = new TextDecoder().decode(SL.encodeBackup({ generation: 1, entropy, manifest: { importedUas: iu, entries } }));
  assert.ok(b.includes('}],"importedUas":[{"kind":264,"source":"native-import:evm:0","ua":"0x' + '22'.repeat(32) + '"}]}}'), b);
  const empty = utf8ToBytes(a.replace('}]}}', '}],"importedUas":[]}}'));
  assert.equal(codeOf(() => SL.decodeBackup(empty)), 'Argument', 'a present empty importedUas');
  assert.equal(codeOf(() => SL.decodeBackup(utf8ToBytes(a))), null, 'positive control: absent');
});

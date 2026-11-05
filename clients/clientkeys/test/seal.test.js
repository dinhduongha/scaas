// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-rs-sign T1b: seal / open per purpose and their refusals, the backup and link containers, their acceptance refusals (C-03),
// replay and rollback rows (C-11) and the 12-word wallet round trip through the vault and a sealed backup (C-10), read back from
// smartcontracts/vectors/ua/{seal,kem,keys,vault}.json (scripts/ua-wallet-vectors.mjs). UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dir } from './ua-vectors-dir.js';
import { hex, fromHex } from '../src/bytes.js';
import * as seedjs from '../src/seed.js';

const KEM = await import('../src/kem.js').catch(() => ({}));
const U = await import('../src/uakey.js').catch(() => ({}));
const SL = await import('../src/seal.js').catch(() => ({}));
const VA = await import('../src/vault.js');
const json = (f) => { try { return JSON.parse(readFileSync(new URL(f, dir), 'utf8')); } catch { return null; } };
const K = json('keys.json');
const S = json('seal.json');
const B = (h) => fromHex(h);
const seeds = () => Object.fromEntries(K.mnemonics.map((m) => [m.id, B(m.seed)]));
const keyOf = (r) => U.deriveUAKey(seeds()[r.mnemonic], { kind: r.kind, account: r.account, index: r.index });
const kemOf = (r) => KEM.kemKeyOf(keyOf(r), typeof r.version === 'string' ? BigInt(r.version) : r.version);
const codeOf = async (p) => { try { await p(); return null; } catch (e) { return e.code ?? e.message; } };
const keyFor = (row) => (row.recipient.ephemeralSeed ? KEM.ephemeralVector(B(row.recipient.ephemeralSeed)) : kemOf(row.recipient));
const openerOf = (o) => (o.kem ? kemOf(o.kem) : null);
const sessionOf = (s, shortCode = s.shortCode) => SL.linkSessionVector(B(s.seed), shortCode, s.start);
// the opener's lookup of an msig sender's member keys by id (the row's `members`; never trusted, re-derived by openContainer)
const lookup = (map) => (id) => map?.[id] ?? null;
// the opener's accepted(id, index) (CTR-UA-37): the row's `accepted` lists each msig's accepted indices; no `accepted`, no lookup
const acceptedOf = (map) => (map ? (id, i) => map[id]?.includes(i) === true : undefined);
const senderOf = (r) => (r.sender.msig ? { ua: B(r.sender.msig.ua), keyData: B(r.sender.msig.keyData), inner: (x) => r.sender.msig.inner?.[x],
  slots: r.sender.msig.slots.map((s) => ({ index: s.index, key: s.key && keyOf(s.key), members: s.members?.map((m) => ({ index: m.index, key: keyOf(m.key) })) })) }
  : keyOf(r.sender));

test('seal.json seal rows: fixed m and e per purpose (backup, link to an ephemeral key, empty pt and aad) reproduce and open', async () => {
  assert.ok(S, 'seal.json');
  assert.equal(S.seal.length, 3);
  for (const r of S.seal) {
    const s = await SL.sealVector(B(r.kemPk), r.purpose, B(r.aad), B(r.pt), { m: B(r.m), e: B(r.e) });
    assert.equal(hex(s.mlkemCt), r.mlkemCt, r.id);
    assert.equal(hex(s.x25519Eph), r.x25519Eph);
    assert.equal(hex(s.ciphertext), r.ciphertext);
    assert.equal(B(r.ciphertext).length, B(r.pt).length + 16);
    assert.equal(hex(SL.wireForm(s)), r.wire);
    const key = keyFor(r);
    assert.equal(hex(key.kemPk), r.kemPk);
    assert.equal(hex(await SL.open(key, r.purpose, B(r.aad), SL.fromWire(B(r.wire)))), r.pt);
  }
  assert.ok(S.seal.some((r) => r.pt === '0x' && r.aad === '0x'));
});

test('seal.json refusals: purpose, aad, version, scheme, a flipped byte in each field, another key; argument refusals', async () => {
  const s0 = S.seal.find((r) => r.id === S.refusals.base);
  const key = kemOf(S.refusals.key);
  // positive control
  assert.equal(hex(await SL.open(key, s0.purpose, B(s0.aad), SL.fromWire(B(s0.wire)))), s0.pt);
  // the named fields as they stand in the wire form, unchecked: open itself must refuse a version or scheme other than 1
  const fields = (w) => ({ version: w[0], scheme: w[1], mlkemCt: w.slice(2, 1570), x25519Eph: w.slice(1570, 1602), ciphertext: w.slice(1602) });
  for (const x of S.refusals.rows) {
    const k = x.key ? kemOf(x.key) : key;
    const got = await codeOf(() => SL.open(k, x.purpose ?? s0.purpose, B(x.aad ?? s0.aad), fields(B(x.wire ?? s0.wire))));
    assert.equal(got, x.error, x.id);
    assert.equal(await codeOf(async () => SL.open(k, x.purpose ?? s0.purpose, B(x.aad ?? s0.aad), SL.fromWire(B(x.wire ?? s0.wire)))), x.error, `${x.id} (wire)`);
  }
  for (const x of S.argumentRefusals) {
    const got = await codeOf(() => SL.sealVector(B(s0.kemPk), x.purpose, new Uint8Array(0), new Uint8Array(x.ptLength), { m: B(s0.m), e: B(s0.e) }));
    assert.equal(got, x.error, x.id);
  }
});

test('seal.json containers: backup, link and msig senders reproduce byte for byte and open with the expected sender', async () => {
  assert.equal(S.containers.length, 4);
  for (const r of S.containers) {
    const sender = senderOf(r);
    const c = r.container;
    const kemPk = r.opener.kem ? kemOf(r.opener.kem).kemPk : sessionOf(r.opener.session).kemPk;
    const recipient = r.expect.recipient.kemPkHash ? { kemPkHash: B(r.expect.recipient.kemPkHash) } : { ua: B(r.expect.recipient.ua), version: r.expect.recipient.version };
    const again = await SL.sealContainer({ kemPk, purpose: c.purpose, recipient, sender, created: c.created, pt: B(r.pt),
      shortCode: r.opener.session?.shortCode }, { m: B(r.m), e: B(r.e), sig: {} });
    assert.deepEqual(again, c, r.id);
    assert.equal(hex(sender.ua), hex(B(r.expect.sender.ua)));
    if (r.opener.kem) assert.equal(hex(await SL.openContainer(openerOf(r.opener), c, r.expect, lookup(r.members), acceptedOf(r.accepted))), r.pt, r.id);
    else assert.equal(hex(await SL.openLink(sessionOf(r.opener.session), c, r.expect, lookup(r.members), acceptedOf(r.accepted))), r.pt, r.id);
  }
  // sender.auth is a full UASig (owner 2026-11-05): a single key carries its key data and signature, an msig its members only
  const [single, msig] = [S.containers[0].container.sender.auth, S.containers[2].container.sender.auth];
  assert.deepEqual(Object.keys(single), ['keyData', 'signature', 'members']);
  assert.deepEqual([single.members.length > 0, single.signature.length > 0], [false, true]);
  assert.deepEqual([msig.members.length > 0, msig.signature.length > 0], [true, false]);
  assert.ok(S.containers[3].container.sender.auth.members.some((m) => m.members.length > 0), 'a nested msig sender signs through its inner msig');
  // a link's aad ends with sha256(shortCode)
  const link = S.containers.find((r) => r.id === 'link');
  const aad = SL.containerAad({ purpose: link.container.purpose, recipient: { kemPkHash: B(link.expect.recipient.kemPkHash) },
    senderUa: B(link.expect.sender.ua), created: link.container.created, shortCode: link.opener.session.shortCode });
  assert.equal(aad.length, 1 + 2 + 13 + 32 + 8 + 32 + 8 + 32);
});

test('container builder: an msig sender signs only in the minimal form (UAPoP), a single key only as a UA key', async () => {
  const r = S.containers[2];
  const kemPk = kemOf(r.opener.kem).kemPk;
  const args = (sender) => ({ kemPk, purpose: r.container.purpose, recipient: { ua: B(r.expect.recipient.ua), version: 0 }, sender,
    created: r.container.created, pt: B(r.pt) });
  const msig = senderOf(r);
  const third = [0, 1, 2].find((i) => !msig.slots.some((s) => s.index === i));
  const extra = { ...msig, slots: [0, 1, 2].map((i) => msig.slots.find((s) => s.index === i)
    ?? { index: third, key: keyOf(r.sender.msig.slots[0].key) }) };
  assert.equal(await codeOf(() => SL.sealContainer(args(extra))), 'UAPoP');
  assert.equal(await codeOf(() => SL.sealContainer(args({ ua: msig.ua }))), 'Argument');
});

test('seal.json acceptance: each refusal from an otherwise valid container (C-03), before decapsulation where it says ContainerSender', async () => {
  assert.equal(S.acceptance.length, 29);
  for (const x of S.acceptance) {
    let got;
    const a = acceptedOf(x.accepted);
    if (x.link) got = await codeOf(() => SL.openLink(sessionOf(S.containers[1].opener.session, x.link.shortCode), x.container, x.expect, lookup(x.members), a));
    else if (x.restore) got = await codeOf(() => SL.restoreBackup(openerOf(x.opener), x.container, x.expect, lookup(x.members), a));
    else got = await codeOf(() => SL.openContainer(openerOf(x.opener), x.container, x.expect, lookup(x.members), a));
    assert.equal(got, x.error, x.id);
  }
  for (const id of ['signed by a different registered UA', 'purpose not the expected one', 'recipient not the expected one',
    'sender key whose UA is not sender.ua', 'backup entropy that does not derive sender.ua', 'link: swapped short code',
    'single-key UASig with members', 'msig sender: non-minimal member set (three of t = 2)',
    'msig sender: nested level-2 non-minimal (inner three of t = 2)', 'msig sender: member keys unknown to the opener',
    'msig sender: a signing member not accepted (the msig active through a non-signer)',
    'msig sender: accepted weight below the threshold (one of t = 2 accepted)', 'msig sender: signers accepted, a non-signer not (accepted)',
    'msig sender: nested, the inner msig\'s slot not accepted (level 1)', 'msig sender: nested, an inner signing member not accepted (level 2)',
    'msig sender: no accepted lookup']) {
    assert.ok(S.acceptance.some((x) => x.id === id), id);
  }
  // ContainerSender comes before decapsulation: a refused container never reaches the KEM key
  const x = S.acceptance.find((r) => r.id === 'purpose not the expected one');
  const spy = { ...openerOf(x.opener), decaps: () => { throw new Error('decapsulated'); } };
  assert.equal(await codeOf(() => SL.openContainer(spy, x.container, x.expect)), 'ContainerSender');
});

test('msig sender acceptance (CTR-UA-37): only a true answer accepts, a single key needs no lookup', async () => {
  const [backup, flat, nested] = [S.containers[0], S.containers[2], S.containers[3]];
  const openFlat = (a) => codeOf(() => SL.openContainer(openerOf(flat.opener), flat.container, flat.expect, lookup(flat.members), a));
  // positive control: every member accepted opens, flat and nested
  assert.equal(await openFlat(() => true), null);
  assert.equal(await codeOf(() => SL.openContainer(openerOf(nested.opener), nested.container, nested.expect, lookup(nested.members), () => true)), null);
  // fail-closed: a missing lookup, an unknown or non-true answer, a lookup that throws
  for (const a of [undefined, null, 'accepted', () => undefined, () => null, () => 1, () => 'true', () => false, () => { throw new Error('rpc'); }]) {
    assert.equal(await openFlat(a), 'ContainerSender', String(a));
  }
  // a single-key sender: the lookup is never asked
  const never = () => { throw new Error('asked'); };
  assert.equal(await codeOf(() => SL.openContainer(openerOf(backup.opener), backup.container, backup.expect, undefined, never)), null);
});

test('seal.json replay and rollback (C-11): link window and one use, backup generation', async () => {
  const session = S.containers[1].opener.session;
  for (const x of S.replay) {
    if (x.kind === 'link') {
      assert.equal(await codeOf(() => SL.openLink(sessionOf(session), x.container, x.expect)), x.error, x.id);
    } else {
      let r = null;
      const got = await codeOf(async () => {
        r = await SL.restoreBackup(openerOf(x.opener), x.container, x.expect, undefined, undefined, { current: x.current, allowRollback: x.allowRollback });
      });
      assert.equal(got, x.error ?? null, x.id);
      if (!x.error) assert.equal(r.install, x.install, x.id);
    }
  }
  const link = S.containers[1];
  const s = sessionOf(session);
  await SL.openLink(s, link.container, link.expect);
  assert.equal(await codeOf(() => SL.openLink(s, link.container, link.expect)), 'ContainerReplay', 'a session is one use');
  assert.equal(SL.LINK_WINDOW, 600);
});

test('12-word wallet round trip (C-10): mnemonic, signing key and KEM key equal before and after, through the vault and a sealed backup', async () => {
  const VJ = json('vault.json');
  const row = VJ.vaults.find((r) => r.id.startsWith('twelve words'));
  const entropy = await VA.openSeedVault(row.vault, row.unlock);
  assert.equal(entropy.length, 16);
  assert.equal(seedjs.entropyToWords(entropy).join(' '), row.words);
  const before = U.deriveUAKey(seedjs.seedFromWords(row.words), { kind: row.uaKey.kind, account: 0, index: 0 });
  const after = U.deriveUAKey(seedjs.seedFromEntropy(entropy), { kind: row.uaKey.kind, account: 0, index: 0 });
  assert.equal(hex(after.ua), row.uaKey.ua);
  assert.equal(hex(before.ua), hex(after.ua));
  const kemAfter = U.deriveUAKey(seedjs.seedFromEntropy(entropy), { kind: row.kemKey.kind, account: 0, index: 0 }).kemKey(0);
  assert.equal(hex(kemAfter.kemPkHash), row.kemKey.kemPkHash);
  // through a sealed backup: the container of seal.json restores the same entropy, so the same keys
  const c = S.containers.find((r) => r.id === 'backup generation 2');
  const { install, payload } = await SL.restoreBackup(openerOf(c.opener), c.container, c.expect);
  assert.equal(install, true);
  assert.equal(hex(payload.entropy), hex(entropy));
  assert.equal(seedjs.entropyToWords(payload.entropy).join(' '), row.words);
  assert.equal(hex(U.deriveUAKey(seedjs.seedFromEntropy(payload.entropy), { kind: row.uaKey.kind }).ua), row.uaKey.ua);
  assert.equal(hex(U.deriveUAKey(seedjs.seedFromEntropy(payload.entropy), { kind: row.kemKey.kind }).kemKey(0).kemPkHash), row.kemKey.kemPkHash);
  // and a fresh seal of the same payload round-trips (release randomness)
  const R = kemOf(S.refusals.key);
  const sender = keyOf(c.sender);
  const fresh = await SL.sealBackup({ kemPk: R.kemPk, recipient: { ua: R.ua, version: 0 }, sender, created: c.container.created, payload });
  const again = await SL.restoreBackup(R, fresh, c.expect);
  assert.equal(hex(again.payload.entropy), hex(entropy));
  assert.notEqual(fresh.sealed.mlkemCt, c.container.sealed.mlkemCt, 'release seal draws fresh m and e');
});

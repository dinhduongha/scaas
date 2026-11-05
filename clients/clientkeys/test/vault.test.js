import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as V from '../src/vault.js';
import { createVault, openVault, enablePrf, needsRewrap, rewrapPin, SCRYPT } from '../src/vault.js';
import { SeedBackup } from '../src/backup.js';
import { entropyToWords } from '../src/seed.js';
import { bytesToHex, fromHex } from '../src/bytes.js';
import { dir as uaDir } from './ua-vectors-dir.js';

const secret = () => crypto.getRandomValues(new Uint8Array(32));

const PASS = 'river-otter-7';

test('vault: passphrase via scrypt N=2^17 r=8 p=1, AES-GCM, fresh IV and salt, parameters recorded', async () => {
  const s = secret();
  const v = await createVault(s, { label: 'seed', pin: PASS });
  assert.deepEqual([v.pin.N, v.pin.r, v.pin.p], [2 ** 17, 8, 1]);
  assert.equal(SCRYPT.N, 131072);
  assert.equal(bytesToHex(await openVault(v, { pin: PASS })), bytesToHex(s));
  await assert.rejects(openVault(v, { pin: 'river-otter-8' }), /Wrong PIN/);
  const v2 = await createVault(s, { label: 'seed', pin: PASS });
  assert.notEqual(v2.data.iv, v.data.iv);
  assert.notEqual(v2.pin.salt, v.pin.salt);
  assert.ok(!JSON.stringify(v).includes(bytesToHex(s)));
  assert.equal(needsRewrap(v), false);
});

test('vault: a new passphrase needs 8+ characters and not only digits', async () => {
  for (const bad of ['', '1234567', '12345678', '123456789012', 'abc', '   12  ']) {
    await assert.rejects(createVault(secret(), { label: 'seed', pin: bad }), /at least 8 characters/, bad);
  }
  await createVault(secret(), { label: 'seed', pin: 'abcdefgh' });
});

test('vault: an old N=2^15 / 6-digit vault still opens, then is re-wrapped with the new parameters', async () => {
  const s = secret();
  const v = await createVault(s, { label: 'seed', pin: PASS });
  // Build the RS4-8 v1 shape: same DEK under a 6-digit PIN at N=2^15 (what old clients stored).
  const old = await rewrapPin(v, PASS, '246810', { N: 2 ** 15, r: 8, p: 1, dkLen: 32 }, { policy: false });
  assert.equal(old.pin.N, 2 ** 15);
  assert.equal(needsRewrap(old), true);
  assert.equal(bytesToHex(await openVault(old, { pin: '246810' })), bytesToHex(s));
  // Upgrade: the weak PIN cannot be kept; a passphrase that passes the policy can.
  await assert.rejects(rewrapPin(old, '246810', '246810'), /at least 8 characters/);
  await assert.rejects(rewrapPin(old, '000000', PASS), /Wrong PIN/);
  const up = await rewrapPin(old, '246810', PASS);
  assert.deepEqual([up.pin.N, up.pin.r, up.pin.p], [2 ** 17, 8, 1]);
  assert.equal(needsRewrap(up), false);
  assert.notEqual(up.pin.salt, old.pin.salt);
  assert.equal(up.data.ct, old.data.ct, 'the data envelope is untouched');
  assert.equal(bytesToHex(await openVault(up, { pin: PASS })), bytesToHex(s));
  await assert.rejects(openVault(up, { pin: '246810' }), /Wrong PIN/);
});

test('vault: tampering and label swap are detected (AAD)', async () => {
  const v = await createVault(secret(), { label: 'seed', pin: PASS });
  const t = structuredClone(v);
  t.data.ct = t.data.ct.slice(0, -2) + (t.data.ct.endsWith('A') ? 'BA' : 'AA');
  await assert.rejects(openVault(t, { pin: PASS }), /altered/);
  await assert.rejects(openVault({ ...structuredClone(v), label: 'other' }, { pin: PASS }), /altered/);
});

test('vault: passkey PRF envelope opens without the PIN; PIN envelope always stays', async () => {
  const s = secret();
  const prfOutput = secret();
  const prf = { output: prfOutput, credentialId: 'cred', salt: secret() };
  const v = await createVault(s, { label: 'seed', pin: PASS, prf });
  assert.equal(bytesToHex(await openVault(v, { prfOutput })), bytesToHex(s));
  assert.equal(bytesToHex(await openVault(v, { pin: PASS })), bytesToHex(s));
  await assert.rejects(openVault(v, { prfOutput: secret() }), /altered|Wrong/);
  const plain = await createVault(s, { label: 'seed', pin: PASS });
  await assert.rejects(openVault(plain, { prfOutput }), /no passkey unlock/);
  await enablePrf(plain, PASS, prf);
  assert.equal(bytesToHex(await openVault(plain, { prfOutput })), bytesToHex(s));
});

test('backup: shown once, verify 3 random words, only then usable', () => {
  const entropy = secret();
  const words = entropyToWords(entropy);
  const b = new SeedBackup(entropy.slice());
  assert.throws(() => b.take(), /Confirm/);
  assert.deepEqual(b.reveal(), words);
  assert.throws(() => b.reveal(), /only once/);
  const pos = b.challenge();
  assert.equal(new Set(pos).size, 3);
  assert.equal(b.verify(pos.map(() => 'wrong')), false);
  assert.throws(() => b.take(), /Confirm/);
  const pos2 = b.challenge();
  assert.equal(b.verify(pos2.map((p) => ` ${words[p - 1].toUpperCase()} `)), true);
  assert.equal(bytesToHex(b.take()), bytesToHex(entropy));
  assert.equal(b.state, 'taken');
  assert.throws(() => b.take(), /Confirm/);
});

test('vault: open refuses an envelope outside N ∈ {2^15, 2^16, 2^17}, r = 8, p = 1 before scrypt runs (CLI-SGN-21)', async () => {
  const s = secret();
  const v = await createVault(s, { label: 'seed', pin: PASS });
  for (const [N, r, p] of [[2 ** 14, 8, 1], [2 ** 20, 8, 1], [2 ** 30, 8, 1], [2 ** 17, 16, 1], [2 ** 17, 8, 2], [undefined, 8, 1]]) {
    const bad = structuredClone(v);
    Object.assign(bad.pin, { N, r, p });
    const t0 = Date.now();
    await assert.rejects(openVault(bad, { pin: PASS }), /Unsupported vault parameters/, `${N} ${r} ${p}`);
    assert.ok(Date.now() - t0 < 200, `refused before scrypt: ${N} ${r} ${p}`);
  }
  // positive control: every allowed N still opens
  for (const N of [2 ** 15, 2 ** 16]) {
    const ok = await rewrapPin(v, PASS, PASS, { N, r: 8, p: 1, dkLen: 32 }, { policy: false });
    assert.equal(bytesToHex(await openVault(ok, { pin: PASS })), bytesToHex(s));
  }
});

// ua-rs-sign T1b: the seed vault rows of smartcontracts/vectors/ua/vault.json (scripts/ua-wallet-vectors.mjs), which ua-rs opens (T9).
const VJ = (() => { try { return JSON.parse(readFileSync(new URL('vault.json', uaDir), 'utf8')); } catch { return null; } })();
const unlockOf = (u) => (u.prfOutput ? { prfOutput: fromHex(u.prfOutput) } : u);
const codeOf = async (p) => { try { await p(); return null; } catch (e) { return e.code ?? e.message; } };

test('vault.json: seed vaults at N = 2^15, 2^16, 2^17, 12 words, NFC sealed / NFD opened (NFKC), PRF; each opens to its entropy', async () => {
  assert.ok(VJ, 'vault.json');
  assert.deepEqual(VJ.vaults.map((r) => r.vault.pin.N).slice(0, 3), [2 ** 15, 2 ** 16, 2 ** 17]);
  for (const r of VJ.vaults) {
    assert.equal(bytesToHex(await V.openSeedVault(r.vault, unlockOf(r.unlock))), r.plaintext.slice(2), r.id);
    assert.equal(r.vault.v, 1);
    assert.equal(r.vault.label, 'seed');
  }
  const nfd = VJ.vaults.find((r) => r.id.startsWith('passphrase in NFD'));
  assert.notEqual(nfd.unlock.pin, nfd.unlock.pin.normalize('NFC'), 'the row opens with the NFD form');
  assert.equal(fromHex(VJ.vaults.find((r) => r.id.startsWith('twelve')).plaintext).length, 16);
});

test('vault.json refusals: wrong passphrase, altered AAD label, N = 2^31 / 3, r = 16, p = 2, v 2 and its tombstone, 31 and 64-byte payloads, label', async () => {
  assert.equal(VJ.refusals.length, 11);
  for (const x of VJ.refusals) assert.equal(await codeOf(() => V.openSeedVault(x.vault, unlockOf(x.unlock))), x.error, x.id);
  // v 2 is never reported as a wrong passphrase, and the parameters are refused before scrypt runs (a 2^31 N would not return)
  assert.ok(VJ.refusals.filter((x) => x.error === 'VaultVersion').length === 2);
});

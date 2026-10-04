import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, openVault, enablePrf, needsRewrap, rewrapPin, SCRYPT } from '../src/vault.js';
import { SeedBackup } from '../src/backup.js';
import { entropyToWords } from '../src/seed.js';
import { bytesToHex } from '../src/bytes.js';

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

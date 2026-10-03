import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, openVault, enablePrf, SCRYPT } from '../src/vault.js';
import { SeedBackup } from '../src/backup.js';
import { entropyToWords } from '../src/seed.js';
import { loadZetherProver, sealConfKey, openConfKey, confLabel } from '../src/zether.js';
import { bytesToHex } from '../src/bytes.js';

const secret = () => crypto.getRandomValues(new Uint8Array(32));

test('vault: PIN via scrypt N=2^15 r=8 p=1, AES-GCM, fresh IV and salt, parameters recorded', async () => {
  const s = secret();
  const v = await createVault(s, { label: 'seed', pin: '123456' });
  assert.deepEqual([v.pin.N, v.pin.r, v.pin.p], [2 ** 15, 8, 1]);
  assert.equal(SCRYPT.N, 32768);
  assert.equal(bytesToHex(await openVault(v, { pin: '123456' })), bytesToHex(s));
  await assert.rejects(openVault(v, { pin: '654321' }), /Wrong PIN/);
  const v2 = await createVault(s, { label: 'seed', pin: '123456' });
  assert.notEqual(v2.data.iv, v.data.iv);
  assert.notEqual(v2.pin.salt, v.pin.salt);
  assert.ok(!JSON.stringify(v).includes(bytesToHex(s)));
  await assert.rejects(createVault(s, { label: 'seed', pin: '12' }), /at least 6/);
});

test('vault: tampering and label swap are detected (AAD)', async () => {
  const v = await createVault(secret(), { label: 'seed', pin: '123456' });
  const t = structuredClone(v);
  t.data.ct = t.data.ct.slice(0, -2) + (t.data.ct.endsWith('A') ? 'BA' : 'AA');
  await assert.rejects(openVault(t, { pin: '123456' }), /altered/);
  await assert.rejects(openVault({ ...structuredClone(v), label: 'other' }, { pin: '123456' }), /altered/);
});

test('vault: passkey PRF envelope opens without the PIN; PIN envelope always stays', async () => {
  const s = secret();
  const prfOutput = secret();
  const prf = { output: prfOutput, credentialId: 'cred', salt: secret() };
  const v = await createVault(s, { label: 'seed', pin: '123456', prf });
  assert.equal(bytesToHex(await openVault(v, { prfOutput })), bytesToHex(s));
  assert.equal(bytesToHex(await openVault(v, { pin: '123456' })), bytesToHex(s));
  await assert.rejects(openVault(v, { prfOutput: secret() }), /altered|Wrong/);
  const plain = await createVault(s, { label: 'seed', pin: '123456' });
  await assert.rejects(openVault(plain, { prfOutput }), /no passkey unlock/);
  await enablePrf(plain, '123456', prf);
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

test('zether seam: no wasm ⇒ null; with S3 prover the conf key is sealed like the seed', async () => {
  assert.equal(await loadZetherProver('/nope.js', async () => { throw new Error('404'); }), null);
  assert.equal(await loadZetherProver('/x.js', async () => ({ other: 1 })), null);
  let inited = false;
  const calls = [];
  const fake = {
    default: async () => { inited = true; },
    zether_conf_key: (curve, seed, coin, account) => { calls.push([curve, seed.length, coin, account]); return new Uint8Array(32).fill(7); },
  };
  const prover = await loadZetherProver('/x.js', async () => fake);
  assert.ok(inited);
  const v = await sealConfKey(prover, { seed: new Uint8Array(64), curve: 'bn254', coin: 60, account: 0, pin: '123456' });
  assert.deepEqual(calls, [['bn254', 64, 60, 0]]);
  assert.equal(v.label, confLabel('bn254', 60, 0));
  assert.equal(bytesToHex(await openConfKey(v, { pin: '123456' })), '07'.repeat(32));
  await assert.rejects(sealConfKey({ zether_conf_key: () => new Uint8Array(32) },
    { seed: new Uint8Array(64), curve: 'bn254', coin: 60, account: 0, pin: '123456' }), /invalid key/);
});

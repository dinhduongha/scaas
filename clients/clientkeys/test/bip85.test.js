// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T5: bip85Child against BIP-85's published vectors (outside data) and smartcontracts/vectors/keys/bip85.json,
// which the generator reproduces byte for byte.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { HDKey } from '@scure/bip32';
import { bip85Child, seedFromWords } from '../src/seed.js';
import { hex } from '../src/bytes.js';

const pub = JSON.parse(readFileSync(new URL('./vectors/bip85-published.json', import.meta.url), 'utf8'));
const FILE = fileURLToPath(new URL('../../../smartcontracts/vectors/keys/bip85.json', import.meta.url));
const v = JSON.parse(readFileSync(FILE, 'utf8'));

test('bip85Child: BIP-85 published BIP-39 vectors at 12, 18, 24 words', () => {
  const root = HDKey.fromExtendedKey(pub.master);
  for (const r of pub.rows) assert.equal(bip85Child(root, r.index, r.words).words.join(' '), r.mnemonic, `${r.words} words`);
});

test('bip85.json: children 0-2 of the main set; another parent passphrase, other children; refusals', () => {
  for (const c of v.children) {
    const got = bip85Child(seedFromWords(v.mnemonic, c.bip39Passphrase), c.index);
    assert.equal(hex(got.entropy), c.entropy);
    assert.equal(got.words.join(' '), c.words);
    assert.equal(got.words.length, 24);
  }
  const main = v.children.filter((c) => c.bip39Passphrase === '');
  const hidden = v.children.filter((c) => c.bip39Passphrase !== '');
  assert.equal(new Set(v.children.map((c) => c.entropy)).size, v.children.length, 'all distinct');
  assert.notEqual(main[0].entropy, hidden[0].entropy);
  for (const r of v.refusals) assert.throws(() => bip85Child(seedFromWords(v.mnemonic), r.index), (e) => e.code === r.error, r.id);
  assert.equal(bip85Child(seedFromWords(v.mnemonic), 2 ** 31 - 1).words.length, 24, 'control: the last index');
  assert.ok(!v.manifests[0].json.includes('bip85Next'), 'absent when zero');
  assert.ok(v.manifests[1].json.endsWith(',"bip85Next":1}'));
});

test('the generator reproduces bip85.json and roots.json byte for byte', () => {
  const out = mkdtempSync(join(tmpdir(), 'keys-vectors-'));
  try {
    execFileSync(process.execPath, [fileURLToPath(new URL('../scripts/keys-vectors.mjs', import.meta.url)), out]);
    assert.equal(readFileSync(join(out, 'bip85.json'), 'utf8'), readFileSync(FILE, 'utf8'));
    assert.equal(readFileSync(join(out, 'roots.json'), 'utf8'), readFileSync(join(FILE, '../roots.json'), 'utf8'));
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

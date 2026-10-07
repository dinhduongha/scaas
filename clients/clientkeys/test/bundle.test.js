// The committed portal assets are exactly `npm run build` of this source, and they work.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const committed = fileURLToPath(new URL('../../../../dms_blockchain_bridge/static/lib/clientkeys/', import.meta.url));
// The vendored copy lives in the client repo that embeds scaas; a standalone scaas checkout has none.
const skip = !existsSync(committed) && 'no vendored bundle next to this checkout';

test('committed bundle == fresh esbuild output', { skip }, () => {
  const out = mkdtempSync(join(tmpdir(), 'clientkeys-'));
  const script = JSON.parse(readFileSync(join(root, 'package.json'))).scripts.build;
  const args = script.split(' ').slice(1).map((a) => (a.startsWith('--outdir=') ? `--outdir=${out}` : a));
  execFileSync(join(root, 'node_modules/.bin/esbuild'), args, { cwd: root, stdio: 'pipe' });
  const fresh = readdirSync(out).sort();
  assert.deepEqual(readdirSync(committed).sort(), fresh);
  for (const f of fresh) assert.ok(readFileSync(join(out, f)).equals(readFileSync(join(committed, f))), `${f} is stale: npm run build`);
});

test('bundles load and work', { skip }, async () => {
  const seed = await import(join(committed, 'seed-signer.js'));
  const pk = await import(join(committed, 'passkey-signer.js'));
  const s = seed.seedFromEntropy(seed.wordsToEntropy(
    'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better'));
  assert.equal(seed.deriveKey(s, 'evm', 0).address, '0x1C6C7EF166c962c2ed755daf726A42cfE4fc77dB');
  assert.equal(typeof pk.derToRS, 'function');
  assert.equal(typeof pk.hashTypedData, 'function');
});

// The directory the UA tests read their vectors from: smartcontracts/vectors/ua/ once Task 8 regenerated it for UA-6
// (kinds.json has `schemes`); until then (UA-6 PENDING) a temporary copy of it with the generators' fresh output laid
// over it, so the tests exercise the new format (no authRef, new register shape, no bn254 Zether rows, holder rows with
// pqzKey). Delete the PENDING branch when Task 8 has committed the regenerated files.
import { readFileSync, mkdtempSync, cpSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const committed = new URL('../../../smartcontracts/vectors/ua/', import.meta.url);
export const PENDING = !('schemes' in JSON.parse(readFileSync(new URL('kinds.json', committed))));

function fresh() {
  const tmp = mkdtempSync(join(tmpdir(), 'ua6-pending-'));
  process.on('exit', () => rmSync(tmp, { recursive: true, force: true }));
  cpSync(fileURLToPath(committed), tmp, { recursive: true });
  for (const g of ['ua-vectors.mjs', 'ua-sig-vectors.mjs']) {
    const r = spawnSync(process.execPath, [fileURLToPath(new URL(`../scripts/${g}`, import.meta.url)), tmp], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`${g}: ${r.stderr}`);
  }
  return new URL(`file://${tmp}/`);
}

/** The vectors directory (a URL ending in `/`). */
export const dir = PENDING ? fresh() : committed;

// The UA identity layer (src/ua.js) against smartcontracts/vectors/ua/: the generator reproduces both files byte for byte,
// the valid, invalid, pop, uaAuth and member rows hold through the public API (the other tables are covered by the regeneration), and pq.js (P6a) agrees on the PQ kinds.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import * as ua from '../src/ua.js';
import { PQ_KINDS, uaId, kindTag } from '../src/pq.js';
import { hex, fromHex } from '../src/bytes.js';

const dir = new URL('../../../smartcontracts/vectors/ua/', import.meta.url);
const K = JSON.parse(readFileSync(new URL('kinds.json', dir)));
const S = JSON.parse(readFileSync(new URL('structures.json', dir)));

test('the generator reproduces kinds.json and structures.json byte for byte', () => {
  const out = mkdtempSync(join(tmpdir(), 'ua-vectors-'));
  try {
    const r = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/ua-vectors.mjs', import.meta.url)), out], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    for (const f of ['kinds.json', 'structures.json']) {
      assert.equal(readFileSync(join(out, f), 'utf8'), readFileSync(new URL(f, dir), 'utf8'), f);
    }
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('valid rows derive, invalid rows fail with their code', () => {
  for (const r of K.valid) {
    assert.equal(hex(ua.deriveUA(r.kind, fromHex(r.keyData), { hederaNative: r.hederaNative })), r.ua, r.name);
    const h = ua.keyHashOf(r.kind, fromHex(r.keyData));
    assert.equal(h && hex(h), r.keyHash, r.name);
  }
  for (const r of K.invalid) {
    assert.throws(() => ua.validateKeyData(r.kind, fromHex(r.keyData), { hederaNative: r.hederaNative }),
      (e) => e instanceof ua.UAError && e.code === r.error, `${r.kind} ${r.reason}`);
  }
});

test('digests: popDigest, UAAuth, member', () => {
  for (const p of S.pop) {
    const c = S.contexts[p.context];
    assert.equal(hex(ua.popDigest({ ...c, ua: p.ua, authRef: p.authRef })), p.popDigest);
  }
  for (const a of S.uaAuth) {
    const domain = { generation: a.generation, ...S.contexts[a.context] };
    assert.equal(hex(ua.uaAuthDigest(domain, a.ua, a.purposeTag, a.digest)), a.uaAuthDigest);
  }
  for (const m of S.member) assert.equal(hex(ua.memberDigest(m.structureUa, m.uaMsg)), m.memberDigest);
});

test('pq.js and ua.js agree on the PQ kinds', () => {
  for (const [name, { kind }] of Object.entries(PQ_KINDS)) {
    assert.equal(hex(kindTag(name)), hex(ua.TAG(kind)), name);
    const r = K.valid.find((v) => v.kind === kind);
    assert.equal(hex(uaId(name, fromHex(r.keyData))), r.ua, name);
  }
});

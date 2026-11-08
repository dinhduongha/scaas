// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Chain-neutral spec §6.4 (plan T74): the CREATE3 derivation and the clone's env bytes against forge's create3_kat.json.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '../src/bytes.js';
import {
  PROXY_INITCODE, PROXY_INITCODE_HASH, create3Address, chainEnvBytes, cloneInitCode, cloneRuntime,
} from '../src/factory.js';
import { keccak_256 } from '../src/bytes.js';

const KAT = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/factory/create3_kat.json', import.meta.url)));

test('the proxy init code and its hash are forge\'s', () => {
  assert.equal(PROXY_INITCODE, KAT.proxyInitCode);
  assert.equal(PROXY_INITCODE_HASH, KAT.proxyInitCodeHash);
});

test('every row: s, proxy, instance', () => {
  assert.ok(KAT.rows.length >= 6);
  for (const r of KAT.rows) {
    const got = create3Address({ factory: KAT.factory, creatorId: r.creatorId, contractClass: r.contractClass, kind: r.kind,
      salt: r.salt });
    assert.equal(got.s, r.s);
    assert.equal(got.proxy.toLowerCase(), r.proxy.toLowerCase());
    assert.equal(got.instance.toLowerCase(), r.instance.toLowerCase());
  }
});

test('a different creator, class, kind or salt moves the address', () => {
  const r = KAT.rows[0];
  const base = create3Address({ factory: KAT.factory, ...r }).instance;
  for (const d of [{ creatorId: KAT.rows[1].creatorId }, { contractClass: 2 }, { kind: 1 }, { salt: '0x' + '11'.repeat(32) }]) {
    assert.notEqual(create3Address({ factory: KAT.factory, ...r, ...d }).instance, base);
  }
});

const ENVS = {
  plain: { smartKeyAccountImpl: '0x4444444444444444444444444444444444444444' },
  pqz: { deps: ['0x5555555555555555555555555555555555555555'] },
  zether: { deps: ['0x6666666666666666666666666666666666666666', '0x7777777777777777777777777777777777777777',
    '0x8888888888888888888888888888888888888888', '0x9999999999999999999999999999999999999999'] },
  pqchat: { params: ['0x' + (131072).toString(16).padStart(64, '0')] },
};
const BASE = { chainUid: '0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464',
  registry: '0x2222222222222222222222222222222222222222', govRouter: '0x3333333333333333333333333333333333333333',
  smartKeyAccountImpl: '0x0000000000000000000000000000000000000000', hedera: false };

test('the ChainEnv layout, byte for byte (plain 95, PQZ 115, Zether 175, PqChat 127)', () => {
  const lengths = { plain: 95, pqz: 115, zether: 175, pqchat: 127 };
  for (const e of KAT.envs) {
    const env = chainEnvBytes({ ...BASE, ...ENVS[e.name] });
    assert.equal(hex(env), e.env, e.name);
    assert.equal(env.length, lengths[e.name]);
    assert.equal(hex(cloneInitCode(KAT.implementation, env)), e.cloneInitCode, e.name);
    assert.equal(hex(keccak_256(cloneRuntime(KAT.implementation, env))), e.cloneRuntimeHash, e.name);
  }
});

test('more than 4 deps or 2 params is refused', () => {
  assert.throws(() => chainEnvBytes({ ...BASE, deps: Array(5).fill(BASE.registry) }), /at most 4 deps/);
  assert.throws(() => chainEnvBytes({ ...BASE, params: Array(3).fill(BASE.chainUid) }), /2 params/);
});

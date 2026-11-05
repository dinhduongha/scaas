// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// T0 Q1 harness (ua-rs-sign): noble 0.7.1 Falcon keys through clientkeys' own path. Rows: the pq_kat.json key (mnemonic,
// account 0, index 0: xi = pqSeed(...)) and N extra seeds xi_i = SHAKE256("scaas.ua-rs-sign.t0.q1." ‖ i, 48).
// Prints one JSON row per (kind, seed): {kind, source, xi, pk, sk}. Imports by relative path; needs clients/clientkeys/node_modules (npm ci --ignore-scripts).
import { readFileSync } from 'node:fs';
import { PQ_KINDS, pqSeed } from '../../../clientkeys/src/pq.js';
import { seedFromWords } from '../../../clientkeys/src/seed.js';
import { shake256 } from '../../../clientkeys/node_modules/@noble/hashes/sha3.js';

const hex = (b) => Buffer.from(b).toString('hex');
const kat = JSON.parse(readFileSync(new URL('../../../../smartcontracts/vectors/ua/pq_kat.json', import.meta.url)));
const N = Number(process.argv[2] ?? 16);
const seed = seedFromWords(kat.mnemonic);
for (const kind of ['fndsa512', 'fndsa1024']) {
  const alg = PQ_KINDS[kind].alg;
  const rows = [{ source: 'pq_kat', xi: pqSeed(seed, kind, kat.account, kat.index) }];
  for (let i = 0; i < N; i++) rows.push({ source: `extra-${i}`, xi: shake256(new TextEncoder().encode(`scaas.ua-rs-sign.t0.q1.${i}`), { dkLen: 48 }) });
  for (const r of rows) {
    const { publicKey, secretKey } = alg.keygen(r.xi);
    const out = { kind, source: r.source, xi: hex(r.xi), pk: hex(publicKey), sk: hex(secretKey) };
    if (r.source === 'pq_kat' && '0x' + out.pk !== kat.kinds[kind].pk) throw new Error(`${kind}: noble pk != pq_kat.json pk`);
    console.log(JSON.stringify(out));
  }
}

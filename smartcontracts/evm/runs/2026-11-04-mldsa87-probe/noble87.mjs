// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ML-DSA-87 probe (2026-11-04): a second implementation over acvp87.json and one UA-shaped row (ua87.json).
// 1. Every ACVP ML-DSA-87 case of acvp87.json through @noble/post-quantum 0.7.1 `ml_dsa87.internal.verify` (M' as
//    extract.py built it); a verdict other than ACVP's refuses.
// 2. A key pair the way clients/clientkeys/src/pq.js derives the PQ kinds (SEP-0005 test mnemonic, HKDF, account 0,
//    index 0) under the PROPOSED tag `scaas.ua.mldsa87.v1` (not built; spec 2026-11-04-mldsa87), a `pop`-purpose ua_msg
//    over pq_kat.json's digest, and the deterministic signature over pq_msg = keccak256(TAG ‖ ua_msg), empty context,
//    plus three mutations with noble's verdict. Probe data only: the production rows come from pq-vectors.mjs.
//   node runs/2026-11-04-mldsa87-probe/noble87.mjs     (from smartcontracts/evm; needs clients/clientkeys/node_modules)
import { readFileSync, writeFileSync } from 'node:fs';
import { ml_dsa87 } from '../../../../clients/clientkeys/node_modules/@noble/post-quantum/ml-dsa.js';
import { hkdf } from '../../../../clients/clientkeys/node_modules/@noble/hashes/hkdf.js';
import { seedFromWords } from '../../../../clients/clientkeys/src/seed.js';
import { keccak_256, sha256, concatBytes, utf8ToBytes, hex } from '../../../../clients/clientkeys/src/bytes.js';

const here = new URL('.', import.meta.url);
const h = (s) => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));
const acvp = JSON.parse(readFileSync(new URL('acvp87.json', here), 'utf8'));
for (const c of acvp.cases) {
  let ok;
  try { ok = ml_dsa87.internal.verify(h(c.sig), h(c.mprime), h(c.pk)); } catch { ok = false; }
  if (ok !== c.valid) throw new Error(`noble disagrees with ACVP tc ${c.tc}`);
}

const TAG = 'scaas.ua.mldsa87.v1';
const M = 'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author '
  + 'capable act festival slice deposit sauce coconut afford frown better';
const kindTag = keccak_256(utf8ToBytes(TAG));
const u32 = (v) => new Uint8Array([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
const xi = hkdf(sha256, seedFromWords(M), utf8ToBytes('scaas.ua.pq.v1'), concatBytes(utf8ToBytes(TAG), u32(0), u32(0)), 32);
const { publicKey: pk, secretKey: sk } = ml_dsa87.keygen(xi);
const digest = keccak_256(utf8ToBytes('scaas p6a pq vector digest'));
const purpose = keccak_256(utf8ToBytes('scaas.ua.purpose.pop.v1'));
const uaMsg = keccak_256(concatBytes(keccak_256(utf8ToBytes('scaas.ua.msg.v1')), kindTag, purpose, digest));
const pqMsg = keccak_256(concatBytes(kindTag, uaMsg));
const sig = ml_dsa87.sign(pqMsg, sk, { extraEntropy: false });
if (sig.length !== 4627 || pk.length !== 2592 || !ml_dsa87.verify(sig, pqMsg, pk)) throw new Error('own signature');
const flip = (b, i, bit = 1) => { const c = Uint8Array.from(b); c[i] ^= bit; return c; };
const mutations = [['c~[0] ^ 0x01', 0], ['z[0] ^ 0x01', 64], ['last hint byte ^ 0x01', 4626]].map(([what, i]) => {
  const s = flip(sig, i);
  let valid;
  try { valid = ml_dsa87.verify(s, pqMsg, pk); } catch { valid = false; }
  return { what, sig: hex(s), valid };
});
const out = {
  note: 'ML-DSA-87 probe row (2026-11-04), @noble/post-quantum 0.7.1; proposed tag, not a built kind. '
    + `All ${acvp.cases.length} ACVP cases of acvp87.json agree with noble.`,
  tag: TAG, tag_hash: hex(kindTag), pk: hex(pk), ua: hex(keccak_256(concatBytes(kindTag, pk))), ua_msg: hex(uaMsg),
  signed_message: hex(pqMsg), sig: hex(sig), mutations,
};
writeFileSync(new URL('ua87.json', here), JSON.stringify(out, null, 1) + '\n');
console.log('acvp87.json: noble agrees on', acvp.cases.length, 'cases; wrote ua87.json');

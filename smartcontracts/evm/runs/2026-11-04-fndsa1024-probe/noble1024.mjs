// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Falcon-1024 probe (2026-11-04): a second implementation over kat1024.json and one UA-shaped row (ua1024.json).
// 1. Every KAT case of kat1024.json through @noble/post-quantum 0.7.1: the original NIST `sm` through
//    `falcon1024.attached.open` (must return the KAT message) and the rebuilt padded signature through
//    `falcon1024padded.verify`; anything else refuses.
// 2. A key pair the way clients/clientkeys/src/pq.js derives `fndsa512` (SEP-0005 test mnemonic, HKDF, 48-byte seed,
//    account 0, index 0) under the PROPOSED tag `scaas.ua.fndsa1024.v1` (not built; spec 2026-11-04-fndsa1024), a
//    `pop`-purpose ua_msg over pq_kat.json's digest, signed as `fndsa512` signs: Falcon over ua_msg itself, the fixed
//    `random` of scripts/pq-vectors.mjs; plus mutations with noble's verdict. Probe data only.
//   node runs/2026-11-04-fndsa1024-probe/noble1024.mjs     (from smartcontracts/evm; needs clients/clientkeys/node_modules)
import { readFileSync, writeFileSync } from 'node:fs';
import { falcon1024, falcon1024padded } from '../../../../clients/clientkeys/node_modules/@noble/post-quantum/falcon.js';
import { hkdf } from '../../../../clients/clientkeys/node_modules/@noble/hashes/hkdf.js';
import { shake256 } from '../../../../clients/clientkeys/node_modules/@noble/hashes/sha3.js';
import { seedFromWords } from '../../../../clients/clientkeys/src/seed.js';
import { keccak_256, sha256, concatBytes, utf8ToBytes, hex } from '../../../../clients/clientkeys/src/bytes.js';

const here = new URL('.', import.meta.url);
const h = (s) => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));
const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const kat = JSON.parse(readFileSync(new URL('kat1024.json', here), 'utf8'));
for (const c of kat.cases) {
  if (!eq(falcon1024.attached.open(h(c.sm), h(c.pk)), h(c.msg))) throw new Error(`NIST sm, count ${c.count}`);
  if (!falcon1024padded.verify(h(c.sig), h(c.msg), h(c.pk))) throw new Error(`padded, count ${c.count}`);
}

const TAG = 'scaas.ua.fndsa1024.v1';
const M = 'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author '
  + 'capable act festival slice deposit sauce coconut afford frown better';
const kindTag = keccak_256(utf8ToBytes(TAG));
const u32 = (v) => new Uint8Array([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
const xi = hkdf(sha256, seedFromWords(M), utf8ToBytes('scaas.ua.pq.v1'), concatBytes(utf8ToBytes(TAG), u32(0), u32(0)), 48);
const { publicKey: pk, secretKey: sk } = falcon1024padded.keygen(xi);
const digest = keccak_256(utf8ToBytes('scaas p6a pq vector digest'));
const purpose = keccak_256(utf8ToBytes('scaas.ua.purpose.pop.v1'));
const uaMsg = keccak_256(concatBytes(keccak_256(utf8ToBytes('scaas.ua.msg.v1')), kindTag, purpose, digest));
const fixed = (n) => shake256(utf8ToBytes('scaas p6a falcon randomness'), { dkLen: n });
const sig = falcon1024padded.sign(uaMsg, sk, { random: fixed });
if (sig.length !== 1280 || pk.length !== 1793 || !falcon1024padded.verify(sig, uaMsg, pk)) throw new Error('own signature');
const flip = (b, i, bit = 1) => { const c = Uint8Array.from(b); c[i] ^= bit; return c; };
const n = sig.length;
const mutations = [
  ['sig[0] ^ 0x01 (header)', pk, flip(sig, 0), uaMsg],
  ['sig[1] ^ 0x01 (salt)', pk, flip(sig, 1), uaMsg],
  ['sig[mid] ^ 0x80', pk, flip(sig, n >> 1, 0x80), uaMsg],
  ['sig[last] ^ 0x01 (padding)', pk, flip(sig, n - 1), uaMsg],
  ['pk[last] ^ 0x01', flip(pk, pk.length - 1), sig, uaMsg],
  ['ua_msg[0] ^ 0x01', pk, sig, flip(uaMsg, 0)],
].map(([what, p, s, u]) => {
  let valid;
  try { valid = falcon1024padded.verify(s, u, p); } catch { valid = false; }
  return { what, pk: hex(p), sig: hex(s), ua_msg: hex(u), valid };
});
const out = {
  note: 'Falcon-1024 probe row (2026-11-04), @noble/post-quantum 0.7.1; proposed tag, not a built kind. '
    + `All ${kat.cases.length} KAT cases of kat1024.json agree with noble (NIST sm and padded).`,
  tag: TAG, tag_hash: hex(kindTag), pk: hex(pk), ua: hex(keccak_256(concatBytes(kindTag, pk))), ua_msg: hex(uaMsg),
  signed_message: hex(uaMsg), sig: hex(sig), mutations,
};
writeFileSync(new URL('ua1024.json', here), JSON.stringify(out, null, 1) + '\n');
console.log('kat1024.json: noble agrees on', kat.cases.length, 'cases; wrote ua1024.json; mutations valid:',
  mutations.map((m) => m.valid).join(','));

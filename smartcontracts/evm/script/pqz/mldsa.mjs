// P6g e2e helper (plan D7): ML-DSA keys and signatures with @noble/post-quantum 0.7.1 (FIPS 204, empty context).
// usage: node mldsa.mjs <clientkeys dir>   (the dir whose node_modules holds @noble/post-quantum)
// stdin, one job per line:  keygen <44|65> <seed32 hex>            -> <pk hex>
//                           sign <44|65> <seed32 hex> <msg hex>    -> <sig hex>   (msg = pq_msg, 32 bytes)
// Test keys only (the seeds are in the run log).
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const dir = process.argv[2];
const { ml_dsa44, ml_dsa65 } = await import(pathToFileURL(`${dir}/node_modules/@noble/post-quantum/ml-dsa.js`).href);
const alg = { 44: ml_dsa44, 65: ml_dsa65 };
const unhex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const hex = (b) => Buffer.from(b).toString('hex');
const keys = new Map();
const key = (lvl, seed) => {
  const k = `${lvl}:${seed}`;
  if (!keys.has(k)) keys.set(k, alg[lvl].keygen(unhex(seed)));
  return keys.get(k);
};
for await (const line of createInterface({ input: process.stdin })) {
  const [op, lvl, seed, msg] = line.trim().split(/\s+/);
  try {
    if (op === 'keygen') console.log(hex(key(lvl, seed).publicKey));
    else if (op === 'sign') console.log(hex(alg[lvl].sign(unhex(msg), key(lvl, seed).secretKey)));
    else console.log('ERR job');
  } catch (e) {
    console.log(`ERR ${e.message}`);
  }
}

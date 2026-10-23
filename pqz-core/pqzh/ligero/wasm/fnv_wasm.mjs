// PQZH-Ligero wasm32 proof fingerprints (plan 5h Task 8c; no timing): native = wasm32 on the same proofs.
//   node wasm/fnv_wasm.mjs <set> [wasm file]  ->  JSON lines {set, idx, seed, proof_bytes, fnv, verify} in the order of
//   `ligero_kat setup` (RELS then multi_rels(), seeds 0 and 1), then one line per relation with the 12 mutation kinds
//   (client::KINDS) of its seed-1 proof: every one must be rejected. Build first:
//   (cd wasm && cargo build --release --offline --target wasm32-unknown-unknown [--features set-<set>])
import { readFileSync } from 'node:fs';

const set = process.argv[2] || 'n2048-kmax1024';
const file = process.argv[3] || new URL('target/wasm32-unknown-unknown/release/pqzh_ligero_wasm.wasm', import.meta.url);
const { instance } = await WebAssembly.instantiate(readFileSync(file), {});
const x = instance.exports;
const kinds = x.step_init(1, 1); // THE preset (proven, radix 431)
let fails = 0;
for (let i = 0; i < x.step_nrel(); i++) {
  for (const seed of [0, 1]) {
    const len = x.step_prove(i, seed);
    const fnv = (x.step_hash(i) >>> 0).toString(16).padStart(8, '0');
    const verify = x.step_verify(i) === 1;
    fails += !len || !verify;
    console.log(JSON.stringify({ set, idx: i, seed, proof_bytes: len, fnv, verify }));
  }
  x.step_prove_other(i);
  let accepted = 0;
  for (let k = 0; k < kinds; k++) accepted += x.step_verify_bad(i, k);
  fails += accepted;
  console.log(JSON.stringify({ set, idx: i, mutations: kinds, accepted }));
}
console.log(JSON.stringify({ set, fails }));
process.exit(fails ? 1 : 0);

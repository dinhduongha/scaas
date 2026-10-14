// PQZH-Ligero wasm32 runner (copy of pqzh/wasm/run_wasm.mjs): prove / verify / adversarial verify timed on the JS side, linear-memory high-water vs 256 MiB.
//   node wasm/run_wasm.mjs [n_prove] [n_verify] [n_adv per kind] [proven 1/0/2] [r431 1/0] [rels, default 0,1]
//   (parameters: the presets of Params::preset, 2 = Johnson; rels: 0 R_REG, 1 R_TX, 2 R_BURN, 3 R_DS, 4 R_DR)
// PQZH_PROOFS=DIR: verify only, proofs made natively by `ligero_bench --dump DIR` with the same parameters.
// Build first: (cd wasm && cargo build --release --offline --target wasm32-unknown-unknown). Prints JSON lines.
import { readFileSync } from 'node:fs';

const [np = 3, nv = 50, nadv = 4, proven = 1, r431 = 1] =
  process.argv.slice(2, 7).map(Number);
const rels = (process.argv[7] || '0,1').split(',').map(Number);
const NAMES = ['R_REG', 'R_TX', 'R_BURN', 'R_DS', 'R_DR'];
const proofs = process.env.PQZH_PROOFS;
const file = process.env.PQZH_WASM_FILE || new URL('target/wasm32-unknown-unknown/release/pqzh_ligero_wasm.wasm', import.meta.url);
const bytes = readFileSync(file);
const { instance } = await WebAssembly.instantiate(bytes, {});
const x = instance.exports;
const MiB = 2 ** 20;
const mem = () => x.memory.buffer.byteLength / MiB; // never shrinks: the high-water mark of the allocator
const out = (o) => console.log(JSON.stringify(o));
const r3 = (t) => Math.round(t * 1000) / 1000;
const stats = (v) => {
  v.sort((a, b) => a - b);
  const n = v.length;
  return { n, mean_ms: r3(v.reduce((s, t) => s + t, 0) / n), p50_ms: r3(v[n >> 1]), p99_ms: r3(v[Math.floor((n - 1) * 0.99)]),
           max_ms: r3(v[n - 1]) };
};

out({ wasm_bytes: bytes.length, node: process.version, args: { np, nv, nadv, proven, r431, rels, proofs } });
let t0 = performance.now();
const kinds = x.step_init(proven, r431);
const load = (tx, which, file) => {
  const b = readFileSync(file);
  const p = x.step_alloc(b.length);
  new Uint8Array(x.memory.buffer, p, b.length).set(b);
  x.step_load(tx, which, p, b.length);
  return b.length;
};
out({ init_ms: r3(performance.now() - t0), memory_mib: mem() });
let fails = 0;
for (const tx of rels) {
  const rel = NAMES[tx];
  const tp = [];
  let len = 0;
  if (proofs) {
    len = load(tx, 0, `${proofs}/${rel}.proof`);
    load(tx, 1, `${proofs}/${rel}.other`);
  }
  for (let i = 0; i < (proofs ? 0 : np); i++) {
    t0 = performance.now();
    len = x.step_prove(tx, i);
    tp.push(performance.now() - t0);
    if (!len) { out({ rel, prove_failed: i }); fails++; }
  }
  const fnv = (x.step_hash(tx) >>> 0).toString(16).padStart(8, '0');
  if (!proofs) out({ rel, proof_bytes: len, fnv_last: fnv, timing: 'prove', stats: stats(tp), memory_mib: mem(), within_256mib: mem() <= 256 });
  else out({ rel, proof_bytes: len, fnv_loaded: fnv, memory_mib: mem() });
  if (!proofs) x.step_prove_other(tx);
  const tv = [];
  for (let i = 0; i < nv; i++) {
    t0 = performance.now();
    fails += x.step_verify(tx) !== 1;
    tv.push(performance.now() - t0);
  }
  out({ rel, timing: 'verify_honest', stats: stats(tv), memory_mib: mem() });
  const ta = [];
  for (let k = 0; k < kinds; k++)
    for (let i = 0; i < nadv; i++) {
      t0 = performance.now();
      const acc = x.step_verify_bad(tx, k);
      ta.push(performance.now() - t0);
      if (acc !== 0) { out({ rel, accepted_kind: k }); fails++; }
    }
  out({ rel, timing: 'verify_adversarial', stats: stats(ta), memory_mib: mem() });
}
out({ fails, memory_mib_final: mem() });
process.exit(fails ? 1 : 0);

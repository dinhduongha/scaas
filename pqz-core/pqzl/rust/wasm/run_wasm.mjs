// pqzl (Rust) wasm32 runner: the steps of the native `bench` (pqzl/test/run_wasm.mjs's loop for the C core's pqz.wasm),
// timed on the JS side; prints the same JSON lines (proofs_fnv equal to the C core's wasm32 run for the same arguments).
//   cargo build --release --target wasm32-unknown-unknown (in this directory), then
//   node wasm/run_wasm.mjs [n_prove] [n_verify] [rel]   (rel: bench's bit mask, default 63; PQZL_WASM_FILE: the module;
//   PQZ_VERIFY=fast: verify with verify_fast, as the native bench)
import { readFileSync } from 'node:fs';

const [np = 3, nv = 3, rels = 63] = process.argv.slice(2).map(Number);
const ALL = ['R_REG', 'R_TX', 'R_BURN', 'R_DS', 'R_DR', 'R_TX0', 'R_TXM1', 'R_TXM2', 'R_TXM4', 'R_TXM8', 'R_TXM1_0',
  'R_TXM2_0', 'R_TXM4_0', 'R_TXM8_0', 'R_TXM16', 'R_TXM16_0'];
const NKIND = 6;
const file = process.env.PQZL_WASM_FILE
  || new URL('target/wasm32-unknown-unknown/release/pqzl_wasm.wasm', import.meta.url);
const { instance } = await WebAssembly.instantiate(readFileSync(file), {});
const x = instance.exports;
const NAMES = ALL.slice(0, x.step_nrel());
const out = (o) => console.log(JSON.stringify(o));
const stats = (name, v) => {
  if (!v.length) return;
  v.sort((a, b) => a - b);
  const r = (t) => Math.round(t * 1000) / 1000;
  out({ timing: name, n: v.length, mean_ms: r(v.reduce((s, t) => s + t, 0) / v.length), p50_ms: r(v[v.length >> 1]),
        p99_ms: r(v[Math.floor(0.99 * (v.length - 1))]), max_ms: r(v[v.length - 1]) });
};

let t0 = performance.now();
const rc = x.step_init();
if (rc !== 0) { out({ error: 'init', rc }); process.exit(1); }
const fast = process.env.PQZ_VERIFY === 'fast';
x.step_set_fast(fast ? 1 : 0);
out({ init_ms: Math.round((performance.now() - t0) * 10) / 10, verify: fast ? 'fast' : 'generic' });

let fails = 0;
for (let tx = 0; tx < NAMES.length; tx++) {
  if (!((rels >> tx) & 1)) continue;
  const rel = NAMES[tx];
  const tp = [];
  let maxlen = 0;
  let hall = 2166136261;
  for (let i = 0; i < np; i++) {
    t0 = performance.now();
    const rc = x.step_prove(tx, i);
    tp.push(performance.now() - t0);
    if (rc !== 0) { out({ rel, prove_rc: rc }); fails++; continue; }
    maxlen = Math.max(maxlen, x.step_len(tx));
    hall = Math.imul((hall ^ x.step_hash(tx)) >>> 0, 16777619) >>> 0;
    if (x.step_verify(tx) !== 1) { out({ rel, verify_honest: 0, run: i }); fails++; }
  }
  stats(`${rel} prove`, tp);
  // wasm_memory_bytes: the module's linear memory after the proves (it only grows: the peak so far in this process)
  out({ rel, proof_bytes_last: x.step_len(tx), proof_bytes_max: maxlen, proofs_fnv: hall.toString(16).padStart(8, '0'),
        wasm_memory_bytes: x.memory.buffer.byteLength });
  const tv = [];
  for (let i = 0; i < nv; i++) {
    t0 = performance.now();
    fails += x.step_verify(tx) !== 1;
    tv.push(performance.now() - t0);
  }
  stats(`${rel} verify valid`, tv);
  const ta = [];
  for (let kind = 0; kind < NKIND; kind++)
    for (let i = 0; i < Math.floor(nv / 5) + 1; i++) {
      t0 = performance.now();
      const r = x.step_verify_bad(tx, kind, kind + NKIND * i);
      ta.push(performance.now() - t0);
      if (r !== 0) { out({ rel, accepted_bad_kind: kind }); fails++; }
    }
  stats(`${rel} verify adversarial`, ta);
}
out({ fails });
process.exit(fails ? 1 : 0);

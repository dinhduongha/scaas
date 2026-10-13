// pqz-core wasm32 runner: the same steps as the native pqz_bench main(), timed on the JS side.
//   node test/run_wasm.mjs [n_prove] [n_verify] [rel]  (after ./build.sh wasm; prints JSON lines)
//   rel: bit mask as pqz_bench (1 R_REG, 2 R_TX, 4 R_BURN, 8 R_DS, 16 R_DR; default 31)
import { readFileSync } from 'node:fs';

const [np = 3, nv = 3, rels = 31] = process.argv.slice(2).map(Number);
const NAMES = ['R_REG', 'R_TX', 'R_BURN', 'R_DS', 'R_DR'];
const NKIND = 6; // tamper kinds of step_verify_bad
const ARENA = 768 * 2 ** 20; // as ARENA_BYTES in pqz_bench.c
const wasm = readFileSync(process.env.PQZ_WASM_FILE || new URL('../build/wasm/pqz.wasm', import.meta.url));
const { instance } = await WebAssembly.instantiate(wasm, {});
const x = instance.exports;
const heap = x.__heap_base.value;
const grow = Math.ceil((heap + ARENA - x.memory.buffer.byteLength) / 65536);
if (grow > 0) x.memory.grow(grow);

const out = (o) => console.log(JSON.stringify(o));
const stats = (name, v) => {
  if (!v.length) return;
  v.sort((a, b) => a - b);
  const r = (t) => Math.round(t * 1000) / 1000;
  out({ timing: name, n: v.length, mean_ms: r(v.reduce((s, t) => s + t, 0) / v.length), p50_ms: r(v[v.length >> 1]),
        p99_ms: r(v[Math.floor(0.99 * (v.length - 1))]), max_ms: r(v[v.length - 1]) });
};

let t0 = performance.now();
if (x.step_init(heap, ARENA) !== 0) { out({ error: 'init' }); process.exit(1); }
out({ init_ms: Math.round((performance.now() - t0) * 10) / 10 });

let fails = 0;
for (let tx = 0; tx < NAMES.length; tx++) {
  if (!((rels >> tx) & 1)) continue;
  const rel = NAMES[tx];
  x.step_peak_reset();
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
  out({ rel, proof_bytes_last: x.step_len(tx), proof_bytes_max: maxlen, arena_peak: x.step_arena_peak(),
       proofs_fnv: hall.toString(16).padStart(8, '0') });
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
      if (x.step_verify_bad(tx, kind, kind + NKIND * i) !== 0) { out({ rel, accepted_bad_kind: kind }); fails++; }
      ta.push(performance.now() - t0);
    }
  stats(`${rel} verify adversarial`, ta);
}
out({ fails });
process.exit(fails ? 1 : 0);

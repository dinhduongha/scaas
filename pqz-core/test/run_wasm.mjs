// pqz-core wasm32 runner: the same steps as the native pqz_bench main(), timed on the JS side.
//   node test/run_wasm.mjs [n_prove] [n_verify]      (after ./build.sh wasm; prints JSON lines)
import { readFileSync } from 'node:fs';

const [np = 3, nv = 3] = process.argv.slice(2).map(Number);
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
        max_ms: r(v[v.length - 1]) });
};

let t0 = performance.now();
if (x.step_init(heap, ARENA) !== 0) { out({ error: 'init' }); process.exit(1); }
out({ init_ms: Math.round((performance.now() - t0) * 10) / 10 });

let fails = 0;
for (const tx of [0, 1]) {
  const rel = tx ? 'R_TX' : 'R_REG';
  const tp = [];
  let maxlen = 0;
  let hall = 2166136261;
  for (let i = 0; i < np; i++) {
    t0 = performance.now();
    const rc = tx ? x.step_prove_tx(i) : x.step_prove_reg(i);
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
  for (let kind = 0; kind < 5; kind++)
    if (x.step_verify_bad(tx, kind, kind) !== 0) { out({ rel, accepted_bad_kind: kind }); fails++; }
}
out({ fails });
process.exit(fails ? 1 : 0);

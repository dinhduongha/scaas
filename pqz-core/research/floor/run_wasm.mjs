// PQZL verifier floor: the portable kernels in wasm32 under node (floor/wasm.c). Same op names as kern.c,
// prefixed "wasm ". Usage: node floor/run_wasm.mjs   (after floor/build.sh; prints JSON lines, median of 7)
import { readFileSync } from 'node:fs';

const wasm = readFileSync(new URL('../../pqzl/build/floor/kern.wasm', import.meta.url));
const { instance } = await WebAssembly.instantiate(wasm, { env: { now: () => performance.now() * 1e6 } });
const x = instance.exports;
if (x.check() !== 1) { console.log(JSON.stringify({ error: 'wasm self-check failed' })); process.exit(1); }

const ops = [
  [0, 'fork pqz_ntt_basemul (pointwise product, 4 x 16x16 schoolbook)', 'per product', 200000],
  [1, 'fork pqz_ntt_fwd (mod q, 2 layers, 4 x 16 blocks)', 'per poly', 200000],
  [2, 'fork pqz_ntt_inv', 'per poly', 200000],
  [3, 'crt30 ntt_fwd, one prime (scalar)', 'per poly per prime', 200000],
  [4, 'crt30 ntt_inv, one prime (scalar)', 'per poly per prime', 200000],
  [5, 'crt30 pointwise multiply-accumulate, one prime (scalar)', 'per product per prime', 1000000],
  [6, 'R_TX JL fold vR = V^T R, 4 x 256 x 9792 ternary, scalar branchless', 'per fold', 5],
  [7, 'fork AES-256-CTR stream (bitsliced, LaZer rng_urandom)', 'per MiB', 5],
  [8, 'fork rng_init + 16 B + clear (AES key schedule per challenge domain)', 'per call', 2000],
  [9, 'fork SHAKE128 squeeze', 'per MiB', 10],
  [10, 'fork SHAKE128 absorb 64 KiB + squeeze 32 B', 'per 64 KiB', 100],
];
console.log(JSON.stringify({ build: `wasm32 (node ${process.version}, no SIMD)` }));
for (const [id, op, unit, iters] of ops) {
  const v = [];
  for (let r = 0; r < 7; r++) v.push(x.bench(id, iters));
  v.sort((a, b) => a - b);
  console.log(JSON.stringify({ op: `wasm ${op}`, unit, ns: Math.round(v[3] * 10) / 10 }));
}

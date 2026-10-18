// pqzl (Rust) native = wasm32 on the vectors (as pqz-ffi's wasm digest lines): replays target/wasm-replay/in.txt
// (written by `cargo test --test vectors wasm_replay_inputs`, with its native digest lines in native.jsonl) in the
// wasm/ module on one Ctx and prints the same digest lines on stdout (run.sh diffs them): per vector row the proof's
// FNV-1a (op 7 with M > WASM_MAX_LEGS = 8 would be refused on wasm32: checked to be Error::Input, not printed), the
// verify and verify_fast verdicts; per negative row both verdicts. On stderr: the refusals (none since Task 12) and the shadow-stack use per operation
// (the stack's free part is painted before each call and scanned after it; the stack is first in linear memory,
// [0, top), as `sp` shows).
//   node wasm/run_vectors.mjs [in.txt]   (PQZL_WASM_FILE: the module)
import { readFileSync } from 'node:fs';

const inFile = process.argv[2] || new URL('../target/wasm-replay/in.txt', import.meta.url);
const file = process.env.PQZL_WASM_FILE
  || new URL('target/wasm32-unknown-unknown/release/pqzl_wasm.wasm', import.meta.url);
const { instance } = await WebAssembly.instantiate(readFileSync(file), {});
const x = instance.exports;
// = pqzl::WASM_MAX_LEGS (8 since port plan Task 12: the M = 8 rows are proved in wasm32 too); PQZL_WASM_MAX_LEGS
// overrides it for a module built otherwise
const MAX_LEGS = Number(process.env.PQZL_WASM_MAX_LEGS || 8), PAINT = 0xa5;
const unhex = (h) => (h === '.' ? new Uint8Array(0) : Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16)));
const fnv = (b) => b.reduce((h, v) => Math.imul((h ^ v) >>> 0, 16777619) >>> 0, 2166136261);
const lines = readFileSync(inFile, 'utf8').trim().split('\n').map((l) => l.split(' '));

// one buffer per field, sized for the largest input
const size = (k) => Math.max(1, ...lines.map((f) => (f[k] === '.' ? 0 : f[k].length / 2)));
const buf = [4, 5, 6, 7].map((k) => ({ n: size(k), p: x.alloc(size(k)) }));
const put = (i, b) => { new Uint8Array(x.memory.buffer, buf[i].p, b.length).set(b); return buf[i].p; };

const top = x.sp();
const stack = {};
// run f with the free stack [0, top - 256) painted; record the deepest address it wrote
const measured = (op, f) => {
  new Uint8Array(x.memory.buffer, 0, top - 256).fill(PAINT);
  const r = f();
  const m = new Uint8Array(x.memory.buffer, 0, top - 256);
  let lo = 0;
  while (lo < m.length && m[lo] === PAINT) lo++;
  const used = top - lo;
  if (!stack[op] || used > stack[op].used) stack[op] = { used, at: cur };
  return r;
};

let cur = '', refused = 0, fails = 0;
for (const [kind, name, ops, legss, st, wit, rnd, pf] of lines) {
  const [op, legs] = [Number(ops), Number(legss)];
  cur = `${kind} ${name}`;
  const s = unhex(st), p = unhex(pf);
  const vfy = (fast) => {
    const sp = put(0, s), pp = put(3, p);
    return measured(fast ? 'verify_fast' : 'verify', () => x.verify_v(op, sp, s.length, pp, p.length, fast));
  };
  if (kind === 'row') {
    const w = unhex(wit), r = unhex(rnd);
    const sp = put(0, s), wp = put(1, w), rp = put(2, r);
    const n = measured(legs > MAX_LEGS ? 'prove (refused)' : 'prove', () => x.prove_v(op, sp, s.length, wp, w.length, rp));
    let pv = '';
    if (legs > MAX_LEGS) {
      const ok = n === (0x80000000 | 3);
      refused += ok;
      fails += !ok;
      process.stderr.write(`wasm32 op 7 M = ${legs} prove refused (Error::Input): ${ok} (${name})\n`);
    } else {
      const proof = (n & 0x80000000) ? new Uint8Array(0) : new Uint8Array(x.memory.buffer, x.proof_ptr(), n).slice();
      pv = `"prove": "${(n & 0x80000000) ? `error ${n & 0xff}` : fnv(proof).toString(16).padStart(8, '0')}", `;
    }
    console.log(`{"row": "${name}", ${pv}"verify": ${vfy(0)}, "verify_fast": ${vfy(1)}}`);
  } else {
    console.log(`{"neg": "${name}", "verify": ${vfy(0)}, "verify_fast": ${vfy(1)}}`);
  }
}
for (const [op, { used, at }] of Object.entries(stack))
  process.stderr.write(`wasm32 stack ${op}: max ${used} B of ${top} B (${at})\n`);
process.stderr.write(`wasm32 M > ${MAX_LEGS} refused: ${refused}; memory ${x.memory.buffer.byteLength} B\n`);
process.exit(fails ? 1 : 0);

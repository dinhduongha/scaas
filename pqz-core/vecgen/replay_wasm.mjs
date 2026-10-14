// wasm32 replay of the vectors (P6e Task 11): every proof of proof_pqzl.json, proof_pqzh.json and
// worstcase_noise.json proved again in wasm32 from the same statement, witness and rnd32 must give the same bytes,
// and verify (PQZL: specialised verifier; PQZH: Ligero). Prints JSON lines; exit 1 on any difference.
//   node replay_wasm.mjs <vec_pqzl.wasm> <pqz_vectors_wasm.wasm> [vector dir]
// vec_pqzl.wasm: build.sh's freestanding wasm32 objects of libpqz linked with pqz_init / pqz_prove / pqz_verify_fast
// exported (run.sh); pqz_vectors_wasm.wasm: wasm/ (Ligero, production build).
import { readFileSync } from 'node:fs';

const [lfile, hfile, dir = new URL('../../smartcontracts/vectors/pqz/', import.meta.url).pathname] = process.argv.slice(2);
const J = (n) => JSON.parse(readFileSync(`${dir}/${n}`, 'utf8'));
const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const out = (o) => console.log(JSON.stringify(o));
const ID = { pqzl: J('proof_pqzl.json').proof_system_id, pqzh: J('proof_pqzh.json').proof_system_id };
const stmts = {};
for (const f of ['statement_transfer.json', 'statement_burn.json', 'statement_refresh.json', 'statement_register.json',
  'statement_disclose.json']) for (const r of J(f).rows) stmts[r.form] = r.stmt;
const withId = (s, id) => hex(s.slice(0, 64) + ID[id] + s.slice(128));

const cases = [];
for (const id of ['pqzl', 'pqzh'])
  for (const r of J(`proof_${id}.json`).rows)
    cases.push({ id, form: r.form, op: r.op, stmt: withId(stmts[r.form], id), wit: hex(r.wit), rnd: hex(r.rnd32), proof: r.proof });
const w = J('worstcase_noise.json').debit;
for (const id of ['pqzl', 'pqzh'])
  cases.push({ id, form: 'worstcase TRANSFER', op: 1, stmt: withId(w.stmt, id), wit: hex(w.wit), rnd: hex(w.rnd32), proof: w[id].proof });

// PQZL: freestanding C core; buffers at __heap_base, then the arena (as test/run_wasm.mjs)
const L = (await WebAssembly.instantiate(readFileSync(lfile), {})).instance.exports;
const ARENA = 512 * 2 ** 20;
const base = L.__heap_base.value;
const [S, W, R, P, PL] = [base, base + 90000, base + 110000, base + 110064, base + 210000];
const arena = (base + 262144 + 65535) & ~65535;
L.memory.grow(Math.ceil((arena + ARENA - L.memory.buffer.byteLength) / 65536));
if (L.pqz_init(arena, ARENA) !== 0) throw new Error('pqz_init');
// PQZH: Ligero
const H = (await WebAssembly.instantiate(readFileSync(hfile), {})).instance.exports;

let fails = 0;
for (const c of cases) {
  const t = performance.now();
  let got;
  let ok;
  if (c.id === 'pqzl') {
    const m = new Uint8Array(L.memory.buffer);
    m.set(c.stmt, S); m.set(c.wit, W); m.set(c.rnd, R);
    new DataView(L.memory.buffer).setUint32(PL, 98304, true);
    const rc = L.pqz_prove(c.op, S, c.stmt.length, W, c.wit.length, R, P, PL);
    const n = new DataView(L.memory.buffer).getUint32(PL, true);
    got = rc === 0 ? Buffer.from(new Uint8Array(L.memory.buffer, P, n)).toString('hex') : `rc ${rc}`;
    ok = L.pqz_verify_fast(c.op, S, c.stmt.length, P, n);
  } else {
    const put = (b) => { const p = H.alloc(b.length); new Uint8Array(H.memory.buffer, p, b.length).set(b); return p; };
    const [s, wt, r] = [put(c.stmt), put(c.wit), put(c.rnd)];
    const n = H.prove_h(c.op, s, c.stmt.length, wt, c.wit.length, r);
    const p = H.out_ptr();
    got = Buffer.from(new Uint8Array(H.memory.buffer, p, n)).toString('hex');
    ok = H.verify_h(c.op, s, c.stmt.length, p, n);
  }
  const equal = got === c.proof;
  fails += !equal || ok !== 1;
  out({ id: c.id, form: c.form, proof_bytes: c.proof.length / 2, wasm_equal_native: equal, wasm_verify: ok,
        ms: Math.round(performance.now() - t) });
}
out({ cases: cases.length, fails, node: process.version });
process.exit(fails ? 1 : 0);

// wasm32 replay of the vectors (P6e Task 11): every proof of proof_pqzl.json, proof_pqzh.json and
// worstcase_noise.json proved again in wasm32 (pqz-ffi's prove feature, ../wasm: the C core freestanding, Ligero)
// from the same statement, witness and rnd32 must give the same bytes and be valid through pqz_ffi::precompile.
// Op 7 rows (P6-ANON S4, statement_transfer_multi.json): the same. The C backend (opt-in) does not prove PQZL M > 4
// in wasm32 (pqzl::WASM_PQZL_MAX_LEGS, one 512 MiB arena; S3): there the native proof is verified through the wasm32
// precompile. The Rust backend (default) proves M = 8 too (port plan Task 12); the module's m8_refused() tells which.
// Prints JSON lines; exit 1 on any difference.
//   node replay_wasm.mjs <pqz_ffi_wasm.wasm> [vector dir]
import { readFileSync } from 'node:fs';

const [file, dir = new URL('../../../smartcontracts/vectors/pqz/', import.meta.url).pathname] = process.argv.slice(2);
const J = (n) => JSON.parse(readFileSync(`${dir}/${n}`, 'utf8'));
const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const out = (o) => console.log(JSON.stringify(o));
const ID = { pqzl: J('proof_pqzl.json').proof_system_id, pqzh: J('proof_pqzh.json').proof_system_id };
const withId = (s, id) => hex(s.slice(0, 64) + ID[id] + s.slice(128));
const stmts = {};
for (const f of ['statement_transfer.json', 'statement_burn.json', 'statement_refresh.json', 'statement_register.json',
  'statement_disclose.json']) for (const r of J(f).rows) stmts[r.form] = r.stmt;
const multi = {};
for (const r of J('statement_transfer_multi.json').rows) multi[r.case] = r;

const cases = [];
const add = (name, op, stmt, wit, rnd, o) => { for (const id of ['pqzl', 'pqzh'])
  cases.push({ id, form: name, op, stmt: withId(stmt, id), wit: hex(wit), rnd: hex(rnd), proof: o[id].proof }); };
for (const id of ['pqzl', 'pqzh'])
  for (const r of J(`proof_${id}.json`).rows) {
    const m = r.case && multi[r.case];
    cases.push({ id, form: r.case ? `${r.form} ${r.case}` : r.form, op: r.op, stmt: withId(m ? m.stmt : stmts[r.form], id),
      wit: hex(r.wit), rnd: hex(r.rnd32), proof: r.proof, pqzlM: m && id === 'pqzl' ? m.M : 0 });
  }
const w = J('worstcase_noise.json');
// the register statement: opTag || id || message || pk; pk comes from the receiver's R_REG witness only in C, so take
// it from the bound debit's statement (pk_f at 640)
const b = w.bound;
const pk = b.debit.stmt.slice(2 * 640, 2 * (640 + 16384));
const regTag = J('statement_register.json').rows[0].stmt.slice(0, 64);
add('bound R_REG', 3, regTag + ID.pqzl + b.receiver.register.message + pk, b.receiver.register.wit, b.receiver.register.rnd32,
  b.receiver.register);
for (const r of b.sender.rows) add(`bound sender R_TX credit ${r.credit}`, 1, r.stmt, b.sender.wit, r.rnd32, r);
add('bound debit', 1, b.debit.stmt, b.debit.wit, b.debit.rnd32, b.debit);
add('illustrative debit', 1, w.illustrative.debit.stmt, w.illustrative.debit.wit, w.illustrative.debit.rnd32,
  w.illustrative.debit);

for (const r of J('fee0.json').rows) add(`fee 0 ${r.form}`, r.op, r.stmt, r.wit, r.rnd32, r);

const x = (await WebAssembly.instantiate(readFileSync(file), {})).instance.exports;
const m8Refused = x.m8_refused() === 1; // the C backend
for (const c of cases) c.verifyOnly = c.pqzlM > 4 && m8Refused;
const put = (bytes) => { const p = x.alloc(bytes.length); new Uint8Array(x.memory.buffer, p, bytes.length).set(bytes); return p; };
let fails = 0;
let verifyOnly = 0;
for (const c of cases) {
  const t = performance.now();
  const n = c.verifyOnly ? c.proof.length / 2
    : x.prove_v(c.op, put(c.stmt), c.stmt.length, put(c.wit), c.wit.length, put(c.rnd));
  const p = c.verifyOnly ? hex(c.proof) : new Uint8Array(x.memory.buffer, x.proof_ptr(), n).slice();
  verifyOnly += !!c.verifyOnly;
  const got = Buffer.from(p).toString('hex');
  const inp = new Uint8Array(5 + c.stmt.length + n);
  inp[0] = c.op;
  new DataView(inp.buffer).setUint32(1, c.stmt.length);
  inp.set(c.stmt, 5);
  inp.set(p, 5 + c.stmt.length);
  const ok = x.precompile_v(put(inp), inp.length);
  const equal = n > 0 && got === c.proof;
  fails += !equal || ok !== 1;
  out({ id: c.id, form: c.form, proof_bytes: n, wasm_equal_native: c.verifyOnly ? 'native proof (verify only)' : equal,
        wasm_precompile: ok, ms: Math.round(performance.now() - t) });
}
out({ cases: cases.length, verify_only: verifyOnly, fails, node: process.version });
process.exit(fails ? 1 : 0);

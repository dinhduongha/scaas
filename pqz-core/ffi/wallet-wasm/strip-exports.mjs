// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// node strip-exports.mjs <in.wasm> <out.wasm>: keeps only the wallet's exports (lib.rs), drops every other one. rustc
// exports every `#[no_mangle]` function of the crate graph, so pqz-ffi's C ABI (`pqz_precompile`, `pqz_max_input`: raw
// caller pointers, review P-E) would be exports of the wallet module too; the loader refuses a module with any other export.
import { readFileSync, writeFileSync } from 'node:fs';

export const WALLET_EXPORTS = ['memory', 'input_ptr', 'input_cap', 'out_ptr', 'pk_bytes', 'check_recipient', 'check_auditor'];

const leb = (b, p) => { let x = 0, s = 0, c; do { c = b[p++]; x += (c & 0x7f) * 2 ** s; s += 7; } while (c & 0x80); return [x, p]; };
const uleb = (x) => { const o = []; do { let c = x & 0x7f; x = Math.floor(x / 128); if (x) c |= 0x80; o.push(c); } while (x); return o; };

export function stripExports(wasm, keep = WALLET_EXPORTS) {
  const out = [wasm.subarray(0, 8)];
  let p = 8;
  while (p < wasm.length) {
    const id = wasm[p];
    const [size, q] = leb(wasm, p + 1);
    const end = q + size;
    if (id !== 7) { out.push(wasm.subarray(p, end)); p = end; continue; }
    let [n, r] = leb(wasm, q);
    const kept = [];
    for (; n > 0; n--) {
      const [len, a] = leb(wasm, r);
      const name = new TextDecoder().decode(wasm.subarray(a, a + len));
      const [, b] = leb(wasm, a + len + 1); // kind byte, then the index
      if (keep.includes(name)) kept.push(wasm.subarray(r, b));
      r = b;
    }
    const body = Buffer.concat([Buffer.from(uleb(kept.length)), ...kept]);
    out.push(Buffer.from([7, ...uleb(body.length)]), body);
    p = end;
  }
  return Buffer.concat(out);
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
  const [src, dst] = process.argv.slice(2);
  const w = stripExports(readFileSync(src));
  const names = WebAssembly.Module.exports(new WebAssembly.Module(w)).map((e) => e.name).sort();
  if (names.join() !== [...WALLET_EXPORTS].sort().join()) throw new Error(`exports after the strip: ${names}`);
  writeFileSync(dst, w);
  console.log(`${dst}: ${w.length} bytes, exports ${names.join(' ')}`);
}

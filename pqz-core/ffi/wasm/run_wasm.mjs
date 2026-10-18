// node run_wasm.mjs <pqz_ffi_wasm.wasm> [sel]  — prints the wasm32 digest lines (pqz-ffi prove feature) and the time
import { readFileSync } from "node:fs";
const [file, sel = "3"] = process.argv.slice(2);
const { instance } = await WebAssembly.instantiate(readFileSync(file), {});
const e = instance.exports;
const t0 = performance.now();
const n = e.run(Number(sel));
const ms = performance.now() - t0;
process.stdout.write(new TextDecoder().decode(new Uint8Array(e.memory.buffer, e.out_ptr(), n)));
process.stderr.write(`wasm run ${ms.toFixed(0)} ms, memory ${e.memory.buffer.byteLength} B\n`);
if (e.m8_refused) process.stderr.write(`wasm PQZL op 7 M = 8 prove refused (Statement(Legs); C backend true, Rust backend false): ${e.m8_refused() === 1}\n`);

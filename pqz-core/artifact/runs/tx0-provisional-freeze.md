# pqz-core reproducibility run (frozen run PROVISIONAL: P6e Task 2 (R_TX statement auditorOn word = 1, P6e R6; R_TX0 added, not in this package's five-relation runs), rel3/runs/tx0 + sv/runs/tx0 (2026-10-14; replace with the reproduce.sh --full freeze run after P6e gate A))

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), Ubuntu 24.04.4 LTS, kernel 7.0.0-34-generic, Ubuntu clang version 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3, node v26.8.1, Python 3.12.3, in Docker: False.

Times are informational (they depend on the machine); `proofs_fnv`, the checks and the sizes are compared.

| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |
|---|---|---|---|---|---|---|
| `R_REG` | 28,113 | 305 / 457 ms | 172 / 210 ms | 3.83 / 2.39 / 6.7 ms | 4.1 / 2.9 / 9.7 ms | 70.3 MiB |
| `R_TX` | 42,799 | 862 / 1,235 ms | 633 / 795 ms | 7.86 / 4.71 / 13.4 ms | 8.6 / 5.4 / 14.1 ms | 221.1 MiB |
| `R_BURN` | 41,939 | 675 / 1,149 ms | 519 / 679 ms | 7.61 / 4.68 / 12.8 ms | 8.4 / 5.8 / 13.8 ms | 210.2 MiB |
| `R_DS` | 28,995 | 353 / 632 ms | 209 / 269 ms | 4.34 / 2.72 / 7.2 ms | 5.2 / 2.9 / 9.2 ms | 73.3 MiB |
| `R_DR` | 28,996 | 373 / 541 ms | 197 / 275 ms | 4.55 / 2.95 / 7.7 ms | 5.8 / 3.3 / 9.1 ms | 79.1 MiB |

## Against expected-results.json: 69 ok, 0 FAIL, 0 warn, 0 info

| status | check | detail |
|---|---|---|
| ok | kat | ok |
| ok | tbox_fixes | ok |
| ok | sv_fixes | ok |
| ok | diff-portable | 3484 cases, 0 mismatches, 0 other fails, PRG 0 |
| ok | diff-x86v3 | 1736 cases, 0 mismatches, 0 other fails, PRG 0 |
| ok | native-generic.jsonl fails | fails 0, verifier disagreements 0 |
| ok | wasm-generic.jsonl fails | fails 0, verifier disagreements 0 |
| ok | fnv-native.jsonl fails | fails 0, verifier disagreements 0 |
| ok | fnv-wasm.jsonl fails | fails 0, verifier disagreements 0 |
| ok | native-fast.jsonl fails | fails 0, verifier disagreements 0 |
| ok | x86v3-fast.jsonl fails | fails 0, verifier disagreements 0 |
| ok | wasm-fast.jsonl fails | fails 0, verifier disagreements 0 |
| ok | wasm-both.jsonl fails | fails 0, verifier disagreements 0 |
| ok | alone-wasm-nosv.jsonl fails | fails 0, verifier disagreements 0 |
| ok | R_REG proofs_fnv native-generic.jsonl n=10 | b82d49f8, expected b82d49f8 |
| ok | R_REG proofs_fnv wasm-generic.jsonl n=5 | 8bd69f2d, expected 8bd69f2d |
| ok | R_REG proofs_fnv fnv-native.jsonl n=5 | 8bd69f2d, expected 8bd69f2d |
| ok | R_REG proofs_fnv fnv-wasm.jsonl n=3 | e70b5dc4, expected e70b5dc4 |
| ok | R_REG proofs_fnv native-fast.jsonl n=2 | 1af59837, expected 1af59837 |
| ok | R_REG proofs_fnv x86v3-fast.jsonl n=2 | 1af59837, expected 1af59837 |
| ok | R_REG proofs_fnv wasm-fast.jsonl n=2 | 1af59837, expected 1af59837 |
| ok | R_REG proofs_fnv wasm-both.jsonl n=2 | 1af59837, expected 1af59837 |
| ok | R_REG proofs_fnv alone-wasm-nosv.jsonl n=1 | 25074bbb, expected 25074bbb |
| ok | R_REG proof_bytes_max | 28113, frozen 28113 (0.00%, tol 0.5%) |
| ok | R_REG wasm_prove_peak_bytes | 73692688, frozen 73692688 (0.00%, tol 1.0%) |
| ok | R_TX proofs_fnv native-generic.jsonl n=10 | 79b9326d, expected 79b9326d |
| ok | R_TX proofs_fnv wasm-generic.jsonl n=5 | 604111c6, expected 604111c6 |
| ok | R_TX proofs_fnv fnv-native.jsonl n=5 | 604111c6, expected 604111c6 |
| ok | R_TX proofs_fnv fnv-wasm.jsonl n=3 | 6780efdd, expected 6780efdd |
| ok | R_TX proofs_fnv native-fast.jsonl n=2 | 3ef1da5b, expected 3ef1da5b |
| ok | R_TX proofs_fnv x86v3-fast.jsonl n=2 | 3ef1da5b, expected 3ef1da5b |
| ok | R_TX proofs_fnv wasm-fast.jsonl n=2 | 3ef1da5b, expected 3ef1da5b |
| ok | R_TX proofs_fnv wasm-both.jsonl n=2 | 3ef1da5b, expected 3ef1da5b |
| ok | R_TX proofs_fnv alone-wasm-nosv.jsonl n=1 | a092f2ff, expected a092f2ff |
| ok | R_TX proof_bytes_max | 42799, frozen 42799 (0.00%, tol 0.5%) |
| ok | R_TX wasm_prove_peak_bytes | 231858048, frozen 231858048 (0.00%, tol 1.0%) |
| ok | R_BURN proofs_fnv native-generic.jsonl n=10 | 049029ff, expected 049029ff |
| ok | R_BURN proofs_fnv wasm-generic.jsonl n=5 | bfb900f9, expected bfb900f9 |
| ok | R_BURN proofs_fnv fnv-native.jsonl n=5 | bfb900f9, expected bfb900f9 |
| ok | R_BURN proofs_fnv fnv-wasm.jsonl n=3 | 37654486, expected 37654486 |
| ok | R_BURN proofs_fnv native-fast.jsonl n=2 | 12f45572, expected 12f45572 |
| ok | R_BURN proofs_fnv x86v3-fast.jsonl n=2 | 12f45572, expected 12f45572 |
| ok | R_BURN proofs_fnv wasm-fast.jsonl n=2 | 12f45572, expected 12f45572 |
| ok | R_BURN proofs_fnv wasm-both.jsonl n=2 | 12f45572, expected 12f45572 |
| ok | R_BURN proofs_fnv alone-wasm-nosv.jsonl n=1 | d8180c60, expected d8180c60 |
| ok | R_BURN proof_bytes_max | 41939, frozen 41939 (0.00%, tol 0.5%) |
| ok | R_BURN wasm_prove_peak_bytes | 220431120, frozen 220431120 (0.00%, tol 1.0%) |
| ok | R_DS proofs_fnv native-generic.jsonl n=10 | 5429242c, expected 5429242c |
| ok | R_DS proofs_fnv wasm-generic.jsonl n=5 | b4aa2e26, expected b4aa2e26 |
| ok | R_DS proofs_fnv fnv-native.jsonl n=5 | b4aa2e26, expected b4aa2e26 |
| ok | R_DS proofs_fnv fnv-wasm.jsonl n=3 | f39a8e64, expected f39a8e64 |
| ok | R_DS proofs_fnv native-fast.jsonl n=2 | 9eb44281, expected 9eb44281 |
| ok | R_DS proofs_fnv x86v3-fast.jsonl n=2 | 9eb44281, expected 9eb44281 |
| ok | R_DS proofs_fnv wasm-fast.jsonl n=2 | 9eb44281, expected 9eb44281 |
| ok | R_DS proofs_fnv wasm-both.jsonl n=2 | 9eb44281, expected 9eb44281 |
| ok | R_DS proofs_fnv alone-wasm-nosv.jsonl n=1 | 478a0d94, expected 478a0d94 |
| ok | R_DS proof_bytes_max | 28995, frozen 28995 (0.00%, tol 0.5%) |
| ok | R_DS wasm_prove_peak_bytes | 76888880, frozen 76888880 (0.00%, tol 1.0%) |
| ok | R_DR proofs_fnv native-generic.jsonl n=10 | e53ad440, expected e53ad440 |
| ok | R_DR proofs_fnv wasm-generic.jsonl n=5 | c800f2c6, expected c800f2c6 |
| ok | R_DR proofs_fnv fnv-native.jsonl n=5 | c800f2c6, expected c800f2c6 |
| ok | R_DR proofs_fnv fnv-wasm.jsonl n=3 | 96a6e906, expected 96a6e906 |
| ok | R_DR proofs_fnv native-fast.jsonl n=2 | 5bb0078c, expected 5bb0078c |
| ok | R_DR proofs_fnv x86v3-fast.jsonl n=2 | 5bb0078c, expected 5bb0078c |
| ok | R_DR proofs_fnv wasm-fast.jsonl n=2 | 5bb0078c, expected 5bb0078c |
| ok | R_DR proofs_fnv wasm-both.jsonl n=2 | 5bb0078c, expected 5bb0078c |
| ok | R_DR proofs_fnv alone-wasm-nosv.jsonl n=1 | cb2f3ced, expected cb2f3ced |
| ok | R_DR proof_bytes_max | 28996, frozen 28996 (0.00%, tol 0.5%) |
| ok | R_DR wasm_prove_peak_bytes | 82951488, frozen 82951488 (0.00%, tol 1.0%) |

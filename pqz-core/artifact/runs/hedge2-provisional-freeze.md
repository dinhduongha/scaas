# pqz-core reproducibility run (frozen run PROVISIONAL: P6e Task 1 hedged prover after review (WIT-V2 inner tag), rel3/runs/hedge2 + sv/runs/hedge2 (2026-10-14; replace with the reproduce.sh --full freeze run after P6e gate A))

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), Ubuntu 24.04.4 LTS, kernel 7.0.0-34-generic, Ubuntu clang version 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3, node v26.8.1, Python 3.12.3, in Docker: False.

Times are informational (they depend on the machine); `proofs_fnv`, the checks and the sizes are compared.

| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |
|---|---|---|---|---|---|---|
| `R_REG` | 28,113 | 305 / 435 ms | 167 / 210 ms | 3.88 / 2.40 / 6.7 ms | 5.5 / 2.7 / 9.9 ms | 70.3 MiB |
| `R_TX` | 42,797 | 792 / 1,176 ms | 624 / 790 ms | 7.92 / 4.70 / 13.4 ms | 9.0 / 5.3 / 14.7 ms | 221.1 MiB |
| `R_BURN` | 41,939 | 709 / 1,119 ms | 514 / 687 ms | 7.82 / 4.55 / 12.9 ms | 8.7 / 5.0 / 14.2 ms | 210.2 MiB |
| `R_DS` | 28,995 | 347 / 632 ms | 207 / 265 ms | 4.35 / 2.82 / 7.2 ms | 6.0 / 3.3 / 8.0 ms | 73.3 MiB |
| `R_DR` | 28,996 | 407 / 505 ms | 187 / 265 ms | 4.49 / 2.95 / 7.6 ms | 5.3 / 3.4 / 9.7 ms | 79.1 MiB |

## Against expected-results.json: 69 ok, 0 FAIL, 0 warn, 0 info

| status | check | detail |
|---|---|---|
| ok | kat | ok |
| ok | tbox_fixes | ok |
| ok | sv_fixes | ok |
| ok | diff-portable | 2710 cases, 0 mismatches, 0 other fails, PRG 0 |
| ok | diff-x86v3 | 1350 cases, 0 mismatches, 0 other fails, PRG 0 |
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
| ok | R_TX proofs_fnv native-generic.jsonl n=10 | cabd8270, expected cabd8270 |
| ok | R_TX proofs_fnv wasm-generic.jsonl n=5 | ca69759d, expected ca69759d |
| ok | R_TX proofs_fnv fnv-native.jsonl n=5 | ca69759d, expected ca69759d |
| ok | R_TX proofs_fnv fnv-wasm.jsonl n=3 | 177e6806, expected 177e6806 |
| ok | R_TX proofs_fnv native-fast.jsonl n=2 | 1d42a571, expected 1d42a571 |
| ok | R_TX proofs_fnv x86v3-fast.jsonl n=2 | 1d42a571, expected 1d42a571 |
| ok | R_TX proofs_fnv wasm-fast.jsonl n=2 | 1d42a571, expected 1d42a571 |
| ok | R_TX proofs_fnv wasm-both.jsonl n=2 | 1d42a571, expected 1d42a571 |
| ok | R_TX proofs_fnv alone-wasm-nosv.jsonl n=1 | e2cf9721, expected e2cf9721 |
| ok | R_TX proof_bytes_max | 42797, frozen 42797 (0.00%, tol 0.5%) |
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

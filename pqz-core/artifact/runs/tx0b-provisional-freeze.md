# pqz-core reproducibility run (frozen run PROVISIONAL: P6e Task 2 after review (R_TX0 own ABDLOP key tag; canonical salt word 16 zero bytes || salt in the R_TX / R_BURN bench statements; R_TX auditorOn = 1), rel3/runs/tx0b + sv/runs/tx0b (2026-10-14; replace with the reproduce.sh --full freeze run after P6e gate A))

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), Ubuntu 24.04.4 LTS, kernel 7.0.0-34-generic, Ubuntu clang version 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3, node v26.8.1, Python 3.12.3, in Docker: False.

Times are informational (they depend on the machine); `proofs_fnv`, the checks and the sizes are compared.

| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |
|---|---|---|---|---|---|---|
| `R_REG` | 28,113 | 293 / 454 ms | 162 / 224 ms | 3.85 / 2.34 / 6.6 ms | 4.2 / 2.9 / 7.5 ms | 70.3 MiB |
| `R_TX` | 42,772 | 1,004 / 1,355 ms | 664 / 769 ms | 7.89 / 4.57 / 13.4 ms | 8.9 / 5.0 / 14.4 ms | 221.1 MiB |
| `R_BURN` | 41,961 | 886 / 1,435 ms | 563 / 688 ms | 7.70 / 4.56 / 13.2 ms | 8.2 / 5.0 / 14.7 ms | 210.2 MiB |
| `R_DS` | 28,995 | 334 / 641 ms | 202 / 276 ms | 4.31 / 2.75 / 7.2 ms | 4.7 / 3.0 / 9.2 ms | 73.3 MiB |
| `R_DR` | 28,996 | 407 / 484 ms | 205 / 252 ms | 4.70 / 2.86 / 7.7 ms | 4.9 / 3.9 / 8.5 ms | 79.1 MiB |

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
| ok | R_TX proofs_fnv native-generic.jsonl n=10 | e55b1313, expected e55b1313 |
| ok | R_TX proofs_fnv wasm-generic.jsonl n=5 | 239c8b8d, expected 239c8b8d |
| ok | R_TX proofs_fnv fnv-native.jsonl n=5 | 239c8b8d, expected 239c8b8d |
| ok | R_TX proofs_fnv fnv-wasm.jsonl n=3 | ced8bcc3, expected ced8bcc3 |
| ok | R_TX proofs_fnv native-fast.jsonl n=2 | 09b11092, expected 09b11092 |
| ok | R_TX proofs_fnv x86v3-fast.jsonl n=2 | 09b11092, expected 09b11092 |
| ok | R_TX proofs_fnv wasm-fast.jsonl n=2 | 09b11092, expected 09b11092 |
| ok | R_TX proofs_fnv wasm-both.jsonl n=2 | 09b11092, expected 09b11092 |
| ok | R_TX proofs_fnv alone-wasm-nosv.jsonl n=1 | 0e0026f2, expected 0e0026f2 |
| ok | R_TX proof_bytes_max | 42772, frozen 42772 (0.00%, tol 0.5%) |
| ok | R_TX wasm_prove_peak_bytes | 231858048, frozen 231858048 (0.00%, tol 1.0%) |
| ok | R_BURN proofs_fnv native-generic.jsonl n=10 | 801e15c2, expected 801e15c2 |
| ok | R_BURN proofs_fnv wasm-generic.jsonl n=5 | d94216dd, expected d94216dd |
| ok | R_BURN proofs_fnv fnv-native.jsonl n=5 | d94216dd, expected d94216dd |
| ok | R_BURN proofs_fnv fnv-wasm.jsonl n=3 | 07fbdc5c, expected 07fbdc5c |
| ok | R_BURN proofs_fnv native-fast.jsonl n=2 | 73ad9a0a, expected 73ad9a0a |
| ok | R_BURN proofs_fnv x86v3-fast.jsonl n=2 | 73ad9a0a, expected 73ad9a0a |
| ok | R_BURN proofs_fnv wasm-fast.jsonl n=2 | 73ad9a0a, expected 73ad9a0a |
| ok | R_BURN proofs_fnv wasm-both.jsonl n=2 | 73ad9a0a, expected 73ad9a0a |
| ok | R_BURN proofs_fnv alone-wasm-nosv.jsonl n=1 | 780a00bb, expected 780a00bb |
| ok | R_BURN proof_bytes_max | 41961, frozen 41961 (0.00%, tol 0.5%) |
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

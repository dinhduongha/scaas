# pqz-core reproducibility run (frozen run PROVISIONAL: P6e Tasks 2 / 5 after the second review (D15 zero words: transfer recipient 0, burn toUA / auditorOn / salt 0; salt word 16 zero bytes || salt), rel3/runs/tx0c + sv/runs/tx0c (2026-10-14; replace with the reproduce.sh --full freeze run after P6e gate A))

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), Ubuntu 24.04.4 LTS, kernel 7.0.0-34-generic, Ubuntu clang version 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3, node v26.8.1, Python 3.12.3, in Docker: False.

Times are informational (they depend on the machine); `proofs_fnv`, the checks and the sizes are compared.

| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |
|---|---|---|---|---|---|---|
| `R_REG` | 28,113 | 295 / 484 ms | 161 / 223 ms | 3.85 / 2.37 / 6.6 ms | 4.5 / 3.1 / 7.7 ms | 70.3 MiB |
| `R_TX` | 42,785 | 965 / 1,304 ms | 648 / 762 ms | 7.98 / 4.76 / 13.4 ms | 8.7 / 5.4 / 14.8 ms | 221.1 MiB |
| `R_BURN` | 41,938 | 874 / 1,158 ms | 556 / 693 ms | 7.75 / 4.63 / 12.9 ms | 8.9 / 5.7 / 14.2 ms | 210.2 MiB |
| `R_DS` | 28,995 | 331 / 646 ms | 200 / 270 ms | 4.42 / 2.86 / 7.3 ms | 4.9 / 3.9 / 8.7 ms | 73.3 MiB |
| `R_DR` | 28,996 | 395 / 504 ms | 206 / 254 ms | 4.50 / 2.69 / 7.5 ms | 4.9 / 3.0 / 8.4 ms | 79.1 MiB |

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
| ok | R_TX proofs_fnv native-generic.jsonl n=10 | 0b786555, expected 0b786555 |
| ok | R_TX proofs_fnv wasm-generic.jsonl n=5 | b9bbf854, expected b9bbf854 |
| ok | R_TX proofs_fnv fnv-native.jsonl n=5 | b9bbf854, expected b9bbf854 |
| ok | R_TX proofs_fnv fnv-wasm.jsonl n=3 | 9304299b, expected 9304299b |
| ok | R_TX proofs_fnv native-fast.jsonl n=2 | 559b3c44, expected 559b3c44 |
| ok | R_TX proofs_fnv x86v3-fast.jsonl n=2 | 559b3c44, expected 559b3c44 |
| ok | R_TX proofs_fnv wasm-fast.jsonl n=2 | 559b3c44, expected 559b3c44 |
| ok | R_TX proofs_fnv wasm-both.jsonl n=2 | 559b3c44, expected 559b3c44 |
| ok | R_TX proofs_fnv alone-wasm-nosv.jsonl n=1 | 008d4495, expected 008d4495 |
| ok | R_TX proof_bytes_max | 42785, frozen 42785 (0.00%, tol 0.5%) |
| ok | R_TX wasm_prove_peak_bytes | 231858048, frozen 231858048 (0.00%, tol 1.0%) |
| ok | R_BURN proofs_fnv native-generic.jsonl n=10 | c7e99b6b, expected c7e99b6b |
| ok | R_BURN proofs_fnv wasm-generic.jsonl n=5 | 0a5976da, expected 0a5976da |
| ok | R_BURN proofs_fnv fnv-native.jsonl n=5 | 0a5976da, expected 0a5976da |
| ok | R_BURN proofs_fnv fnv-wasm.jsonl n=3 | 0ea1c7a6, expected 0ea1c7a6 |
| ok | R_BURN proofs_fnv native-fast.jsonl n=2 | 7694fd9f, expected 7694fd9f |
| ok | R_BURN proofs_fnv x86v3-fast.jsonl n=2 | 7694fd9f, expected 7694fd9f |
| ok | R_BURN proofs_fnv wasm-fast.jsonl n=2 | 7694fd9f, expected 7694fd9f |
| ok | R_BURN proofs_fnv wasm-both.jsonl n=2 | 7694fd9f, expected 7694fd9f |
| ok | R_BURN proofs_fnv alone-wasm-nosv.jsonl n=1 | ad3e8a12, expected ad3e8a12 |
| ok | R_BURN proof_bytes_max | 41938, frozen 41938 (0.00%, tol 0.5%) |
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

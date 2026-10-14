# pqz-core reproducibility run (frozen run PROVISIONAL: P6e Task 1 hedged prover, rel3/runs/hedge + sv/runs/hedge (2026-10-14; replace with the reproduce.sh --full freeze run after P6e gate A))

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), Ubuntu 24.04.4 LTS, kernel 7.0.0-34-generic, Ubuntu clang version 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3, node v26.8.1, Python 3.12.3, in Docker: False.

Times are informational (they depend on the machine); `proofs_fnv`, the checks and the sizes are compared.

| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |
|---|---|---|---|---|---|---|
| `R_REG` | 28,114 | 268 / 514 ms | 175 / 220 ms | 3.95 / 2.39 / 6.7 ms | 4.5 / 3.0 / 9.4 ms | 70.3 MiB |
| `R_TX` | 42,753 | 862 / 1,122 ms | 651 / 822 ms | 8.07 / 4.67 / 13.4 ms | 9.4 / 5.2 / 14.2 ms | 221.1 MiB |
| `R_BURN` | 41,946 | 939 / 1,619 ms | 543 / 713 ms | 7.69 / 4.63 / 12.9 ms | 9.5 / 5.2 / 13.7 ms | 210.2 MiB |
| `R_DS` | 28,989 | 312 / 358 ms | 207 / 265 ms | 4.35 / 2.85 / 7.2 ms | 4.8 / 3.9 / 7.8 ms | 73.3 MiB |
| `R_DR` | 28,997 | 260 / 420 ms | 194 / 271 ms | 4.58 / 2.93 / 7.7 ms | 5.5 / 3.8 / 8.5 ms | 79.1 MiB |

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
| ok | R_REG proofs_fnv native-generic.jsonl n=10 | d4d4ef83, expected d4d4ef83 |
| ok | R_REG proofs_fnv wasm-generic.jsonl n=5 | edf1b937, expected edf1b937 |
| ok | R_REG proofs_fnv fnv-native.jsonl n=5 | edf1b937, expected edf1b937 |
| ok | R_REG proofs_fnv fnv-wasm.jsonl n=3 | 3e34faff, expected 3e34faff |
| ok | R_REG proofs_fnv native-fast.jsonl n=2 | 95c626e4, expected 95c626e4 |
| ok | R_REG proofs_fnv x86v3-fast.jsonl n=2 | 95c626e4, expected 95c626e4 |
| ok | R_REG proofs_fnv wasm-fast.jsonl n=2 | 95c626e4, expected 95c626e4 |
| ok | R_REG proofs_fnv wasm-both.jsonl n=2 | 95c626e4, expected 95c626e4 |
| ok | R_REG proofs_fnv alone-wasm-nosv.jsonl n=1 | 04429652, expected 04429652 |
| ok | R_REG proof_bytes_max | 28114, frozen 28114 (0.00%, tol 0.5%) |
| ok | R_REG wasm_prove_peak_bytes | 73692688, frozen 73692688 (0.00%, tol 1.0%) |
| ok | R_TX proofs_fnv native-generic.jsonl n=10 | 41fd0d94, expected 41fd0d94 |
| ok | R_TX proofs_fnv wasm-generic.jsonl n=5 | 4ec9c6e9, expected 4ec9c6e9 |
| ok | R_TX proofs_fnv fnv-native.jsonl n=5 | 4ec9c6e9, expected 4ec9c6e9 |
| ok | R_TX proofs_fnv fnv-wasm.jsonl n=3 | 98fa56d9, expected 98fa56d9 |
| ok | R_TX proofs_fnv native-fast.jsonl n=2 | 785a380d, expected 785a380d |
| ok | R_TX proofs_fnv x86v3-fast.jsonl n=2 | 785a380d, expected 785a380d |
| ok | R_TX proofs_fnv wasm-fast.jsonl n=2 | 785a380d, expected 785a380d |
| ok | R_TX proofs_fnv wasm-both.jsonl n=2 | 785a380d, expected 785a380d |
| ok | R_TX proofs_fnv alone-wasm-nosv.jsonl n=1 | 451d28c1, expected 451d28c1 |
| ok | R_TX proof_bytes_max | 42753, frozen 42753 (0.00%, tol 0.5%) |
| ok | R_TX wasm_prove_peak_bytes | 231858048, frozen 231858048 (0.00%, tol 1.0%) |
| ok | R_BURN proofs_fnv native-generic.jsonl n=10 | 9c5da57f, expected 9c5da57f |
| ok | R_BURN proofs_fnv wasm-generic.jsonl n=5 | 242a6785, expected 242a6785 |
| ok | R_BURN proofs_fnv fnv-native.jsonl n=5 | 242a6785, expected 242a6785 |
| ok | R_BURN proofs_fnv fnv-wasm.jsonl n=3 | c32fe93d, expected c32fe93d |
| ok | R_BURN proofs_fnv native-fast.jsonl n=2 | 496c53b7, expected 496c53b7 |
| ok | R_BURN proofs_fnv x86v3-fast.jsonl n=2 | 496c53b7, expected 496c53b7 |
| ok | R_BURN proofs_fnv wasm-fast.jsonl n=2 | 496c53b7, expected 496c53b7 |
| ok | R_BURN proofs_fnv wasm-both.jsonl n=2 | 496c53b7, expected 496c53b7 |
| ok | R_BURN proofs_fnv alone-wasm-nosv.jsonl n=1 | 819bba23, expected 819bba23 |
| ok | R_BURN proof_bytes_max | 41946, frozen 41946 (0.00%, tol 0.5%) |
| ok | R_BURN wasm_prove_peak_bytes | 220431120, frozen 220431120 (0.00%, tol 1.0%) |
| ok | R_DS proofs_fnv native-generic.jsonl n=10 | 4f4a10ab, expected 4f4a10ab |
| ok | R_DS proofs_fnv wasm-generic.jsonl n=5 | dac15c76, expected dac15c76 |
| ok | R_DS proofs_fnv fnv-native.jsonl n=5 | dac15c76, expected dac15c76 |
| ok | R_DS proofs_fnv fnv-wasm.jsonl n=3 | 3c9cde98, expected 3c9cde98 |
| ok | R_DS proofs_fnv native-fast.jsonl n=2 | 3f530c3f, expected 3f530c3f |
| ok | R_DS proofs_fnv x86v3-fast.jsonl n=2 | 3f530c3f, expected 3f530c3f |
| ok | R_DS proofs_fnv wasm-fast.jsonl n=2 | 3f530c3f, expected 3f530c3f |
| ok | R_DS proofs_fnv wasm-both.jsonl n=2 | 3f530c3f, expected 3f530c3f |
| ok | R_DS proofs_fnv alone-wasm-nosv.jsonl n=1 | 4075f5f5, expected 4075f5f5 |
| ok | R_DS proof_bytes_max | 28989, frozen 28989 (0.00%, tol 0.5%) |
| ok | R_DS wasm_prove_peak_bytes | 76888880, frozen 76888880 (0.00%, tol 1.0%) |
| ok | R_DR proofs_fnv native-generic.jsonl n=10 | 2da4e9b2, expected 2da4e9b2 |
| ok | R_DR proofs_fnv wasm-generic.jsonl n=5 | 37a226ae, expected 37a226ae |
| ok | R_DR proofs_fnv fnv-native.jsonl n=5 | 37a226ae, expected 37a226ae |
| ok | R_DR proofs_fnv fnv-wasm.jsonl n=3 | 78688027, expected 78688027 |
| ok | R_DR proofs_fnv native-fast.jsonl n=2 | 2d06acff, expected 2d06acff |
| ok | R_DR proofs_fnv x86v3-fast.jsonl n=2 | 2d06acff, expected 2d06acff |
| ok | R_DR proofs_fnv wasm-fast.jsonl n=2 | 2d06acff, expected 2d06acff |
| ok | R_DR proofs_fnv wasm-both.jsonl n=2 | 2d06acff, expected 2d06acff |
| ok | R_DR proofs_fnv alone-wasm-nosv.jsonl n=1 | 7db4b018, expected 7db4b018 |
| ok | R_DR proof_bytes_max | 28997, frozen 28997 (0.00%, tol 0.5%) |
| ok | R_DR wasm_prove_peak_bytes | 82951488, frozen 82951488 (0.00%, tol 1.0%) |

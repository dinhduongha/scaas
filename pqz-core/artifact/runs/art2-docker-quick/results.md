# pqz-core reproducibility run (quick)

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), Ubuntu 24.04.5 LTS, kernel 7.0.0-34-generic, Ubuntu clang version 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3, node v26.8.1, Python 3.12.3, rustc 1.97.1 (8bab26f4f 2026-07-14), in Docker: True.

Times are informational (they depend on the machine); the proof hashes, the checks and the sizes are compared.

## PQZL (the LaZer fork, C)

| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |
|---|---|---|---|---|---|---|
| `R_REG` | 28,113 | 270 / 545 ms | 178 / 266 ms | 4.12 / 2.50 / 7.5 ms | 5.8 / 3.1 / 8.6 ms | 70.3 MiB |
| `R_TX` | 42,780 | 939 / 1,287 ms | 663 / 782 ms | 8.01 / 4.66 / 14.9 ms | 10.2 / 6.1 / 19.2 ms | 221.1 MiB |
| `R_BURN` | 41,935 | 843 / 1,117 ms | 626 / 692 ms | 7.68 / 4.50 / 12.9 ms | 10.3 / 5.1 / 13.2 ms | 210.2 MiB |
| `R_DS` | 28,974 | 380 / 626 ms | 274 / 331 ms | 4.37 / 2.81 / 7.0 ms | 4.9 / 3.3 / 7.8 ms | 73.3 MiB |
| `R_DR` | 28,994 | 281 / 494 ms | 239 / 274 ms | 4.61 / 2.91 / 7.4 ms | 4.8 / 4.2 / 7.7 ms | 79.1 MiB |

## PQZH (Ligero, Rust; the proven preset)

| | proof bytes (max) | max_len_exact | prove p50 native / wasm32 | verify p50 / p99 native | verify p50 / p99 wasm32 | prove memory native heap / wasm32 linear | verifies native / wasm32 |
|---|---|---|---|---|---|---|---|
| `R_REG` | 187,098 | 190,458 | 423 / 814 ms | 7.56 / 8.55 ms | 11.68 / 13.41 ms | 25.9 / 28.6 MiB | 20 / 20 |
| `R_TX` | 231,416 | 235,470 | 666 / 1,331 ms | 9.87 / 10.01 ms | 17.04 / 17.23 ms | 43.2 / 46.4 MiB | 20 / 20 |
| `R_BURN` | 232,344 | 234,744 | 637 / 1,288 ms | 9.38 / 9.63 ms | 16.30 / 16.66 ms | 42.9 / 46.4 MiB | 20 / 20 |
| `R_DS` | 187,546 | 190,458 | 406 / 749 ms | 7.33 / 7.84 ms | 11.99 / 12.67 ms | 25.9 / 46.8 MiB | 20 / 20 |
| `R_DR` | 185,462 | 190,458 | 390 / 765 ms | 7.09 / 7.34 ms | 11.61 / 12.69 ms | 25.9 / 46.8 MiB | 20 / 20 |
| `R_TX0` | 231,320 | 234,744 | 696 / 1,468 ms | 9.37 / 9.49 ms | 16.51 / 17.09 ms | 42.9 / 48.1 MiB | 20 / 20 |

## pqz-ffi (one precompile, both systems)

Self-test hash: `ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205`.

| system | form | proof bytes | verify p50 / p99 through the C ABI | adversarial p50 |
|---|---|---|---|---|
| PQZL | Transfer | 42,759 | 7.91 / 8.09 ms | 8.16 ms |
| PQZL | Transfer0 | 42,387 | 7.80 / 8.01 ms | 7.76 ms |
| PQZL | Burn | 41,914 | 7.57 / 9.01 ms | 7.63 ms |
| PQZL | Refresh | 41,902 | 10.90 / 15.09 ms | 9.42 ms |
| PQZL | Register | 28,068 | 4.94 / 7.42 ms | 4.02 ms |
| PQZL | DiscloseSender | 28,964 | 4.27 / 4.99 ms | 4.19 ms |
| PQZL | DiscloseReceiver | 28,990 | 4.56 / 5.25 ms | 4.68 ms |
| PQZL | DiscloseAuditor | 28,995 | 4.57 / 4.98 ms | 4.70 ms |
| PQZH | Transfer | 231,022 | 10.16 / 11.96 ms | 1.26 ms |
| PQZH | Transfer0 | 231,064 | 9.72 / 10.25 ms | 1.24 ms |
| PQZH | Burn | 231,320 | 10.25 / 12.03 ms | 0.58 ms |
| PQZH | Refresh | 231,928 | 9.49 / 10.93 ms | 1.19 ms |
| PQZH | Register | 187,738 | 7.35 / 9.14 ms | 0.38 ms |
| PQZH | DiscloseSender | 186,842 | 7.56 / 7.74 ms | 0.42 ms |
| PQZH | DiscloseReceiver | 187,098 | 7.24 / 7.42 ms | 0.42 ms |
| PQZH | DiscloseAuditor | 186,778 | 7.25 / 7.86 ms | 0.41 ms |

## Against expected-results.json: 148 ok, 0 FAIL, 0 warn, 0 info

| status | check | detail |
|---|---|---|
| ok | kat | ok |
| ok | tbox_fixes | ok |
| ok | sv_fixes | ok |
| ok | diff-portable | 2972 cases, 0 mismatches, 0 other fails, PRG 0 |
| ok | native-generic.jsonl fails | fails 0, verifier disagreements 0 |
| ok | wasm-generic.jsonl fails | fails 0, verifier disagreements 0 |
| ok | native-fast.jsonl fails | fails 0, verifier disagreements 0 |
| ok | x86v3-fast.jsonl fails | fails 0, verifier disagreements 0 |
| ok | wasm-fast.jsonl fails | fails 0, verifier disagreements 0 |
| ok | wasm-both.jsonl fails | fails 0, verifier disagreements 0 |
| ok | alone-wasm-nosv.jsonl fails | fails 0, verifier disagreements 0 |
| ok | R_REG proofs_fnv native-generic.jsonl n=3 | e70b5dc4, expected e70b5dc4 |
| ok | R_REG proofs_fnv wasm-generic.jsonl n=3 | e70b5dc4, expected e70b5dc4 |
| ok | R_REG proofs_fnv native-fast.jsonl n=2 | 1af59837, expected 1af59837 |
| ok | R_REG proofs_fnv x86v3-fast.jsonl n=2 | 1af59837, expected 1af59837 |
| ok | R_REG proofs_fnv wasm-fast.jsonl n=2 | 1af59837, expected 1af59837 |
| ok | R_REG proofs_fnv wasm-both.jsonl n=2 | 1af59837, expected 1af59837 |
| ok | R_REG proofs_fnv alone-wasm-nosv.jsonl n=1 | 25074bbb, expected 25074bbb |
| ok | R_REG proof_bytes_max | 28113, frozen 28113 (0.00%, tol 0.5%) |
| ok | R_REG wasm_prove_peak_bytes | 73692688, frozen 73692688 (0.00%, tol 1.0%) |
| ok | R_REG ratio sv_speedup | 43.3, frozen 41.8 (4%, tol 50%; machine-dependent) |
| ok | R_REG ratio wasm_over_native_prove | 2.02, frozen 1.64 (23%, tol 50%; machine-dependent) |
| ok | R_TX proofs_fnv native-generic.jsonl n=3 | 9304299b, expected 9304299b |
| ok | R_TX proofs_fnv wasm-generic.jsonl n=3 | 9304299b, expected 9304299b |
| ok | R_TX proofs_fnv native-fast.jsonl n=2 | 559b3c44, expected 559b3c44 |
| ok | R_TX proofs_fnv x86v3-fast.jsonl n=2 | 559b3c44, expected 559b3c44 |
| ok | R_TX proofs_fnv wasm-fast.jsonl n=2 | 559b3c44, expected 559b3c44 |
| ok | R_TX proofs_fnv wasm-both.jsonl n=2 | 559b3c44, expected 559b3c44 |
| ok | R_TX proofs_fnv alone-wasm-nosv.jsonl n=1 | 008d4495, expected 008d4495 |
| ok | R_TX proof_bytes_max | 42780, frozen 42785 (0.01%, tol 0.5%) |
| ok | R_TX wasm_prove_peak_bytes | 231858048, frozen 231858048 (0.00%, tol 1.0%) |
| ok | R_TX ratio sv_speedup | 82.8, frozen 81.3 (2%, tol 50%; machine-dependent) |
| ok | R_TX ratio wasm_over_native_prove | 1.37, frozen 1.35 (1%, tol 50%; machine-dependent) |
| ok | R_BURN proofs_fnv native-generic.jsonl n=3 | 0ea1c7a6, expected 0ea1c7a6 |
| ok | R_BURN proofs_fnv wasm-generic.jsonl n=3 | 0ea1c7a6, expected 0ea1c7a6 |
| ok | R_BURN proofs_fnv native-fast.jsonl n=2 | 7694fd9f, expected 7694fd9f |
| ok | R_BURN proofs_fnv x86v3-fast.jsonl n=2 | 7694fd9f, expected 7694fd9f |
| ok | R_BURN proofs_fnv wasm-fast.jsonl n=2 | 7694fd9f, expected 7694fd9f |
| ok | R_BURN proofs_fnv wasm-both.jsonl n=2 | 7694fd9f, expected 7694fd9f |
| ok | R_BURN proofs_fnv alone-wasm-nosv.jsonl n=1 | ad3e8a12, expected ad3e8a12 |
| ok | R_BURN proof_bytes_max | 41935, frozen 41938 (0.01%, tol 0.5%) |
| ok | R_BURN wasm_prove_peak_bytes | 220431120, frozen 220431120 (0.00%, tol 1.0%) |
| ok | R_BURN ratio sv_speedup | 81.5, frozen 71.7 (14%, tol 50%; machine-dependent) |
| ok | R_BURN ratio wasm_over_native_prove | 1.33, frozen 1.32 (1%, tol 50%; machine-dependent) |
| ok | R_DS proofs_fnv native-generic.jsonl n=3 | f39a8e64, expected f39a8e64 |
| ok | R_DS proofs_fnv wasm-generic.jsonl n=3 | f39a8e64, expected f39a8e64 |
| ok | R_DS proofs_fnv native-fast.jsonl n=2 | 9eb44281, expected 9eb44281 |
| ok | R_DS proofs_fnv x86v3-fast.jsonl n=2 | 9eb44281, expected 9eb44281 |
| ok | R_DS proofs_fnv wasm-fast.jsonl n=2 | 9eb44281, expected 9eb44281 |
| ok | R_DS proofs_fnv wasm-both.jsonl n=2 | 9eb44281, expected 9eb44281 |
| ok | R_DS proofs_fnv alone-wasm-nosv.jsonl n=1 | 478a0d94, expected 478a0d94 |
| ok | R_DS proof_bytes_max | 28974, frozen 28995 (0.07%, tol 0.5%) |
| ok | R_DS wasm_prove_peak_bytes | 76888880, frozen 76888880 (0.00%, tol 1.0%) |
| ok | R_DS ratio sv_speedup | 62.7, frozen 45.2 (39%, tol 50%; machine-dependent) |
| ok | R_DS ratio wasm_over_native_prove | 1.65, frozen 1.95 (15%, tol 50%; machine-dependent) |
| ok | R_DR proofs_fnv native-generic.jsonl n=3 | 96a6e906, expected 96a6e906 |
| ok | R_DR proofs_fnv wasm-generic.jsonl n=3 | 96a6e906, expected 96a6e906 |
| ok | R_DR proofs_fnv native-fast.jsonl n=2 | 5bb0078c, expected 5bb0078c |
| ok | R_DR proofs_fnv x86v3-fast.jsonl n=2 | 5bb0078c, expected 5bb0078c |
| ok | R_DR proofs_fnv wasm-fast.jsonl n=2 | 5bb0078c, expected 5bb0078c |
| ok | R_DR proofs_fnv wasm-both.jsonl n=2 | 5bb0078c, expected 5bb0078c |
| ok | R_DR proofs_fnv alone-wasm-nosv.jsonl n=1 | cb2f3ced, expected cb2f3ced |
| ok | R_DR proof_bytes_max | 28994, frozen 28996 (0.01%, tol 0.5%) |
| ok | R_DR wasm_prove_peak_bytes | 82951488, frozen 82951488 (0.00%, tol 1.0%) |
| ok | R_DR ratio sv_speedup | 51.8, frozen 45.8 (13%, tol 50%; machine-dependent) |
| ok | R_DR ratio wasm_over_native_prove | 1.76, frozen 1.28 (38%, tol 50%; machine-dependent) |
| ok | pqzh-test.txt | rc 0 and its markers |
| ok | pqzh-nobench.txt | rc 0 and its markers |
| ok | pqzh-xcheck.txt | rc 0 and its markers |
| ok | stmt-xcheck.txt | rc 0 and its markers |
| ok | ffi-test.txt | rc 0 and its markers |
| ok | ffi-native.txt | rc 0 and its markers |
| ok | ffi-wasm-build.txt | rc 0 and its markers |
| ok | vectors-build.txt | rc 0 and its markers |
| ok | vectors-check.txt | rc 0 and its markers |
| ok | vectors-pqz-kat.txt | rc 0 and its markers |
| ok | PQZH pqzh-native.jsonl | fails 0, forms 6 / 6 |
| ok | PQZH pqzh-wasm.jsonl | fails 0, forms 6 / 6 |
| ok | PQZH R_REG fnv seed 0 pqzh-native.jsonl | 0ecf451a, expected 0ecf451a |
| ok | PQZH R_REG fnv seed 1 pqzh-native.jsonl | 36b1d3e5, expected 36b1d3e5 |
| ok | PQZH R_REG fnv seed 1 pqzh-wasm.jsonl | 36b1d3e5, expected 36b1d3e5 |
| ok | PQZH R_REG proof bytes seed 1 pqzh-native.jsonl | 186904, expected 186904 |
| ok | PQZH R_REG proof bytes seed 1 pqzh-wasm.jsonl | 186904, expected 186904 |
| ok | PQZH R_REG native = wasm32 seed 1 | 36b1d3e5 |
| ok | PQZH R_REG max_len_exact | 190458, expected 190458 |
| ok | PQZH R_REG proofs within the bound | max 187098 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_REG wasm32 memory <= 256 MiB | 28.5625 MiB |
| ok | PQZH R_REG ratio wasm_over_native_prove | 1.92, frozen 2.23 (14%, tol 50%; machine-dependent) |
| ok | PQZH R_REG ratio wasm_over_native_verify | 1.54, frozen 1.62 (5%, tol 50%; machine-dependent) |
| ok | PQZH R_TX fnv seed 0 pqzh-native.jsonl | 534b3a74, expected 534b3a74 |
| ok | PQZH R_TX fnv seed 1 pqzh-native.jsonl | 720b94e0, expected 720b94e0 |
| ok | PQZH R_TX fnv seed 1 pqzh-wasm.jsonl | 720b94e0, expected 720b94e0 |
| ok | PQZH R_TX proof bytes seed 1 pqzh-native.jsonl | 231416, expected 231416 |
| ok | PQZH R_TX proof bytes seed 1 pqzh-wasm.jsonl | 231416, expected 231416 |
| ok | PQZH R_TX native = wasm32 seed 1 | 720b94e0 |
| ok | PQZH R_TX max_len_exact | 235470, expected 235470 |
| ok | PQZH R_TX proofs within the bound | max 231416 <= max_len_exact 235470 = verifier bound 235470 |
| ok | PQZH R_TX wasm32 memory <= 256 MiB | 46.4375 MiB |
| ok | PQZH R_TX ratio wasm_over_native_prove | 2.0, frozen 2.02 (1%, tol 50%; machine-dependent) |
| ok | PQZH R_TX ratio wasm_over_native_verify | 1.73, frozen 1.76 (2%, tol 50%; machine-dependent) |
| ok | PQZH R_BURN fnv seed 0 pqzh-native.jsonl | f4fef37e, expected f4fef37e |
| ok | PQZH R_BURN fnv seed 1 pqzh-native.jsonl | e270d5c8, expected e270d5c8 |
| ok | PQZH R_BURN fnv seed 1 pqzh-wasm.jsonl | e270d5c8, expected e270d5c8 |
| ok | PQZH R_BURN proof bytes seed 1 pqzh-native.jsonl | 231256, expected 231256 |
| ok | PQZH R_BURN proof bytes seed 1 pqzh-wasm.jsonl | 231256, expected 231256 |
| ok | PQZH R_BURN native = wasm32 seed 1 | e270d5c8 |
| ok | PQZH R_BURN max_len_exact | 234744, expected 234744 |
| ok | PQZH R_BURN proofs within the bound | max 232344 <= max_len_exact 234744 = verifier bound 234744 |
| ok | PQZH R_BURN wasm32 memory <= 256 MiB | 46.4375 MiB |
| ok | PQZH R_BURN ratio wasm_over_native_prove | 2.02, frozen 2.06 (2%, tol 50%; machine-dependent) |
| ok | PQZH R_BURN ratio wasm_over_native_verify | 1.74, frozen 1.76 (1%, tol 50%; machine-dependent) |
| ok | PQZH R_DS fnv seed 0 pqzh-native.jsonl | 0a7acf34, expected 0a7acf34 |
| ok | PQZH R_DS fnv seed 1 pqzh-native.jsonl | 020286c2, expected 020286c2 |
| ok | PQZH R_DS fnv seed 1 pqzh-wasm.jsonl | 020286c2, expected 020286c2 |
| ok | PQZH R_DS proof bytes seed 1 pqzh-native.jsonl | 187482, expected 187482 |
| ok | PQZH R_DS proof bytes seed 1 pqzh-wasm.jsonl | 187482, expected 187482 |
| ok | PQZH R_DS native = wasm32 seed 1 | 020286c2 |
| ok | PQZH R_DS max_len_exact | 190458, expected 190458 |
| ok | PQZH R_DS proofs within the bound | max 187546 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_DS wasm32 memory <= 256 MiB | 46.75 MiB |
| ok | PQZH R_DS ratio wasm_over_native_prove | 1.84, frozen 2.0 (8%, tol 50%; machine-dependent) |
| ok | PQZH R_DS ratio wasm_over_native_verify | 1.63, frozen 1.64 (1%, tol 50%; machine-dependent) |
| ok | PQZH R_DR fnv seed 0 pqzh-native.jsonl | e42aa3da, expected e42aa3da |
| ok | PQZH R_DR fnv seed 1 pqzh-native.jsonl | c5f5fb23, expected c5f5fb23 |
| ok | PQZH R_DR fnv seed 1 pqzh-wasm.jsonl | c5f5fb23, expected c5f5fb23 |
| ok | PQZH R_DR proof bytes seed 1 pqzh-native.jsonl | 185462, expected 185462 |
| ok | PQZH R_DR proof bytes seed 1 pqzh-wasm.jsonl | 185462, expected 185462 |
| ok | PQZH R_DR native = wasm32 seed 1 | c5f5fb23 |
| ok | PQZH R_DR max_len_exact | 190458, expected 190458 |
| ok | PQZH R_DR proofs within the bound | max 185462 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_DR wasm32 memory <= 256 MiB | 46.75 MiB |
| ok | PQZH R_DR ratio wasm_over_native_prove | 1.96, frozen 2.13 (8%, tol 50%; machine-dependent) |
| ok | PQZH R_DR ratio wasm_over_native_verify | 1.64, frozen 1.61 (2%, tol 50%; machine-dependent) |
| ok | PQZH R_TX0 fnv seed 0 pqzh-native.jsonl | 360216a0, expected 360216a0 |
| ok | PQZH R_TX0 fnv seed 1 pqzh-native.jsonl | a69e9010, expected a69e9010 |
| ok | PQZH R_TX0 fnv seed 1 pqzh-wasm.jsonl | a69e9010, expected a69e9010 |
| ok | PQZH R_TX0 proof bytes seed 1 pqzh-native.jsonl | 231320, expected 231320 |
| ok | PQZH R_TX0 proof bytes seed 1 pqzh-wasm.jsonl | 231320, expected 231320 |
| ok | PQZH R_TX0 native = wasm32 seed 1 | a69e9010 |
| ok | PQZH R_TX0 max_len_exact | 234744, expected 234744 |
| ok | PQZH R_TX0 proofs within the bound | max 231320 <= max_len_exact 234744 = verifier bound 234744 |
| ok | PQZH R_TX0 wasm32 memory <= 256 MiB | 48.0625 MiB |
| ok | PQZH R_TX0 ratio wasm_over_native_prove | 2.11, frozen 2.15 (2%, tol 50%; machine-dependent) |
| ok | PQZH R_TX0 ratio wasm_over_native_verify | 1.76, frozen 1.77 (1%, tol 50%; machine-dependent) |
| ok | pqz-ffi selftest hash | ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205, expected ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205 |
| ok | pqz-ffi digest lines native = wasm32 | 17 / 17 lines |
| ok | pqz-ffi digest lines = frozen | 17 lines, 0 differ |
| ok | vectors wasm32 replay | 34 proofs, 34 byte-equal and valid, fails 0 |

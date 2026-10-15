# pqz-core reproducibility run (frozen run PROVISIONAL (2026-10-15): PQZL from rel3/runs/tx0c + sv/runs/tx0c (P6e Tasks 2 / 5 after the second review; six relations incl. R_TX0); PQZH from pqzh/ligero/runs/l15-tx0-proven (+ -wasm; p6e-b3 review fixes, d58e20a); pqz-ffi from ffi/runs/ffi1f2 (P6e Task 7, 072bec1). Replace with the reproduce.sh --full freeze run after P6e gates A / B)

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), Ubuntu 24.04.4 LTS, kernel 7.0.0-34-generic, Ubuntu clang version 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3, node v26.8.1, Python 3.12.3, rustc 1.97.1 (8bab26f4f 2026-07-14), in Docker: False.

Times are informational (they depend on the machine); the proof hashes, the checks and the sizes are compared.

## PQZL (the LaZer fork, C)

| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |
|---|---|---|---|---|---|---|
| `R_REG` | 28,113 | 295 / 484 ms | 161 / 223 ms | 3.85 / 2.37 / 6.6 ms | 4.5 / 3.1 / 7.7 ms | 70.3 MiB |
| `R_TX` | 42,785 | 965 / 1,304 ms | 648 / 762 ms | 7.98 / 4.76 / 13.4 ms | 8.7 / 5.4 / 14.8 ms | 221.1 MiB |
| `R_BURN` | 41,938 | 874 / 1,158 ms | 556 / 693 ms | 7.75 / 4.63 / 12.9 ms | 8.9 / 5.7 / 14.2 ms | 210.2 MiB |
| `R_DS` | 28,995 | 331 / 646 ms | 200 / 270 ms | 4.42 / 2.86 / 7.3 ms | 4.9 / 3.9 / 8.7 ms | 73.3 MiB |
| `R_DR` | 28,996 | 395 / 504 ms | 206 / 254 ms | 4.50 / 2.69 / 7.5 ms | 4.9 / 3.0 / 8.4 ms | 79.1 MiB |
| `R_TX0` | 42,441 | 827 / 1,398 ms | 577 / 760 ms | 8.03 / 4.68 / 13.4 ms | 8.8 / 5.5 / 14.7 ms | 216.7 MiB |

## PQZH (Ligero, Rust; the proven preset)

| | proof bytes (max) | max_len_exact | prove p50 native / wasm32 | verify p50 / p99 native | verify p50 / p99 wasm32 | prove memory native heap / wasm32 linear | verifies native / wasm32 |
|---|---|---|---|---|---|---|---|
| `R_REG` | 187,674 | 190,458 | 366 / 816 ms | 7.00 / 7.83 ms | 11.32 / 14.89 ms | 25.9 / 28.6 MiB | 1,000 / 1,000 |
| `R_TX` | 232,302 | 235,470 | 652 / 1,316 ms | 9.75 / 10.49 ms | 17.14 / 19.44 ms | 43.2 / 46.4 MiB | 1,000 / 1,000 |
| `R_BURN` | 232,632 | 234,744 | 629 / 1,294 ms | 9.23 / 10.63 ms | 16.25 / 20.76 ms | 42.9 / 46.4 MiB | 1,000 / 1,000 |
| `R_DS` | 187,802 | 190,458 | 376 / 752 ms | 7.34 / 8.16 ms | 12.04 / 13.71 ms | 25.9 / 46.8 MiB | 1,000 / 1,000 |
| `R_DR` | 187,226 | 190,458 | 358 / 765 ms | 7.18 / 8.33 ms | 11.53 / 14.31 ms | 25.9 / 46.8 MiB | 1,000 / 1,000 |
| `R_TX0` | 231,800 | 234,744 | 637 / 1,368 ms | 9.38 / 11.36 ms | 16.60 / 20.88 ms | 42.9 / 48.1 MiB | 1,000 / 1,000 |

## pqz-ffi (one precompile, both systems)

Self-test hash: `ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205`.

| system | form | proof bytes | verify p50 / p99 through the C ABI | adversarial p50 |
|---|---|---|---|---|
| PQZL | Transfer | 42,759 | 8.21 / 10.42 ms | 8.05 ms |
| PQZL | Transfer0 | 42,387 | 7.93 / 9.40 ms | 7.89 ms |
| PQZL | Burn | 41,914 | 7.81 / 10.13 ms | 7.82 ms |
| PQZL | Refresh | 41,902 | 7.68 / 8.64 ms | 7.68 ms |
| PQZL | Register | 28,068 | 4.05 / 5.01 ms | 3.99 ms |
| PQZL | DiscloseSender | 28,964 | 4.28 / 5.23 ms | 4.28 ms |
| PQZL | DiscloseReceiver | 28,990 | 4.50 / 5.14 ms | 4.55 ms |
| PQZL | DiscloseAuditor | 28,995 | 4.58 / 5.29 ms | 4.62 ms |
| PQZH | Transfer | 231,022 | 9.78 / 10.76 ms | 1.25 ms |
| PQZH | Transfer0 | 231,064 | 9.42 / 10.20 ms | 1.22 ms |
| PQZH | Burn | 231,320 | 9.25 / 9.87 ms | 0.57 ms |
| PQZH | Refresh | 231,928 | 9.27 / 9.53 ms | 1.18 ms |
| PQZH | Register | 187,738 | 7.00 / 9.22 ms | 0.37 ms |
| PQZH | DiscloseSender | 186,842 | 7.23 / 9.67 ms | 0.41 ms |
| PQZH | DiscloseReceiver | 187,098 | 7.12 / 7.81 ms | 0.41 ms |
| PQZH | DiscloseAuditor | 186,778 | 7.11 / 7.96 ms | 0.41 ms |

## Against expected-results.json: 101 ok, 0 FAIL, 0 warn, 50 info

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
| ok | R_TX0 proofs_fnv native-generic.jsonl n=10 | a2759b37, expected a2759b37 |
| ok | R_TX0 proofs_fnv wasm-generic.jsonl n=5 | a29a5747, expected a29a5747 |
| ok | R_TX0 proofs_fnv fnv-native.jsonl n=5 | a29a5747, expected a29a5747 |
| ok | R_TX0 proofs_fnv fnv-wasm.jsonl n=3 | a0afafc7, expected a0afafc7 |
| ok | R_TX0 proofs_fnv native-fast.jsonl n=2 | 8b99b979, expected 8b99b979 |
| ok | R_TX0 proofs_fnv x86v3-fast.jsonl n=2 | 8b99b979, expected 8b99b979 |
| ok | R_TX0 proofs_fnv wasm-fast.jsonl n=2 | 8b99b979, expected 8b99b979 |
| ok | R_TX0 proofs_fnv wasm-both.jsonl n=2 | 8b99b979, expected 8b99b979 |
| ok | R_TX0 proofs_fnv alone-wasm-nosv.jsonl n=1 | bfdc29df, expected bfdc29df |
| ok | R_TX0 proof_bytes_max | 42441, frozen 42441 (0.00%, tol 0.5%) |
| ok | R_TX0 wasm_prove_peak_bytes | 227275456, frozen 227275456 (0.00%, tol 1.0%) |
| ok | PQZH pqzh-native.jsonl | fails 0, forms 6 / 6 |
| ok | PQZH pqzh-wasm.jsonl | fails 0, forms 6 / 6 |
| info | PQZH R_REG fnv seed 0 pqzh-native.jsonl | 0ecf451a (no frozen value for seed 0) |
| info | PQZH R_REG fnv seed 1 pqzh-native.jsonl | 36b1d3e5 (no frozen value for seed 1) |
| info | PQZH R_REG fnv seed 2 pqzh-native.jsonl | bd7e088c (no frozen value for seed 2) |
| info | PQZH R_REG fnv seed 3 pqzh-native.jsonl | e1019551 (no frozen value for seed 3) |
| info | PQZH R_REG fnv seed 4 pqzh-native.jsonl | b6215ec2 (no frozen value for seed 4) |
| info | PQZH R_REG fnv seed 1 pqzh-wasm.jsonl | 36b1d3e5 (no frozen value for seed 1) |
| info | PQZH R_REG proof bytes seed 4 pqzh-native.jsonl | 186938 (no frozen value for seed 4) |
| info | PQZH R_REG proof bytes seed 1 pqzh-wasm.jsonl | 186904 (no frozen value for seed 1) |
| ok | PQZH R_REG native = wasm32 seed 1 | 36b1d3e5 |
| ok | PQZH R_REG proofs within the bound | max 187674 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_REG wasm32 memory <= 256 MiB | 28.5625 MiB |
| info | PQZH R_TX fnv seed 0 pqzh-native.jsonl | 534b3a74 (no frozen value for seed 0) |
| info | PQZH R_TX fnv seed 1 pqzh-native.jsonl | 720b94e0 (no frozen value for seed 1) |
| info | PQZH R_TX fnv seed 2 pqzh-native.jsonl | f5bb1d99 (no frozen value for seed 2) |
| info | PQZH R_TX fnv seed 3 pqzh-native.jsonl | b28db0b7 (no frozen value for seed 3) |
| info | PQZH R_TX fnv seed 4 pqzh-native.jsonl | f8c936d9 (no frozen value for seed 4) |
| info | PQZH R_TX fnv seed 1 pqzh-wasm.jsonl | 720b94e0 (no frozen value for seed 1) |
| info | PQZH R_TX proof bytes seed 4 pqzh-native.jsonl | 232302 (no frozen value for seed 4) |
| info | PQZH R_TX proof bytes seed 1 pqzh-wasm.jsonl | 231416 (no frozen value for seed 1) |
| ok | PQZH R_TX native = wasm32 seed 1 | 720b94e0 |
| ok | PQZH R_TX proofs within the bound | max 232302 <= max_len_exact 235470 = verifier bound 235470 |
| ok | PQZH R_TX wasm32 memory <= 256 MiB | 46.4375 MiB |
| info | PQZH R_BURN fnv seed 0 pqzh-native.jsonl | f4fef37e (no frozen value for seed 0) |
| info | PQZH R_BURN fnv seed 1 pqzh-native.jsonl | e270d5c8 (no frozen value for seed 1) |
| info | PQZH R_BURN fnv seed 2 pqzh-native.jsonl | 400f16e3 (no frozen value for seed 2) |
| info | PQZH R_BURN fnv seed 3 pqzh-native.jsonl | 37999f9a (no frozen value for seed 3) |
| info | PQZH R_BURN fnv seed 4 pqzh-native.jsonl | e6464eb5 (no frozen value for seed 4) |
| info | PQZH R_BURN fnv seed 1 pqzh-wasm.jsonl | e270d5c8 (no frozen value for seed 1) |
| info | PQZH R_BURN proof bytes seed 4 pqzh-native.jsonl | 231640 (no frozen value for seed 4) |
| info | PQZH R_BURN proof bytes seed 1 pqzh-wasm.jsonl | 231256 (no frozen value for seed 1) |
| ok | PQZH R_BURN native = wasm32 seed 1 | e270d5c8 |
| ok | PQZH R_BURN proofs within the bound | max 232632 <= max_len_exact 234744 = verifier bound 234744 |
| ok | PQZH R_BURN wasm32 memory <= 256 MiB | 46.4375 MiB |
| info | PQZH R_DS fnv seed 0 pqzh-native.jsonl | 0a7acf34 (no frozen value for seed 0) |
| info | PQZH R_DS fnv seed 1 pqzh-native.jsonl | 020286c2 (no frozen value for seed 1) |
| info | PQZH R_DS fnv seed 2 pqzh-native.jsonl | 59182207 (no frozen value for seed 2) |
| info | PQZH R_DS fnv seed 3 pqzh-native.jsonl | 0c0d5a95 (no frozen value for seed 3) |
| info | PQZH R_DS fnv seed 4 pqzh-native.jsonl | e62e8079 (no frozen value for seed 4) |
| info | PQZH R_DS fnv seed 1 pqzh-wasm.jsonl | 020286c2 (no frozen value for seed 1) |
| info | PQZH R_DS proof bytes seed 4 pqzh-native.jsonl | 187354 (no frozen value for seed 4) |
| info | PQZH R_DS proof bytes seed 1 pqzh-wasm.jsonl | 187482 (no frozen value for seed 1) |
| ok | PQZH R_DS native = wasm32 seed 1 | 020286c2 |
| ok | PQZH R_DS proofs within the bound | max 187802 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_DS wasm32 memory <= 256 MiB | 46.75 MiB |
| info | PQZH R_DR fnv seed 0 pqzh-native.jsonl | e42aa3da (no frozen value for seed 0) |
| info | PQZH R_DR fnv seed 1 pqzh-native.jsonl | c5f5fb23 (no frozen value for seed 1) |
| info | PQZH R_DR fnv seed 2 pqzh-native.jsonl | f8cd4b87 (no frozen value for seed 2) |
| info | PQZH R_DR fnv seed 3 pqzh-native.jsonl | caa4fc89 (no frozen value for seed 3) |
| info | PQZH R_DR fnv seed 4 pqzh-native.jsonl | d83e24fc (no frozen value for seed 4) |
| info | PQZH R_DR fnv seed 1 pqzh-wasm.jsonl | c5f5fb23 (no frozen value for seed 1) |
| info | PQZH R_DR proof bytes seed 4 pqzh-native.jsonl | 187066 (no frozen value for seed 4) |
| info | PQZH R_DR proof bytes seed 1 pqzh-wasm.jsonl | 185462 (no frozen value for seed 1) |
| ok | PQZH R_DR native = wasm32 seed 1 | c5f5fb23 |
| ok | PQZH R_DR proofs within the bound | max 187226 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_DR wasm32 memory <= 256 MiB | 46.75 MiB |
| info | PQZH R_TX0 fnv seed 0 pqzh-native.jsonl | 360216a0 (no frozen value for seed 0) |
| info | PQZH R_TX0 fnv seed 1 pqzh-native.jsonl | a69e9010 (no frozen value for seed 1) |
| info | PQZH R_TX0 fnv seed 2 pqzh-native.jsonl | 4820dd60 (no frozen value for seed 2) |
| info | PQZH R_TX0 fnv seed 3 pqzh-native.jsonl | 6db6d5aa (no frozen value for seed 3) |
| info | PQZH R_TX0 fnv seed 4 pqzh-native.jsonl | d1b4f175 (no frozen value for seed 4) |
| info | PQZH R_TX0 fnv seed 1 pqzh-wasm.jsonl | a69e9010 (no frozen value for seed 1) |
| info | PQZH R_TX0 proof bytes seed 4 pqzh-native.jsonl | 231800 (no frozen value for seed 4) |
| info | PQZH R_TX0 proof bytes seed 1 pqzh-wasm.jsonl | 231320 (no frozen value for seed 1) |
| ok | PQZH R_TX0 native = wasm32 seed 1 | a69e9010 |
| ok | PQZH R_TX0 proofs within the bound | max 231800 <= max_len_exact 234744 = verifier bound 234744 |
| ok | PQZH R_TX0 wasm32 memory <= 256 MiB | 48.0625 MiB |
| info | pqz-ffi selftest hash | ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205, expected None |
| ok | pqz-ffi digest lines native = wasm32 | 17 / 17 lines |
| info | pqz-ffi digest lines = frozen | 17 lines |

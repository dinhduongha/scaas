# pqz-core reproducibility run (quick)

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), Ubuntu 24.04.5 LTS, kernel 7.0.0-38-generic, Ubuntu clang version 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3, node v26.8.1, Python 3.12.3, rustc 1.97.1 (8bab26f4f 2026-07-14), in Docker: True.

Times are informational (they depend on the machine); the proof hashes, the checks and the sizes are compared.

## PQZL (the LaZer fork, C)

| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |
|---|---|---|---|---|---|---|
| `R_REG` | 30,376 | 304 / 656 ms | 209 / 371 ms | 4.29 / 2.60 / 7.3 ms | 4.5 / 2.7 / 7.7 ms | 86.2 MiB |
| `R_REG` Rust | 30,388 | 202 / 692 ms | 110 / 284 ms | – / – / – ms | – / – / – ms | – MiB |
| `R_TX` | 46,670 | 1,277 / 2,245 ms | 772 / 1,243 ms | 8.79 / 5.06 / 14.8 ms | 9.1 / 5.3 / 15.3 ms | 270.1 MiB |
| `R_TX` Rust | 46,673 | 665 / 2,150 ms | 359 / 792 ms | – / – / – ms | – / – / – ms | – MiB |
| `R_BURN` | 45,857 | 998 / 1,727 ms | 664 / 1,087 ms | 8.45 / 4.97 / 14.2 ms | 9.2 / 5.4 / 14.8 ms | 258.1 MiB |
| `R_BURN` Rust | 45,857 | 543 / 1,512 ms | 314 / 730 ms | – / – / – ms | – / – / – ms | – MiB |
| `R_DS` | 30,813 | 590 / 1,172 ms | 259 / 464 ms | 4.58 / 2.91 / 7.8 ms | 5.0 / 3.1 / 8.3 ms | 89.6 MiB |
| `R_DS` Rust | 30,813 | 293 / 1,392 ms | 130 / 331 ms | – / – / – ms | – / – / – ms | – MiB |
| `R_DR` | 31,552 | 903 / 2,102 ms | 249 / 423 ms | 4.82 / 3.08 / 8.1 ms | 5.0 / 3.3 / 8.6 ms | 95.5 MiB |
| `R_DR` Rust | 31,562 | 390 / 2,990 ms | 134 / 345 ms | – / – / – ms | – / – / – ms | – MiB |
| `R_TX0` | 46,346 | 1,308 / 2,590 ms | 782 / 1,166 ms | 8.76 / 5.18 / 14.8 ms | 9.2 / 5.5 / 15.7 ms | 265.3 MiB |
| `R_TX0` Rust | 46,346 | 682 / 2,884 ms | 351 / 771 ms | – / – / – ms | – / – / – ms | – MiB |

"Rust" rows: the Rust core (`pqzl/rust/`) in this run's "Rust = C" stage (bench 5 5 63 native, 3 1 63 wasm32; --full also verify_fast), on the same machine as the C rows but with other sample sizes.

## PQZH (Ligero, Rust; the proven preset)

| | proof bytes (max) | max_len_exact | prove p50 native / wasm32 | verify p50 / p99 native | verify p50 / p99 wasm32 | prove memory native heap / wasm32 linear | verifies native / wasm32 |
|---|---|---|---|---|---|---|---|
| `R_REG` | 186,810 | 190,458 | 377 / 851 ms | 6.77 / 6.92 ms | 13.53 / 13.69 ms | 25.9 / 29.1 MiB | 20 / 20 |
| `R_TX` | 232,334 | 235,470 | 677 / 1,512 ms | 9.85 / 9.93 ms | 20.97 / 21.27 ms | 43.2 / 46.9 MiB | 20 / 20 |
| `R_BURN` | 231,512 | 234,744 | 638 / 1,437 ms | 9.27 / 9.52 ms | 19.61 / 20.89 ms | 42.9 / 46.9 MiB | 20 / 20 |
| `R_DS` | 186,744 | 190,458 | 366 / 818 ms | 7.04 / 7.12 ms | 14.22 / 14.28 ms | 25.9 / 47.2 MiB | 20 / 20 |
| `R_DR` | 187,866 | 190,458 | 398 / 851 ms | 6.89 / 7.11 ms | 13.75 / 13.91 ms | 25.9 / 47.2 MiB | 20 / 20 |
| `R_TX0` | 231,896 | 234,744 | 620 / 1,411 ms | 9.51 / 9.61 ms | 20.01 / 20.34 ms | 42.9 / 48.6 MiB | 20 / 20 |

## pqz-ffi (one precompile, both systems)

Self-test hash: `d6c01fbcda23be8d8dc72d0b245be63713bd37a5ffa58c4093b39c83d6c4f68d`.

| system | form | proof bytes | verify p50 / p99 through the C ABI | adversarial p50 |
|---|---|---|---|---|
| PQZL | Transfer | 46,670 | 11.13 / 14.39 ms | 11.25 ms |
| PQZL | Transfer0 | 46,304 | 10.95 / 11.38 ms | 11.01 ms |
| PQZL | Burn | 45,842 | 10.73 / 11.32 ms | 11.02 ms |
| PQZL | Refresh | 45,842 | 10.77 / 11.45 ms | 11.00 ms |
| PQZL | Register | 30,372 | 5.96 / 7.20 ms | 6.14 ms |
| PQZL | DiscloseSender | 30,784 | 6.47 / 6.76 ms | 6.50 ms |
| PQZL | DiscloseReceiver | 31,570 | 6.51 / 6.72 ms | 6.54 ms |
| PQZL | DiscloseAuditor | 31,542 | 6.56 / 6.95 ms | 6.63 ms |
| PQZL | TransferMulti1 | 46,674 | 13.00 / 15.02 ms | 11.44 ms |
| PQZL | TransferMulti2 | 47,508 | 12.14 / 17.55 ms | 12.45 ms |
| PQZL | TransferMulti4 | 63,874 | 16.71 / 17.24 ms | 16.78 ms |
| PQZL | TransferMulti8 | 80,264 | 13.71 / 14.39 ms | 13.74 ms |
| PQZL | TransferMulti1_0 | 46,327 | 6.82 / 6.88 ms | 6.82 ms |
| PQZL | TransferMulti2_0 | 46,848 | 6.94 / 7.19 ms | 6.88 ms |
| PQZL | TransferMulti4_0 | 47,881 | 7.29 / 7.47 ms | 7.27 ms |
| PQZL | TransferMulti8_0 | 64,588 | 10.44 / 10.70 ms | 10.48 ms |
| PQZH | Transfer | 248,856 | 10.98 / 11.10 ms | 1.31 ms |
| PQZH | Transfer0 | 248,728 | 10.81 / 12.26 ms | 1.27 ms |
| PQZH | Burn | 247,496 | 10.52 / 10.65 ms | 1.21 ms |
| PQZH | Refresh | 248,824 | 10.66 / 10.76 ms | 1.23 ms |
| PQZH | Register | 204,552 | 7.79 / 7.87 ms | 0.39 ms |
| PQZH | DiscloseSender | 203,430 | 8.13 / 8.46 ms | 0.44 ms |
| PQZH | DiscloseReceiver | 203,846 | 7.93 / 8.05 ms | 0.44 ms |
| PQZH | DiscloseAuditor | 204,776 | 8.10 / 8.70 ms | 0.44 ms |
| PQZH | TransferMulti1 | 248,824 | 11.11 / 13.88 ms | 1.31 ms |
| PQZH | TransferMulti2 | 249,096 | 11.55 / 12.04 ms | 1.36 ms |
| PQZH | TransferMulti4 | 292,664 | 14.45 / 14.62 ms | 1.66 ms |
| PQZH | TransferMulti1_0 | 247,992 | 10.78 / 10.86 ms | 1.26 ms |
| PQZH | TransferMulti2_0 | 248,408 | 10.97 / 11.07 ms | 1.32 ms |
| PQZH | TransferMulti4_0 | 248,936 | 11.58 / 11.70 ms | 1.40 ms |

## Against expected-results.json: 106 ok, 137 FAIL, 1 warn, 8 info

| status | check | detail |
|---|---|---|
| FAIL | kat | FAIL |
| ok | tbox_fixes | ok |
| ok | sv_fixes | ok |
| ok | diff-portable | 3484 cases, 0 mismatches, 0 other fails, PRG 0 |
| ok | native-generic.jsonl fails | fails 0, verifier disagreements 0 |
| ok | wasm-generic.jsonl fails | fails 0, verifier disagreements 0 |
| ok | native-fast.jsonl fails | fails 0, verifier disagreements 0 |
| ok | x86v3-fast.jsonl fails | fails 0, verifier disagreements 0 |
| ok | wasm-fast.jsonl fails | fails 0, verifier disagreements 0 |
| ok | wasm-both.jsonl fails | fails 0, verifier disagreements 0 |
| ok | alone-wasm-nosv.jsonl fails | fails 0, verifier disagreements 0 |
| FAIL | R_REG proofs_fnv native-generic.jsonl n=3 | 03527227, expected e70b5dc4 |
| FAIL | R_REG proofs_fnv wasm-generic.jsonl n=3 | 03527227, expected e70b5dc4 |
| FAIL | R_REG proofs_fnv native-fast.jsonl n=2 | 60d64ae3, expected 1af59837 |
| FAIL | R_REG proofs_fnv x86v3-fast.jsonl n=2 | 60d64ae3, expected 1af59837 |
| FAIL | R_REG proofs_fnv wasm-fast.jsonl n=2 | 60d64ae3, expected 1af59837 |
| FAIL | R_REG proofs_fnv wasm-both.jsonl n=2 | 60d64ae3, expected 1af59837 |
| FAIL | R_REG proofs_fnv alone-wasm-nosv.jsonl n=1 | 5983527c, expected 25074bbb |
| FAIL | R_REG proof_bytes_max | 30376, frozen 28113 (8.05%, tol 0.5%) |
| FAIL | R_REG wasm_prove_peak_bytes | 90407712, frozen 73692688 (22.68%, tol 1.0%) |
| ok | R_REG ratio sv_speedup | 48.9, frozen 40.8 (20%, tol 50%; machine-dependent) |
| ok | R_REG ratio wasm_over_native_prove | 2.16, frozen 1.75 (23%, tol 50%; machine-dependent) |
| FAIL | R_TX proofs_fnv native-generic.jsonl n=3 | 630ceb5e, expected 9304299b |
| FAIL | R_TX proofs_fnv wasm-generic.jsonl n=3 | 630ceb5e, expected 9304299b |
| FAIL | R_TX proofs_fnv native-fast.jsonl n=2 | 242af686, expected 559b3c44 |
| FAIL | R_TX proofs_fnv x86v3-fast.jsonl n=2 | 242af686, expected 559b3c44 |
| FAIL | R_TX proofs_fnv wasm-fast.jsonl n=2 | 242af686, expected 559b3c44 |
| FAIL | R_TX proofs_fnv wasm-both.jsonl n=2 | 242af686, expected 559b3c44 |
| FAIL | R_TX proofs_fnv alone-wasm-nosv.jsonl n=1 | ab9867c3, expected 008d4495 |
| FAIL | R_TX proof_bytes_max | 46670, frozen 42785 (9.08%, tol 0.5%) |
| FAIL | R_TX wasm_prove_peak_bytes | 283239328, frozen 231858048 (22.16%, tol 1.0%) |
| ok | R_TX ratio sv_speedup | 87.9, frozen 78.7 (12%, tol 50%; machine-dependent) |
| ok | R_TX ratio wasm_over_native_prove | 1.76, frozen 1.4 (26%, tol 50%; machine-dependent) |
| FAIL | R_BURN proofs_fnv native-generic.jsonl n=3 | dc058b31, expected 0ea1c7a6 |
| FAIL | R_BURN proofs_fnv wasm-generic.jsonl n=3 | dc058b31, expected 0ea1c7a6 |
| FAIL | R_BURN proofs_fnv native-fast.jsonl n=2 | 2f3c4d9c, expected 7694fd9f |
| FAIL | R_BURN proofs_fnv x86v3-fast.jsonl n=2 | 2f3c4d9c, expected 7694fd9f |
| FAIL | R_BURN proofs_fnv wasm-fast.jsonl n=2 | 2f3c4d9c, expected 7694fd9f |
| FAIL | R_BURN proofs_fnv wasm-both.jsonl n=2 | 2f3c4d9c, expected 7694fd9f |
| FAIL | R_BURN proofs_fnv alone-wasm-nosv.jsonl n=1 | 8da2f946, expected ad3e8a12 |
| FAIL | R_BURN proof_bytes_max | 45857, frozen 41938 (9.34%, tol 0.5%) |
| FAIL | R_BURN wasm_prove_peak_bytes | 270671168, frozen 220429488 (22.79%, tol 1.0%) |
| ok | R_BURN ratio sv_speedup | 78.6, frozen 79.7 (1%, tol 50%; machine-dependent) |
| ok | R_BURN ratio wasm_over_native_prove | 1.73, frozen 1.47 (18%, tol 50%; machine-dependent) |
| FAIL | R_DS proofs_fnv native-generic.jsonl n=3 | a220f40a, expected f39a8e64 |
| FAIL | R_DS proofs_fnv wasm-generic.jsonl n=3 | a220f40a, expected f39a8e64 |
| FAIL | R_DS proofs_fnv native-fast.jsonl n=2 | cb5a80a3, expected 9eb44281 |
| FAIL | R_DS proofs_fnv x86v3-fast.jsonl n=2 | cb5a80a3, expected 9eb44281 |
| FAIL | R_DS proofs_fnv wasm-fast.jsonl n=2 | cb5a80a3, expected 9eb44281 |
| FAIL | R_DS proofs_fnv wasm-both.jsonl n=2 | cb5a80a3, expected 9eb44281 |
| FAIL | R_DS proofs_fnv alone-wasm-nosv.jsonl n=1 | 5a4ca497, expected 478a0d94 |
| FAIL | R_DS proof_bytes_max | 30813, frozen 28995 (6.27%, tol 0.5%) |
| FAIL | R_DS wasm_prove_peak_bytes | 93937472, frozen 76888880 (22.17%, tol 1.0%) |
| ok | R_DS ratio sv_speedup | 56.5, frozen 54.0 (5%, tol 50%; machine-dependent) |
| ok | R_DS ratio wasm_over_native_prove | 1.99, frozen 1.58 (26%, tol 50%; machine-dependent) |
| FAIL | R_DR proofs_fnv native-generic.jsonl n=3 | 31a05c99, expected 96a6e906 |
| FAIL | R_DR proofs_fnv wasm-generic.jsonl n=3 | 31a05c99, expected 96a6e906 |
| FAIL | R_DR proofs_fnv native-fast.jsonl n=2 | 61c33a97, expected 5bb0078c |
| FAIL | R_DR proofs_fnv x86v3-fast.jsonl n=2 | 61c33a97, expected 5bb0078c |
| FAIL | R_DR proofs_fnv wasm-fast.jsonl n=2 | 61c33a97, expected 5bb0078c |
| FAIL | R_DR proofs_fnv wasm-both.jsonl n=2 | 61c33a97, expected 5bb0078c |
| FAIL | R_DR proofs_fnv alone-wasm-nosv.jsonl n=1 | 569048d7, expected cb2f3ced |
| FAIL | R_DR proof_bytes_max | 31552, frozen 28996 (8.82%, tol 0.5%) |
| FAIL | R_DR wasm_prove_peak_bytes | 100174000, frozen 82951488 (20.76%, tol 1.0%) |
| ok | R_DR ratio sv_speedup | 51.6, frozen 52.5 (2%, tol 50%; machine-dependent) |
| warn | R_DR ratio wasm_over_native_prove | 2.33, frozen 1.11 (110%, tol 50%; machine-dependent) |
| FAIL | R_TX0 proofs_fnv native-generic.jsonl n=3 | 962ff0c7, expected a0afafc7 |
| FAIL | R_TX0 proofs_fnv wasm-generic.jsonl n=3 | 962ff0c7, expected a0afafc7 |
| FAIL | R_TX0 proofs_fnv native-fast.jsonl n=2 | 453f2835, expected 8b99b979 |
| FAIL | R_TX0 proofs_fnv x86v3-fast.jsonl n=2 | 453f2835, expected 8b99b979 |
| FAIL | R_TX0 proofs_fnv wasm-fast.jsonl n=2 | 453f2835, expected 8b99b979 |
| FAIL | R_TX0 proofs_fnv wasm-both.jsonl n=2 | 453f2835, expected 8b99b979 |
| FAIL | R_TX0 proofs_fnv alone-wasm-nosv.jsonl n=1 | a090b8b0, expected bfdc29df |
| FAIL | R_TX0 proof_bytes_max | 46346, frozen 42441 (9.20%, tol 0.5%) |
| FAIL | R_TX0 wasm_prove_peak_bytes | 278193712, frozen 227275456 (22.40%, tol 1.0%) |
| ok | R_TX0 ratio sv_speedup | 89.3, frozen 90.6 (1%, tol 50%; machine-dependent) |
| ok | R_TX0 ratio wasm_over_native_prove | 1.98, frozen 1.38 (43%, tol 50%; machine-dependent) |
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
| ok | rust-build.txt | rc 0 and its markers |
| ok | rust-keys-pqz-kat.txt | rc 0 and its markers |
| ok | PQZH pqzh-native.jsonl | fails 0, forms 6 / 6 |
| ok | PQZH pqzh-wasm.jsonl | fails 0, forms 6 / 6 |
| FAIL | PQZH R_REG fnv seed 0 pqzh-native.jsonl | 11bc45ad, expected 0ecf451a |
| FAIL | PQZH R_REG fnv seed 1 pqzh-native.jsonl | c775e64c, expected 36b1d3e5 |
| FAIL | PQZH R_REG fnv seed 1 pqzh-wasm.jsonl | c775e64c, expected 36b1d3e5 |
| FAIL | PQZH R_REG proof bytes seed 1 pqzh-native.jsonl | 186810, expected 186904 |
| FAIL | PQZH R_REG proof bytes seed 1 pqzh-wasm.jsonl | 186810, expected 186904 |
| ok | PQZH R_REG native = wasm32 seed 1 | c775e64c |
| ok | PQZH R_REG max_len_exact | 190458, expected 190458 |
| ok | PQZH R_REG proofs within the bound | max 186810 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_REG wasm32 memory <= 256 MiB | 29.125 MiB |
| ok | PQZH R_REG ratio wasm_over_native_prove | 2.26, frozen 2.23 (1%, tol 50%; machine-dependent) |
| ok | PQZH R_REG ratio wasm_over_native_verify | 2.0, frozen 1.7 (18%, tol 50%; machine-dependent) |
| FAIL | PQZH R_TX fnv seed 0 pqzh-native.jsonl | 36954e01, expected 534b3a74 |
| FAIL | PQZH R_TX fnv seed 1 pqzh-native.jsonl | bf065344, expected 720b94e0 |
| FAIL | PQZH R_TX fnv seed 1 pqzh-wasm.jsonl | bf065344, expected 720b94e0 |
| FAIL | PQZH R_TX proof bytes seed 1 pqzh-native.jsonl | 232334, expected 231416 |
| FAIL | PQZH R_TX proof bytes seed 1 pqzh-wasm.jsonl | 232334, expected 231416 |
| ok | PQZH R_TX native = wasm32 seed 1 | bf065344 |
| ok | PQZH R_TX max_len_exact | 235470, expected 235470 |
| ok | PQZH R_TX proofs within the bound | max 232334 <= max_len_exact 235470 = verifier bound 235470 |
| ok | PQZH R_TX wasm32 memory <= 256 MiB | 46.9375 MiB |
| ok | PQZH R_TX ratio wasm_over_native_prove | 2.23, frozen 2.08 (7%, tol 50%; machine-dependent) |
| ok | PQZH R_TX ratio wasm_over_native_verify | 2.13, frozen 1.81 (18%, tol 50%; machine-dependent) |
| FAIL | PQZH R_BURN fnv seed 0 pqzh-native.jsonl | 73f201e9, expected f4fef37e |
| FAIL | PQZH R_BURN fnv seed 1 pqzh-native.jsonl | 68cddb3c, expected e270d5c8 |
| FAIL | PQZH R_BURN fnv seed 1 pqzh-wasm.jsonl | 68cddb3c, expected e270d5c8 |
| FAIL | PQZH R_BURN proof bytes seed 1 pqzh-native.jsonl | 230536, expected 231256 |
| FAIL | PQZH R_BURN proof bytes seed 1 pqzh-wasm.jsonl | 230536, expected 231256 |
| ok | PQZH R_BURN native = wasm32 seed 1 | 68cddb3c |
| ok | PQZH R_BURN max_len_exact | 234744, expected 234744 |
| ok | PQZH R_BURN proofs within the bound | max 231512 <= max_len_exact 234744 = verifier bound 234744 |
| ok | PQZH R_BURN wasm32 memory <= 256 MiB | 46.9375 MiB |
| ok | PQZH R_BURN ratio wasm_over_native_prove | 2.25, frozen 2.08 (8%, tol 50%; machine-dependent) |
| ok | PQZH R_BURN ratio wasm_over_native_verify | 2.12, frozen 1.84 (15%, tol 50%; machine-dependent) |
| FAIL | PQZH R_DS fnv seed 0 pqzh-native.jsonl | c94debf2, expected 0a7acf34 |
| FAIL | PQZH R_DS fnv seed 1 pqzh-native.jsonl | 5797a517, expected 020286c2 |
| FAIL | PQZH R_DS fnv seed 1 pqzh-wasm.jsonl | 5797a517, expected 020286c2 |
| FAIL | PQZH R_DS proof bytes seed 1 pqzh-native.jsonl | 186744, expected 187482 |
| FAIL | PQZH R_DS proof bytes seed 1 pqzh-wasm.jsonl | 186744, expected 187482 |
| ok | PQZH R_DS native = wasm32 seed 1 | 5797a517 |
| ok | PQZH R_DS max_len_exact | 190458, expected 190458 |
| ok | PQZH R_DS proofs within the bound | max 186744 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_DS wasm32 memory <= 256 MiB | 47.25 MiB |
| ok | PQZH R_DS ratio wasm_over_native_prove | 2.24, frozen 1.91 (17%, tol 50%; machine-dependent) |
| ok | PQZH R_DS ratio wasm_over_native_verify | 2.02, frozen 1.63 (24%, tol 50%; machine-dependent) |
| FAIL | PQZH R_DR fnv seed 0 pqzh-native.jsonl | 37ca37ce, expected e42aa3da |
| FAIL | PQZH R_DR fnv seed 1 pqzh-native.jsonl | dca26488, expected c5f5fb23 |
| FAIL | PQZH R_DR fnv seed 1 pqzh-wasm.jsonl | dca26488, expected c5f5fb23 |
| FAIL | PQZH R_DR proof bytes seed 1 pqzh-native.jsonl | 186584, expected 185462 |
| FAIL | PQZH R_DR proof bytes seed 1 pqzh-wasm.jsonl | 186584, expected 185462 |
| ok | PQZH R_DR native = wasm32 seed 1 | dca26488 |
| ok | PQZH R_DR max_len_exact | 190458, expected 190458 |
| ok | PQZH R_DR proofs within the bound | max 187866 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_DR wasm32 memory <= 256 MiB | 47.25 MiB |
| ok | PQZH R_DR ratio wasm_over_native_prove | 2.14, frozen 1.99 (8%, tol 50%; machine-dependent) |
| ok | PQZH R_DR ratio wasm_over_native_verify | 2.0, frozen 1.68 (19%, tol 50%; machine-dependent) |
| FAIL | PQZH R_TX0 fnv seed 0 pqzh-native.jsonl | 199e0a34, expected 360216a0 |
| FAIL | PQZH R_TX0 fnv seed 1 pqzh-native.jsonl | c5531c9d, expected a69e9010 |
| FAIL | PQZH R_TX0 fnv seed 1 pqzh-wasm.jsonl | c5531c9d, expected a69e9010 |
| FAIL | PQZH R_TX0 proof bytes seed 1 pqzh-native.jsonl | 231896, expected 231320 |
| FAIL | PQZH R_TX0 proof bytes seed 1 pqzh-wasm.jsonl | 231896, expected 231320 |
| ok | PQZH R_TX0 native = wasm32 seed 1 | c5531c9d |
| ok | PQZH R_TX0 max_len_exact | 234744, expected 234744 |
| ok | PQZH R_TX0 proofs within the bound | max 231896 <= max_len_exact 234744 = verifier bound 234744 |
| ok | PQZH R_TX0 wasm32 memory <= 256 MiB | 48.625 MiB |
| ok | PQZH R_TX0 ratio wasm_over_native_prove | 2.27, frozen 2.39 (5%, tol 50%; machine-dependent) |
| ok | PQZH R_TX0 ratio wasm_over_native_verify | 2.1, frozen 1.79 (17%, tol 50%; machine-dependent) |
| FAIL | pqz-ffi selftest hash | d6c01fbcda23be8d8dc72d0b245be63713bd37a5ffa58c4093b39c83d6c4f68d, expected ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205 |
| ok | pqz-ffi digest lines native = wasm32 | 29 / 29 lines |
| FAIL | pqz-ffi digest lines = frozen | 29 lines, 29 differ |
| ok | vectors wasm32 replay | 61 proofs, 61 byte-equal and valid, 0 native PQZL op 7 M > 4 proofs valid (verify only), fails 0 |
| FAIL | op 7 pqzh M1-off native | proof 246984 B, ...01 through pqz_precompile, expected 232248 B |
| ok | op 7 pqzh M1-off wasm32 | 246984 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzh M1-on native | proof 249400 B, ...01 through pqz_precompile, expected 232494 B |
| ok | op 7 pqzh M1-on wasm32 | 249400 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzh M2-off native | proof 248440 B, ...01 through pqz_precompile, expected 232078 B |
| ok | op 7 pqzh M2-off wasm32 | 248440 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzh M2-off-two-real native | proof 248152 B, ...01 through pqz_precompile, expected 231640 B |
| ok | op 7 pqzh M2-off-two-real wasm32 | 248152 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzh M2-on native | proof 248872 B, ...01 through pqz_precompile, expected 231256 B |
| ok | op 7 pqzh M2-on wasm32 | 248872 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzh M4-off native | proof 249512 B, ...01 through pqz_precompile, expected 232494 B |
| ok | op 7 pqzh M4-off wasm32 | 249512 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzh M4-off-decoys native | proof 248872 B, ...01 through pqz_precompile, expected 231726 B |
| ok | op 7 pqzh M4-off-decoys wasm32 | 248872 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzh M4-on native | proof 293112 B, ...01 through pqz_precompile, expected 232708 B |
| ok | op 7 pqzh M4-on wasm32 | 293112 B, proved again, byte-equal, precompile 1 |
| info | op 7 pqzh M4-on-leg2-auditor native | proof 204680 B, ...01 through pqz_precompile (no frozen value) |
| FAIL | op 7 pqzh M4-on-leg2-auditor wasm32 | not replayed |
| info | op 7 pqzh M8-on-boundary-leg5-auditor native | proof 204584 B, ...01 through pqz_precompile (no frozen value) |
| FAIL | op 7 pqzh M8-on-boundary-leg5-auditor wasm32 | not replayed |
| info | op 7 pqzh M8-on-boundary-leg6-auditor native | proof 204840 B, ...01 through pqz_precompile (no frozen value) |
| FAIL | op 7 pqzh M8-on-boundary-leg6-auditor wasm32 | not replayed |
| info | op 7 pqzh M8-on-boundary-leg6-receiver native | proof 205640 B, ...01 through pqz_precompile (no frozen value) |
| FAIL | op 7 pqzh M8-on-boundary-leg6-receiver wasm32 | not replayed |
| FAIL | op 7 pqzl M1-off native | proof 46342 B, ...01 through pqz_precompile, expected 42426 B |
| ok | op 7 pqzl M1-off wasm32 | 46342 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzl M1-on native | proof 46678 B, ...01 through pqz_precompile, expected 42716 B |
| ok | op 7 pqzl M1-on wasm32 | 46678 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzl M2-off native | proof 46857 B, ...01 through pqz_precompile, expected 42919 B |
| ok | op 7 pqzl M2-off wasm32 | 46857 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzl M2-off-two-real native | proof 46802 B, ...01 through pqz_precompile, expected 42923 B |
| ok | op 7 pqzl M2-off-two-real wasm32 | 46802 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzl M2-on native | proof 47503 B, ...01 through pqz_precompile, expected 43604 B |
| ok | op 7 pqzl M2-on wasm32 | 47503 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzl M4-off native | proof 47821 B, ...01 through pqz_precompile, expected 43932 B |
| ok | op 7 pqzl M4-off wasm32 | 47821 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzl M4-off-decoys native | proof 47801 B, ...01 through pqz_precompile, expected 43917 B |
| ok | op 7 pqzl M4-off-decoys wasm32 | 47801 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzl M4-on native | proof 63885 B, ...01 through pqz_precompile, expected 45275 B |
| ok | op 7 pqzl M4-on wasm32 | 63885 B, proved again, byte-equal, precompile 1 |
| info | op 7 pqzl M4-on-leg2-auditor native | proof 31547 B, ...01 through pqz_precompile (no frozen value) |
| FAIL | op 7 pqzl M4-on-leg2-auditor wasm32 | not replayed |
| FAIL | op 7 pqzl M8-off native | proof 64607 B, ...01 through pqz_precompile, expected 58975 B |
| ok | op 7 pqzl M8-off wasm32 | 64607 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzl M8-on native | proof 80290 B, ...01 through pqz_precompile, expected 61794 B |
| ok | op 7 pqzl M8-on wasm32 | 80290 B, proved again, byte-equal, precompile 1 |
| FAIL | op 7 pqzl M8-on-boundary native | proof 80288 B, ...01 through pqz_precompile, expected 61795 B |
| ok | op 7 pqzl M8-on-boundary wasm32 | 80288 B, proved again, byte-equal, precompile 1 |
| info | op 7 pqzl M8-on-boundary-leg5-auditor native | proof 31571 B, ...01 through pqz_precompile (no frozen value) |
| FAIL | op 7 pqzl M8-on-boundary-leg5-auditor wasm32 | not replayed |
| info | op 7 pqzl M8-on-boundary-leg6-auditor native | proof 31543 B, ...01 through pqz_precompile (no frozen value) |
| FAIL | op 7 pqzl M8-on-boundary-leg6-auditor wasm32 | not replayed |
| info | op 7 pqzl M8-on-boundary-leg6-receiver native | proof 31551 B, ...01 through pqz_precompile (no frozen value) |
| FAIL | op 7 pqzl M8-on-boundary-leg6-receiver wasm32 | not replayed |
| FAIL | op 7 pqzl negatives | 198 rows of negative.json, 198 expect 0 / revert, replayed by pqz-vectors --check (same negative.json), expected 177 rows |
| FAIL | op 7 pqzh negatives | 177 rows of negative.json, 177 expect 0 / revert, replayed by pqz-vectors --check (same negative.json), expected 165 rows |
| ok | Rust rust-fnv-native.jsonl present | reproduce.sh quick |
| ok | Rust rust-fnv-wasm.jsonl present | reproduce.sh quick |
| ok | Rust rust-fnv-txm.jsonl present | reproduce.sh quick |
| ok | Rust rust-keys-kat.jsonl present | reproduce.sh quick |
| ok | Rust rust-build.txt present | reproduce.sh quick |
| ok | Rust rust-keys-pqz-kat.txt present | reproduce.sh quick |
| ok | expected-results.json rust.txm_fnv present | the C values the Rust core is checked against |
| ok | expected-results.json rust.keys_kat present | the C values the Rust core is checked against |
| ok | Rust rust-fnv-native.jsonl fails | fails 0, verifier disagreements 0, last rc= line 0 |
| ok | Rust rust-fnv-wasm.jsonl fails | fails 0, verifier disagreements 0, last rc= line 0 |
| ok | Rust rust-fnv-txm.jsonl fails | fails 0, verifier disagreements 0, last rc= line 0 |
| ok | Rust rust-fnv-native.jsonl relations | 6 relations at n=5 |
| ok | Rust rust-fnv-wasm.jsonl relations | 6 relations at n=3 |
| ok | Rust rust-fnv-txm.jsonl relations | 8 relations at n=2 |
| FAIL | Rust R_REG proofs_fnv rust-fnv-native.jsonl n=5 | 54eec2a7, C core 8bd69f2d |
| FAIL | Rust R_REG proofs_fnv rust-fnv-wasm.jsonl n=3 | 03527227, C core e70b5dc4 |
| FAIL | Rust R_TX proofs_fnv rust-fnv-native.jsonl n=5 | f0858eff, C core b9bbf854 |
| FAIL | Rust R_TX proofs_fnv rust-fnv-wasm.jsonl n=3 | 630ceb5e, C core 9304299b |
| FAIL | Rust R_BURN proofs_fnv rust-fnv-native.jsonl n=5 | 879bb5fe, C core 0a5976da |
| FAIL | Rust R_BURN proofs_fnv rust-fnv-wasm.jsonl n=3 | dc058b31, C core 0ea1c7a6 |
| FAIL | Rust R_DS proofs_fnv rust-fnv-native.jsonl n=5 | c655a73a, C core b4aa2e26 |
| FAIL | Rust R_DS proofs_fnv rust-fnv-wasm.jsonl n=3 | a220f40a, C core f39a8e64 |
| FAIL | Rust R_DR proofs_fnv rust-fnv-native.jsonl n=5 | 0238d721, C core c800f2c6 |
| FAIL | Rust R_DR proofs_fnv rust-fnv-wasm.jsonl n=3 | 31a05c99, C core 96a6e906 |
| FAIL | Rust R_TX0 proofs_fnv rust-fnv-native.jsonl n=5 | 78439ad0, C core a29a5747 |
| FAIL | Rust R_TX0 proofs_fnv rust-fnv-wasm.jsonl n=3 | 962ff0c7, C core a0afafc7 |
| FAIL | Rust R_TXM1 proofs_fnv rust-fnv-txm.jsonl n=2 | 90b26a33, C core ee87e7a4 |
| FAIL | Rust R_TXM2 proofs_fnv rust-fnv-txm.jsonl n=2 | 35933def, C core 4294a892 |
| FAIL | Rust R_TXM4 proofs_fnv rust-fnv-txm.jsonl n=2 | 79bad5ef, C core 4ff8974f |
| FAIL | Rust R_TXM8 proofs_fnv rust-fnv-txm.jsonl n=2 | 6a89067f, C core cd21b056 |
| FAIL | Rust R_TXM1_0 proofs_fnv rust-fnv-txm.jsonl n=2 | 0df2ad05, C core bba9cd96 |
| FAIL | Rust R_TXM2_0 proofs_fnv rust-fnv-txm.jsonl n=2 | 0bc7768a, C core 2fef961b |
| FAIL | Rust R_TXM4_0 proofs_fnv rust-fnv-txm.jsonl n=2 | 686de49f, C core 74c6be73 |
| FAIL | Rust R_TXM8_0 proofs_fnv rust-fnv-txm.jsonl n=2 | 384ee242, C core 90c8fc70 |
| FAIL | Rust keys KAT = C | sha256 ad0c6c621889c914367e89e779e02c9a18233d7c38660e64482e13318595f633, expected 7d787b167f641138f3ef6e26f4cdd938c6f27433c4815ddbb587daa94dfa4a80 |

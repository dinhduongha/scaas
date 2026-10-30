# pqz-core reproducibility run (quick)

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), Ubuntu 24.04.5 LTS, kernel 7.0.0-38-generic, Ubuntu clang version 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3, node v26.8.1, Python 3.12.3, rustc 1.97.1 (8bab26f4f 2026-07-14), in Docker: True.

Times are informational (they depend on the machine); the proof hashes, the checks and the sizes are compared.

## PQZL (the LaZer fork, C)

| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |
|---|---|---|---|---|---|---|
| `R_REG` | 30,376 | 534 / 1,138 ms | 339 / 664 ms | 6.94 / 2.93 / 8.5 ms | 10.4 / 3.8 / 10.6 ms | 86.2 MiB |
| `R_REG` Rust | 30,388 | 236 / 846 ms | 137 / 363 ms | – / – / – ms | – / – / – ms | – MiB |
| `R_TX` | 46,670 | 1,977 / 3,943 ms | 1,099 / 2,244 ms | 15.10 / 6.03 / 17.4 ms | 17.5 / 7.1 / 21.0 ms | 270.1 MiB |
| `R_TX` Rust | 46,673 | 786 / 2,559 ms | 467 / 1,002 ms | – / – / – ms | – / – / – ms | – MiB |
| `R_BURN` | 45,857 | 1,364 / 2,807 ms | 1,017 / 1,876 ms | 13.72 / 5.90 / 16.6 ms | 15.2 / 7.0 / 18.4 ms | 258.1 MiB |
| `R_BURN` Rust | 45,857 | 812 / 2,054 ms | 412 / 1,108 ms | – / – / – ms | – / – / – ms | – MiB |
| `R_DS` | 30,813 | 807 / 2,063 ms | 400 / 803 ms | 8.41 / 3.96 / 9.4 ms | 9.5 / 4.6 / 10.9 ms | 89.6 MiB |
| `R_DS` Rust | 30,813 | 478 / 2,171 ms | 208 / 520 ms | – / – / – ms | – / – / – ms | – MiB |
| `R_DR` | 31,552 | 1,315 / 3,617 ms | 394 / 779 ms | 7.74 / 3.60 / 9.5 ms | 9.1 / 4.5 / 12.2 ms | 95.5 MiB |
| `R_DR` Rust | 31,562 | 620 / 3,552 ms | 221 / 395 ms | – / – / – ms | – / – / – ms | – MiB |
| `R_TX0` | 46,346 | 1,984 / 4,706 ms | 984 / 2,243 ms | 10.32 / 6.28 / 17.1 ms | 12.6 / 7.3 / 19.7 ms | 265.3 MiB |
| `R_TX0` Rust | 46,346 | 1,197 / 3,539 ms | 508 / 990 ms | – / – / – ms | – / – / – ms | – MiB |

"Rust" rows: the Rust core (`pqzl/rust/`) in this run's "Rust = C" stage (bench 5 5 63 native, 3 1 63 wasm32; --full also verify_fast), on the same machine as the C rows but with other sample sizes.

## PQZH (Ligero, Rust; the proven preset)

| | proof bytes (max) | max_len_exact | prove p50 native / wasm32 | verify p50 / p99 native | verify p50 / p99 wasm32 | prove memory native heap / wasm32 linear | verifies native / wasm32 |
|---|---|---|---|---|---|---|---|
| `R_REG` | 186,810 | 190,458 | 430 / 1,053 ms | 7.74 / 8.38 ms | 16.81 / 20.78 ms | 25.9 / 29.1 MiB | 20 / 20 |
| `R_TX` | 232,334 | 235,470 | 774 / 1,777 ms | 11.30 / 12.97 ms | 24.15 / 25.73 ms | 43.2 / 46.9 MiB | 20 / 20 |
| `R_BURN` | 231,512 | 234,744 | 793 / 1,667 ms | 11.85 / 13.07 ms | 22.87 / 25.22 ms | 42.9 / 46.9 MiB | 20 / 20 |
| `R_DS` | 186,744 | 190,458 | 439 / 1,067 ms | 8.19 / 8.45 ms | 16.31 / 17.10 ms | 25.9 / 47.2 MiB | 20 / 20 |
| `R_DR` | 187,866 | 190,458 | 460 / 998 ms | 7.79 / 9.28 ms | 15.74 / 17.17 ms | 25.9 / 47.2 MiB | 20 / 20 |
| `R_TX0` | 231,896 | 234,744 | 708 / 1,667 ms | 11.82 / 14.12 ms | 23.21 / 25.61 ms | 42.9 / 48.6 MiB | 20 / 20 |

## pqz-ffi (one precompile, both systems)

Self-test hash: `d6c01fbcda23be8d8dc72d0b245be63713bd37a5ffa58c4093b39c83d6c4f68d`.

| system | form | proof bytes | verify p50 / p99 through the C ABI | adversarial p50 |
|---|---|---|---|---|
| PQZL | Transfer | 46,670 | 10.99 / 14.07 ms | 10.93 ms |
| PQZL | Transfer0 | 46,304 | 10.19 / 13.73 ms | 10.67 ms |
| PQZL | Burn | 45,842 | 10.62 / 13.57 ms | 10.49 ms |
| PQZL | Refresh | 45,842 | 10.71 / 11.25 ms | 10.66 ms |
| PQZL | Register | 30,372 | 7.00 / 8.00 ms | 6.99 ms |
| PQZL | DiscloseSender | 30,784 | 6.26 / 7.59 ms | 6.27 ms |
| PQZL | DiscloseReceiver | 31,570 | 6.27 / 6.75 ms | 6.27 ms |
| PQZL | DiscloseAuditor | 31,542 | 6.15 / 6.46 ms | 6.09 ms |
| PQZL | TransferMulti1 | 46,674 | 10.82 / 11.61 ms | 11.38 ms |
| PQZL | TransferMulti2 | 47,508 | 11.63 / 14.60 ms | 11.93 ms |
| PQZL | TransferMulti4 | 63,874 | 16.14 / 20.28 ms | 15.69 ms |
| PQZL | TransferMulti8 | 80,264 | 21.70 / 22.14 ms | 21.66 ms |
| PQZL | TransferMulti1_0 | 46,327 | 10.72 / 11.13 ms | 10.66 ms |
| PQZL | TransferMulti2_0 | 46,848 | 10.99 / 11.21 ms | 11.58 ms |
| PQZL | TransferMulti4_0 | 47,881 | 12.04 / 26.12 ms | 12.19 ms |
| PQZL | TransferMulti8_0 | 64,588 | 16.55 / 17.13 ms | 16.54 ms |
| PQZH | Transfer | 248,856 | 17.05 / 20.22 ms | 2.32 ms |
| PQZH | Transfer0 | 248,728 | 17.47 / 17.96 ms | 2.40 ms |
| PQZH | Burn | 247,496 | 18.86 / 24.65 ms | 2.38 ms |
| PQZH | Refresh | 248,824 | 16.03 / 17.68 ms | 2.04 ms |
| PQZH | Register | 204,552 | 12.10 / 12.63 ms | 0.76 ms |
| PQZH | DiscloseSender | 203,430 | 12.95 / 16.39 ms | 0.84 ms |
| PQZH | DiscloseReceiver | 203,846 | 11.55 / 12.54 ms | 0.72 ms |
| PQZH | DiscloseAuditor | 204,776 | 12.61 / 12.93 ms | 0.83 ms |
| PQZH | TransferMulti1 | 248,824 | 17.62 / 35.99 ms | 2.53 ms |
| PQZH | TransferMulti2 | 249,096 | 16.93 / 35.05 ms | 2.60 ms |
| PQZH | TransferMulti4 | 292,664 | 23.70 / 24.66 ms | 3.15 ms |
| PQZH | TransferMulti1_0 | 247,992 | 17.09 / 17.53 ms | 2.43 ms |
| PQZH | TransferMulti2_0 | 248,408 | 17.10 / 18.05 ms | 2.04 ms |
| PQZH | TransferMulti4_0 | 248,936 | 18.26 / 24.86 ms | 2.59 ms |

## Against expected-results.json: 252 ok, 0 FAIL, 0 warn, 0 info

| status | check | detail |
|---|---|---|
| ok | kat | ok |
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
| ok | R_REG proofs_fnv native-generic.jsonl n=3 | 03527227, expected 03527227 |
| ok | R_REG proofs_fnv wasm-generic.jsonl n=3 | 03527227, expected 03527227 |
| ok | R_REG proofs_fnv native-fast.jsonl n=2 | 60d64ae3, expected 60d64ae3 |
| ok | R_REG proofs_fnv x86v3-fast.jsonl n=2 | 60d64ae3, expected 60d64ae3 |
| ok | R_REG proofs_fnv wasm-fast.jsonl n=2 | 60d64ae3, expected 60d64ae3 |
| ok | R_REG proofs_fnv wasm-both.jsonl n=2 | 60d64ae3, expected 60d64ae3 |
| ok | R_REG proofs_fnv alone-wasm-nosv.jsonl n=1 | 5983527c, expected 5983527c |
| ok | R_REG proof_bytes_max | 30376, frozen 30376 (0.00%, tol 0.5%) |
| ok | R_REG wasm_prove_peak_bytes | 90407712, frozen 90407712 (0.00%, tol 1.0%) |
| ok | R_REG ratio sv_speedup | 48.9, frozen 48.9 (0%, tol 50%; machine-dependent) |
| ok | R_REG ratio wasm_over_native_prove | 2.13, frozen 2.16 (1%, tol 50%; machine-dependent) |
| ok | R_TX proofs_fnv native-generic.jsonl n=3 | 630ceb5e, expected 630ceb5e |
| ok | R_TX proofs_fnv wasm-generic.jsonl n=3 | 630ceb5e, expected 630ceb5e |
| ok | R_TX proofs_fnv native-fast.jsonl n=2 | 242af686, expected 242af686 |
| ok | R_TX proofs_fnv x86v3-fast.jsonl n=2 | 242af686, expected 242af686 |
| ok | R_TX proofs_fnv wasm-fast.jsonl n=2 | 242af686, expected 242af686 |
| ok | R_TX proofs_fnv wasm-both.jsonl n=2 | 242af686, expected 242af686 |
| ok | R_TX proofs_fnv alone-wasm-nosv.jsonl n=1 | ab9867c3, expected ab9867c3 |
| ok | R_TX proof_bytes_max | 46670, frozen 46670 (0.00%, tol 0.5%) |
| ok | R_TX wasm_prove_peak_bytes | 283239328, frozen 283239328 (0.00%, tol 1.0%) |
| ok | R_TX ratio sv_speedup | 72.8, frozen 87.9 (17%, tol 50%; machine-dependent) |
| ok | R_TX ratio wasm_over_native_prove | 1.99, frozen 1.76 (13%, tol 50%; machine-dependent) |
| ok | R_BURN proofs_fnv native-generic.jsonl n=3 | dc058b31, expected dc058b31 |
| ok | R_BURN proofs_fnv wasm-generic.jsonl n=3 | dc058b31, expected dc058b31 |
| ok | R_BURN proofs_fnv native-fast.jsonl n=2 | 2f3c4d9c, expected 2f3c4d9c |
| ok | R_BURN proofs_fnv x86v3-fast.jsonl n=2 | 2f3c4d9c, expected 2f3c4d9c |
| ok | R_BURN proofs_fnv wasm-fast.jsonl n=2 | 2f3c4d9c, expected 2f3c4d9c |
| ok | R_BURN proofs_fnv wasm-both.jsonl n=2 | 2f3c4d9c, expected 2f3c4d9c |
| ok | R_BURN proofs_fnv alone-wasm-nosv.jsonl n=1 | 8da2f946, expected 8da2f946 |
| ok | R_BURN proof_bytes_max | 45857, frozen 45857 (0.00%, tol 0.5%) |
| ok | R_BURN wasm_prove_peak_bytes | 270671168, frozen 270671168 (0.00%, tol 1.0%) |
| ok | R_BURN ratio sv_speedup | 74.1, frozen 78.6 (6%, tol 50%; machine-dependent) |
| ok | R_BURN ratio wasm_over_native_prove | 2.06, frozen 1.73 (19%, tol 50%; machine-dependent) |
| ok | R_DS proofs_fnv native-generic.jsonl n=3 | a220f40a, expected a220f40a |
| ok | R_DS proofs_fnv wasm-generic.jsonl n=3 | a220f40a, expected a220f40a |
| ok | R_DS proofs_fnv native-fast.jsonl n=2 | cb5a80a3, expected cb5a80a3 |
| ok | R_DS proofs_fnv x86v3-fast.jsonl n=2 | cb5a80a3, expected cb5a80a3 |
| ok | R_DS proofs_fnv wasm-fast.jsonl n=2 | cb5a80a3, expected cb5a80a3 |
| ok | R_DS proofs_fnv wasm-both.jsonl n=2 | cb5a80a3, expected cb5a80a3 |
| ok | R_DS proofs_fnv alone-wasm-nosv.jsonl n=1 | 5a4ca497, expected 5a4ca497 |
| ok | R_DS proof_bytes_max | 30813, frozen 30813 (0.00%, tol 0.5%) |
| ok | R_DS wasm_prove_peak_bytes | 93937472, frozen 93937472 (0.00%, tol 1.0%) |
| ok | R_DS ratio sv_speedup | 47.6, frozen 56.5 (16%, tol 50%; machine-dependent) |
| ok | R_DS ratio wasm_over_native_prove | 2.55, frozen 1.99 (28%, tol 50%; machine-dependent) |
| ok | R_DR proofs_fnv native-generic.jsonl n=3 | 31a05c99, expected 31a05c99 |
| ok | R_DR proofs_fnv wasm-generic.jsonl n=3 | 31a05c99, expected 31a05c99 |
| ok | R_DR proofs_fnv native-fast.jsonl n=2 | 61c33a97, expected 61c33a97 |
| ok | R_DR proofs_fnv x86v3-fast.jsonl n=2 | 61c33a97, expected 61c33a97 |
| ok | R_DR proofs_fnv wasm-fast.jsonl n=2 | 61c33a97, expected 61c33a97 |
| ok | R_DR proofs_fnv wasm-both.jsonl n=2 | 61c33a97, expected 61c33a97 |
| ok | R_DR proofs_fnv alone-wasm-nosv.jsonl n=1 | 569048d7, expected 569048d7 |
| ok | R_DR proof_bytes_max | 31552, frozen 31552 (0.00%, tol 0.5%) |
| ok | R_DR wasm_prove_peak_bytes | 100174000, frozen 100174000 (0.00%, tol 1.0%) |
| ok | R_DR ratio sv_speedup | 50.9, frozen 51.6 (1%, tol 50%; machine-dependent) |
| ok | R_DR ratio wasm_over_native_prove | 2.75, frozen 2.33 (18%, tol 50%; machine-dependent) |
| ok | R_TX0 proofs_fnv native-generic.jsonl n=3 | 962ff0c7, expected 962ff0c7 |
| ok | R_TX0 proofs_fnv wasm-generic.jsonl n=3 | 962ff0c7, expected 962ff0c7 |
| ok | R_TX0 proofs_fnv native-fast.jsonl n=2 | 453f2835, expected 453f2835 |
| ok | R_TX0 proofs_fnv x86v3-fast.jsonl n=2 | 453f2835, expected 453f2835 |
| ok | R_TX0 proofs_fnv wasm-fast.jsonl n=2 | 453f2835, expected 453f2835 |
| ok | R_TX0 proofs_fnv wasm-both.jsonl n=2 | 453f2835, expected 453f2835 |
| ok | R_TX0 proofs_fnv alone-wasm-nosv.jsonl n=1 | a090b8b0, expected a090b8b0 |
| ok | R_TX0 proof_bytes_max | 46346, frozen 46346 (0.00%, tol 0.5%) |
| ok | R_TX0 wasm_prove_peak_bytes | 278193712, frozen 278193712 (0.00%, tol 1.0%) |
| ok | R_TX0 ratio sv_speedup | 95.4, frozen 89.3 (7%, tol 50%; machine-dependent) |
| ok | R_TX0 ratio wasm_over_native_prove | 2.37, frozen 1.98 (20%, tol 50%; machine-dependent) |
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
| ok | PQZH R_REG fnv seed 0 pqzh-native.jsonl | 11bc45ad, expected 11bc45ad |
| ok | PQZH R_REG fnv seed 1 pqzh-native.jsonl | c775e64c, expected c775e64c |
| ok | PQZH R_REG fnv seed 1 pqzh-wasm.jsonl | c775e64c, expected c775e64c |
| ok | PQZH R_REG proof bytes seed 1 pqzh-native.jsonl | 186810, expected 186810 |
| ok | PQZH R_REG proof bytes seed 1 pqzh-wasm.jsonl | 186810, expected 186810 |
| ok | PQZH R_REG native = wasm32 seed 1 | c775e64c |
| ok | PQZH R_REG max_len_exact | 190458, expected 190458 |
| ok | PQZH R_REG proofs within the bound | max 186810 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_REG wasm32 memory <= 256 MiB | 29.125 MiB |
| ok | PQZH R_REG ratio wasm_over_native_prove | 2.45, frozen 2.26 (8%, tol 50%; machine-dependent) |
| ok | PQZH R_REG ratio wasm_over_native_verify | 2.17, frozen 2.0 (8%, tol 50%; machine-dependent) |
| ok | PQZH R_TX fnv seed 0 pqzh-native.jsonl | 36954e01, expected 36954e01 |
| ok | PQZH R_TX fnv seed 1 pqzh-native.jsonl | bf065344, expected bf065344 |
| ok | PQZH R_TX fnv seed 1 pqzh-wasm.jsonl | bf065344, expected bf065344 |
| ok | PQZH R_TX proof bytes seed 1 pqzh-native.jsonl | 232334, expected 232334 |
| ok | PQZH R_TX proof bytes seed 1 pqzh-wasm.jsonl | 232334, expected 232334 |
| ok | PQZH R_TX native = wasm32 seed 1 | bf065344 |
| ok | PQZH R_TX max_len_exact | 235470, expected 235470 |
| ok | PQZH R_TX proofs within the bound | max 232334 <= max_len_exact 235470 = verifier bound 235470 |
| ok | PQZH R_TX wasm32 memory <= 256 MiB | 46.9375 MiB |
| ok | PQZH R_TX ratio wasm_over_native_prove | 2.29, frozen 2.23 (3%, tol 50%; machine-dependent) |
| ok | PQZH R_TX ratio wasm_over_native_verify | 2.14, frozen 2.13 (0%, tol 50%; machine-dependent) |
| ok | PQZH R_BURN fnv seed 0 pqzh-native.jsonl | 73f201e9, expected 73f201e9 |
| ok | PQZH R_BURN fnv seed 1 pqzh-native.jsonl | 68cddb3c, expected 68cddb3c |
| ok | PQZH R_BURN fnv seed 1 pqzh-wasm.jsonl | 68cddb3c, expected 68cddb3c |
| ok | PQZH R_BURN proof bytes seed 1 pqzh-native.jsonl | 230536, expected 230536 |
| ok | PQZH R_BURN proof bytes seed 1 pqzh-wasm.jsonl | 230536, expected 230536 |
| ok | PQZH R_BURN native = wasm32 seed 1 | 68cddb3c |
| ok | PQZH R_BURN max_len_exact | 234744, expected 234744 |
| ok | PQZH R_BURN proofs within the bound | max 231512 <= max_len_exact 234744 = verifier bound 234744 |
| ok | PQZH R_BURN wasm32 memory <= 256 MiB | 46.9375 MiB |
| ok | PQZH R_BURN ratio wasm_over_native_prove | 2.1, frozen 2.25 (7%, tol 50%; machine-dependent) |
| ok | PQZH R_BURN ratio wasm_over_native_verify | 1.93, frozen 2.12 (9%, tol 50%; machine-dependent) |
| ok | PQZH R_DS fnv seed 0 pqzh-native.jsonl | c94debf2, expected c94debf2 |
| ok | PQZH R_DS fnv seed 1 pqzh-native.jsonl | 5797a517, expected 5797a517 |
| ok | PQZH R_DS fnv seed 1 pqzh-wasm.jsonl | 5797a517, expected 5797a517 |
| ok | PQZH R_DS proof bytes seed 1 pqzh-native.jsonl | 186744, expected 186744 |
| ok | PQZH R_DS proof bytes seed 1 pqzh-wasm.jsonl | 186744, expected 186744 |
| ok | PQZH R_DS native = wasm32 seed 1 | 5797a517 |
| ok | PQZH R_DS max_len_exact | 190458, expected 190458 |
| ok | PQZH R_DS proofs within the bound | max 186744 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_DS wasm32 memory <= 256 MiB | 47.25 MiB |
| ok | PQZH R_DS ratio wasm_over_native_prove | 2.43, frozen 2.24 (8%, tol 50%; machine-dependent) |
| ok | PQZH R_DS ratio wasm_over_native_verify | 1.99, frozen 2.02 (1%, tol 50%; machine-dependent) |
| ok | PQZH R_DR fnv seed 0 pqzh-native.jsonl | 37ca37ce, expected 37ca37ce |
| ok | PQZH R_DR fnv seed 1 pqzh-native.jsonl | dca26488, expected dca26488 |
| ok | PQZH R_DR fnv seed 1 pqzh-wasm.jsonl | dca26488, expected dca26488 |
| ok | PQZH R_DR proof bytes seed 1 pqzh-native.jsonl | 186584, expected 186584 |
| ok | PQZH R_DR proof bytes seed 1 pqzh-wasm.jsonl | 186584, expected 186584 |
| ok | PQZH R_DR native = wasm32 seed 1 | dca26488 |
| ok | PQZH R_DR max_len_exact | 190458, expected 190458 |
| ok | PQZH R_DR proofs within the bound | max 187866 <= max_len_exact 190458 = verifier bound 190458 |
| ok | PQZH R_DR wasm32 memory <= 256 MiB | 47.25 MiB |
| ok | PQZH R_DR ratio wasm_over_native_prove | 2.17, frozen 2.14 (1%, tol 50%; machine-dependent) |
| ok | PQZH R_DR ratio wasm_over_native_verify | 2.02, frozen 2.0 (1%, tol 50%; machine-dependent) |
| ok | PQZH R_TX0 fnv seed 0 pqzh-native.jsonl | 199e0a34, expected 199e0a34 |
| ok | PQZH R_TX0 fnv seed 1 pqzh-native.jsonl | c5531c9d, expected c5531c9d |
| ok | PQZH R_TX0 fnv seed 1 pqzh-wasm.jsonl | c5531c9d, expected c5531c9d |
| ok | PQZH R_TX0 proof bytes seed 1 pqzh-native.jsonl | 231896, expected 231896 |
| ok | PQZH R_TX0 proof bytes seed 1 pqzh-wasm.jsonl | 231896, expected 231896 |
| ok | PQZH R_TX0 native = wasm32 seed 1 | c5531c9d |
| ok | PQZH R_TX0 max_len_exact | 234744, expected 234744 |
| ok | PQZH R_TX0 proofs within the bound | max 231896 <= max_len_exact 234744 = verifier bound 234744 |
| ok | PQZH R_TX0 wasm32 memory <= 256 MiB | 48.625 MiB |
| ok | PQZH R_TX0 ratio wasm_over_native_prove | 2.35, frozen 2.27 (4%, tol 50%; machine-dependent) |
| ok | PQZH R_TX0 ratio wasm_over_native_verify | 1.96, frozen 2.1 (7%, tol 50%; machine-dependent) |
| ok | pqz-ffi selftest hash | d6c01fbcda23be8d8dc72d0b245be63713bd37a5ffa58c4093b39c83d6c4f68d, expected d6c01fbcda23be8d8dc72d0b245be63713bd37a5ffa58c4093b39c83d6c4f68d |
| ok | pqz-ffi digest lines native = wasm32 | 29 / 29 lines |
| ok | pqz-ffi digest lines = frozen | 29 lines, 0 differ |
| ok | vectors wasm32 replay | 61 proofs, 61 byte-equal and valid, 0 native PQZL op 7 M > 4 proofs valid (verify only), fails 0 |
| ok | op 7 pqzh M1-off native | proof 246984 B, ...01 through pqz_precompile, expected 246984 B |
| ok | op 7 pqzh M1-off wasm32 | 246984 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M1-on native | proof 249400 B, ...01 through pqz_precompile, expected 249400 B |
| ok | op 7 pqzh M1-on wasm32 | 249400 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M2-off native | proof 248440 B, ...01 through pqz_precompile, expected 248440 B |
| ok | op 7 pqzh M2-off wasm32 | 248440 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M2-off-two-real native | proof 248152 B, ...01 through pqz_precompile, expected 248152 B |
| ok | op 7 pqzh M2-off-two-real wasm32 | 248152 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M2-on native | proof 248872 B, ...01 through pqz_precompile, expected 248872 B |
| ok | op 7 pqzh M2-on wasm32 | 248872 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M4-off native | proof 249512 B, ...01 through pqz_precompile, expected 249512 B |
| ok | op 7 pqzh M4-off wasm32 | 249512 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M4-off-decoys native | proof 248872 B, ...01 through pqz_precompile, expected 248872 B |
| ok | op 7 pqzh M4-off-decoys wasm32 | 248872 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M4-on native | proof 293112 B, ...01 through pqz_precompile, expected 293112 B |
| ok | op 7 pqzh M4-on wasm32 | 293112 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M4-on-leg2-auditor native | proof 204680 B, ...01 through pqz_precompile, expected 204680 B |
| ok | op 7 pqzh M4-on-leg2-auditor wasm32 | 204680 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M8-on-boundary-leg5-auditor native | proof 204584 B, ...01 through pqz_precompile, expected 204584 B |
| ok | op 7 pqzh M8-on-boundary-leg5-auditor wasm32 | 204584 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M8-on-boundary-leg6-auditor native | proof 204840 B, ...01 through pqz_precompile, expected 204840 B |
| ok | op 7 pqzh M8-on-boundary-leg6-auditor wasm32 | 204840 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzh M8-on-boundary-leg6-receiver native | proof 205640 B, ...01 through pqz_precompile, expected 205640 B |
| ok | op 7 pqzh M8-on-boundary-leg6-receiver wasm32 | 205640 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M1-off native | proof 46342 B, ...01 through pqz_precompile, expected 46342 B |
| ok | op 7 pqzl M1-off wasm32 | 46342 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M1-on native | proof 46678 B, ...01 through pqz_precompile, expected 46678 B |
| ok | op 7 pqzl M1-on wasm32 | 46678 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M2-off native | proof 46857 B, ...01 through pqz_precompile, expected 46857 B |
| ok | op 7 pqzl M2-off wasm32 | 46857 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M2-off-two-real native | proof 46802 B, ...01 through pqz_precompile, expected 46802 B |
| ok | op 7 pqzl M2-off-two-real wasm32 | 46802 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M2-on native | proof 47503 B, ...01 through pqz_precompile, expected 47503 B |
| ok | op 7 pqzl M2-on wasm32 | 47503 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M4-off native | proof 47821 B, ...01 through pqz_precompile, expected 47821 B |
| ok | op 7 pqzl M4-off wasm32 | 47821 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M4-off-decoys native | proof 47801 B, ...01 through pqz_precompile, expected 47801 B |
| ok | op 7 pqzl M4-off-decoys wasm32 | 47801 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M4-on native | proof 63885 B, ...01 through pqz_precompile, expected 63885 B |
| ok | op 7 pqzl M4-on wasm32 | 63885 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M4-on-leg2-auditor native | proof 31547 B, ...01 through pqz_precompile, expected 31547 B |
| ok | op 7 pqzl M4-on-leg2-auditor wasm32 | 31547 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M8-off native | proof 64607 B, ...01 through pqz_precompile, expected 64607 B |
| ok | op 7 pqzl M8-off wasm32 | 64607 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M8-on native | proof 80290 B, ...01 through pqz_precompile, expected 80290 B |
| ok | op 7 pqzl M8-on wasm32 | 80290 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M8-on-boundary native | proof 80288 B, ...01 through pqz_precompile, expected 80288 B |
| ok | op 7 pqzl M8-on-boundary wasm32 | 80288 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M8-on-boundary-leg5-auditor native | proof 31571 B, ...01 through pqz_precompile, expected 31571 B |
| ok | op 7 pqzl M8-on-boundary-leg5-auditor wasm32 | 31571 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M8-on-boundary-leg6-auditor native | proof 31543 B, ...01 through pqz_precompile, expected 31543 B |
| ok | op 7 pqzl M8-on-boundary-leg6-auditor wasm32 | 31543 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl M8-on-boundary-leg6-receiver native | proof 31551 B, ...01 through pqz_precompile, expected 31551 B |
| ok | op 7 pqzl M8-on-boundary-leg6-receiver wasm32 | 31551 B, proved again, byte-equal, precompile 1 |
| ok | op 7 pqzl negatives | 198 rows of negative.json, 198 expect 0 / revert, replayed by pqz-vectors --check (same negative.json), expected 198 rows |
| ok | op 7 pqzh negatives | 177 rows of negative.json, 177 expect 0 / revert, replayed by pqz-vectors --check (same negative.json), expected 177 rows |
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
| ok | Rust R_REG proofs_fnv rust-fnv-native.jsonl n=5 | 54eec2a7, C core 54eec2a7 |
| ok | Rust R_REG proofs_fnv rust-fnv-wasm.jsonl n=3 | 03527227, C core 03527227 |
| ok | Rust R_TX proofs_fnv rust-fnv-native.jsonl n=5 | f0858eff, C core f0858eff |
| ok | Rust R_TX proofs_fnv rust-fnv-wasm.jsonl n=3 | 630ceb5e, C core 630ceb5e |
| ok | Rust R_BURN proofs_fnv rust-fnv-native.jsonl n=5 | 879bb5fe, C core 879bb5fe |
| ok | Rust R_BURN proofs_fnv rust-fnv-wasm.jsonl n=3 | dc058b31, C core dc058b31 |
| ok | Rust R_DS proofs_fnv rust-fnv-native.jsonl n=5 | c655a73a, C core c655a73a |
| ok | Rust R_DS proofs_fnv rust-fnv-wasm.jsonl n=3 | a220f40a, C core a220f40a |
| ok | Rust R_DR proofs_fnv rust-fnv-native.jsonl n=5 | 0238d721, C core 0238d721 |
| ok | Rust R_DR proofs_fnv rust-fnv-wasm.jsonl n=3 | 31a05c99, C core 31a05c99 |
| ok | Rust R_TX0 proofs_fnv rust-fnv-native.jsonl n=5 | 78439ad0, C core 78439ad0 |
| ok | Rust R_TX0 proofs_fnv rust-fnv-wasm.jsonl n=3 | 962ff0c7, C core 962ff0c7 |
| ok | Rust R_TXM1 proofs_fnv rust-fnv-txm.jsonl n=2 | 90b26a33, C core 90b26a33 |
| ok | Rust R_TXM2 proofs_fnv rust-fnv-txm.jsonl n=2 | 35933def, C core 35933def |
| ok | Rust R_TXM4 proofs_fnv rust-fnv-txm.jsonl n=2 | 79bad5ef, C core 79bad5ef |
| ok | Rust R_TXM8 proofs_fnv rust-fnv-txm.jsonl n=2 | 6a89067f, C core 6a89067f |
| ok | Rust R_TXM1_0 proofs_fnv rust-fnv-txm.jsonl n=2 | 0df2ad05, C core 0df2ad05 |
| ok | Rust R_TXM2_0 proofs_fnv rust-fnv-txm.jsonl n=2 | 0bc7768a, C core 0bc7768a |
| ok | Rust R_TXM4_0 proofs_fnv rust-fnv-txm.jsonl n=2 | 686de49f, C core 686de49f |
| ok | Rust R_TXM8_0 proofs_fnv rust-fnv-txm.jsonl n=2 | 384ee242, C core 384ee242 |
| ok | Rust keys KAT = C | sha256 ad0c6c621889c914367e89e779e02c9a18233d7c38660e64482e13318595f633, expected ad0c6c621889c914367e89e779e02c9a18233d7c38660e64482e13318595f633 |

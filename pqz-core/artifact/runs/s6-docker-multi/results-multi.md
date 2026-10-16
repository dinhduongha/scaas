# Op 7 R_TXM measurements (reproduce.sh --multi-bench)

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), in Docker: True. Times are informational.

## PQZL (research/pqzl-measure/txm-bench.sh, the L3 method)

| M | auditor | built | proof bytes (max) | prove p50 native / wasm32 | generic verify p50 / p99 native | SV p99 portable / x86-64-v3 / wasm32 | wasm32 prove peak (no SV) |
|---|---|---|---|---|---|---|---|
| 1 | on | yes | 42,784 | 914 / 1,296 ms | 583 / 596 ms | 7.8 / 4.8 / 13.2 ms | 221.1 MiB |
| 2 | on | yes | 43,616 | 978 / 1,371 ms | 674 / 936 ms | 8.6 / 5.0 / 14.2 ms | 232.3 MiB |
| 4 | on | yes | 45,295 | 1,354 / 1,827 ms | 865 / 880 ms | 9.1 / 5.3 / 15.0 ms | 255.6 MiB |
| 8 | on | yes | 61,822 | 2,398 / 2,931 ms | 2,007 / 2,138 ms | 13.6 / 8.3 / 23.1 ms | 495.3 MiB |
| 16 | on | no (oversize, bench build only) | 92,367 | 7,466 / 8,336 ms | 6,230 / 6,425 ms | 21.9 / 12.6 / 35.7 ms | 1,199.1 MiB |
| 1 | off | yes | 42,442 | 784 / 1,112 ms | 542 / 550 ms | 7.9 / 4.7 / 12.9 ms | 216.7 MiB |
| 2 | off | yes | 42,936 | 1,003 / 1,650 ms | 591 / 597 ms | 8.4 / 4.8 / 13.2 ms | 223.4 MiB |
| 4 | off | yes | 43,956 | 1,110 / 2,605 ms | 691 / 720 ms | 8.7 / 4.9 / 13.8 ms | 237.2 MiB |
| 8 | off | yes | 59,048 | 1,776 / 2,370 ms | 1,444 / 1,546 ms | 12.9 / 7.2 / 21.9 ms | 447.0 MiB |
| 16 | off | no (oversize, bench build only) | 86,581 | 5,167 / 5,504 ms | 4,302 / 4,498 ms | 20.3 / 11.1 / 32.6 ms | 1,051.1 MiB |

## PQZH (Ligero, the proven preset; the H2 method of pqzh/ligero/runs/txm.sh)

| M | auditor | built | proof bytes (max) | max_len_exact | prove p50 native / wasm32 | verify p50 / p99 native | verify p50 / p99 wasm32 | prove memory native heap / wasm32 linear |
|---|---|---|---|---|---|---|---|---|
| 1 | on | yes | 233,102 | 235,470 | 631 / 1,340 ms | 9.60 / 9.86 ms | 17.04 / 18.54 ms | 43.2 / 46.3 MiB |
| 2 | on | yes | 232,526 | 235,470 | 635 / 1,346 ms | 9.83 / 10.12 ms | 17.46 / 19.01 ms | 43.2 / 46.9 MiB |
| 4 | on | yes | 233,604 | 236,196 | 626 / 1,297 ms | 10.64 / 10.90 ms | 18.64 / 20.36 ms | 43.6 / 47.8 MiB |
| 8 | on | no (oversize, bench build only) | 278,456 | 281,208 | 902 / 1,882 ms | 13.73 / 13.96 ms | 24.90 / 25.35 ms | 61.4 / 67.6 MiB |
| 16 | on | no (oversize, bench build only) | 369,420 | 372,684 | 1,394 / 2,943 ms | 19.99 / 20.19 ms | 37.58 / 38.03 ms | 96.6 / 104 MiB |
| 1 | off | yes | 232,440 | 234,744 | 618 / 1,272 ms | 9.30 / 9.83 ms | 16.32 / 17.67 ms | 42.9 / 47.8 MiB |
| 2 | off | yes | 232,590 | 235,470 | 627 / 1,305 ms | 9.63 / 10.05 ms | 17.02 / 18.65 ms | 43.2 / 48.4 MiB |
| 4 | off | yes | 232,654 | 235,470 | 652 / 1,281 ms | 9.96 / 10.72 ms | 17.45 / 18.60 ms | 43.2 / 48.8 MiB |
| 8 | off | no (oversize, bench build only) | 276,780 | 279,756 | 877 / 1,798 ms | 12.35 / 13.30 ms | 22.55 / 22.93 ms | 60.6 / 104 MiB |
| 16 | off | no (oversize, bench build only) | 366,078 | 369,054 | 1,361 / 2,884 ms | 17.39 / 18.61 ms | 33.00 / 33.78 ms | 94.9 / 105.8 MiB |

## Checks: 29 ok, 0 FAIL

| status | check | detail |
|---|---|---|
| ok | pqzl-txm.txt | rc 0 |
| ok | pqzh-txm-build.txt | rc 0 |
| ok | pqzh-txm-oversize-build.txt | rc 0 |
| ok | pqzh-txm-wasm-build.txt | rc 0 |
| ok | pqzh-txm-oversize-wasm-build.txt | rc 0 |
| ok | pqzl-txm-native-generic.jsonl | fails 0, verifier disagreements 0 |
| ok | pqzl-txm-native-fast.jsonl | fails 0, verifier disagreements 0 |
| ok | pqzl-txm-x86v3-fast.jsonl | fails 0, verifier disagreements 0 |
| ok | pqzl-txm-wasm-fast.jsonl | fails 0, verifier disagreements 0 |
| ok | pqzl-txm-wasm-generic.jsonl | fails 0, verifier disagreements 0 |
| ok | pqzl-txm-wasm-nosv.jsonl | fails 0, verifier disagreements 0 |
| ok | pqzh-txm-native.jsonl | fails 0 (mutations accepted, panics, rc) |
| ok | pqzh-txm-oversize.jsonl | fails 0 (mutations accepted, panics, rc) |
| ok | pqzh-txm-wasm.jsonl | fails 0 (mutations accepted, panics, rc) |
| ok | pqzh-txm-oversize-wasm.jsonl | fails 0 (mutations accepted, panics, rc) |
| ok | pqzl R_TXM (1, on) measured | built shape |
| ok | pqzl R_TXM (1, off) measured | built shape |
| ok | pqzl R_TXM (2, on) measured | built shape |
| ok | pqzl R_TXM (2, off) measured | built shape |
| ok | pqzl R_TXM (4, on) measured | built shape |
| ok | pqzl R_TXM (4, off) measured | built shape |
| ok | pqzl R_TXM (8, on) measured | built shape |
| ok | pqzl R_TXM (8, off) measured | built shape |
| ok | pqzh R_TXM (1, on) measured | built shape |
| ok | pqzh R_TXM (1, off) measured | built shape |
| ok | pqzh R_TXM (2, on) measured | built shape |
| ok | pqzh R_TXM (2, off) measured | built shape |
| ok | pqzh R_TXM (4, on) measured | built shape |
| ok | pqzh R_TXM (4, off) measured | built shape |

# P6d-2: pqz-core optimisation (2026-10-13)

The owner asked to optimise the fork after the upstream cross-check (`../xcheck/`). Branch `p6d2-opt`, merged into
main as `b87078a`. Only the implementation changed: parameters, relations, proof format and `proofSystemId` are the
same. Summary and analysis: `docs/research/pqz-core-e-s1.md` §11; state: `../STATUS.md`.

## Result

Medians, one session on an AMD Ryzen 5 7235HS. Native is `pqz_bench 5 5` (clang `-O2`, portable). Wasm is
`run_wasm.mjs 3 1` under node. Everything ran under `scripts/capped`.

| | Before (main `fd8600f`) | After (P6d-2) | Upstream LaZer (AVX2, `../xcheck/`) |
|---|---|---|---|
| `R_TX` prove / verify, native | 17.0 s / 14.9 s | **1.10 s / 0.72 s** | 6.6 s / 6.6 s |
| `R_TX` prove / verify, wasm | 39.6 s / 34.5 s | **1.59 s / 0.82 s** | — |
| `R_REG` prove / verify, native | 1.30 s / 1.02 s | 0.25 s / 0.17 s | 0.62 s / 0.57 s |
| `R_REG` prove / verify, wasm | 3.30 s / 2.61 s | 0.38 s / 0.23 s | — |
| Arena peak `R_TX`, native / wasm | 612 / 476 MB | 316 / 241 MB | — |
| Proof bytes `R_TX` / `R_REG` | 42,734–42,770 / 28,070–28,107 | unchanged | same |

Against the kill criteria (CTR-PQZ-09, roadmap P6d row):
- Prove meets the 6 s limit.
- Verify (0.72 s honest, 0.67 s worst adversarial) is still about 14× over the 50 ms limit; before this work it was about 300×.

Against the browser budgets (CTR-PQZ-18):
- Wasm prove (1.59 s) is inside the 5 s desktop budget.
- The wasm arena (230 MiB) is under the 256 MiB hard limit but 1.8× the 128 MiB budget.

## Step by step (`R_TX`, cumulative; files in `runs/`)

| Step | Change | Commit | Native prove / verify | Wasm prove / verify |
|---|---|---|---|---|
| 0 | baseline (main) | `41b226d` (harness) | 17.02 / 14.86 s | 39.64 / 34.50 s |
| 1 | base multiplication mod X^16 − ρ: one u128 column sum per output, reduction in 64-bit only; on wasm32, 21-bit limbs (no `__multi3`) | `53b5597` | 12.15 / 10.96 s | 18.40 / 18.61 s |
| 2 | `pqz_qsort` as heapsort (was insertion sort, O(n²)) | `ad03fe4` | 8.40 / 7.54 s | 13.93 / 11.59 s |
| 3 | Schwartz–Zippel accumulators swapped instead of copied | `fb5a4ab` | 7.74 / 6.88 s | 13.50 / 11.53 s |
| 4 | ℓ2 / binary Gram terms skip the zero columns of the public selection matrices | `6d95a35` | **1.74 / 0.91 s** | 2.61 / 1.35 s |
| 5 | `poly_scale` fast path (no gain; reverted in `4b7cab3`) | `36ba69b` | 1.77 / 0.85 s | 2.59 / 1.31 s |
| 6 | bitsliced AES: Boyar–Peralta S-box, transposed bit planes (1 MiB 60 → 8.8 ms) | `405a3e3` | 1.24 / 0.88 s | 2.06 / 1.25 s |
| 7 | `polyvec_mul2` skips zero columns | `5c7e6be` | 1.19 / 0.78 s | 1.94 / 1.13 s |
| 8 | Gram entries as dot products, zero products skipped | `6717d5f` | 1.10 / 0.75 s | 1.72 / 0.95 s |
| 9 | z3 term accumulated in int64 | `b8767b4` | **1.10 / 0.72 s** | **1.59 / 0.82 s** |

**Step 4 was the biggest win.** Each ℓ2 equation of `R_TX` selects 32 of the 146 witness polynomials. The generic
code still built all 146² Gram entries, nearly all of them zero, and carried them through every sum, sort and copy
after that. Upstream LaZer does the same work, which is why the fork is now faster than upstream.

Tried and dropped:
- the `poly_scale` fast path (step 5);
- Karatsuba for the degree-16 products, which was slower than the column kernel in `micro_basemul.c`.

Not done, and why:
- **Asserts off**: pq-zero-knowledge.md §10 keeps the invariant checks in release builds; the gain would be about 4 %.
- **`-O3` / `-march=native`**: §10 prescribes a portable `-O2` build.
- **An AVX2 backend and integer CRT multiplication**: the base multiplication is now only about 7 % of the profile.

## Checks after every step

- **Same proofs.** For the same seeds, every step left the proofs byte-identical to main; the bench prints an FNV-1a
  hash of them. Native and wasm proofs are also equal byte for byte (seeds 0..2).
- **KAT** 19/19 against `../kat/lazer-3330e48.json`.
- **Symbol scan** clean, native and wasm.
- **Tampered proofs**: all five kinds rejected (`fails: 0`).
- **ASan + UBSan** (`asan.sh`): nothing beyond the four known upstream UBSan findings.

## Rerun

```sh
cd pqz-core
./build.sh all                   # native + wasm
opt/bench.sh <label>             # -> opt/runs/<label>-{native,wasm}.jsonl (5 proves, 5 + 5 verifies; wasm 3 / 1)
opt/prof.sh <label> [1|2]        # gprof flat profile -> opt/runs/<label>-gprof.txt (1 = R_REG, 2 = R_TX)
opt/asan.sh                      # ASan + UBSan on the malloc path -> opt/runs/asan.jsonl
```

Microbenchmarks: `micro_basemul.c` (base multiplication kernels, Karatsuba) and `micro_aes.c` (PRNG throughput).
The host is noisy (±20 % run to run), so compare runs made in the same session. `perf` is blocked on the dev host,
so the profiles come from gprof.

## Open

- **Verify against 50 ms.** The profile is now flat: LaZer's generic bookkeeping (`intvec_set`, sparse inserts,
  `int_mod`). Getting to 50 ms needs structural work, such as fewer `R_TX` equations or a typed accumulation in place
  of the generic sparse matrices. The verifier-floor analysis (`pqz-verifier-floor`) estimates how low it can go.
- Arena exhaustion still fails non-gracefully.
- No run yet in a real browser or on a phone.

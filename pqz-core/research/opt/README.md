# P6d-2: pqz-core optimisation (2026-10-13)

This is the record of one optimisation pass on PQZL, the lattice proof system of PQZ (a C fork of IBM's LaZer; see the
parent [pqz-core README](../../README.md)). The upstream cross-check ([`../upstream/`](../upstream/README.md)) had shown
that the fork was 1.75–2.6× slower than upstream LaZer, so the owner asked to optimise the fork. Nine steps (one of them later reverted) made the
transfer proof (`R_TX`) about 15× faster to create and 20× faster to verify, with byte-identical proofs. The folder
keeps the scripts and the raw runs so the numbers can be rerun.

- Branch `p6d2-opt`, merged into main as `b87078a`.
- Only the implementation changed: parameters, relations, proof format and `proofSystemId` are the same.
- Summary and analysis: `docs/research/pqz-core-e-s1.md` §11; current state: [`../../STATUS.md`](../../STATUS.md).
- **Later:** the verify time was solved by a different route, the specialised verifier `pqz_verify_fast`
  (`pqzl/sv/`): `R_TX` verifies in 8.7 ms at p99 natively in the frozen run of 2026-10-17 (parent README,
  [§1](../../README.md#1-at-a-glance)). The numbers below are the state of 2026-10-13.

## Result

Medians, one session on an AMD Ryzen 5 7235HS. Native is `pqz_bench 5 5` (clang `-O2`, portable). Wasm (the
WebAssembly build a browser wallet would run) is `run_wasm.mjs 3 1` under node. Everything ran under `scripts/capped`,
the repository's machine lock. "Arena" is the fixed memory area PQZL uses instead of `malloc`.

| | Before (main `fd8600f`) | After (P6d-2) | Upstream LaZer (AVX2, `../upstream/`) |
|---|---|---|---|
| `R_TX` prove / verify, native | 17.0 s / 14.9 s | **1.10 s / 0.72 s** | 6.6 s / 6.6 s |
| `R_TX` prove / verify, wasm | 39.6 s / 34.5 s | **1.59 s / 0.82 s** | — |
| `R_REG` prove / verify, native | 1.30 s / 1.02 s | 0.25 s / 0.17 s | 0.62 s / 0.57 s |
| `R_REG` prove / verify, wasm | 3.30 s / 2.61 s | 0.38 s / 0.23 s | — |
| Arena peak `R_TX`, native / wasm | 612 / 476 MB | 316 / 241 MB | — |
| Proof bytes `R_TX` / `R_REG` | 42,734–42,770 / 28,070–28,107 | unchanged | same |

Against the kill criteria (CTR-PQZ-09, roadmap P6d row: the limits PQZL had to meet to stay in the project):
- Prove meets the 6 s limit.
- Verify (0.72 s honest, 0.67 s worst adversarial) is still about 14× over the 50 ms limit; before this work it was about 300×.

Against the browser budgets (CTR-PQZ-18):
- Wasm prove (1.59 s) is inside the 5 s desktop budget.
- The wasm arena (230 MiB) is under the 256 MiB hard limit but 1.8× the 128 MiB budget.

## Step by step (`R_TX`, cumulative; files in `runs/`)

Each row adds one change on top of the rows above it; times are prove / verify in seconds.

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

**Step 4 was the biggest win.** Each ℓ2 equation of `R_TX` (a bound on the length of a block of secret values) selects
32 of the 146 witness polynomials. The generic code still built all 146² Gram entries (the pairwise products the norm
check needs), nearly all of them zero, and carried them through every sum, sort and copy
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
- **KAT** 19/19 against `../../pqzl/kat/lazer-3330e48.json`.
- **Symbol scan** clean, native and wasm.
- **Tampered proofs**: all five kinds rejected (`fails: 0`).
- **ASan + UBSan** (`asan.sh`): nothing beyond the four known upstream UBSan findings.

## Rerun

From the repository root (the first line changes into `pqz-core`):

```sh
cd pqz-core
pqzl/build.sh all               # native + wasm
research/opt/bench.sh <label>             # -> research/opt/runs/<label>-{native,wasm}.jsonl (5 proves, 5 + 5 verifies; wasm 3 / 1)
research/opt/prof.sh <label> [1|2]        # gprof flat profile -> research/opt/runs/<label>-gprof.txt (1 = R_REG, 2 = R_TX)
research/opt/asan.sh                      # ASan + UBSan on the malloc path -> research/opt/runs/asan.jsonl
```

Microbenchmarks: `micro_basemul.c` (base multiplication kernels, Karatsuba) and `micro_aes.c` (PRNG throughput).
The host is noisy (±20 % run to run), so compare runs made in the same session. `perf` is blocked on the dev host,
so the profiles come from gprof.

## Open

These were the open points on 2026-10-13.

- **Verify against 50 ms.** Since solved by the specialised verifier (see the note at the top). On 2026-10-13: the
  profile is now flat: LaZer's generic bookkeeping (`intvec_set`, sparse inserts,
  `int_mod`). Getting to 50 ms needs structural work, such as fewer `R_TX` equations or a typed accumulation in place
  of the generic sparse matrices. The verifier-floor analysis (`pqz-verifier-floor`) estimates how low it can go.
- Arena exhaustion still fails non-gracefully (still open: [STATUS.md "Open"](../../STATUS.md#open)).
- No run yet in a real browser or on a phone.

# P6d (E-S1 `pqz-core` spike) and P6d-2 (optimisation) — status (2026-10-13)

Spike: branch `p6d-pqz-core`, merged to main. Optimisation P6d-2 (owner: "optimise the fork"): branch `p6d2-opt`, not
merged. README, research note `docs/research/pqz-core-e-s1.md` (§11 = P6d-2), roadmap and TODO rows written for the
spike; the roadmap / TODO rows do not carry the P6d-2 numbers yet.

## Done

- **Fork layout.** `lazer/` = LaZer `3330e48` subset (pristine copy in commit `c91b3ab`, MIT, IBM; licence in
  `lazer/LICENSE`), modified in place with `PQZ:` comments; `src/` = the rewritten layers; `params/` = codegen,
  sizing, generated headers; `kat/` = golden dump; `test/` = bench (native + wasm runner);
  `./build.sh native|wasm|all`; `./check_symbols.sh` (run by every build).
- **Six layers rewritten**: integers without GMP (`src/pqz_mpn.h`, constant-time limb ops); incomplete NTT mod
  q = 2^42 − 215, l = 4, no HEXL / CRT / float (`src/pqz_ntt.c`); integer discrete Gaussian (`lazer/grandom.c`,
  `src/pqz_fixexp.h`); fixed-point rejection (`lazer/rejection.c`, no MPFR); arena (`src/pqz_arena.c`,
  `lazer/memory.h`); ERR/ASSERT → sticky error with file:line (`src/pqz_rt.h`); bitsliced software
  AES-256-CTR; no stdio in the library; capped rejection loops; bounded proof decoder.
- **Arithmetic-layer KAT = upstream, 19/19 cases** (`kat/lazer_dump.c`, `kat/check.py`; golden
  `kat/lazer-3330e48.json` from a static upstream binary under Intel SDE 9.48.0 `-spr`, AVX2 build too).
  Re-run after all changes below: still 19/19. Upstream finding: `aes256ctr-amd64.c` strict-aliasing bug
  (dump builds with `-fno-strict-aliasing`).
- **Parameters (nprime = 1).** LaZer's tbox needs nprime > 0 (nprime = 0 is broken upstream: beta at
  `l + 2·256/d` vs tbeta at `l + loff`), so both relations carry a one-poly approximate ℓ∞ filler:
  R_REG Ds selects s[0] (coefficients in [−1, 1], Bprime 1), R_TX Ds selects e2_t (|coeff| ≤ 20, Bprime 64),
  u = 0. Headers `params/pqz_{reg,tx}_params.h` regenerated; sizing rerun `params/estimator-e-s1.txt`
  (lattice-estimator `53da598`, RC.ADPS16, pqz_delta 1.00366):

  | | kmsis | kmlwe | m2 | MSIS β | MLWE uSVP β (dual_hybrid β) | codegen proof size | expected attempts |
  |---|---|---|---|---|---|---|---|
  | R_REG | 22 | 33 | 67 | 452 (2^132.0 cl.) | 470 (462) | ≈ 29,188 B | 6.46 |
  | R_TX | 23 | 33 | 68 | 456 (2^133.2 cl.) | 470 (462) | ≈ 44,638 B | 10.15 |

  Both above the β 450 target and Kyber-512's 406. LaZer's own constants: ω = 8, η = 140, |C| = 2^129, λ = 4,
  B = 4η√(B1² + B2²), bimodal s2, γ1 = 14, JL constant 41.
- **Arena crash fixed (commit `b3ebf33`).** The hypothesis of an `nelems_max` overflow in the Schwartz–Zippel
  accumulators was wrong: there `np = 2(m1+Z+quad_many->l) > n_ = 2(m1+Z+quad_eval->l)`, so `nelems_max` is
  lowered, not raised, and ASan on the malloc path is clean. Evidence (gdb): `pqz_err = PQZ_ERR_ARENA`
  (512 MiB exhausted) then the sink handed out garbage pointers. Cause: LaZer allocates crtreps lazily, so a
  long-lived poly converted mid-call (e.g. a caller's `Ds` in `polyvec_addmul`) pinned every block freed below
  it in the lazy-LIFO arena (67 MB pinned by one 512-byte crtrep after one prove). Fix: freed inner blocks go
  on per-size free lists (≤ 32 sizes; LaZer uses ~6) and are reused; the arena peak is now within 2 % of the
  live set (measured: R_REG live 141 MB vs peak 144 MB; R_TX 603 vs 612 MB). Two upstream leaks fixed too
  (`poly_free` freed crtrep only when crt = 1; `_lnp_tbox_compute_z34` leaked `tmp_polyvec`). Upstream's
  `lnp-tbox-test.c` on q = 2^42 − 215 (scratch harness, params from `codegen/run.sh` on `lnp-tbox-params1.sage`
  + `q_fixed`, `pqz_L = 4`) passes with the arena (peak 43 MB over prove + 30 verifies) and with
  malloc + ASan/LSan/UBSan (`-DPQZ_DEBUG_MALLOC`, no leaks).
- **R_REG / R_TX prove and verify (commit `2a47f5a`).** `build/native/pqz_bench` proves, verifies, and rejects
  all five tampering kinds (bit flip, random bytes, statement coefficient changed, truncated, long unary run)
  for both relations; also clean under ASan/UBSan (malloc path). Fixes on the way: A1/A2'/B' converted to NTT
  form at init (below the arena mark), verifier asserts accept NULL Es/Em/v arrays, `__evaleq` scratch only
  for a quadratic part, z4 coded with `log2stdev4`.
- **wasm32 (commit `9e63d9f`).** `./build.sh wasm` (clang 18 `--target=wasm32-unknown-unknown`, `wasm-ld-18`,
  freestanding, `src/pqz_wasm_rt.c` for mem* and `__multi3` / branchless `__ashlti3` / `__lshrti3`, 8 MiB stack
  first, `pqz.wasm` 337 KB) and `node test/run_wasm.mjs`. Two ILP32 bugs fixed: `int_lshift` loop index `long`
  compared unsigned (wrote below the limbs), coder grandom used `long`. Same proof lengths as native for the
  same seeds; honest proofs verify, tampered ones are rejected.
- **Symbols.** `check_symbols.sh`: native and wasm library objects reference only `memcpy`, `memset`,
  `__stack_chk_fail` (+ wasm `__stack_pointer`) outside themselves. Passes on both.

## Optimisation P6d-2 (branch `p6d2-opt`)

Pure implementation changes: same parameters, same proof format, **proofs byte-identical** to main for the same
seeds after every step (the bench now prints an FNV-1a hash over the seeds' proofs: native 5 seeds `12ec7452` R_REG /
`cb562b47` R_TX, wasm and native 3 seeds `3bc7e9b3` / `834d6853`, so native and wasm proofs are also equal byte for
byte). KAT 19/19 after every step, symbol scan clean (native and wasm), tampered proofs rejected (all five kinds).

| Step (commit) | What | R_TX prove / verify native | wasm | Arena R_TX native / wasm |
|---|---|---|---|---|
| 0 main `fd8600f` | | 17.0 s / 14.9 s | 39.6 s / 34.5 s | 612 / 476 MB |
| 1 `53b5597` | base multiplication: one u128 column sum per output with a twisted operand (rho b), 64-bit `pqz_red128`; wasm32: 21-bit limbs, 64-bit products, Karatsuba on the limbs (no `__multi3`) | 12.1 / 11.0 | 18.4 / 18.6 | = |
| 2 `ad03fe4` | `pqz_qsort` heapsort (was insertion sort) | 8.4 / 7.5 | 13.9 / 11.6 | = |
| 3 `fb5a4ab` | accumulators swap instead of copying (`spolymat_swap` / `spolyvec_swap`) | 7.7 / 6.9 | 13.5 / 11.5 | = |
| 4 `6d95a35` | l2 / binary Gram terms skip zero columns of the public selection matrices (R_TX: 146² entries per l2 equation, all but 32 zero) | 1.74 / 0.91 | 2.61 / 1.35 | 325 / 251 MB |
| (5) `36ba69b`, reverted `4b7cab3` | `poly_scale` single-limb path: no measurable gain after step 4 | 1.77 / 0.85 | 2.59 / 1.31 | |
| 6 `405a3e3` | bitsliced AES: Boyar–Peralta S-box (113 gates), 8 × 8 transposes for the bit planes; 1 MiB 60 → 8.8 ms | 1.24 / 0.88 | 2.06 / 1.25 | |
| 7 `5c7e6be` | `polyvec_mul2` skips zero columns (public matrices only) | 1.19 / 0.78 | 1.94 / 1.13 | 316 / 241 MB |
| 8 `6717d5f` | Gram entries as dots over public operands that skip zero products | 1.10 / 0.75 | 1.72 / 0.95 | |
| 9 `b8767b4` | z3 term: `V R` accumulated in int64 | **1.10 / 0.72** | **1.59 / 0.82** | 316 / 241 MB |

Medians: native `pqz_bench 5 5`, wasm `run_wasm.mjs 3 1`, every run under `scripts/capped`; raw JSON in `opt/runs/`
(`opt/bench.sh`, `opt/prof.sh` gprof, `opt/asan.sh`, microbenches `opt/micro_basemul.c`, `opt/micro_aes.c`). The steps
were measured in one session, the host is noisy (±20 %), so differences under ~10 % are not resolved (steps 5, 9 native
prove). Not done, with the reason: asserts stay on (pq-zether.md §10: release builds keep the invariant checks; ~4 %);
`-O2` portable kept (§10); no AVX2 backend (the base multiplication is ~7 % of the R_TX profile now); no integer CRT
multiplication and no Karatsuba on the polynomials (the microbench: Karatsuba with u128 sums is slower than the
column kernel).

## Measured (2026-10-13, this machine, single thread)

Native: clang -O2, `pqz_bench 5 5` under `scripts/capped` (5 proves, 5 + 5 honest verifies, 10 adversarial). wasm32:
node v26.8.1, `run_wasm.mjs 3 1`. Medians. P6d-2 (`b8767b4`) against main (`fd8600f`), same session:

| | proof bytes | prove native | verify native | prove wasm | verify wasm | arena peak native / wasm |
|---|---|---|---|---|---|---|
| R_REG main | 28,070–28,107 | 1.30 s | 1.02 s | 3.30 s | 2.61 s | 144 MB / 113 MB |
| R_REG P6d-2 | same bytes | **0.25 s** | **0.17 s** | **0.38 s** | **0.23 s** | 112 MB / 87 MB |
| R_TX main | 42,734–42,770 | 17.0 s | 14.9 s | 39.6 s | 34.5 s | 612 MB / 476 MB |
| R_TX P6d-2 | same bytes | **1.10 s** | **0.72 s** | **1.59 s** | **0.82 s** | 316 MB / 241 MB |

Adversarial verifies (P6d-2): rejected in ~3 ms (R_REG) / ~16 ms (R_TX) when the decoder or the hash check fails,
else after a full verify (R_TX max 0.67 s). Init (A expansion + ABDLOP keys) 0.11 s native, 0.15 s wasm. Rejection
iterations (both loops, mean over the 5 seeds) 5.0 R_REG / 12.6 R_TX.

Kill criteria: **R_TX prove 1.10 s native meets the 6 s limit** (and the former 3 s). **Verify misses**: p99
adversarial / honest verify ≈ 0.7 s against 50 ms, ≈ 14× (was ≈ 300×); upstream LaZer verifies the same R_TX in
6.6 s (xcheck), so P6d-2 is ~9× faster than upstream there.

Browser budgets (pq-zether.md CTR-PQZ-18, node not a browser, medians not p95): R_TX wasm prove 1.59 s against 5 s
desktop / 15 s phone / 30 s hard limit (inside); wasm arena peak 241 MB = 230 MiB against 128 MiB budget (1.8×) /
256 MiB hard limit (inside, 10 % margin); `pqz.wasm` 333 KB. wasm/native now 1.1–1.5×. No decision (owner).

Profile after P6d-2 (gprof, R_TX 1 prove + 1 verify, `opt/runs/9-z3-gprof.txt`): flat; LaZer's generic sparse-matrix
and int bookkeeping (`intvec_set` 17 %, `spolymat_insert_elem` 9 %, `int_mod` / `int_redc` 15 %, `polymat_alloc`
9 %), the base multiplication 7 %, AES ~4 %. E-S1 profile (main): ~55 % ring arithmetic, 8 % insertion sort, the
rest bookkeeping; the zero entries of the selection matrices' Gram matrices were most of that bookkeeping.

## Open

1. **Verify.** After P6d-2 R_TX verifies in ≈ 0.7 s native (prove 1.1 s meets the 6 s limit); the 50 ms p99
   criterion is missed by ≈ 14×. What is left is LaZer's generic sparse-matrix bookkeeping (flat profile). Further
   levers, not done: fewer R_TX equations (e.g. merge the 16 per-digit evaleqs), restructuring the Schwartz–Zippel
   accumulation (typed dense / structured matrices instead of `spolymat` copies), verifier-side reuse; each is a
   larger change than P6d-2's. Owner's kill decision input. wasm arena 230 MiB: under the 256 MiB hard limit, 1.8×
   the 128 MiB budget.
2. **Arena exhaustion is not graceful.** On exhaustion the sink block is shared by every later allocation;
   sparse structures in it then hold garbage pointers and the call can crash instead of returning
   PQZ_ERR_ARENA. Size the arena from the measured peaks (bench uses 768 MiB; P6d-2 peaks 316 MB native) or make
   exhaustion abort the call.
3. **wasm.** Proofs equal byte for byte with native (P6d-2, seeds 0..2); no browser run (node only); R_TX needs
   ~0.25 GB of the 4 GiB wasm32 memory.
4. UBSan nits left as upstream: zero-length VLAs when M = 0 / nbin = 0 (`lnp-tbox.c` 223, 875, 3451),
   null + 0 in `aes256ctr.c:339` (P6d-2 `opt/asan.sh`: nothing else). LSan on the malloc path reports the relation
   layer's statement objects (`pqz_rel.c` frees them by arena release), on main as well; `opt/asan.sh` runs with
   `detect_leaks=0`.
5. ~~Docs: README, research note, roadmap P6d row + TODO P6 row, docs_check.~~ (done)

Scratch (not needed to resume, re-creatable): LaZer and lattice-estimator clones, the upstream tbox harness and
debug builds under the session scratchpad `p6d/`.

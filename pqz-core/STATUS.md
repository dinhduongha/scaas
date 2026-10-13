# P6d (E-S1 `pqz-core` spike) — status (2026-10-13)

Branch `p6d-pqz-core`. Not merged. No README / research note / roadmap / TODO written yet (controller's job).

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

## Measured (2026-10-13, this machine, single thread)

Native: clang -O2, `build/native/pqz_bench 7 7` under `scripts/capped` (7 proves, 7 + 7 honest verifies,
10 adversarial). wasm32: node v26.8.1, `run_wasm.mjs 3 1`. Medians.

| | proof bytes | prove native | verify native | prove wasm | verify wasm | arena peak native / wasm | rejection-loop iterations (mean) |
|---|---|---|---|---|---|---|---|
| R_REG | 28,070–28,107 | 1.20 s | 0.99 s | 3.27 s | 2.61 s | 144 MB / 113 MB | 4.3 (n = 7) |
| R_TX | 42,738–42,770 | 17.0 s | 15.2 s | 39.3 s | 33.4 s | 612 MB / 476 MB | 13.0 (n = 7) |

Adversarial verifies reject in ~3 ms (R_REG) / ~15 ms (R_TX) when the decoder or hash check fails, else after a
full verify. Init (A expansion + ABDLOP keys) 0.33 s native, 0.49 s wasm. Rejection iterations count both
loops (z3/z4 and z1/z2), so they are not directly the codegen's "total" attempts. Native timings vary ±20 %
between runs on this machine (R_TX prove 13.7–17.0 s).

Profile (gprof, R_TX): ~55 % in the ring arithmetic (`pqz_red128` 3.6·10^9 calls + `basemul16` 5.9·10^7: a
128-bit reduction per product term), 8 % `spolymat_sort` (insertion sort `pqz_qsort`), the rest LaZer's
sparse-matrix Schwartz–Zippel bookkeeping. Verify costs about as much as prove: the verifier redoes the same
Schwartz–Zippel accumulation over 2(m1+Z+l)-dimensional sparse matrices (R_TX: 64 quadratic + 80 evaluation
equations).

## Open

1. **Speed / memory.** R_TX at 15–17 s native / 33–39 s wasm and 0.5–0.6 GB is far from a wallet-friendly
   prover and an on-chain-relevant verifier; candidate work (not done): lazy reduction in `basemul16`, a
   proper sort in `pqz_qsort`, fewer R_TX equations (e.g. merge the 16 per-digit evaleqs), and verifier-side
   reuse of the accumulated matrices. Owner's kill decision input.
2. **Arena exhaustion is not graceful.** On exhaustion the sink block is shared by every later allocation;
   sparse structures in it then hold garbage pointers and the call can crash instead of returning
   PQZ_ERR_ARENA. Size the arena from the measured peaks (bench uses 768 MiB) or make exhaustion abort the call.
3. **wasm/native byte equality** of proofs not checked (only lengths and cross-checks of validity); no browser
   run (node only); 4 GiB max memory, needs ~0.5 GB for R_TX.
4. UBSan nits left as upstream: zero-length VLAs when M = 0 / nbin = 0 (`lnp-tbox.c` 223, 875, 3358),
   null + 0 in `aes256ctr.c:212`.
5. Docs: README, research note `docs/research/pqz-core-e-s1.md`, roadmap P6d row + TODO P6 row, docs_check.

Scratch (not needed to resume, re-creatable): LaZer and lattice-estimator clones, the upstream tbox harness and
debug builds under the session scratchpad `p6d/`.

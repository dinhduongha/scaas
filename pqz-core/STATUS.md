# P6d (E-S1 `pqz-core` spike) — status at checkpoint (2026-10-13, machine shutdown)

WIP branch `p6d-pqz-core`. Not merged, no docs (README / research note / roadmap / TODO) written yet.

## Done

- **Fork layout.** `lazer/` = LaZer `3330e48` subset (pristine copy in commit `c91b3ab`, MIT, IBM; licence in
  `lazer/LICENSE`), modified in place with `PQZ:` comments; `src/` = the rewritten layers; `params/` = codegen,
  sizing, generated headers; `kat/` = golden dump; `test/` = test + bench; `build.sh native`.
- **Six layers rewritten** (library objects reference only `memcpy`, `memset`, `__stack_chk_fail` + own symbols:
  `nm -u build/native/pqz_lazer.o`):
  integers without GMP (`src/pqz_mpn.h`, constant-time limb ops; `int_mod` by q pseudo-Mersenne / masked
  shift-subtract, `src/pqz_glue.h`); incomplete NTT mod q = 2^42 − 215, l = 4, no HEXL / CRT / float
  (`src/pqz_ntt.c`; upstream's CRT reconstruction used `float` + `lroundf`); integer discrete Gaussian
  (`lazer/grandom.c`, `src/pqz_fixexp.h`); fixed-point rejection (`lazer/rejection.c`, no MPFR); arena
  (`src/pqz_arena.c`, `lazer/memory.h`); ERR/ASSERT → sticky error with file:line (`src/pqz_rt.h`); bitsliced
  software AES-256-CTR (`lazer/aes256ctr.c`, generated perms `src/gen_aes.py`); no stdio in the library; capped
  rejection loops; bounded proof decoder (`lazer/coder.c`, `coder_dec_begin_len`).
- **Arithmetic-layer KAT = upstream, 19/19 cases** (`kat/lazer_dump.c` one source for both backends,
  `kat/check.py`): golden `kat/lazer-3330e48.json` from a static upstream binary built with
  `kat/build-lazer-dump.sh <dir> v4` (HEXL AVX-512 kernels forced in) and run under **Intel SDE 9.48.0
  (2024-11-25) `sde64 -spr`** (52,872 AVX512-IFMA instructions executed; tarball sha256 3173d2a5…e6; Intel
  Simplified Software License, free for any use; not vendored). The v3 (AVX2) static upstream binary gives the
  same 19/19. Cases: ring products, products accumulated in the transform domain, add/sub/neg/scale, X→X⁻¹,
  ℓ2²/ℓ∞, mat-vec, dot, decompose/power2round, AES stream, uniform and binomial samplers.
  Upstream finding: `aes256ctr-amd64.c` reads the uint64_t nonce through `unsigned long long *`; gcc 13 -O2
  -march=x86-64-v3 then drops the rng domain separator (all `dom` give the dom-0 stream); the dump builds with
  `-fno-strict-aliasing`.
- **Parameters.** LaZer codegen patched for fixed q, L = 4, and a root-Hermite target (`pqz_delta`); sized with
  lattice-estimator `53da598` (`params/e_s1_proof.sage`, `run_e_s1.sh`, record `params/estimator-e-s1.txt`).
  LaZer's own target δ = 1.0044 gives MSIS β 353 / MLWE β 357 (below Kyber-512's 406); δ = 1.00366 gives
  R_REG kmsis 22, kmlwe 33, m2 63 (MSIS β 452, MLWE β 470) and R_TX kmsis 23, kmlwe 33, m2 64 (β 456 / 470).
  LaZer's real constants: challenge ω = 8, η = 140, |C| = 2^129; λ = 4; B = 4η√(B1² + B2²) (E-S0 assumed 8η);
  bimodal s2; standard rejection on s1 with γ1 = 14; JL constant 41 confirmed.
- **Codegen proof-size estimates** (LaZer formula, nprime = 0): R_REG ≈ 27.0 KB, R_TX ≈ 42.3 KB (expected
  attempts 6.0 / 9.4). With the nprime = 1 filler (below) add ≈ 2 KB.
- Upstream's own `lnp-tbox-test.c` on q = 2^42 − 215 (nprime = 2) **passes on the fork** when memory comes from
  libc (`-DPQZ_DEBUG_MALLOC`).

## In progress / known broken

1. **Arena bug.** The same upstream tbox test crashes with the arena (SEGV in `spolyvec_free` from
   `__schwartz_zippel_accumulate`, `lnp-tbox.c:2144`, during verify). Malloc path works, so it is
   `src/pqz_arena.c` semantics (lazy LIFO free) vs some LaZer allocation pattern — likely a block freed and
   reused while a sparse vector still points into it (`nelems_max` raised after allocation, lnp-tbox.c:475-505,
   697-743: upstream enlarges `nelems_max` of spolyvecs allocated smaller; `spolyvec_free` then walks past the
   allocation). Check that first: allocate those with the larger capacity or make `pqz_arena_free` ignore it.
2. **nprime = 0 is broken upstream** (lnp-tbox.c puts beta at `l + 2·256/d` but tbeta at `l + loff`); the codegen
   now refuses nprime = 0 and `params/{reg,tx}_params.sage` use a one-poly approximate ℓ∞ filler (nprime = 1).
   **The sizing rerun with nprime = 1 was killed at shutdown**: `params/estimator-e-s1.txt` and the generated
   `params/pqz_{reg,tx}_params.h` are still the nprime = 0 versions and must be regenerated.
3. `src/pqz_rel.c` (R_REG / R_TX as tbox statements, C ABI `src/pqz.h`, proof encoding, A / ABDLOP caches) and
   `test/pqz_bench.c` compile but have not produced a valid proof yet (blocked on 1 and 2). Input R2 / R2' are
   NULL for linear equations (asserts patched to accept NULL).
4. Not started: wasm32 build (clang 18 `--target=wasm32-unknown-unknown`, `wasm-ld-18`, node runner; needs
   `memcpy`/`memset`/`__multi3` in a small rt file), forbidden-symbol scan script, README, research note
   `docs/research/pqz-core-e-s1.md`, roadmap P6d row + TODO P6 row, docs_check.

No measured prove / verify times yet (the only timings came from failing ASan -O1 debug runs and mean nothing).

## Resume (next 3 steps)

1. Regenerate params with nprime = 1: `params/run_e_s1.sh <lazer> <le> > params/estimator-e-s1.txt` (≈ 20 min,
   via `scripts/capped`), then `params/codegen/run.sh <lazer> params/{reg,tx}_params.sage >
   params/pqz_{reg,tx}_params.h`; set the Ds/u filler in `src/pqz_rel.c` (Ds selecting s[0] / e2_t, u = 0, and
   allocate/decode z4 in encproof/decproof).
2. Fix the arena crash using the upstream tbox test (scratch harness: `lnp-tbox-test.c` + `stub_rt.c`, params
   from `codegen/run.sh` on a copy of `tests/lnp-tbox-params1.sage` with `q_fixed = 2^42 - 215`, `pqz_L = 4`),
   then get `build/native/pqz_bench` to prove and verify R_REG and R_TX.
3. Measure (native, then wasm32), scan symbols, write README + research note + roadmap/TODO rows, docs_check.

Scratch at shutdown (not needed to resume, all re-creatable): LaZer clone, lattice-estimator clone, SDE,
static dump binaries and the upstream test harness under the session scratchpad `p6d/`.

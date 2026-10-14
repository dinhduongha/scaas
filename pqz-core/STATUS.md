# P6d (E-S1 `pqz-core` spike), P6d-2 (optimisation) and P6e — status (2026-10-14)

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

## Specialised verifier P6-SV (branch `pqz-sv-relfix`, not merged)

**On v2, all five relations (branch `pqz-sv-relfix` = `pqz-sv-rel3` + main; run `sv/rel3.sh v2`, `sv/runs/v2-*`;
note §0).** `pqz_sv.c` follows both tbox fixes (P6-SZ: λ × M rows in `sz_eval_challenges`; P6-L2: domain dom + i per
exact-ℓ2 equation) and the v2 statements (§7.7 `R_TX` header, `kind` word). Differential test 2,710 portable + 1,350
x86-64-v3 + 360 wasm cases over all five relations, **0 disagreements**; `sv/check_sv_fixes.sh` ok (either fix
reverted in a copy of `pqz_sv.c`: 10 / 10 disagreements; the tree: 0 / 10); `check_tbox_fixes.sh` ok, KAT 19/19,
ASan + UBSan clean. Tables built per op at its first `pqz_verify_fast` (≤ 5.2 MB per op, init back to A alone);
`SV=0 ./build.sh` leaves the specialised verifier out (`pqz.wasm` 404,755 → 350,585 B). wasm `R_TX` prover alone
221.1 MiB (13.6 % under 256 MiB), with or without the specialised verifier (v1 eager tables: 284 MB).

| v2, ms [measured] | p50 portable | p99 portable (honest / adv.) | p50 x86-64-v3 | p50 / p99 wasm | generic p50 |
|---|---|---|---|---|---|
| `R_TX` | **8.00** | 11.1 / 10.1 | 4.65 | 13.5 / 16.0 | 638 |
| `R_BURN` | 7.74 | 9.7 / 9.8 | 4.52 | 13.0 / 15.5 | 535 |
| `R_REG` | 3.87 | 5.9 / 5.5 | 2.39 | 6.8 / 9.2 | 178 |
| `R_DS` | 4.35 | 5.9 / 5.5 | 2.68 | 7.1 / 8.8 | 213 |
| `R_DR` | 4.50 | 6.1 / 6.2 | 2.87 | 7.6 / 9.8 | 204 |

Same as v1 within host noise; every relation ≥ 3× under the 50 ms p99 limit on every build. The rest of this
section is the v1 (pre-fix transcript) record.

`pqz_verify_fast` (`src/pqz_sv.c`, ABI in `pqz.h`): same decoder, transcript, challenges and checks as
`pqz_verify`, but v and w1 computed by evaluating each equation on the proof directly (selection blocks as identity
blocks, no sparse matrices), 4 × 30-bit CRT primes with a complete NTT, table-based AES-256-CTR for the JL rows,
8-row subset-sum tables for the JL fold. `pqz_verify` stays the reference. Write-up:
`docs/research/pqz-specialised-verifier.md`; runs `sv/runs/`.

| | `R_TX` p50 honest | p99 adversarial | `R_REG` p50 | generic `R_TX` | working arena `R_TX` |
|---|---|---|---|---|---|
| native portable (`-O2`) | **7.85 ms** | 10.4 ms | 3.97 ms | 660 ms | 1.7 MB (generic 273 MB) |
| native x86-64-v3 + AES-NI (`build.sh native-x86v3`) | 4.54 ms | 5.6 ms | 2.38 ms | | |
| wasm32 (node) | 11.9 ms | 13.4 ms | 5.9 ms | 741 ms | |

- Differential test (`sv/diff.sh`, `test/pqz_sv_diff.c`): 8,538 native cases (honest proofs on fresh statements, byte /
  statement mutations, 14 re-encoded field mutations, random multi-edit fuzz) + 244 wasm cases, **0 disagreements**;
  PRG check against LaZer 0 mismatches; ASan + UBSan bench and 10 min libFuzzer: no findings.
- Constraints: no malloc / GMP / MPFR / float / abort on the path, arena only (+9.1 MB of tables at init), invariant
  checks as error returns; symbol scan clean on native, x86-64-v3 and wasm objects. Prover unchanged (`proofs_fnv`
  `3bc7e9b3` / `834d6853`), KAT 19/19.
- `R_BURN` / `R_DS` / `R_DR` (branch `pqz-sv-rel3` = `pqz-sv` + `pqz-rel3`, `sv/rel3.sh`, runs `sv/runs/r3-*`):
  native portable p50 7.69 / 4.17 / 4.37 ms (p99 adversarial ≤ 10.9 / 6.5 / 7.3 ms), x86-64-v3 4.47 / 2.82 / 2.67 ms,
  wasm 13.2 / 7.2 / 7.8 ms; differential test 2,710 portable + 1,350 x86-64-v3 + 360 wasm cases over all five
  relations, **0 disagreements**; ASan + UBSan bench clean. Tables for five relations: 20.8 MB (wasm `R_TX` prove
  peak with them 284 MB, over 256 MiB).
- Open: independent review of `pqz_sv.c` against `lnp-tbox.c` (a second implementation of a soundness-critical
  check); hand-written AVX2 (floor 2.5 ms); a run on the chain host.

## R_BURN, R_DS, R_DR (branch `pqz-rel3`)

The three remaining relations (pq-zether.md §7.5, §7.9) through the same `pqz_prove` / `pqz_verify`: specs
`params/{burn,ds,dr}_params.sage`, builders in `src/pqz_rel.c` (`R_BURN` shares the `R_TX` builder), statements as
§7.7 / §7.9 (burn 50,048 B, disclosure 33,153 B), runs `rel3/runs/`. All six tamper kinds rejected, KAT 19/19,
`R_REG` / `R_TX` `proofs_fnv` unchanged, symbol scan clean. The keys of all five relations lived in the arena base:
+27 MB native / +21 MB wasm on every op (wasm `R_TX` peak 263 MB, 2 % under 256 MiB). Write-up:
`docs/research/pqz-relations-burn-disclose.md`.

**Fix-ups (branch `pqz-relfix`, owner 2026-10-13, note §5).** `R_TX` on the §7.7 layout (header 640 B, fee word at
256; 83,072 B), disclosure `kind` a 32-byte word (33,184 B, pk at 288), burn / refresh randomness fresh (spec),
e′ ∈ [−2^24, 2^24) (spec), ABDLOP keys built at a relation's first prove or verify (`pqz_init` expands A only), arena
release rebuilds the size classes. Run `rel3/relfix.sh f2` (`rel3/runs/f2-*`) [measured]: KAT 19/19; `fails 0`
(honest + six tamper kinds, all five relations, native, wasm, ASan + UBSan with only the upstream nits of Open 4);
`proofs_fnv` `R_REG` `12ec7452` / `3bc7e9b3` and `R_BURN` unchanged, `R_TX` changed by design (native
`cb562b47` → `4690aaa0`, wasm `834d6853` → `f1c3e7f6`), `R_DS` / `R_DR` changed by design; native and wasm proofs
equal byte for byte (same 5-seed hashes, all five relations). Generic verifier, `pqz_bench 10 100 31` /
`run_wasm.mjs 5 30 31`, before (`r1`) → after:

| | proof bytes | prove p50 / p99 native | verify p50 / p99 native | verify p50 wasm | arena peak per op native / wasm |
|---|---|---|---|---|---|
| `R_TX` | 42,741–42,772 | 949 / 1,155 ms | 620 / 709 ms | 761 ms | 344 / 263 → **304 / 232 MB** |
| `R_BURN` | 41,916–41,939 (same proofs) | 818 / 1,062 → 683 / 993 ms | 561 / 664 → 526 / 599 ms | 707 → 664 ms | 327 / 251 → **289 / 220 MB** |
| `R_DS` | 28,937–28,975 | 263 / 313 → 271 / 303 ms | 208 / 244 → 195 / 221 ms | 286 → 263 ms | 144 / 112 → **100 / 77 MB** |
| `R_DR` | 28,987–29,001 | 326 / 372 → 295 / 373 ms | 198 / 229 → 194 / 232 ms | 262 → 252 ms | 168 / 126 → **108 / 83 MB** |
| `R_REG` | 28,097–28,107 | 228 / 294 ms | 165 / 190 ms | 217 ms | 139 / 108 → **96 / 74 MB** |

Times and sizes unchanged within host noise (±20 %); memory is the change: "per op" is one relation per process
(`f2-alone.jsonl`), wasm `R_TX` 251 → 221 MiB (2 % → 13.6 % under 256 MiB), init 212 → 10 ms native, 292 → 26 ms
wasm, init arena 54.5 → 3.1 MB native. p99 verify (honest or adversarial, the larger) against 50 ms: `R_BURN` 624 ms
(12.5×), `R_DS` 221 ms (4.4×), `R_DR` 232 ms (4.6×).

## proofSystemId v2: the LaZer tbox soundness fixes (branch `pqz-v2`)

Two Schwartz–Zippel findings in `lazer/lnp-tbox.c`, public as [lazer#24](https://github.com/lazer-crypto/lazer/issues/24)
(P6-SZ: one challenge pair reused for all λ/2 evaluation accumulators; fix: the full λ × M matrix) and
[lazer#25](https://github.com/lazer-crypto/lazer/issues/25) (P6-L2: one domain for all exact-ℓ2 equations, only the
sum of the block norms checked; fix: `dom + i`). Both change the transcript, so one bump:
`proofSystemId = keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")` (`PQZ_PROOF_SYSTEM_ID` in `src/pqz.h`; the bench
statements now carry it at bytes 32..63). Harnesses and the regression check: `sz/README.md`, `check_tbox_fixes.sh`
(with either fix reverted it exits 1: P6-L2 reverted, the production verifier accepts the 4 pooled-slack proofs;
P6-SZ reverted, the trace reports 2 independent tests). Run `NP=10 NV=30 NPW=5 NVW=10 rel3/relfix.sh v2`
(`rel3/runs/v2-*`) [measured]: KAT 19/19, `check_tbox_fixes: ok`, `fails 0` (native, wasm, ASan + UBSan with only
the upstream nits of Open 4), symbol scan clean; native and wasm proofs equal byte for byte (5-seed and 1-seed hashes).

| `proofs_fnv` f2 → v2 | native 5 seeds | wasm 3 seeds | native 10 seeds | wasm 5 seeds (= native 5) |
|---|---|---|---|---|
| `R_REG` | `12ec7452` → `5124b5f8` | `3bc7e9b3` → `e23b746d` | `41a5db50` → `e2a4ba8d` | `12ec7452` → `5124b5f8` |
| `R_TX` | `4690aaa0` → `fa87fff6` | `f1c3e7f6` → `762dacd2` | `58c67500` → `b69bb773` | `4690aaa0` → `fa87fff6` |
| `R_BURN` | `13b973e1` → `8df6b744` | `84a163ba` → `3d80d4a8` | `3289ff3e` → `626710cc` | `13b973e1` → `8df6b744` |
| `R_DS` | `50dfbe90` → `46c77f3e` | `02f903f8` → `216b75fc` | `b6e547db` → `f4b59d4b` | `50dfbe90` → `46c77f3e` |
| `R_DR` | `7cbb59f8` → `84a15cd2` | `f5c53099` → `e0d2deda` | `d66d665a` → `ea72ce2d` | `7cbb59f8` → `84a15cd2` |

Proof sizes and arena peaks unchanged (same parameters and proof format; per-op peaks identical to `f2-alone`). Times
within host noise (the fix draws 2 M more challenge coefficients per evaluation call, the accumulations are the same):
native p50 prove / verify `R_TX` 949 / 620 → 1,061 / 648 ms, `R_BURN` 683 / 526 → 755 / 544 ms, `R_REG` 228 / 165 →
252 / 177 ms, `R_DS` 271 / 195 → 314 / 211 ms, `R_DR` 295 / 194 → 323 / 212 ms; wasm verify p50 `R_TX` 761 → 818 ms.

## z21 norm check P6-Z21 (branch `pqz-z21`, merged 2026-10-14 `a8b5b66`; no `proofSystemId` bump)

Third LaZer finding, from the independent SV review (finding 1), public as
[lazer#26](https://github.com/lazer-crypto/lazer/issues/26): `lnp_quad_verify` / `abdlop_verify` bounded ‖w − γ·w1‖
(the z22 part) but never `z21`; LNP22 Fig. 18, the codegen's `Bound_` / `Bsq` and the honest prover bound the whole
z2. Both verifiers (`lazer/lnp-quad.c`, `lazer/abdlop.c`, `src/pqz_sv.c`) now check ‖z21‖² + ‖w − γ·w1‖² ≤ Bsq.
Verifier only: transcript and honest proofs unchanged, `proofSystemId` stays v2 (recommendation: no bump; owner).
Before the fix the enforced MSIS instances were β 286–311 instead of 452–461 (`params/estimator-z21.txt`). Write-up
`docs/research/pqz-z21-norm.md`. Regression: `check_tbox_fixes.sh` runs `sv/review/review.sh norm` (z21_big
rejected by both verifiers, accepted by the control without the z21 term); `sv/diff.sh` runs the z21 differential
`sv/review/review.sh zdiff`. SV hardening from the review folded in (findings 2, 4–7; finding 8 is Open 6).

Run `NP=10 NV=30 NPW=5 NVW=10 rel3/relfix.sh z21full` + `sv/check_sv_fixes.sh` + `ZN=2 sv/diff.sh z21` + ASan
z21 differential [measured]: KAT 19/19; `check_tbox_fixes: ok`; `check_sv_fixes: ok`; `fails 0` (native, wasm,
ASan + UBSan with only the Open 4 nits); `proofs_fnv` of all five relations unchanged from v2 (native 5 / 10 seeds,
wasm 3 / 5 seeds); PoC `z21_big` ACCEPT / ACCEPT before (`rel3/runs/z21-before-norm.txt`) → REJECT / REJECT
(`z21full-norm.txt`), PoC proofs byte-identical; differential test (v2-sized sample) 2,710 cases, 0 mismatches
(`sv/runs/z21s-diff-portable.jsonl`); z21 differential 290 z21-inflated proofs, 0 disagreements, verdict = (‖z2‖² ≤
Bsq) in every case (`sv/runs/z21s-z21diff.jsonl`); the same under ASan + UBSan 145 cases, 0 disagreements, no sanitizer report (`sv/runs/z21s-asan-*`). Generic verify p50 native `R_TX` 677 ms, `R_REG` 184 ms
(v2 648 / 177, noise).

## Hedged prover P6e Task 1 (branch `p6e-a1`; CTR-PQZ-19, P6e plan gap G2 / decision D6; no `proofSystemId` bump)

`do_prove` derived the commitment randomness and every mask from `rnd32` alone (`SCAAS-PQZ-PROVER-RND-V1` /
`…-SUB-V1`): a repeated `rnd32` (a weak browser RNG) for two witnesses repeated the masks. Now
`pqz_prover_seeds` (`src/pqz_rel.c`) = `SHAKE128("SCAAS-PQZ-PROVER-RND-V2" ‖ rnd32 ‖ wh ‖ hash0)` and `…-SUB-V2`, with
`wh = SHAKE128("SCAAS-PQZ-PROVER-WIT-V2" ‖ wit)[0..32)` (inner tag added after review, run `hedge2`) and `hash0` the
statement digest; `do_prove` zeroes the seeds after use. Prover only: verifiers, transcript, proof format unchanged;
honest proofs change. Tests: `pqz_bench` (every run with `R_REG`): the seeds of two valid `R_REG` witnesses (keys
`KF`, `KT`) under one `rnd32` and statement differ in 245 / 512 bits, one witness under two statements in 248 / 512,
equal inputs give equal seeds, two proves with one `rnd32` give the same proof (`{"hedge": true}`); `pqz_sv_diff`
(test hooks): the seeds `do_prove` used equal `pqz_prover_seeds(rnd32, wit, hash0)` for one prove per relation
(`"prover_seeds_match": 1`, all five, portable and x86-64-v3). The Ligero (PQZH) half of D6 is Part B.

Runs [measured], current = `hedge2` (the first run without the inner tag, `hedge`, is kept):
`NP=10 NV=30 NPW=5 NVW=10 rel3/relfix.sh hedge2` (`rel3/runs/hedge2-*`, summary `hedge2-relfix-summary.txt`) and
`sv/rel3.sh hedge2` + `sv/review/review.sh zdiff 1` (`sv/runs/hedge2-*`, summary `hedge2-summary.txt`), one capped
job: KAT 19/19; `check_tbox_fixes: ok`; `check_sv_fixes: ok` (tree 0 / 10, either fix reverted 10 / 10); differential
test 2,710 portable + 1,350 x86-64-v3 cases, 0 mismatches, PRG 0; wasm `PQZ_VERIFY=both` 0 mismatches; z21
differential 145 cases, 0 disagreements; `fails 0` everywhere (native, wasm, ASan + UBSan with only the Open 4 nits);
symbol scan clean (native, x86-64-v3, wasm, wasm without SV). Native and wasm proofs equal byte for byte (native 5
seeds = wasm 5 seeds; one seed alone: native = wasm generic = wasm fast = wasm without SV). Proof sizes within noise
(largest proof ±30 B: 28,113 / 42,797 / 41,939 / 28,995 / 28,996 B against v2's 28,108 / 42,770 / 41,940 / 28,976 /
28,999); arena and wasm prove peaks identical (wasm `R_TX` 231,858,048 B); times within host noise.
`../artifact/expected-results.json` regenerated from `hedge2` (provisional, 69 / 69 checks ok).

| `proofs_fnv` v2 → hedge → **hedge2** | native 5 seeds (= wasm 5) | wasm 3 seeds | native 10 seeds | 2 seeds (SV runs) | 1 seed (alone) |
|---|---|---|---|---|---|
| `R_REG` | `5124b5f8` → `edf1b937` → **`8bd69f2d`** | `e23b746d` → `3e34faff` → **`e70b5dc4`** | `e2a4ba8d` → `d4d4ef83` → **`b82d49f8`** | `a0faa73c` → `95c626e4` → **`1af59837`** | `a4477f23` → `04429652` → **`25074bbb`** |
| `R_TX` | `fa87fff6` → `4ec9c6e9` → **`ca69759d`** | `762dacd2` → `98fa56d9` → **`177e6806`** | `b69bb773` → `41fd0d94` → **`cabd8270`** | `71396f48` → `785a380d` → **`1d42a571`** | `6ffad36b` → `451d28c1` → **`e2cf9721`** |
| `R_BURN` | `8df6b744` → `242a6785` → **`bfb900f9`** | `3d80d4a8` → `c32fe93d` → **`37654486`** | `626710cc` → `9c5da57f` → **`049029ff`** | `330c19fd` → `496c53b7` → **`12f45572`** | `478eb819` → `819bba23` → **`d8180c60`** |
| `R_DS` | `46c77f3e` → `dac15c76` → **`b4aa2e26`** | `216b75fc` → `3c9cde98` → **`f39a8e64`** | `f4b59d4b` → `4f4a10ab` → **`5429242c`** | `d7fbc082` → `3f530c3f` → **`9eb44281`** | `10639246` → `4075f5f5` → **`478a0d94`** |
| `R_DR` | `84a15cd2` → `37a226ae` → **`c800f2c6`** | `e0d2deda` → `78688027` → **`96a6e906`** | `ea72ce2d` → `2da4e9b2` → **`e53ad440`** | `22be6479` → `2d06acff` → **`5bb0078c`** | `82621a18` → `7db4b018` → **`cb2f3ced`** |

## KeyGen / Enc / Dec from seeds P6e Task 3 (branch `p6e-a1`; pq-zether.md §4.2, P6e plan gap G4)

`src/pqz_keys.c` (ABI in `pqz.h`): `pqz_keygen(seed32, pk, s, e, &ctr)`, `pqz_enc_seed(pks, n, msgs, seed_enc, u, vs,
r, e1, e2, &ctr)`, `pqz_dec(s, ct, M, noise)`, §4.2 literally: one SHAKE256 stream per counter (`SCAAS-PQZ-KEYGEN-V1`
/ `SCAAS-PQZ-ENC-V1` ‖ seed ‖ be4(ctr)), CBD bits LSB-first, `s` then `e` (`r`, `e1`, then `e2_j` in recipient order),
resample above 36 / 164 / 64, error at counter 64; pk / ciphertext coefficients ≥ q and digits > 15 rejected; the ring
work is `pqz_rel.c`'s. SHAKE256 = LaZer's Keccak core at rate 136 (`lazer/shake128.c`, `PQZ:`). Independent check:
`smartcontracts/vectors/pqz/pqz_kat.py` (Python stdlib, Task 4). Run [measured] (`test/runs/keys-*`, `./build.sh all`
+ wasm without SV + x86-64-v3 under one capped job): symbol scan clean on all five object sets; `pqz_keys_kat 1000`:
SHAKE256 on 10 inputs (absorb and squeeze split in two), KeyGen on 20 seeds, Enc to two recipients and Dec on 20 seeds
all equal to `pqz_kat.py --c-keys` (`keys-pqz-kat.txt`: ok; a tampered copy fails on each changed field); round trip
1,000 seeds `Dec(Enc(m)) = m`, max |noise| 543 ≤ B_FRESH 11,872, every counter 0, 3 / 3 non-canonical inputs rejected;
1.9 s, 5.7 MB RSS. After review (`test/runs/keys2-*`, built in the `hedge2` job): Dec by both recipients checked in
Python (40 Decs); the resample path and the counter-64 error pinned with lowered thresholds through test hooks
(`PQZ_TEST_HOOKS` object of `pqz_keys.c`, never in libpqz; `‖s‖ ≤ 32`, `‖e‖ ≤ 143`, `‖e2_j‖ ≤ 12`, and a threshold 0):
6 + 6 lowered KeyGen / Enc lines, 4 KeyGen and 3 Enc resampled (counter ≥ 1), 2 counter-64 errors, all equal to
`pqz_kat.py`; every keys entry point and the three `pqz_rel.c` helpers return `PQZ_ERR_INTERNAL` before `pqz_init`
(6 / 6); `pqz_dec` rounds branch-free (one unsigned division by the constant 2Δ) and zeroes `w`; the CBD bit buffer is
zeroed with the SHAKE state (`keys2-pqz-kat.txt`: ok; a tampered copy fails on each changed field). Not measured: wasm
(P6e Task 7, `pqz-ffi` `prove` feature).

## Auditor-off transfer `R_TX0` P6e Task 2 (branch `p6e-a2`; CTR-PQZ-24, P6e plan gap G1 / decision D8, ruling R6; no `proofSystemId` bump)

`R_TX` without the auditor: no `pk_a`, `v_a`, `e2_a`, row 5 skipped, every other row and norm of `R_TX` kept (the same
917 bits). Op 1 with the 66,560-byte statement (header ‖ `pk_f ‖ pk_t ‖ T ‖ u ‖ v_t ‖ v_f`), witness 12,384 B
(`PQZ_TX0_STMT_BYTES`, `PQZ_TX0_WIT_BYTES`); `pqz_rel.c` picks `R_TX` / `R_TX0` by the length and both verifiers and the
prover require the `auditorOn` word (offset 448, `PQZ_HDR_AUDITOR_ON`) = 1 on the 83,072-byte form and 0 on the
66,560-byte one (R6). Spec `params/tx0_params.sage` → `params/pqz_tx0_params.h` by LaZer's codegen: kmsis 23, kmlwe 33,
m1 145 + m2 68, MSIS β 457 (2^133.4 classical / 2^121.1 quantum), MLWE uSVP β 470 (dual_hybrid 462), knowledge error
≤ 2^-127 (`params/estimator-e-s1-tx0.txt`). D1: the codegen rerun reproduces the five checked-in headers byte for byte
(`params/codegen-tx0.txt`, `params/regen.sh`). ABDLOP keys of its own, `SCAAS-PQZ-ABDLOP-PP-V1 ‖ 0x81` (run
`tx0b`; the first run `tx0` shared op 1's tag); the specialised verifier names it by the same internal code
`PQZ_REL_TX0` (0x81, never on the wire). Bench / diff / fuzz
relation 5 (`pqz_bench` mask 32), from the bench's `R_TX` transfer without the auditor leg.

**The bench's `R_TX` statement changed** (R6): its header word 448 was filler (`i·3`), now 1; so `R_TX`'s proofs and
`proofs_fnv` change (native 5 / 10 seeds `ca69759d` → `604111c6` / `cabd8270` → `79b9326d`, wasm 3 seeds `177e6806` →
`6780efdd`, 1 seed `e2cf9721` → `a092f2ff`); proof bytes, times and peaks the same. `R_REG`, `R_BURN`, `R_DS`, `R_DR`
proofs byte-identical to `hedge2`. Also set to 1 in `test/pqz_sv_diff.c`, `test/pqz_sv_fuzz.c` (input byte 0 now picks
`R_REG` / `R_TX` / `R_TX0`), `l2dom/l2dom_tx.c`, `xcheck/shim/bench.c`. The Ligero crate's `client::setup` writes
the same header (auditorOn 1 since `p6e-b2`; the salt word and the zero words of D15 since the merge, run `tx0c`, so
`xcheck/ligero.sh` stays byte-equal); the Plonky3 crate's `pqzh/src/client.rs` (backup, unbuilt by P6e) still writes
the filler.

Runs [measured] (`NP=10 NV=30 NPW=5 NVW=10 rel3/relfix.sh tx0`, `sv/rel3.sh tx0`, `sv/review/review.sh zdiff 1`, one
capped job each; `rel3/runs/tx0-*`, `sv/runs/tx0-*`): KAT 19/19; `check_tbox_fixes: ok`; `check_sv_fixes: ok` (tree 0 /
12, either fix reverted 12 / 12); differential test 3,484 portable + 1,736 x86-64-v3 cases over six relations, 0
mismatches (`R_TX0` 766 + 382, incl. 24 + 12 `stmt_auditor` cases: `auditorOn` changed on `R_TX` / `R_TX0`, both
verifiers reject every one), PRG 0; wasm `PQZ_VERIFY=both` 0 mismatches; z21 differential 174 cases over six relations,
0 disagreements; `fails 0` everywhere (native, wasm, ASan + UBSan with only the Open 4 nits), including all six tamper
kinds on `R_TX0` and `auditor_check` (9 cases: `R_TX` with `auditorOn` 0 — the dummy-auditor form —, 2, a high byte;
`R_TX0` with 1, 2, a high byte; each proof under the other form's statement: rejected by both verifiers, refused by
the prover); symbol scan clean; native and wasm proofs equal byte for byte (native 5 seeds `64ce6572` = wasm 5 seeds;
1 seed `bdf2a395` native = wasm generic = wasm fast = wasm without SV). `pqz.wasm` 411,419 B (without SV 356,523 B).

| `R_TX0` [measured] | value | for reference `R_TX` (same runs) |
|---|---|---|
| proof bytes, max of 10 native seeds (codegen estimate) | 42,448 (44,286) | 42,799 (44,638) |
| prove p50 / p99 native; p50 wasm | 857 / 1,002 ms; 1,272 ms | 862 / 1,062 ms; 1,235 ms |
| generic verify p50 / p99 native (adversarial p99); p50 wasm | 592 / 637 ms (669); 771 ms | 633 / 696 ms (663); 795 ms |
| SV p50 / p99 portable (adversarial p99) | 8.23 / 9.36 ms (9.60) | 7.86 / 8.61 ms (8.05) |
| SV p50 / p99 x86-64-v3 (adversarial p99) | 4.81 / 5.28 ms (5.65) | 4.71 / 5.00 ms (5.44) |
| SV p50 / p99 wasm (adversarial p99) | 13.5 / 15.2 ms (14.3) | 13.4 / 13.9 ms (14.1) |
| arena peak, one op, native / wasm | 298.0 / 227.3 MB (216.7 MiB, 15.3 % under 256 MiB) | 304.2 / 231.9 MB |
| SV tables / SV verify working set / generic verify working set | 5.17 / 1.66 / 267 MB | 5.22 / 1.67 / 273 MB |

Every `R_TX0` number is within host noise of `R_TX` or just under it (one key and one ciphertext slot fewer); SV p99
≤ 15.2 ms against the 60 ms limit on every build.

**After review (controller 2026-10-14), run `tx0b`** (`rel3/runs/tx0b-*`, `sv/runs/tx0b-*`; `tx0` kept): `R_TX0` gets
its own ABDLOP keys (tag byte 0x81), and the bench's debit statements carry the canonical salt word (16 zero bytes ‖
salt, CTR-PQZ-19; `R_TX` / `R_TX0` keep the filler as the 16-byte salt, `R_BURN` salt 0), which the decoder (`pqz-stmt`,
`pqz_kat.py`) now enforces (pqz-core only hashes the word). So `R_TX`, `R_TX0` and `R_BURN` proofs change once;
`R_REG`, `R_DS`, `R_DR` stay byte-identical to `hedge2`. Same checks, all green [measured]: KAT 19/19,
`check_tbox_fixes: ok`, `check_sv_fixes: ok`, differential 3,484 + 1,736 cases 0 mismatches (24 + 12 `stmt_auditor`
on `R_TX0`, 0 accepted), wasm both 0, z21 differential 174 / 0, `fails 0` native, wasm, ASan + UBSan, `auditor_check`
9 / 9, native = wasm proofs. `R_TX0` in `tx0b`: proof ≤ 42,456 B, prove p50 / p99 native 917 / 1,256 ms, wasm 1,047
ms, generic verify p50 / p99 native 574 / 594 ms (adversarial 656), wasm 766 ms, SV p50 / p99 portable 8.01 / 9.25
(adversarial 8.63), x86-64-v3 4.83 / 6.49 (4.93), wasm 13.3 / 15.5 (16.8) ms, peaks as `tx0` (298.0 / 227.3 MB).
`../artifact/expected-results.json` regenerated from `tx0b` (provisional, 69 / 69).

**Second review (controller 2026-10-14), run `tx0c`** (`tx0`, `tx0b` kept), after merging `main` (`p6e-b2`): the
`auditorOn` read in `parse_debit` / the SV's `parse_stmt` split into two statements (it was read unsequenced with the
call, C11 6.5.2.2p10; no other such read in `src/` or `lazer/`); D15 now also pins the header words §7.7 / §7.5 fix to 0
(a transfer's `amount` / `recipient`, a burn's `toUA` / `auditorOn` / whole `salt`, a refresh's `toUA` / `amount` /
`recipient` / `auditorOn` / `salt`; decoder only, `pqz-stmt` and `pqz_kat.py`), and the bench writes them so (`R_TX`
recipient 0; `R_BURN` toUA, auditorOn 0), so `R_TX`, `R_TX0`, `R_BURN` proofs change once more; `R_REG`, `R_DS`,
`R_DR` still byte-identical to `hedge2`. All green [measured]: KAT 19/19, `check_tbox_fixes: ok`, `check_sv_fixes:
ok`, differential 3,484 + 1,736 cases 0 mismatches, wasm both 0, z21 differential 174 / 0, `fails 0` native, wasm,
ASan + UBSan, `auditor_check` 9 / 9, native = wasm proofs (5 and 1 seeds). `R_TX0` in `tx0c`: proof ≤ 42,441 B, prove
p50 / p99 native 827 / 1,128 ms, wasm 1,398 ms, generic verify p50 / p99 native 577 / 627 ms (adversarial 627), wasm
760 ms, SV p50 / p99 portable 8.03 / 8.49 (adversarial 8.82), x86-64-v3 4.68 / 5.53 (4.92), wasm 13.4 / 14.7 (14.4)
ms. `../artifact/expected-results.json` regenerated from `tx0c` (provisional, 69 / 69). The Ligero crate's
`client::setup` writes the same header words: `pqzh/ligero/runs/l13-*` (EVM fixtures re-exported, `cargo test` 15 +
14 ok, `--no-default-features` ok, wasm32 build ok, `xcheck/ligero.sh` all ten files equal + `kat_stmt: ok`, forge
16 / 16 passed on the re-exported fixtures; its first try failed only because this worktree had no `lib/`,
`l13-forge-failed-nolib.txt`).

| `proofs_fnv` hedge2 → tx0 → tx0b → **tx0c** | native 5 seeds (= wasm 5) | wasm 3 seeds | native 10 seeds | 2 seeds (SV runs) | 1 seed (alone) |
|---|---|---|---|---|---|
| `R_REG` | **`8bd69f2d`** (unchanged) | **`e70b5dc4`** | **`b82d49f8`** | **`1af59837`** | **`25074bbb`** |
| `R_TX` | `ca69759d` → `604111c6` → `239c8b8d` → **`b9bbf854`** | `177e6806` → `6780efdd` → `ced8bcc3` → **`9304299b`** | `cabd8270` → `79b9326d` → `e55b1313` → **`0b786555`** | `1d42a571` → `3ef1da5b` → `09b11092` → **`559b3c44`** | `e2cf9721` → `a092f2ff` → `0e0026f2` → **`008d4495`** |
| `R_BURN` | `bfb900f9` → `bfb900f9` → `d94216dd` → **`0a5976da`** | `37654486` → `37654486` → `07fbdc5c` → **`0ea1c7a6`** | `049029ff` → `049029ff` → `801e15c2` → **`c7e99b6b`** | `12f45572` → `12f45572` → `73ad9a0a` → **`7694fd9f`** | `d8180c60` → `d8180c60` → `780a00bb` → **`ad3e8a12`** |
| `R_DS` | **`b4aa2e26`** (unchanged) | **`f39a8e64`** | **`5429242c`** | **`9eb44281`** | **`478a0d94`** |
| `R_DR` | **`c800f2c6`** (unchanged) | **`96a6e906`** | **`e53ad440`** | **`5bb0078c`** | **`cb2f3ced`** |
| `R_TX0` (new) | `64ce6572` → `17bbacad` → **`a29a5747`** | `2ae5a78d` → `ac79db76` → **`a0afafc7`** | `8721892b` → `30b085ff` → **`a2759b37`** | `a41428e2` → `b10b632d` → **`8b99b979`** | `bdf2a395` → `0fe80168` → **`bfdc29df`** |

## `pqz-stmt`, the statement codec P6e Task 5 (branch `p6e-a2`; plan R2, D15, R6, D5 limits, D2 / D3 ids)

`stmt/` (Rust 1.97.1, `no_std` + `alloc`, no dependencies, no `unsafe`, no floats): `parse(op, stmt)` for every form
(`TRANSFER` 83,072 B, `TRANSFER0` 66,560 B by length, `BURN` / `REFRESH`, `REGISTER`, `DISCLOSE-SENDER` /
`-RECEIVER` / `-AUDITOR`, `SELFTEST` empty) with the D15 / R6 rules in `pqz_kat.py`'s order (opTag of the op, known
`proofSystemId`, length, `fee` / `amount` < 2^64, `auditorOn` by length, coefficients < q), borrowing (no allocation);
`Stmt::encode` (`encode(parse(x)) = x`); `pk` / ciphertext / coefficient codecs; bundle (16,688 / 16,560 B) and the
canonical `abi.encode(bytes, bytes)` opening; `decode_input` for the precompile (`≤ MAX_INPUT` 393,216, `1 ≤
len(proof) ≤ MAX_PROOF(id)`: PQZL 98,304, PQZH 262,144; SELFTEST exactly `06 00000000`); the opTags, both ids, the
form lengths and the prover-API witness lengths. Not in it (they need Keccak): `ctHash`, `authDigest`, `entryRef` (in
`pqz_kat.py`; `pqz-ffi` later). Run `scripts/capped pqz-core/stmt/xcheck.sh stmt1` (`stmt/runs/stmt1-*`) [measured]:
7 unit tests (round trip of every form under both ids, field offsets, 32 rejection cases one per D15 / R6 rule incl.
coefficient = q / = 2^42, fee = 2^64, `auditorOn` 2 / 0 on 83,072 B / 1 on 66,560 B, length ± 1, foreign opTag,
unknown id; bundle, opening, input) ok; cross-check ok: the six C statements of `pqz_bench.c` (`pqzh/xcheck/
dump_setup`, opTag word set to the form's: the bench writes a marker there) parse, re-encode and rebuild from their
fields byte for byte, and `pqz_kat.py` rebuilds the same six; 32 random statements built by `pqz_kat.py` (both ids)
parse to the same fields and are built back to the same bytes; 178 mutations `pqz_kat.py` rejects are rejected for
the same reason; `cargo build --target wasm32-unknown-unknown` ok, `cargo tree`: no dependency. After review (run
`stmt2`, `stmt1` kept): `fee` / `amount` < 2^64 checked on every debit form (stricter than the relations, which read
`amount` only for BURN), and the salt word must be 16 zero bytes ‖ salt (`Reject::Salt`; pqz-core only hashes it, so
the decoder is where it is enforced), in `pqz-stmt` and `pqz_kat.py` alike; 7 unit tests ok (32 rejection cases), C 6
/ 6 equal (the bench statements now canonical, no salt rewrite), 32 `pqz_kat.py` statements equal, 186 rejections
with the same reason, wasm32 ok. Second review (run `stmt3`): `parse_opening` checks every sum on a length word
(`checked_next_multiple_of` / `checked_add`; unit cases with length words near 2^64), the D15 zero words above
(`Reject::MustBeZero(field)`, `pqz_kat.py` "<field> must be 0", same order), the C statements now come from `dump_setup
DIR pqzh` (real opTags and the PQZH id, no rewrite); 7 unit tests ok in release and in debug (overflow checks on), C 6 /
6 equal, 32 `pqz_kat.py` statements equal, 210 rejections with the same reason, wasm32 ok. The Ligero crate moves
onto it in Part B Task 6.

## `pqz-ffi`, the precompile boundary P6e Task 7 (branch `p6e-a3`; plan D10, R5, D13; CTR-PQZ-10)

`ffi/` (Rust 1.97.1; `ffi/README.md`): `pqz_precompile(input, len, out, out_len) -> status` (`ffi/pqz_ffi.h`, for P6f's
P/Invoke: 0 ok, 1 revert = input over `MAX_INPUT` 393,216 B, 2 bad arguments, 3 caught panic / core fault ⇒ `…00`),
`precompile` / `decode` / `verify_input` in Rust, feature `prove` (PQZL `pqz_prove` / PQZH Ligero by the statement's
id, keygen / enc / dec, the witness layouts, a seeded fixture of every form). Input → `pqz_stmt::decode_input` (D5,
D15, R6) → `proofSystemId`: PQZL to `pqz_verify_fast` (the generic verifier only in tests, R5), PQZH to Ligero
(`default-features = false`, behind `src/pqzh.rs` only: the Ligero API moves in `p6e-b3`), op 6 to the cached self-test
(D13). libpqz is compiled by `build.rs` from `src/`, `lazer/`, `params/` with `build.sh`'s flags and
`check_symbols.sh` on the archive (wasm32: `pqz_wasm_rt.c`'s branch-free 128-bit helpers kept, Rust provides `mem*`).
**Open 6 closed at this layer**: every libpqz call runs under one process-wide lock, on one worker thread with a fixed
16 MiB stack (found by the first run `ffi1`: a test thread's 2 MiB overflows in the prover, so the core's stack must not
depend on the caller's thread); a poisoned lock re-initialises the core. Arenas allocated once: verify-only 136 MiB =
1.5 × the measured peak 94,615,600 B (all six forms' ABDLOP keys and SV tables kept, plus the self-test), prove /
generic verify 448 MiB. Self-test: `keccak256(kat_digest ‖ 1 ‖ 0 ‖ 1 ‖ 0)` =
`ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205` (A digest = `pqz_kat.py`'s `f176b313…`, KeyGen,
Enc / Dec, a Ligero FFT round trip; one compiled-in `R_REG` proof per id, `ffi/selftest/*.hex`), cold 83 ms.

Runs [measured] `scripts/capped pqz-core/ffi/run.sh ffi1c` (`ffi/runs/ffi1c-*`; `ffi1` stack overflow and too small an
arena, `ffi1b` one wrong expectation in the test, both kept): 11 + 1 tests ok — round trip of every form (PQZL 8 = six
relations + REFRESH + AUDITOR, PQZH 7; PQZH `R_TX0` pending Ligero Task 8), 412 rejection cases (each D15 / R6 rule
with its `Reject`, op / opTag / id confusion, lengths ± 1, `MAX_PROOF + 1`, truncated / extended / flipped proofs, the
other system's id, framing; `MAX_INPUT + 1` = revert), PQZL differential SV vs generic through the FFI 56 cases / 0
disagreements, abort-freedom 10,240 inputs serial and from 8 threads through the C ABI (identical results, status 3
never, 158 valid = exactly the unedited honest ones, Ligero panics 0), C ABI arguments, self-test, compiled-in proofs =
a fresh prove, the precompile path on a 1 MiB caller stack, `pqz_ffi.h` constants; C smoke test against the header
ok; `libpqz_ffi.so` needs only libc / libgcc_s, 0 GMP / MPFR / HEXL names or strings, 0 libm imports; clippy
`float_arithmetic` clean; wasm32: verify-only lib builds, the prove harness (`ffi/wasm/`, 850 KB) proves every form
of both ids in node (15.6 s) and prints the same 17 digest lines as native (fixtures, proofs byte-equal, verdicts,
self-test hash).

| verify through the FFI [measured] p50 / p99 ms, native, n = 200 | direct (bare call) | `precompile` | C ABI | adversarial (C ABI, one flipped proof bit) |
|---|---|---|---|---|
| PQZL `R_TX` / `R_TX0` | 7.91 / 9.71; 7.80 / 11.18 | 7.91 / 8.65; 7.90 / 12.13 | 7.93 / 9.28; 7.94 / 12.18 | 8.11 / 9.27; 7.72 / 8.50 |
| PQZL `R_BURN` / REFRESH | 7.49 / 7.82; 7.49 / 8.47 | 7.59 / 8.67; 7.55 / 8.83 | 7.64 / 8.92; 7.56 / 8.23 | 7.60 / 9.04; 7.59 / 8.37 |
| PQZL `R_REG` / `R_DS` / `R_DR` / AUDITOR | 3.98–4.55 / 4.78–5.39 | 4.02–4.58 / 4.71–5.76 | 4.04–4.59 / 4.88–5.33 | 4.03–4.61 / 4.82–6.20 |
| PQZH `R_TX` / `R_BURN` / REFRESH | 9.21–9.71 / 9.98–10.50 | 9.22–9.73 / 9.97–11.96 | 9.23–9.78 / 9.76–12.21 | 0.57–1.26 / 0.64–1.73 (rejected early) |
| PQZH `R_REG` / `R_DS` / `R_DR` / AUDITOR | 6.95–7.21 / 7.37–8.52 | 6.95–7.23 / 7.32–9.14 | 6.93–7.23 / 7.21–8.16 | 0.37–0.41 / 0.44–0.53 |

The boundary (decode ≤ 0.01 ms p99, `catch_unwind`, the lock, the worker hop) adds ≤ 0.1 ms at p50; the p99 columns
differ by host noise (± 3 ms between runs of the same call). Every op ≤ 12.2 ms p99 against the 60 ms limit.

**Fault split (controller 2026-10-14), run `ffi1d`** (`ffi/runs/ffi1d-*`; its first attempt crashed in the injection,
below): status 3 (`…00`) only for a panic in the decode / verify logic (input-caused, the same on every node); status 4
`PQZ_FFI_NODE_FAULT` = no result, `out` untouched, for a fault of the node (arena or `pqz_init` failure, worker not
created or a job on it panicked, `pqz_err == PQZ_ERR_ARENA` after a call — the core is then dropped and re-initialised —,
a failed self-test computation, an unclassified panic); Rust `Error::{Revert, NodeFault}`, `verify_input` /
`pqzl::verify_fast` return `Result<bool, NodeFault>`. `tests/fault.rs` (own process, test hooks): a 16 MiB arena and a
failing worker give status 4 with `out` untouched for verify and the self-test, PQZH unaffected, and the core recovers.
**Finding:** a fixed arena of 4–12 MiB crashes the process (SIGSEGV) instead of reporting exhaustion: exhaustion inside
LaZer's key generation is not graceful (Open 2); 14–20 MiB fails gracefully, ≥ 24 MiB verifies `R_TX`
(`ffi/runs/ffi1d-arena-probe.txt`, `ffi/runs/arena-probe.sh`). Status 4 therefore covers the exhaustion the core survives;
the production arena (136 MiB, 1.5 × the six-form peak) keeps it out of reach. All other `ffi1d` checks as `ffi1c`.

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
   larger change than P6d-2's. Owner's kill decision input. wasm arena `R_TX` 221 MiB per op since the fix-ups
   (230 MiB after P6d-2): under the 256 MiB hard limit, 1.7× the 128 MiB budget.
2. **Arena exhaustion is not graceful.** On exhaustion the sink block is shared by every later allocation;
   sparse structures in it then hold garbage pointers and the call can crash instead of returning
   PQZ_ERR_ARENA. Size the arena from the measured peaks (bench uses 768 MiB; P6d-2 peaks 316 MB native) or make
   exhaustion abort the call. `pqz-ffi` (P6e Task 7) sizes both from measurement (verify-only 136 MiB =
   1.5 × 94.6 MB, prove 448 MiB); its first run `ffi1` used 64 MiB for verify-only and the core, out of arena, rejected
   honest proofs (`ffi/runs/ffi1-bench.jsonl`, `all_valid: false`) without crashing, and `ffi/runs/ffi1d-arena-probe.txt`
   shows the crash: a 4–12 MiB arena (exhaustion in the relation's key generation) segfaults. `pqz-ffi` reports the
   exhaustion the core survives as a node fault (status 4). The core's behaviour is unchanged.
3. **wasm.** Proofs equal byte for byte with native (P6d-2, seeds 0..2); no browser run (node only); R_TX needs
   ~0.23 GB of the 4 GiB wasm32 memory (fix-ups, one op per process).
4. UBSan nits left as upstream: zero-length VLAs when M = 0 / nbin = 0 (`lnp-tbox.c` 223, 875, 3451),
   null + 0 in `aes256ctr.c:339` (P6d-2 `opt/asan.sh`: nothing else). LSan on the malloc path reports the relation
   layer's statement objects (`pqz_rel.c` frees them by arena release), on main as well; `opt/asan.sh` runs with
   `detect_leaks=0`.
5. ~~Docs: README, research note, roadmap P6d row + TODO P6 row, docs_check.~~ (done)
6. **Global library state (SV review finding 8, for P6f).** `pqz_sv.c` keeps per-call bookkeeping in statics (`svb`,
   `nsvb`) and its tables in `SR` / `SA`; `pqz_rel.c` has one arena, one base mark and the sticky `pqz_err`; `pqz.h`
   says single-threaded. The node can enter the precompile concurrently (eth_call, tracing, parallel import): two
   concurrent calls would release each other's arena and reset each other's error (expected failure: a crash or a
   wrong reject; a wrong accept would still need the final hash to match). The P6f cgo wrapper must serialise every
   libpqz call (one process-wide lock) or move to per-thread contexts. Status: **closed at the `pqz-ffi` layer** (P6e Task 7: one process-wide lock around every libpqz call, one worker thread; P6f calls `pqz_precompile` and needs no lock of its own); per-thread contexts not done.

7. ~~`keygen.json` "one seed with ≥ 1 resample (searched)" cannot be searched (≈ 2^-70 per seed).~~ Settled
   (controller 2026-10-14): the row is dropped from the plan's Task 11; the resample path and the counter-64 error are
   pinned by the test-hook KATs of Task 3 (`test/runs/keys2-*`).
8. **Secret material in the arena is not zeroed** (project-wide): the witness copies in `s1`, the masks `y`, `s2` and
   the keys `pqz_keygen` writes live in the arena (or the caller's buffers) until overwritten; `pqz_arena_release`
   does not clear them. `do_prove` zeroes its seeds, `pqz_keys.c` its SHAKE state, bit buffer and `w`. Zeroing on
   release (or per call) is open, for P6f / P6h (cost: one memset of the used arena per prove).

9. **`check_symbols.sh` passes when its files are missing** (found in P6e Task 7, run `ffi1`): it `cd`s to its own
   directory, so relative paths from elsewhere name nothing, `llvm-nm` errors inside the command substitution and the
   script still prints "symbols ok". `build.sh` and `pqz-ffi` pass existing paths (absolute in `ffi/`), so no scan so far
   was empty; a fix is `set -o pipefail`-style checking of `nm`'s status. Open.

Scratch (not needed to resume, re-creatable): LaZer and lattice-estimator clones, the upstream tbox harness and
debug builds under the session scratchpad `p6d/`.

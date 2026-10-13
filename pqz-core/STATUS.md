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

## Specialised verifier P6-SV (branch `pqz-sv`, not merged)

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
   exhaustion abort the call.
3. **wasm.** Proofs equal byte for byte with native (P6d-2, seeds 0..2); no browser run (node only); R_TX needs
   ~0.23 GB of the 4 GiB wasm32 memory (fix-ups, one op per process).
4. UBSan nits left as upstream: zero-length VLAs when M = 0 / nbin = 0 (`lnp-tbox.c` 223, 875, 3451),
   null + 0 in `aes256ctr.c:339` (P6d-2 `opt/asan.sh`: nothing else). LSan on the malloc path reports the relation
   layer's statement objects (`pqz_rel.c` frees them by arena release), on main as well; `opt/asan.sh` runs with
   `detect_leaks=0`.
5. ~~Docs: README, research note, roadmap P6d row + TODO P6 row, docs_check.~~ (done)

Scratch (not needed to resume, re-creatable): LaZer and lattice-estimator clones, the upstream tbox harness and
debug builds under the session scratchpad `p6d/`.

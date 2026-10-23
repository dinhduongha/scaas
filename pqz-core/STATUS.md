# `pqz-core` status log

This is the dated work log of record for `pqz-core`: the PQZL proof core (our fork of the LaZer lattice library)
and the Rust crates around it. It started with the P6d spike (the E-S1 experiment: the first `pqz-core`
prototype, 2026-10-13/14) and runs through the P6e relations round, the multi-recipient transfer and the
2026-10-17 freeze. For a plain overview of what PQZ is and how to build it, read [README.md](README.md) first.

## How to read this file

- **Current state** (just below): where things stand today, in a few lines.
- **Done**: what the first spike built.
- **One section per work round**, in the order the work was done. Each section heading names the round, the
  branch it was built on, and the plan labels it implements. Each section starts with what was built, then the
  runs (marked [measured] where the numbers come from a run), then any review fixes.
- **Measured (2026-10-13)**: the spike's original measurement table and its verdict against the kill criteria.
- **Open**: numbered open items. Other sections refer to them as "Open item N".

Terms used throughout:

| Term | Meaning |
|---|---|
| PQZL | the lattice proof system (LNP22 via our LaZer fork, this directory's `pqzl/`) |
| PQZH | the hash-based proof system (Ligero over F_q), the second `proofSystemId` the precompile accepts |
| relation | one kind of statement a proof proves: `R_REG` (register a key), `R_TX` (transfer), `R_TX0` (transfer without the auditor), `R_BURN` (debit with a public amount: the BURN and REFRESH forms), `R_DS` / `R_DR` (sender / receiver disclosure), `R_TXM` (the multi-recipient transfer, op 7) |
| `proofSystemId` | the 32-byte id at bytes 32..63 of every statement; any change to the transcript, parameters or format needs a new one |
| SV | the specialised verifier `pqz_verify_fast`, the fast verifier the precompile uses; the generic verifier `pqz_verify` is the reference |
| KAT 19/19 | the arithmetic-layer known-answer test: our layers against upstream LaZer, 19 cases |
| `proofs_fnv` | an FNV-1a hash the bench prints over the proofs for a fixed set of seeds; equal hashes = byte-identical proofs |
| `fails 0` | the bench's honest proofs all verify and every tampered proof is rejected |
| "plan D15", "gap G2", "R6" | labels in the P6e plan `docs/superpowers/plans/2026-10-14-p6e-relations.md` (D = decision, R = rule, G = gap); "S3", "D19" etc. under the multi-recipient work refer to the P6-ANON plan `docs/superpowers/plans/2026-10-14-p6-anon.md` |
| CTR-PQZ-NN | decision entries in `docs/decisions.md` |
| [measured] | the numbers come from the named run; raw output under the given `runs/` path |
| p50 / p99 | median / 99th-percentile time |

## Current state (2026-10-19)

- **Parameter sets (plan 5h Task 8b, 2026-10-22, branch `pqz-16k`).** PQZ's parameters are now one directory per set,
  [`params/sets/<set>/`](params/README.md), selected at compile time (C `PQZ_SET`, Rust feature `set-<set>`; one set
  per library build); the only input of a set is its `set.toml`, `params/sets/gen_set.py` derives the rest and
  `params/sets/make.sh <set> all` runs estimator → codegen → KATs → vectors → gate. Sets: `n2048-kmax1024` (the frozen
  v3 set: main's constants, vectors byte-identical, contracts until 8d), `n2304-kmax4096` (the default, owner
  2026-10-21: C = Rust = wasm32, its own vectors under `smartcontracts/vectors/pqz/n2304-kmax4096/`, PQZH compiled out
  until 8c, the v3 `proofSystemId` until 8d), `n2560-kmax16384` (shippable for customer chains: its own vectors under
  `smartcontracts/vectors/pqz/n2560-kmax16384/`, PQZH in 8c part 2) and `n2816-kmax65536` (research record, core only:
  C + Rust, no pqz-stmt / precompile / PQZH). Details: the sets' `SET.md` and [`params/sets/README.md`](params/sets/README.md).

- **PQZL v2 is forgeable; PQZL v3 fixes it on branch `pqzl-fs3`, not merged yet.** The whole-code review of
  2026-10-19 found that LaZer's tbox absorbs `z3`, `z4` and `h` after the challenges that check them
  ([lazer#28](https://github.com/lazer-crypto/lazer/issues/28), Open item 11). The fix is in all four PQZL
  verifiers and both provers, with `proofSystemId` v3, regenerated vectors and the prover-side fixes D-2 / D-3
  (section "PQZL v3: Fiat–Shamir fix"). Gate A's PASS and the frozen v2 id predate the finding; v2 is retired.
  Still to do before the merge: the reproduction package and the fuzz campaign on v3, the gate, reviews A (Rust crate)
  and B (transcript audit) (plan Tasks 6, 7, 9–12). Review fixes A–E (Codex G / agy H) are in progress, see
  `research/code-review-2026-10-19/G`, `H`.
- **Review round 2 (PQZH Rust) fixes P-A…P-H are on branch `rev2-pqzh`** (plan Task 5c), not merged: no PQZH proof
  byte or verdict changes (section "PQZH review fixes"); P-I is a gate before the STARK backup is ever
  promoted (Open item 12).
- **Chain 7622 still runs PQZL v2** (image `pqz2`, the C core), which accepts forgeable v2 proofs (a test chain; owner
  ruling), until the v3 roll-out resets it from genesis (decision F9, path B; plan Task 13).

- Every round below is merged into `main` (merge commits in the table), except PQZL v3.
- **Gate A (PQZL) and gate B (PQZH) passed on 2026-10-17**, and both `proofSystemId`s are frozen. **The freeze**
  is done: `artifact/runs/freeze-2026-10-17/` (section "Gates A / B and the freeze").
- The multi-recipient transfer (`R_TXM`, op 7) is live in the `PQZ` precompile on chain 7622 since 2026-10-17 and
  is used by the PQZ tokens.
- **The PQZL Rust port is done** on branch `pqzl-rust` (plan `docs/superpowers/plans/2026-10-17-pqzl-rust-port.md`;
  merge into `main` pending): crate `pqzl` in `pqzl/rust/`, byte-for-byte equal to the C core. Tasks 1–12 (Task 10b's
  hardening follow-ups in both cores; Task 11: `pqz-ffi` builds the Rust core by default, the C core opt-in, the 2 h
  fuzz differential clean; `gate.sh`'s gate A now covers both PQZL cores, step `rust`). Task 12:
  - the package stage "Rust = C" (`artifact/reproduce.sh`): the Rust prover's `proofs_fnv` against the C core's
    frozen hashes and the keys KAT; the pqz-ffi and vectors stages already run the Rust core (the default backend);
  - the Rust rows in `results.py`'s tables and in README §5 / `artifact/README.md`;
  - D6 (below) and the wasm32 op 7 limit raised to M = 8 on the Rust backend;
  - checks: the package's Docker quick run PASS (225 ok, `artifact/runs/t12-docker-quick/`), the node Dockerfile's
    `ffi` stage builds (`nethermind/runs/2026-10-18-ffi-stage-t12.txt`), `gate.sh t12` PASS (`runs/gate/t12-*`).
- **D6, Rust against C (port plan D6; reported, not a gate): run `d6`, 2026-10-18** (`pqzl/rust/d6.sh`, C and Rust in
  one session; the C rows of `R_TXM8`, `R_TXM1_0`, `R_TXM2_0` and their Rust rows re-run on a quiet machine after
  external load, owner ruling). The full table (six forms and eight `R_TXM` shapes, p50 / p99 native and wasm32,
  peak memory, `ffi_bench` on both backends) is in
  [pqzl/rust/README.md](pqzl/rust/README.md#d6-rust-against-c-plan-d6-task-12). Every `proofs_fnv` Rust = C, every
  bench `fails 0`. The Rust core is faster natively on every relation and needs 4–6× less memory; in wasm32 its
  verify_fast is about 2× slower than the C core's (p99 ≤ 51.0 ms, under the 60 ms limit).

  | relation | prove p50 native, C / Rust (ms) | verify_fast p99 native, C / Rust (ms) | verify_fast p99 wasm32, C / Rust (ms) | prove peak native: C arena / Rust heap (MiB) |
  |---|---|---|---|---|
  | `R_TX` | 983 / 529 | 11.4 / 8.9 | 17.5 / 32.0 | 290.1 / 60.0 |
  | `R_TXM8` (M = 8, auditor on) | 2,825 / 1,128 | 17.9 / 13.9 | 29.0 / 51.0 | 655.6 / 110.1 |
  | wasm32 op 7 M = 8 (Task 12) | — | — | — | Rust wasm32 peak 117.4 MiB (on) / 105.9 MiB (off), budget 255.6 MiB (the C M = 4 peak): **enough**, the Rust backend proves M = 8 in wasm32 (the C backend keeps M ≤ 4; CTR-PQZ-09) |
- **Which core goes to production (owner, 2026-10-18; `docs/decisions.md`):** the Rust crate `pqzl` becomes the
  production PQZL core of the `PQZ` precompile once the port is finished and verified (Rust = C on the vectors, the
  fuzz differential clean, the review passed). `pqz-ffi` then switches its default backend to it (port Task 11).
  The C core stays in the repository as the reference and the differential oracle (kept, less maintained). **Not
  live yet:** the precompile on chain 7622 still runs the C core today.

| Round (section below) | Branch | Merged into `main` |
|---|---|---|
| P6d spike ("Done") | `p6d-pqz-core` | `132d5c2`, 2026-10-13 |
| P6d-2 optimisation | `p6d2-opt` | `b87078a`, 2026-10-13 |
| P6-SV specialised verifier | `pqz-sv-relfix` | `dcf0da3`, 2026-10-13 |
| `R_BURN`, `R_DS`, `R_DR` | `pqz-rel3` | `3ad4069`, 2026-10-13 |
| Relation fix-ups | `pqz-relfix` | `7e6e9b0`, 2026-10-13 |
| `proofSystemId` v2 | `pqz-v2` | `98695de`, 2026-10-13 |
| z21 norm check | `pqz-z21` | `a8b5b66`, 2026-10-14 |
| P6e Tasks 1, 3 (hedged prover, keys from seeds) | `p6e-a1` | `09b9cc3`, 2026-10-14 |
| P6e Tasks 2, 5 (`R_TX0`, `pqz-stmt`) | `p6e-a2` | `9f55013`, 2026-10-14 |
| P6e Task 7 (`pqz-ffi`) | `p6e-a3` | `072bec1`, 2026-10-14 |
| P6e Task 11 (vectors) | `p6e-a4` | `0807e41`, 2026-10-14 |
| P6e Task 10 (fuzzing) | `p6e-a5` | `32e7ad3`, 2026-10-15 |
| P6e Task 12 (serialization spec) | `p6e-a6` | `1783ea8`, 2026-10-14 |
| Multi-recipient transfer S3 (`pqz-stmt` / `pqz-ffi`) | `p6-anon-s3` | `d7b22ec`, 2026-10-16 |
| Multi-recipient transfer S4 (vectors) | `p6-anon-s4` | `59522d6`, 2026-10-16 |
| Multi-recipient transfer S6 (reproducibility package) | `p6-anon-s6b` | `926a481`, 2026-10-17 |
| Multi-recipient transfer S8 (live on chain 7622) | `p6-anon-s8` | `63e672f`, 2026-10-17 |
| PQZL v3: Fiat–Shamir fix | `pqzl-fs3` | not yet (plan Tasks 9–12) |

Original header of this log: "P6d (E-S1 `pqz-core` spike), P6d-2 (optimisation) and P6e — status (2026-10-14)".
The spike's README, research note `docs/research/pqz-core-e-s1.md` (§11 covers P6d-2), roadmap row and TODO row
were written for the spike; the roadmap (`docs/superpowers/plans/2026-10-12-p6-roadmap.md`) and the TODO P6d row
now carry the P6d-2 numbers too.

## Done

What the first spike (P6d, branch `p6d-pqz-core`) built: a LaZer fork with six layers rewritten so that it runs
without GMP, MPFR, floats or malloc, natively and in wasm32, and proves and verifies `R_REG` and `R_TX`.

- **Fork layout.**

  | Path | Content |
  |---|---|
  | `pqzl/lazer/` | the LaZer `3330e48` subset (pristine copy in commit `c91b3ab`; MIT, IBM; licence in `pqzl/lazer/LICENSE`), modified in place, each change marked with a `PQZ:` comment |
  | `pqzl/src/` | the rewritten layers |
  | `pqzl/params/` | codegen, sizing, generated headers |
  | `pqzl/kat/` | the golden dump |
  | `pqzl/test/` | the bench (native and wasm runner) |
  | `pqzl/build.sh native\|wasm\|all` | the build |
  | `pqzl/check_symbols.sh` | the symbol scan, run by every build |

- **Six layers rewritten:**
  - integers without GMP (`pqzl/src/pqz_mpn.h`, constant-time limb operations);
  - an incomplete NTT mod q = 2^42 − 215, l = 4, with no HEXL, CRT or floats (`pqzl/src/pqz_ntt.c`);
  - an integer discrete Gaussian (`pqzl/lazer/grandom.c`, `pqzl/src/pqz_fixexp.h`);
  - fixed-point rejection sampling (`pqzl/lazer/rejection.c`, no MPFR);
  - an arena allocator (`pqzl/src/pqz_arena.c`, `pqzl/lazer/memory.h`);
  - ERR / ASSERT turned into a sticky error with file:line (`pqzl/src/pqz_rt.h`).

  Also: bitsliced software AES-256-CTR, no stdio in the library, capped rejection loops, a bounded proof decoder.
- **Arithmetic-layer KAT equals upstream, 19/19 cases** (`pqzl/kat/lazer_dump.c`, `pqzl/kat/check.py`). The golden
  file `pqzl/kat/lazer-3330e48.json` comes from a static upstream binary run under Intel SDE 9.48.0 `-spr`, and from
  an AVX2 build too. Re-run after all the changes below: still 19/19. Upstream finding: `aes256ctr-amd64.c` has a
  strict-aliasing bug (the dump builds with `-fno-strict-aliasing`).
- **Parameters (nprime = 1).** LaZer's tbox needs nprime > 0. nprime = 0 is broken upstream: beta is computed at
  `l + 2·256/d` but tbeta at `l + loff`. So both relations carry a one-polynomial approximate ℓ∞ filler:
  - `R_REG`: Ds selects s[0] (coefficients in [−1, 1], Bprime 1);
  - `R_TX`: Ds selects e2_t (|coeff| ≤ 20, Bprime 64);
  - u = 0.

  Headers `pqzl/params/pqz_{reg,tx}_params.h` regenerated; sizing rerun in `pqzl/params/estimator-e-s1.txt`
  (lattice-estimator `53da598`, RC.ADPS16, pqz_delta 1.00366):

  | | kmsis | kmlwe | m2 | MSIS β | MLWE uSVP β (dual_hybrid β) | codegen proof size | expected attempts |
  |---|---|---|---|---|---|---|---|
  | R_REG | 22 | 33 | 67 | 452 (2^132.0 cl.) | 470 (462) | ≈ 29,188 B | 6.46 |
  | R_TX | 23 | 33 | 68 | 456 (2^133.2 cl.) | 470 (462) | ≈ 44,638 B | 10.15 |

  Both are above the β 450 target and Kyber-512's 406. LaZer's own constants: ω = 8, η = 140, |C| = 2^129, λ = 4,
  B = 4η√(B1² + B2²), bimodal s2, γ1 = 14, JL constant 41.
- **Arena crash fixed (commit `b3ebf33`).**
  - *Wrong first guess.* The hypothesis was an `nelems_max` overflow in the Schwartz–Zippel accumulators. It was
    wrong: there `np = 2(m1+Z+quad_many->l) > n_ = 2(m1+Z+quad_eval->l)`, so `nelems_max` is lowered, not raised,
    and ASan on the malloc path is clean.
  - *Evidence (gdb):* `pqz_err = PQZ_ERR_ARENA` (512 MiB exhausted), after which the sink handed out garbage
    pointers.
  - *Cause:* LaZer allocates crtreps lazily. A long-lived polynomial converted in the middle of a call (for
    example a caller's `Ds` in `polyvec_addmul`) pinned every block freed below it in the lazy-LIFO arena: one
    512-byte crtrep pinned 67 MB after one prove.
  - *Fix:* freed inner blocks go on per-size free lists (≤ 32 sizes; LaZer uses ~6) and are reused. The arena
    peak is now within 2 % of the live set (measured: `R_REG` live 141 MB vs peak 144 MB; `R_TX` 603 vs 612 MB).
  - Two upstream leaks fixed too: `poly_free` freed the crtrep only when crt = 1; `_lnp_tbox_compute_z34` leaked
    `tmp_polyvec`.
  - Upstream's `lnp-tbox-test.c` on q = 2^42 − 215 passes with the arena (peak 43 MB over one prove + 30
    verifies) and with malloc + ASan/LSan/UBSan (`-DPQZ_DEBUG_MALLOC`, no leaks). Harness: a scratch harness,
    parameters from `codegen/run.sh` on `lnp-tbox-params1.sage` + `q_fixed`, `pqz_L = 4`.
- **`R_REG` / `R_TX` prove and verify (commit `2a47f5a`).** `pqzl/build/native/pqz_bench` proves, verifies, and
  rejects all five tampering kinds (bit flip, random bytes, statement coefficient changed, truncated, long unary
  run) for both relations; also clean under ASan/UBSan (malloc path). Fixes made on the way: A1 / A2′ / B′
  converted to NTT form at init (below the arena mark); the verifier's asserts accept NULL Es / Em / v arrays;
  `__evaleq` scratch only for a quadratic part; z4 coded with `log2stdev4`.
- **wasm32 (commit `9e63d9f`).** `pqzl/build.sh wasm` and `node pqzl/test/run_wasm.mjs`. Build: clang 18
  `--target=wasm32-unknown-unknown`, `wasm-ld-18`, freestanding, `pqzl/src/pqz_wasm_rt.c` for mem* and `__multi3`
  / branchless `__ashlti3` / `__lshrti3`, 8 MiB stack first, `pqz.wasm` 337 KB. Two ILP32 (32-bit `long`) bugs
  fixed: the `int_lshift` loop index was a `long` compared unsigned (it wrote below the limbs), and the coder's
  grandom used `long`. Same proof lengths as native for the same seeds; honest proofs verify, tampered ones are
  rejected.
- **Symbols.** `pqzl/check_symbols.sh`: native and wasm library objects reference only `memcpy`, `memset` and
  `__stack_chk_fail` (+ wasm `__stack_pointer`) outside themselves. Passes on both.

## Optimisation P6d-2 (branch `p6d2-opt`)

P6d-2 is the optimisation round (owner: "optimise the fork"); merged as `b87078a` on 2026-10-13. In short: `R_TX`
prove went from 17.0 s to 1.10 s native and verify from 14.9 s to 0.72 s, with byte-identical proofs.

Only the implementation changed: same parameters, same proof format, and **proofs byte-identical** to main for the
same seeds after every step. The bench now prints an FNV-1a hash over the seeds' proofs:

| Seeds | `R_REG` | `R_TX` |
|---|---|---|
| native, 5 seeds | `12ec7452` | `cb562b47` |
| native and wasm, 3 seeds | `3bc7e9b3` | `834d6853` |

So native and wasm proofs are also equal byte for byte. After every step: KAT 19/19, symbol scan clean (native and
wasm), tampered proofs rejected (all five kinds).

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

How measured: medians of native `pqz_bench 5 5` and wasm `run_wasm.mjs 3 1`, every run under `scripts/capped`. Raw
JSON in `research/opt/runs/`; scripts `research/opt/bench.sh`, `research/opt/prof.sh` (gprof),
`research/opt/asan.sh`, microbenches `research/opt/micro_basemul.c`, `research/opt/micro_aes.c`. All steps were
measured in one session on a noisy host (±20 %), so differences under ~10 % are not resolved (steps 5 and 9,
native prove).

Not done, and why:

- asserts stay on: pq-zero-knowledge.md §10 says release builds keep the invariant checks (cost ~4 %);
- portable `-O2` kept (§10);
- no AVX2 backend: the base multiplication is now only ~7 % of the `R_TX` profile;
- no integer CRT multiplication and no Karatsuba on the polynomials: the microbench shows Karatsuba with u128 sums
  is slower than the column kernel.

## Specialised verifier P6-SV (branch `pqz-sv-relfix`, merged `dcf0da3` 2026-10-13)

P6-SV is the specialised verifier `pqz_verify_fast`: it accepts exactly what the generic verifier accepts, but in
about 4–8 ms instead of 180–640 ms, which brings verify under the 50 ms p99 limit.

**Current version: v2, all five relations.** Branch `pqz-sv-relfix` = `pqz-sv-rel3` + main; run
`pqzl/sv/rel3.sh v2`, output `pqzl/sv/runs/v2-*`; see the write-up's §0.

- `pqz_sv.c` follows both tbox soundness fixes (P6-SZ: λ × M rows in `sz_eval_challenges`; P6-L2: domain dom + i
  per exact-ℓ2 equation; see the `proofSystemId` v2 section) and the v2 statements (the §7.7 `R_TX` header, the
  `kind` word).
- Differential test (SV against the generic verifier): 2,710 portable + 1,350 x86-64-v3 + 360 wasm cases over
  all five relations, **0 disagreements**.
- `pqzl/sv/check_sv_fixes.sh` ok: with either fix reverted in a copy of `pqz_sv.c`, 10 / 10 disagreements; on the
  tree, 0 / 10. `pqzl/check_tbox_fixes.sh` ok, KAT 19/19, ASan + UBSan clean.
- Tables are built per op at its first `pqz_verify_fast` (≤ 5.2 MB per op; init is back to expanding A alone).
  `SV=0 pqzl/build.sh` leaves the specialised verifier out (`pqz.wasm` 404,755 → 350,585 B).
- wasm `R_TX` prover alone: 221.1 MiB (13.6 % under 256 MiB), with or without the specialised verifier (v1's
  eager tables: 284 MB).

| v2, ms [measured] | p50 portable | p99 portable (honest / adv.) | p50 x86-64-v3 | p50 / p99 wasm | generic p50 |
|---|---|---|---|---|---|
| `R_TX` | **8.00** | 11.1 / 10.1 | 4.65 | 13.5 / 16.0 | 638 |
| `R_BURN` | 7.74 | 9.7 / 9.8 | 4.52 | 13.0 / 15.5 | 535 |
| `R_REG` | 3.87 | 5.9 / 5.5 | 2.39 | 6.8 / 9.2 | 178 |
| `R_DS` | 4.35 | 5.9 / 5.5 | 2.68 | 7.1 / 8.8 | 213 |
| `R_DR` | 4.50 | 6.1 / 6.2 | 2.87 | 7.6 / 9.8 | 204 |

Same as v1 within host noise; every relation is ≥ 3× under the 50 ms p99 limit on every build.

**The rest of this section is the v1 record** (before the transcript fixes).

How it works: `pqz_verify_fast` (`pqzl/src/pqz_sv.c`, ABI in `pqz.h`) uses the same decoder, transcript,
challenges and checks as `pqz_verify`. The difference: it computes v and w1 by evaluating each equation on the
proof directly (selection blocks as identity blocks, no sparse matrices), with 4 × 30-bit CRT primes and a complete
NTT, table-based AES-256-CTR for the JL rows, and 8-row subset-sum tables for the JL fold. `pqz_verify` stays the
reference. Write-up: `docs/research/pqz-specialised-verifier.md`; runs `pqzl/sv/runs/`.

| | `R_TX` p50 honest | p99 adversarial | `R_REG` p50 | generic `R_TX` | working arena `R_TX` |
|---|---|---|---|---|---|
| native portable (`-O2`) | **7.85 ms** | 10.4 ms | 3.97 ms | 660 ms | 1.7 MB (generic 273 MB) |
| native x86-64-v3 + AES-NI (`pqzl/build.sh native-x86v3`) | 4.54 ms | 5.6 ms | 2.38 ms | | |
| wasm32 (node) | 11.9 ms | 13.4 ms | 5.9 ms | 741 ms | |

- **Differential test** (`pqzl/sv/diff.sh`, `pqzl/test/pqz_sv_diff.c`): 8,538 native cases (honest proofs on fresh
  statements, byte / statement mutations, 14 re-encoded field mutations, random multi-edit fuzz) + 244 wasm cases,
  **0 disagreements**. PRG check against LaZer: 0 mismatches. ASan + UBSan bench and 10 min of libFuzzer: no
  findings.
- **Constraints:** no malloc, GMP, MPFR, float or abort on the path; arena only (+9.1 MB of tables at init);
  invariant checks are error returns; symbol scan clean on native, x86-64-v3 and wasm objects. Prover unchanged
  (`proofs_fnv` `3bc7e9b3` / `834d6853`), KAT 19/19.
- **`R_BURN` / `R_DS` / `R_DR`** (branch `pqz-sv-rel3` = `pqz-sv` + `pqz-rel3`, `pqzl/sv/rel3.sh`, runs
  `pqzl/sv/runs/r3-*`):

  | v1 | `R_BURN` | `R_DS` | `R_DR` |
  |---|---|---|---|
  | native portable p50 | 7.69 ms | 4.17 ms | 4.37 ms |
  | native portable p99 adversarial | ≤ 10.9 ms | ≤ 6.5 ms | ≤ 7.3 ms |
  | x86-64-v3 p50 | 4.47 ms | 2.82 ms | 2.67 ms |
  | wasm p50 | 13.2 ms | 7.2 ms | 7.8 ms |

  Differential test 2,710 portable + 1,350 x86-64-v3 + 360 wasm cases over all five relations, **0
  disagreements**; ASan + UBSan bench clean. Tables for five relations: 20.8 MB (with them, the wasm `R_TX` prove
  peak is 284 MB, over 256 MiB; v2 builds the tables lazily, see above).
- Open:
  - an independent review of `pqz_sv.c` against `lnp-tbox.c` (a second implementation of a soundness-critical
    check). *Done since:* the independent SV review produced the z21 finding and the SV hardening in section
    "z21 norm check P6-Z21" below; its finding 8 is Open item 6;
  - hand-written AVX2 (floor 2.5 ms);
  - a run on the chain host.

## R_BURN, R_DS, R_DR (branch `pqz-rel3`)

The three remaining relations (burn / refresh, sender disclosure, receiver disclosure); merged as `3ad4069` on
2026-10-13.

- They run through the same `pqz_prove` / `pqz_verify` (pq-zero-knowledge.md §7.5, §7.9).
- Specs `pqzl/params/{burn,ds,dr}_params.sage`; builders in `pqzl/src/pqz_rel.c` (`R_BURN` shares the `R_TX`
  builder); statements as in §7.7 / §7.9 (burn 50,048 B, disclosure 33,153 B); runs `research/pqzl-measure/runs/`.
- All six tamper kinds rejected, KAT 19/19, `R_REG` / `R_TX` `proofs_fnv` unchanged, symbol scan clean.
- Memory problem found: the keys of all five relations lived in the arena base, which cost +27 MB native / +21 MB
  wasm on every op (wasm `R_TX` peak 263 MB, 2 % under 256 MiB). The fix-ups below solved it.
- Write-up: `docs/research/pqz-relations-burn-disclose.md`.

**Fix-ups (branch `pqz-relfix`, owner 2026-10-13, note §5; merged `7e6e9b0`).** Changes:

- `R_TX` on the §7.7 layout (header 640 B, fee word at 256; 83,072 B);
- the disclosure `kind` is a 32-byte word (33,184 B, pk at 288);
- burn / refresh randomness is fresh (as the spec says);
- e′ ∈ [−2^24, 2^24) (as the spec says);
- ABDLOP keys are built at a relation's first prove or verify (`pqz_init` expands A only);
- arena release rebuilds the size classes.

Run `research/pqzl-measure/relfix.sh f2` (`research/pqzl-measure/runs/f2-*`) [measured]:

- KAT 19/19; `fails 0` (honest + six tamper kinds, all five relations, native, wasm, ASan + UBSan with only the
  upstream nits of Open item 4).
- `proofs_fnv`: `R_REG` `12ec7452` / `3bc7e9b3` and `R_BURN` unchanged. `R_TX` changed by design (native
  `cb562b47` → `4690aaa0`, wasm `834d6853` → `f1c3e7f6`); `R_DS` / `R_DR` changed by design.
- Native and wasm proofs equal byte for byte (same 5-seed hashes, all five relations).

Generic verifier, `pqz_bench 10 100 31` / `run_wasm.mjs 5 30 31`, before (run `r1`) → after:

| | proof bytes | prove p50 / p99 native | verify p50 / p99 native | verify p50 wasm | arena peak per op native / wasm |
|---|---|---|---|---|---|
| `R_TX` | 42,741–42,772 | 949 / 1,155 ms | 620 / 709 ms | 761 ms | 344 / 263 → **304 / 232 MB** |
| `R_BURN` | 41,916–41,939 (same proofs) | 818 / 1,062 → 683 / 993 ms | 561 / 664 → 526 / 599 ms | 707 → 664 ms | 327 / 251 → **289 / 220 MB** |
| `R_DS` | 28,937–28,975 | 263 / 313 → 271 / 303 ms | 208 / 244 → 195 / 221 ms | 286 → 263 ms | 144 / 112 → **100 / 77 MB** |
| `R_DR` | 28,987–29,001 | 326 / 372 → 295 / 373 ms | 198 / 229 → 194 / 232 ms | 262 → 252 ms | 168 / 126 → **108 / 83 MB** |
| `R_REG` | 28,097–28,107 | 228 / 294 ms | 165 / 190 ms | 217 ms | 139 / 108 → **96 / 74 MB** |

Times and sizes are unchanged within host noise (±20 %); memory is what changed. "Per op" means one relation per
process (`f2-alone.jsonl`). wasm `R_TX` 251 → 221 MiB (2 % → 13.6 % under 256 MiB); init 212 → 10 ms native,
292 → 26 ms wasm; init arena 54.5 → 3.1 MB native. Generic verify p99 (honest or adversarial, whichever is larger)
against the 50 ms limit: `R_BURN` 624 ms (12.5×), `R_DS` 221 ms (4.4×), `R_DR` 232 ms (4.6×).

## proofSystemId v2: the LaZer tbox soundness fixes (branch `pqz-v2`)

Two soundness bugs in LaZer's tbox proof (both in its Schwartz–Zippel checks) were fixed; because the fixes change
the transcript, PQZL moved to `proofSystemId` v2. Merged as `98695de` on 2026-10-13.

The two findings in `pqzl/lazer/lnp-tbox.c`, both reported publicly:

| Name | Issue | Bug | Fix |
|---|---|---|---|
| P6-SZ | [lazer#24](https://github.com/lazer-crypto/lazer/issues/24) | one challenge pair reused for all λ/2 evaluation accumulators | the full λ × M matrix |
| P6-L2 | [lazer#25](https://github.com/lazer-crypto/lazer/issues/25) | one domain for all exact-ℓ2 equations, so only the sum of the block norms was checked | `dom + i` |

Both change the transcript, so one bump: `proofSystemId = keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")`
(`PQZ_PROOF_SYSTEM_ID` in `pqzl/src/pqz.h`; the bench statements now carry it at bytes 32..63).

Harnesses and the regression check: `pqzl/sz/README.md`, `pqzl/check_tbox_fixes.sh`. With either fix reverted the
check exits 1: with P6-L2 reverted, the production verifier accepts the 4 pooled-slack proofs; with P6-SZ reverted,
the trace reports 2 independent tests.

Run `NP=10 NV=30 NPW=5 NVW=10 research/pqzl-measure/relfix.sh v2` (`research/pqzl-measure/runs/v2-*`)
[measured]: KAT 19/19, `check_tbox_fixes: ok`, `fails 0` (native, wasm, ASan + UBSan with only the upstream nits
of Open item 4), symbol scan clean; native and wasm proofs equal byte for byte (5-seed and 1-seed hashes).

| `proofs_fnv` f2 → v2 | native 5 seeds | wasm 3 seeds | native 10 seeds | wasm 5 seeds (= native 5) |
|---|---|---|---|---|
| `R_REG` | `12ec7452` → `5124b5f8` | `3bc7e9b3` → `e23b746d` | `41a5db50` → `e2a4ba8d` | `12ec7452` → `5124b5f8` |
| `R_TX` | `4690aaa0` → `fa87fff6` | `f1c3e7f6` → `762dacd2` | `58c67500` → `b69bb773` | `4690aaa0` → `fa87fff6` |
| `R_BURN` | `13b973e1` → `8df6b744` | `84a163ba` → `3d80d4a8` | `3289ff3e` → `626710cc` | `13b973e1` → `8df6b744` |
| `R_DS` | `50dfbe90` → `46c77f3e` | `02f903f8` → `216b75fc` | `b6e547db` → `f4b59d4b` | `50dfbe90` → `46c77f3e` |
| `R_DR` | `7cbb59f8` → `84a15cd2` | `f5c53099` → `e0d2deda` | `d66d665a` → `ea72ce2d` | `7cbb59f8` → `84a15cd2` |

Proof sizes and arena peaks are unchanged (same parameters and proof format; per-op peaks identical to
`f2-alone`). Times are within host noise (the fix draws 2 M more challenge coefficients per evaluation call; the
accumulations are the same):

| native p50 prove / verify, f2 → v2 | |
|---|---|
| `R_TX` | 949 / 620 → 1,061 / 648 ms |
| `R_BURN` | 683 / 526 → 755 / 544 ms |
| `R_REG` | 228 / 165 → 252 / 177 ms |
| `R_DS` | 271 / 195 → 314 / 211 ms |
| `R_DR` | 295 / 194 → 323 / 212 ms |
| wasm verify p50 `R_TX` | 761 → 818 ms |

## z21 norm check P6-Z21 (branch `pqz-z21`, merged 2026-10-14 `a8b5b66`; no `proofSystemId` bump)

A third LaZer soundness bug: the verifier never bounded part of the proof (`z21`). Fixed in both verifiers; the
honest proofs and the transcript do not change, so the id stays v2.

- **Source:** the independent review of the specialised verifier (finding 1). Public as
  [lazer#26](https://github.com/lazer-crypto/lazer/issues/26).
- **Bug:** `lnp_quad_verify` / `abdlop_verify` bounded ‖w − γ·w1‖ (the z22 part) but never `z21`. LNP22 Fig. 18,
  the codegen's `Bound_` / `Bsq` and the honest prover all bound the whole z2.
- **Fix:** both verifiers (`pqzl/lazer/lnp-quad.c`, `pqzl/lazer/abdlop.c`, `pqzl/src/pqz_sv.c`) now check
  ‖z21‖² + ‖w − γ·w1‖² ≤ Bsq. Verifier only: transcript and honest proofs unchanged, `proofSystemId` stays v2
  (recommendation: no bump; owner).
- **Impact:** before the fix the enforced MSIS instances were β 286–311 instead of 452–461
  (`pqzl/params/estimator-z21.txt`).
- Write-up `docs/research/pqz-z21-norm.md`.
- **Regression checks:** `pqzl/check_tbox_fixes.sh` runs `pqzl/sv/review/review.sh norm` (z21_big is rejected by
  both verifiers and accepted by the control without the z21 term); `pqzl/sv/diff.sh` runs the z21 differential
  `pqzl/sv/review/review.sh zdiff`.
- SV hardening from the review is folded in (findings 2, 4–7; finding 8 is Open item 6).

Run `NP=10 NV=30 NPW=5 NVW=10 research/pqzl-measure/relfix.sh z21full` + `pqzl/sv/check_sv_fixes.sh` +
`ZN=2 pqzl/sv/diff.sh z21` + the ASan z21 differential [measured]:

- KAT 19/19; `check_tbox_fixes: ok`; `check_sv_fixes: ok`; `fails 0` (native, wasm, ASan + UBSan with only the
  nits of Open item 4).
- `proofs_fnv` of all five relations unchanged from v2 (native 5 / 10 seeds, wasm 3 / 5 seeds).
- Proof of concept `z21_big`: ACCEPT / ACCEPT before the fix (`research/pqzl-measure/runs/z21-before-norm.txt`) →
  REJECT / REJECT after (`z21full-norm.txt`); the PoC proofs are byte-identical.
- Differential test (v2-sized sample): 2,710 cases, 0 mismatches (`pqzl/sv/runs/z21s-diff-portable.jsonl`).
- z21 differential: 290 z21-inflated proofs, 0 disagreements, verdict = (‖z2‖² ≤ Bsq) in every case
  (`pqzl/sv/runs/z21s-z21diff.jsonl`); the same under ASan + UBSan, 145 cases, 0 disagreements, no sanitizer report
  (`pqzl/sv/runs/z21s-asan-*`).
- Generic verify p50 native: `R_TX` 677 ms, `R_REG` 184 ms (v2: 648 / 177, noise).

## Hedged prover P6e Task 1 (branch `p6e-a1`; CTR-PQZ-19, P6e plan gap G2 / decision D6; no `proofSystemId` bump)

The PQZL prover's randomness now also depends on the witness and the statement ("hedged"), so a weak or repeated
random input no longer repeats the masks. Merged with Task 3 as `09b9cc3` on 2026-10-14.

- **Problem (gap G2: "the PQZL prover is not hedged"):** `do_prove` derived the commitment randomness and every
  mask from `rnd32` alone (`SCAAS-PQZ-PROVER-RND-V1` / `…-SUB-V1`). A repeated `rnd32` (for example from a weak
  browser RNG) for two witnesses repeated the masks.
- **Fix (decision D6: "hedge both provers before the vectors freeze"):** `pqz_prover_seeds` (`pqzl/src/pqz_rel.c`)
  = `SHAKE128("SCAAS-PQZ-PROVER-RND-V2" ‖ rnd32 ‖ wh ‖ hash0)` and `…-SUB-V2`, where
  `wh = SHAKE128("SCAAS-PQZ-PROVER-WIT-V2" ‖ wit)[0..32)` (the inner tag was added after review, run `hedge2`) and
  `hash0` is the statement digest. `do_prove` zeroes the seeds after use.
- Prover only: verifiers, transcript and proof format unchanged; honest proofs change.
- **Tests in `pqz_bench`** (every run with `R_REG`):
  - the seeds of two valid `R_REG` witnesses (keys `KF`, `KT`) under one `rnd32` and statement differ in 245 / 512
    bits; one witness under two statements, in 248 / 512;
  - equal inputs give equal seeds; two proves with one `rnd32` give the same proof (`{"hedge": true}`).
- **Tests in `pqz_sv_diff`** (test hooks): the seeds `do_prove` used equal `pqz_prover_seeds(rnd32, wit, hash0)`
  for one prove per relation (`"prover_seeds_match": 1`, all five relations, portable and x86-64-v3).
- The Ligero (PQZH) half of D6 is Part B.

Runs [measured]. The current run is `hedge2`; the first run without the inner tag, `hedge`, is kept.

- `NP=10 NV=30 NPW=5 NVW=10 research/pqzl-measure/relfix.sh hedge2` (`research/pqzl-measure/runs/hedge2-*`,
  summary `hedge2-relfix-summary.txt`) and `pqzl/sv/rel3.sh hedge2` + `pqzl/sv/review/review.sh zdiff 1`
  (`pqzl/sv/runs/hedge2-*`, summary `hedge2-summary.txt`), in one capped job.
- KAT 19/19; `check_tbox_fixes: ok`; `check_sv_fixes: ok` (tree 0 / 10, either fix reverted 10 / 10).
- Differential test 2,710 portable + 1,350 x86-64-v3 cases, 0 mismatches, PRG 0; wasm `PQZ_VERIFY=both` 0
  mismatches; z21 differential 145 cases, 0 disagreements.
- `fails 0` everywhere (native, wasm, ASan + UBSan with only the nits of Open item 4); symbol scan clean (native,
  x86-64-v3, wasm, wasm without SV).
- Native and wasm proofs equal byte for byte (native 5 seeds = wasm 5 seeds; one seed alone: native = wasm generic
  = wasm fast = wasm without SV).
- Proof sizes within noise: largest proof ±30 B (28,113 / 42,797 / 41,939 / 28,995 / 28,996 B against v2's
  28,108 / 42,770 / 41,940 / 28,976 / 28,999). Arena and wasm prove peaks identical (wasm `R_TX` 231,858,048 B);
  times within host noise.
- `../artifact/expected-results.json` regenerated from `hedge2` (provisional, 69 / 69 checks ok).

| `proofs_fnv` v2 → hedge → **hedge2** | native 5 seeds (= wasm 5) | wasm 3 seeds | native 10 seeds | 2 seeds (SV runs) | 1 seed (alone) |
|---|---|---|---|---|---|
| `R_REG` | `5124b5f8` → `edf1b937` → **`8bd69f2d`** | `e23b746d` → `3e34faff` → **`e70b5dc4`** | `e2a4ba8d` → `d4d4ef83` → **`b82d49f8`** | `a0faa73c` → `95c626e4` → **`1af59837`** | `a4477f23` → `04429652` → **`25074bbb`** |
| `R_TX` | `fa87fff6` → `4ec9c6e9` → **`ca69759d`** | `762dacd2` → `98fa56d9` → **`177e6806`** | `b69bb773` → `41fd0d94` → **`cabd8270`** | `71396f48` → `785a380d` → **`1d42a571`** | `6ffad36b` → `451d28c1` → **`e2cf9721`** |
| `R_BURN` | `8df6b744` → `242a6785` → **`bfb900f9`** | `3d80d4a8` → `c32fe93d` → **`37654486`** | `626710cc` → `9c5da57f` → **`049029ff`** | `330c19fd` → `496c53b7` → **`12f45572`** | `478eb819` → `819bba23` → **`d8180c60`** |
| `R_DS` | `46c77f3e` → `dac15c76` → **`b4aa2e26`** | `216b75fc` → `3c9cde98` → **`f39a8e64`** | `f4b59d4b` → `4f4a10ab` → **`5429242c`** | `d7fbc082` → `3f530c3f` → **`9eb44281`** | `10639246` → `4075f5f5` → **`478a0d94`** |
| `R_DR` | `84a15cd2` → `37a226ae` → **`c800f2c6`** | `e0d2deda` → `78688027` → **`96a6e906`** | `ea72ce2d` → `2da4e9b2` → **`e53ad440`** | `22be6479` → `2d06acff` → **`5bb0078c`** | `82621a18` → `7db4b018` → **`cb2f3ced`** |

## KeyGen / Enc / Dec from seeds P6e Task 3 (branch `p6e-a1`; pq-zero-knowledge.md §4.2, P6e plan gap G4)

Key generation, encryption and decryption from seeds, in C, exactly as the spec's §4.2 describes (gap G4: "KeyGen /
Enc from seeds are not in C"). Merged with Task 1 as `09b9cc3`.

- **API** (`pqzl/src/pqz_keys.c`, ABI in `pqz.h`): `pqz_keygen(seed32, pk, s, e, &ctr)`,
  `pqz_enc_seed(pks, n, msgs, seed_enc, u, vs, r, e1, e2, &ctr)`, `pqz_dec(s, ct, M, noise)`.
- **What it does (§4.2 literally):**
  - one SHAKE256 stream per counter (`SCAAS-PQZ-KEYGEN-V1` / `SCAAS-PQZ-ENC-V1` ‖ seed ‖ be4(ctr));
  - CBD bits LSB-first; `s` then `e` (for Enc: `r`, `e1`, then `e2_j` in recipient order);
  - resample above 36 / 164 / 64; error at counter 64;
  - pk / ciphertext coefficients ≥ q and digits > 15 are rejected;
  - the ring arithmetic is `pqz_rel.c`'s.
- SHAKE256 = LaZer's Keccak core at rate 136 (`pqzl/lazer/shake128.c`, marked `PQZ:`).
- Independent check: `smartcontracts/vectors/pqz/pqz_kat.py` (Python stdlib only, Task 4).

Run [measured] (`pqzl/test/runs/keys-*`; `pqzl/build.sh all` + wasm without SV + x86-64-v3 under one capped job):

- symbol scan clean on all five object sets;
- `pqz_keys_kat 1000`: SHAKE256 on 10 inputs (absorb and squeeze split in two), KeyGen on 20 seeds, Enc to two
  recipients and Dec on 20 seeds, all equal to `pqz_kat.py --c-keys` (`keys-pqz-kat.txt`: ok; a tampered copy
  fails on each changed field);
- round trip on 1,000 seeds: `Dec(Enc(m)) = m`, max |noise| 543 ≤ B_FRESH 11,872, every counter 0, 3 / 3
  non-canonical inputs rejected; 1.9 s, 5.7 MB RSS.

After review (`pqzl/test/runs/keys2-*`, built in the `hedge2` job):

- Dec by both recipients checked in Python (40 Decs).
- The resample path and the counter-64 error are pinned with lowered thresholds through test hooks
  (`PQZ_TEST_HOOKS` object of `pqz_keys.c`, never in libpqz; `‖s‖ ≤ 32`, `‖e‖ ≤ 143`, `‖e2_j‖ ≤ 12`, and a
  threshold 0): 6 + 6 lowered KeyGen / Enc lines, 4 KeyGen and 3 Enc resampled (counter ≥ 1), 2 counter-64 errors,
  all equal to `pqz_kat.py`.
- Every keys entry point and the three `pqz_rel.c` helpers return `PQZ_ERR_INTERNAL` before `pqz_init` (6 / 6).
- `pqz_dec` rounds branch-free (one unsigned division by the constant 2Δ) and zeroes `w`; the CBD bit buffer is
  zeroed with the SHAKE state (`keys2-pqz-kat.txt`: ok; a tampered copy fails on each changed field).
- Not measured here: wasm (that came with P6e Task 7, `pqz-ffi`'s `prove` feature).

## Auditor-off transfer `R_TX0` P6e Task 2 (branch `p6e-a2`; CTR-PQZ-24, P6e plan gap G1 / decision D8, ruling R6; no `proofSystemId` bump)

`R_TX0` is a transfer without the auditor: the statement simply leaves out the auditor's key and ciphertext slot.
Merged with Task 5 as `9f55013` on 2026-10-14. (Gap G1: "the auditor-off transfer is not built"; decision D8: build
`R_TX` without the auditor in both systems rather than with a dummy auditor key.)

- **What changes against `R_TX`:** no `pk_a`, `v_a`, `e2_a`; row 5 is skipped; every other row and norm of `R_TX`
  is kept (the same 917 bits).
- **Sizes:** op 1 with a 66,560-byte statement (header ‖ `pk_f ‖ pk_t ‖ T ‖ u ‖ v_t ‖ v_f`), witness 12,384 B
  (`PQZ_TX0_STMT_BYTES`, `PQZ_TX0_WIT_BYTES`).
- **How op 1 tells the two apart (rule R6: `auditorOn` is bound by length):** `pqz_rel.c` picks `R_TX` / `R_TX0`
  by the statement length. Both verifiers and the prover require the `auditorOn` word (offset 448,
  `PQZ_HDR_AUDITOR_ON`) = 1 on the 83,072-byte form and = 0 on the 66,560-byte form.
- **Parameters:** spec `pqzl/params/tx0_params.sage` → `pqzl/params/pqz_tx0_params.h` by LaZer's codegen: kmsis
  23, kmlwe 33, m1 145 + m2 68, MSIS β 457 (2^133.4 classical / 2^121.1 quantum), MLWE uSVP β 470 (dual_hybrid
  462), knowledge error ≤ 2^-127 (`pqzl/params/estimator-e-s1-tx0.txt`).
- **Plan decision D1 (keep the hand-built relations, prove the generated headers reproducible):** the codegen
  rerun reproduces the five checked-in headers byte for byte (`pqzl/params/codegen-tx0.txt`,
  `pqzl/params/regen.sh`).
- **Keys:** ABDLOP keys of its own, `SCAAS-PQZ-ABDLOP-PP-V1 ‖ 0x81` (from run `tx0b`; the first run `tx0` shared
  op 1's tag). The specialised verifier names it by the same internal code `PQZ_REL_TX0` (0x81, never on the
  wire).
- In the bench, diff and fuzz harnesses it is relation 5 (`pqz_bench` mask 32), built from the bench's `R_TX`
  transfer without the auditor leg.

**The bench's `R_TX` statement changed** (because of R6): its header word 448 used to be filler (`i·3`) and is now
1. So `R_TX`'s proofs and `proofs_fnv` change: native 5 / 10 seeds `ca69759d` → `604111c6` / `cabd8270` →
`79b9326d`, wasm 3 seeds `177e6806` → `6780efdd`, 1 seed `e2cf9721` → `a092f2ff`. Proof bytes, times and peaks
stay the same. `R_REG`, `R_BURN`, `R_DS`, `R_DR` proofs are byte-identical to `hedge2`.

The word is also set to 1 in `pqzl/test/pqz_sv_diff.c`, `pqzl/test/pqz_sv_fuzz.c` (input byte 0 now picks
`R_REG` / `R_TX` / `R_TX0`), `pqzl/l2dom/l2dom_tx.c` and `research/upstream/shim/bench.c`. The Ligero crate's
`client::setup` writes the same header (`auditorOn` 1 since `p6e-b2`; the salt word and the zero words of D15
since the merge, run `tx0c`, so `research/upstream/ligero.sh` stays byte-equal). The Plonky3 crate's
`pqzh/src/client.rs` (a backup, not built by P6e) still writes the filler.

Runs [measured] (`NP=10 NV=30 NPW=5 NVW=10 research/pqzl-measure/relfix.sh tx0`, `pqzl/sv/rel3.sh tx0`,
`pqzl/sv/review/review.sh zdiff 1`, one capped job each; `research/pqzl-measure/runs/tx0-*`, `pqzl/sv/runs/tx0-*`):

- KAT 19/19; `check_tbox_fixes: ok`; `check_sv_fixes: ok` (tree 0 / 12, either fix reverted 12 / 12).
- Differential test 3,484 portable + 1,736 x86-64-v3 cases over six relations, 0 mismatches. Of these, `R_TX0`
  766 + 382, including 24 + 12 `stmt_auditor` cases (`auditorOn` changed on `R_TX` / `R_TX0`; both verifiers
  reject every one). PRG 0.
- wasm `PQZ_VERIFY=both` 0 mismatches; z21 differential 174 cases over six relations, 0 disagreements.
- `fails 0` everywhere (native, wasm, ASan + UBSan with only the nits of Open item 4), including all six tamper
  kinds on `R_TX0`.
- `auditor_check`, 9 cases: `R_TX` with `auditorOn` 0 (the dummy-auditor form), 2, or a high byte; `R_TX0` with
  1, 2, or a high byte; and each proof under the other form's statement. All rejected by both verifiers and
  refused by the prover.
- Symbol scan clean; native and wasm proofs equal byte for byte (native 5 seeds `64ce6572` = wasm 5 seeds; 1 seed
  `bdf2a395`: native = wasm generic = wasm fast = wasm without SV).
- `pqz.wasm` 411,419 B (without SV 356,523 B).

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

Every `R_TX0` number is within host noise of `R_TX` or just under it (one key and one ciphertext slot fewer). SV
p99 is ≤ 15.2 ms against the 60 ms limit on every build.

**After review (controller 2026-10-14), run `tx0b`** (`research/pqzl-measure/runs/tx0b-*`, `pqzl/sv/runs/tx0b-*`;
`tx0` kept). Two changes:

- `R_TX0` gets its own ABDLOP keys (tag byte 0x81).
- The bench's debit statements carry the canonical salt word (16 zero bytes ‖ salt, CTR-PQZ-19; `R_TX` / `R_TX0`
  keep the filler as the 16-byte salt, `R_BURN` salt 0). The decoder (`pqz-stmt`, `pqz_kat.py`) now enforces it;
  pqz-core only hashes the word.

So `R_TX`, `R_TX0` and `R_BURN` proofs change once; `R_REG`, `R_DS`, `R_DR` stay byte-identical to `hedge2`. Same
checks, all green [measured]: KAT 19/19, `check_tbox_fixes: ok`, `check_sv_fixes: ok`, differential 3,484 + 1,736
cases 0 mismatches (24 + 12 `stmt_auditor` on `R_TX0`, 0 accepted), wasm both 0, z21 differential 174 / 0,
`fails 0` native, wasm, ASan + UBSan, `auditor_check` 9 / 9, native = wasm proofs.

`R_TX0` in `tx0b`: proof ≤ 42,456 B; prove p50 / p99 native 917 / 1,256 ms, wasm 1,047 ms; generic verify p50 /
p99 native 574 / 594 ms (adversarial 656), wasm 766 ms; SV p50 / p99 portable 8.01 / 9.25 (adversarial 8.63),
x86-64-v3 4.83 / 6.49 (4.93), wasm 13.3 / 15.5 (16.8) ms; peaks as in `tx0` (298.0 / 227.3 MB).
`../artifact/expected-results.json` regenerated from `tx0b` (provisional, 69 / 69).

**Second review (controller 2026-10-14), run `tx0c`** (`tx0`, `tx0b` kept), after merging `main` (`p6e-b2`).
Changes:

- The `auditorOn` read in `parse_debit` and in the SV's `parse_stmt` is split into two statements. It was read
  unsequenced with the call (C11 6.5.2.2p10); there is no other such read in `pqzl/src/` or `pqzl/lazer/`.
- D15 (canonical encodings: every decoder accepts exactly one encoding) now also pins to 0 the header words that
  §7.7 / §7.5 fix: a transfer's `amount` / `recipient`; a burn's `toUA` / `auditorOn` / whole `salt`; a refresh's
  `toUA` / `amount` / `recipient` / `auditorOn` / `salt`. Decoder only (`pqz-stmt` and `pqz_kat.py`).
- The bench writes those words that way (`R_TX` recipient 0; `R_BURN` toUA and auditorOn 0), so `R_TX`, `R_TX0`
  and `R_BURN` proofs change once more; `R_REG`, `R_DS`, `R_DR` are still byte-identical to `hedge2`.

All green [measured]: KAT 19/19, `check_tbox_fixes: ok`, `check_sv_fixes: ok`, differential 3,484 + 1,736 cases 0
mismatches, wasm both 0, z21 differential 174 / 0, `fails 0` native, wasm, ASan + UBSan, `auditor_check` 9 / 9,
native = wasm proofs (5 and 1 seeds).

`R_TX0` in `tx0c`: proof ≤ 42,441 B; prove p50 / p99 native 827 / 1,128 ms, wasm 1,398 ms; generic verify p50 /
p99 native 577 / 627 ms (adversarial 627), wasm 760 ms; SV p50 / p99 portable 8.03 / 8.49 (adversarial 8.82),
x86-64-v3 4.68 / 5.53 (4.92), wasm 13.4 / 14.7 (14.4) ms. `../artifact/expected-results.json` regenerated from
`tx0c` (provisional, 69 / 69).

The Ligero crate's `client::setup` writes the same header words: `pqzh/ligero/runs/l13-*` (EVM fixtures
re-exported, `cargo test` 15 + 14 ok, `--no-default-features` ok, wasm32 build ok, `research/upstream/ligero.sh`
all ten files equal + `kat_stmt: ok`, forge 16 / 16 passed on the re-exported fixtures; its first try failed only
because this worktree had no `lib/`, `l13-forge-failed-nolib.txt`).

| `proofs_fnv` hedge2 → tx0 → tx0b → **tx0c** | native 5 seeds (= wasm 5) | wasm 3 seeds | native 10 seeds | 2 seeds (SV runs) | 1 seed (alone) |
|---|---|---|---|---|---|
| `R_REG` | **`8bd69f2d`** (unchanged) | **`e70b5dc4`** | **`b82d49f8`** | **`1af59837`** | **`25074bbb`** |
| `R_TX` | `ca69759d` → `604111c6` → `239c8b8d` → **`b9bbf854`** | `177e6806` → `6780efdd` → `ced8bcc3` → **`9304299b`** | `cabd8270` → `79b9326d` → `e55b1313` → **`0b786555`** | `1d42a571` → `3ef1da5b` → `09b11092` → **`559b3c44`** | `e2cf9721` → `a092f2ff` → `0e0026f2` → **`008d4495`** |
| `R_BURN` | `bfb900f9` → `bfb900f9` → `d94216dd` → **`0a5976da`** | `37654486` → `37654486` → `07fbdc5c` → **`0ea1c7a6`** | `049029ff` → `049029ff` → `801e15c2` → **`c7e99b6b`** | `12f45572` → `12f45572` → `73ad9a0a` → **`7694fd9f`** | `d8180c60` → `d8180c60` → `780a00bb` → **`ad3e8a12`** |
| `R_DS` | **`b4aa2e26`** (unchanged) | **`f39a8e64`** | **`5429242c`** | **`9eb44281`** | **`478a0d94`** |
| `R_DR` | **`c800f2c6`** (unchanged) | **`96a6e906`** | **`e53ad440`** | **`5bb0078c`** | **`cb2f3ced`** |
| `R_TX0` (new) | `64ce6572` → `17bbacad` → **`a29a5747`** | `2ae5a78d` → `ac79db76` → **`a0afafc7`** | `8721892b` → `30b085ff` → **`a2759b37`** | `a41428e2` → `b10b632d` → **`8b99b979`** | `bdf2a395` → `0fe80168` → **`bfdc29df`** |

## `pqz-stmt`, the statement codec P6e Task 5 (branch `p6e-a2`; plan R2, D15, R6, D5 limits, D2 / D3 ids)

`pqz-stmt` is the one small Rust crate that parses and builds every statement form and accepts exactly one
encoding of each (rule R2: one statement codec, no dependencies). Merged with Task 2 as `9f55013`.

**What is in `stmt/`** (Rust 1.97.1, `no_std` + `alloc`, no dependencies, no `unsafe`, no floats):

- `parse(op, stmt)` for every form: `TRANSFER` 83,072 B and `TRANSFER0` 66,560 B (told apart by length), `BURN` /
  `REFRESH`, `REGISTER`, `DISCLOSE-SENDER` / `-RECEIVER` / `-AUDITOR`, `SELFTEST` (empty). It applies the D15 / R6
  rules in the same order as `pqz_kat.py`: opTag of the op, known `proofSystemId`, length, `fee` / `amount` < 2^64,
  `auditorOn` by length, coefficients < q. It borrows the input (no allocation).
- `Stmt::encode`, with `encode(parse(x)) = x`.
- `pk` / ciphertext / coefficient codecs; the bundle (16,688 / 16,560 B) and the canonical
  `abi.encode(bytes, bytes)` opening.
- `decode_input` for the precompile: `≤ MAX_INPUT` 393,216, `1 ≤ len(proof) ≤ MAX_PROOF(id)` (PQZL 98,304, PQZH
  262,144; D5 sets these limits); SELFTEST is exactly `06 00000000`.
- The opTags, both ids (D2: PQZL, D3: PQZH), the form lengths and the prover-API witness lengths.
- Not in it, because they need Keccak: `ctHash`, `authDigest`, `entryRef` (they are in `pqz_kat.py`; `pqz-ffi`
  later).

Run `scripts/capped pqz-core/stmt/xcheck.sh stmt1` (`stmt/runs/stmt1-*`) [measured]:

- 7 unit tests ok: round trip of every form under both ids, field offsets, 32 rejection cases one per D15 / R6
  rule (including coefficient = q / = 2^42, fee = 2^64, `auditorOn` 2 / 0 on 83,072 B / 1 on 66,560 B, length ± 1,
  foreign opTag, unknown id), bundle, opening, input.
- Cross-check ok: the six C statements of `pqz_bench.c` (`pqzh/xcheck/dump_setup`, with the opTag word set to the
  form's, since the bench writes a marker there) parse, re-encode and rebuild from their fields byte for byte, and
  `pqz_kat.py` rebuilds the same six.
- 32 random statements built by `pqz_kat.py` (both ids) parse to the same fields and are built back to the same
  bytes; 178 mutations that `pqz_kat.py` rejects are rejected for the same reason.
- `cargo build --target wasm32-unknown-unknown` ok; `cargo tree`: no dependency.

After review (run `stmt2`, `stmt1` kept):

- `fee` / `amount` < 2^64 is checked on every debit form (stricter than the relations, which read `amount` only
  for BURN).
- The salt word must be 16 zero bytes ‖ salt (`Reject::Salt`). pqz-core only hashes it, so the decoder is where it
  is enforced; `pqz-stmt` and `pqz_kat.py` alike.
- 7 unit tests ok (32 rejection cases), C 6 / 6 equal (the bench statements are now canonical, no salt rewrite),
  32 `pqz_kat.py` statements equal, 186 rejections with the same reason, wasm32 ok.

Second review (run `stmt3`):

- `parse_opening` checks every sum on a length word (`checked_next_multiple_of` / `checked_add`; unit cases with
  length words near 2^64).
- The D15 zero words of the `tx0c` section above are enforced (`Reject::MustBeZero(field)`; `pqz_kat.py` says
  "<field> must be 0", in the same order).
- The C statements now come from `dump_setup DIR pqzh` (real opTags and the PQZH id, no rewrite).
- 7 unit tests ok in release and in debug (overflow checks on), C 6 / 6 equal, 32 `pqz_kat.py` statements equal,
  210 rejections with the same reason, wasm32 ok.

The Ligero crate moves onto it in Part B Task 6.

## `pqz-ffi`, the precompile boundary P6e Task 7 (branch `p6e-a3`; plan D10, R5, D13; CTR-PQZ-10)

`pqz-ffi` is the one entry point the node calls: it decodes the precompile input and verifies it with PQZL or PQZH,
and never crashes the node on bad input. Merged as `072bec1` on 2026-10-14. (D10 sets its scope: decode + verify
for both systems, plus a `prove` feature.)

**Interface** (`ffi/`, Rust 1.97.1; `ffi/README.md`):

- C ABI `pqz_precompile(input, len, out, out_len) -> status` (`ffi/pqz_ffi.h`, for P6f's P/Invoke):

  | Status | Meaning |
  |---|---|
  | 0 | ok |
  | 1 | revert: input over `MAX_INPUT` 393,216 B |
  | 2 | bad arguments |
  | 3 | input-caused panic ⇒ output `…00` |
  | 4 | node fault ⇒ no result (see "Fault split" below) |

- Rust: `precompile` / `decode` / `verify_input`. Feature `prove`: PQZL `pqz_prove` / PQZH Ligero by the
  statement's id, keygen / enc / dec, the witness layouts, a seeded fixture of every form.

**Path:** input → `pqz_stmt::decode_input` (D5, D15, R6) → by `proofSystemId`:

- PQZL → `pqz_verify_fast` (rule R5: the precompile path uses the specialised verifier; the generic verifier only
  in tests);
- PQZH → Ligero (`default-features = false`, behind `src/pqzh.rs` only, because the Ligero API moves in
  `p6e-b3`);
- op 6 → the cached self-test (D13).

**Build:** libpqz is compiled by `build.rs` from `pqzl/src/`, `pqzl/lazer/`, `pqzl/params/` with `pqzl/build.sh`'s
flags, and `pqzl/check_symbols.sh` runs on the archive (wasm32: `pqz_wasm_rt.c`'s branch-free 128-bit helpers are
kept, Rust provides `mem*`).

**Open item 6 closed at this layer:** every libpqz call runs under one process-wide lock, on one worker thread with
a fixed 16 MiB stack. The first run `ffi1` found why the fixed stack is needed: a test thread's 2 MiB stack
overflows in the prover, so the core's stack must not depend on the caller's thread. A poisoned lock
re-initialises the core.

**Arenas**, allocated once: verify-only 136 MiB = 1.5 × the measured peak 94,615,600 B (all six forms' ABDLOP keys
and SV tables kept, plus the self-test; 144 MiB since `ffi1f2`, below); prove / generic verify 448 MiB.

**Self-test** (D13): `keccak256(kat_digest ‖ 1 ‖ 0 ‖ 1 ‖ 0)` =
`ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205`. It covers the A digest (= `pqz_kat.py`'s
`f176b313…`), KeyGen, Enc / Dec, a Ligero FFT round trip, and one compiled-in `R_REG` proof per id
(`ffi/selftest/*.hex`). Cold: 83 ms.

Runs [measured] `scripts/capped pqz-core/ffi/run.sh ffi1c` (`ffi/runs/ffi1c-*`; kept: `ffi1`, stack overflow and
too small an arena; `ffi1b`, one wrong expectation in the test). 11 + 1 tests ok:

- round trip of every form: PQZL 8 (six relations + REFRESH + AUDITOR), PQZH 7 (PQZH `R_TX0` was pending Ligero
  Task 8; it was added in run `ffi1e`, below);
- 412 rejection cases: each D15 / R6 rule with its `Reject`, op / opTag / id confusion, lengths ± 1,
  `MAX_PROOF + 1`, truncated / extended / flipped proofs, the other system's id, framing; `MAX_INPUT + 1` = revert;
- PQZL differential SV vs generic through the FFI: 56 cases, 0 disagreements;
- abort-freedom: 10,240 inputs, serially and from 8 threads, through the C ABI: identical results, status 3 never,
  158 valid = exactly the unedited honest ones, Ligero panics 0;
- C ABI arguments, self-test, compiled-in proofs = a fresh prove, the precompile path on a 1 MiB caller stack,
  `pqz_ffi.h` constants;
- C smoke test against the header ok;
- `libpqz_ffi.so` needs only libc / libgcc_s; 0 GMP / MPFR / HEXL names or strings; 0 libm imports; clippy
  `float_arithmetic` clean;
- wasm32: the verify-only lib builds; the prove harness (`ffi/wasm/`, 850 KB) proves every form of both ids in
  node (15.6 s) and prints the same 17 digest lines as native (fixtures, proofs byte-equal, verdicts, self-test
  hash).

| verify through the FFI [measured] p50 / p99 ms, native, n = 200 | direct (bare call) | `precompile` | C ABI | adversarial (C ABI, one flipped proof bit) |
|---|---|---|---|---|
| PQZL `R_TX` / `R_TX0` | 7.91 / 9.71; 7.80 / 11.18 | 7.91 / 8.65; 7.90 / 12.13 | 7.93 / 9.28; 7.94 / 12.18 | 8.11 / 9.27; 7.72 / 8.50 |
| PQZL `R_BURN` / REFRESH | 7.49 / 7.82; 7.49 / 8.47 | 7.59 / 8.67; 7.55 / 8.83 | 7.64 / 8.92; 7.56 / 8.23 | 7.60 / 9.04; 7.59 / 8.37 |
| PQZL `R_REG` / `R_DS` / `R_DR` / AUDITOR | 3.98–4.55 / 4.78–5.39 | 4.02–4.58 / 4.71–5.76 | 4.04–4.59 / 4.88–5.33 | 4.03–4.61 / 4.82–6.20 |
| PQZH `R_TX` / `R_BURN` / REFRESH | 9.21–9.71 / 9.98–10.50 | 9.22–9.73 / 9.97–11.96 | 9.23–9.78 / 9.76–12.21 | 0.57–1.26 / 0.64–1.73 (rejected early) |
| PQZH `R_REG` / `R_DS` / `R_DR` / AUDITOR | 6.95–7.21 / 7.37–8.52 | 6.95–7.23 / 7.32–9.14 | 6.93–7.23 / 7.21–8.16 | 0.37–0.41 / 0.44–0.53 |

The boundary (decode ≤ 0.01 ms p99, `catch_unwind`, the lock, the worker hop) adds ≤ 0.1 ms at p50; the p99
columns differ by host noise (± 3 ms between runs of the same call). Every op is ≤ 12.2 ms p99 against the 60 ms
limit.

**Fault split (controller 2026-10-14), run `ffi1d`** (`ffi/runs/ffi1d-*`; its first attempt crashed in the fault
injection, see the finding below). The rule: a fault caused by the input gives the same answer on every node; a
fault of the node itself gives no answer.

- **Status 3** (output `…00`): only for a panic in the decode / verify logic (input-caused, the same on every
  node).
- **Status 4** `PQZ_FFI_NODE_FAULT` (no result, `out` untouched): a fault of the node — arena or `pqz_init`
  failure; worker not created, or a job on it panicked; `pqz_err == PQZ_ERR_ARENA` after a call (the core is then
  dropped and re-initialised); a failed self-test computation; an unclassified panic.
- Rust: `Error::{Revert, NodeFault}`; `verify_input` / `pqzl::verify_fast` return `Result<bool, NodeFault>`.
- `tests/fault.rs` (own process, test hooks): a 16 MiB arena and a failing worker give status 4 with `out`
  untouched, for verify and for the self-test; PQZH is unaffected; the core recovers.
- **Finding:** a fixed arena of 4–12 MiB crashes the process (SIGSEGV) instead of reporting exhaustion, because
  exhaustion inside LaZer's key generation is not graceful (Open item 2). 14–20 MiB fails gracefully; ≥ 24 MiB
  verifies `R_TX` (`ffi/runs/ffi1d-arena-probe.txt`, `ffi/runs/arena-probe.sh`). So status 4 covers the exhaustion
  the core survives, and the production arena (144 MiB since `ffi1f2`, 1.59 × the adversarial peak) keeps
  exhaustion out of reach.
- All other `ffi1d` checks as in `ffi1c`.

**After `p6e-b3` (merged into `p6e-a3`), run `ffi1e`:**

- The adapter takes `Params::proven()` (now a `const fn`) instead of the written-out preset.
- PQZH gets `R_TX0` (Ligero Task 8), so both ids run all 8 forms: round trips 8 + 8; the digest lines 16 + the
  self-test equal native = wasm32 (17 lines); the PQZH self-test proof is byte-identical (no regeneration, hash
  still `ed910a2c…`). All other checks green as in `ffi1d`.
- PQZH `R_TX0` through the FFI [measured]: proof 231,064 B, p50 / p99 direct 9.44 / 10.13 ms, C ABI 9.41 / 10.71
  ms.

**Review fixes (controller 2026-10-14), runs `ffi1f` (136 MiB) and `ffi1f2` (final, 144 MiB):**

- any failed core call drops the core (also arena exhaustion; the fault test re-verifies `R_REG` at the same fixed
  18 MiB after an `R_TX` fault);
- `pqz_err` is read as a `static mut` through `addr_of!(..).read_volatile()`;
- a native build with `panic = "abort"` is a compile error;
- the arena is reserved with `div_ceil(16)`;
- the fault and measurement hooks sit behind feature `test-hooks` (0 hook names in the production cdylib);
- the C ABI reverts before building a slice over an oversized input.

New evidence, `tests/verify_only.rs` [measured]: a fresh process that never proves, on the verify-only arena, runs
the whole corpus (10,698 inputs: every rejection and framing case, the 16 honest inputs, the self-test, the
10,240-input generator) serially, then the generator again from 8 threads and on a 1 MiB caller stack, then 5,000
repeated mixed calls. Results: identical, status 3 / 4 never, 174 valid = the unedited honest inputs,
`arena_used()` 93,498,368 B after every call, `arena_peak()` unchanged.

- **Finding:** the adversarial corpus peaks at 95,169,680 B, above the honest-only 94,615,600 B, so 136 MiB was
  only 1.498 × (`ffi1f`). `ARENA_SMALL` is now 144 MiB (1.59 ×; the test asserts ≥ 1.5 ×).
- Arenas filled with 0x00 / 0xA5 / 0x5A before `pqz_init` (child processes; prove and verify arenas) give
  identical digest lines (16 forms' proofs, verdicts, self-test) and 2,506 corpus results
  (`ffi/runs/ffi1f-fill.txt`): the core reads no arena byte it did not write.
- MSan / valgrind not run: valgrind is not installed, and MSan needs an instrumented Rust std (nightly).

## Vectors P6e Task 11 (branch `p6e-a4`; plan R4, D9, D13)

The frozen test vectors for both proof systems, all written by one generator so every value comes from the real
code (rule R4). Merged as `0807e41` on 2026-10-14.

- **Where:** `smartcontracts/vectors/pqz/`, the one canonical directory (D9). Its `README.md` lists every file,
  the schema, the scenarios, and what Python pins versus what only the generator pins.
- **Generator:** `pqz-ffi`'s binary `pqz-vectors` (`ffi/src/bin/`, feature `prove`). Every value comes from the
  crate's API, every expected output from `pqz_precompile` (and `selftest()`), and the generic PQZL verifier agrees
  on every decoded PQZL input.
- **Files:** 15 files, 11,371,429 B of JSON:
  - `matrix`, `cbd`, `keygen`, `enc`;
  - five `statement_*` files (8 forms);
  - `proof_pqzl` / `proof_pqzh` (8 rows each: six relations + REFRESH + AUDITOR);
  - `fee0` (fee = 0, owner 2026-10-14: TRANSFER, TRANSFER0, BURN, REFRESH, both ids);
  - `negative` (389 inputs: 221 decoder rejections with `pqz-stmt`'s reason, 168 verifier rejections, the revert
    at `MAX_INPUT + 1`; the limits exactly; PQZH encodings: element = q, opened columns swapped / repeated; PQZL
    coder padding; plus 9 openings for `parse_opening`);
  - `selftest` (D13; `pqz-ffi`'s `build.rs` compiles the REGISTER rows' proofs in, and its `selftest/*.hex`
    copies are removed);
  - `worstcase_noise`.
- First built as its own crate `vecgen/` (run `vec1`; `pqz-ffi` was then still on `p6e-a3`), moved into `pqz-ffi`
  after the merge (review 2026-10-14).

**Worst case the verifier accepts** (review 2026-10-14, `worstcase_noise.json` `bound`) [measured]. This pins the
largest decryption noise an attacker can reach with keys and credits that all pass verification:

- a receiver key at the norm bounds (s = 36 at poly 1 coefficient 0, e = 164 at poly 0 coefficient 0) registers
  (`R_REG` proves and verifies in both systems);
- a credit with r = 36 along rot(e), e1 = −164 against rot(s), e2_t = (64, 0, …) has noise exactly B_FRESH =
  11,872, and its sender's `R_TX` (e2_t at PQZL's B′ = 64 filler) proves and verifies in both systems (credit 0
  and the last);
- `T` = 1,023 such credits + the plain unit (noise 0): noise 12,145,056, margin 1.38× to 2^24 and 4.14× to the
  mint threshold Δ − 2^24; the receiver's debit over `T` proves and verifies in both systems.

pq-zero-knowledge.md §4.3 notes the reachable maximum (12,156,928, which counts 1,024 units). The honest-key
construction stays in the file as `illustrative` (10,254,552).

Run `scripts/capped pqz-core/ffi/vectors/run.sh vec3 write` [measured] (`ffi/vectors/runs/vec3-*`; `vec1-*` = the
first build; `vec2-*` = the same as `vec3` before the files' generator field named the new location):

- generation 52.2 s, 440 MB RSS;
- `pqz-vectors --check` byte-identical, 15 / 15 files; compiled-in self-test proofs current; `OP_SELFTEST` through
  `pqz_precompile` = `ed910a2c…1333d205`;
- `pqz_kat.py --check` ok in 26.7 s; `tamper.py` 179 / 179 changed leaves caught;
- `pqz-ffi` tests (`--features prove,test-hooks`) all ok, including `selftest_vectors`;
- wasm32 replay through `pqz-ffi` (node v26.8.1): 34 / 34 proofs byte-equal with native and valid through its
  precompile.

| Proof bytes [measured] | TRANSFER | TRANSFER0 | BURN | REFRESH | REGISTER | DS | DR | AUDITOR |
|---|---|---|---|---|---|---|---|---|
| PQZL | 42,762 | 42,431 | 41,904 | 41,915 | 28,093 | 28,977 | 28,996 | 28,986 |
| PQZH | 230,946 | 231,480 | 232,184 | 230,280 | 186,778 | 186,456 | 187,226 | 187,194 |
| PQZL fee 0 | 42,756 | 42,427 | 41,908 | 41,926 | | | | |
| PQZH fee 0 | 232,142 | 231,384 | 229,608 | 231,544 | | | | |

## Fuzzing P6e Task 10 (branch `p6e-a5`; plan D12, D15; CTR-PQZ-10)

Coverage-guided fuzzing of the precompile boundary; the first campaigns found nothing. Merged as `32e7ad3` on
2026-10-15. (D12 sets the fuzzing set-up: clang 18 libFuzzer on stable Rust.)

`fuzz/` ([fuzz/README.md](fuzz/README.md)) has three libFuzzer targets on `pqz-ffi` in the production
configuration (verify-only 144 MiB arena, warmed with every form):

| Target | What it feeds |
|---|---|
| `precompile` | raw bytes into the C ABI |
| `mutate` | edit scripts over the 24 honest inputs of the vectors; PQZL decoded-field mutations through `pqz_test_mutate`; the specialised vs the generic verifier on every 256th mutated PQZL input that decodes |
| `codec` | D15 canonical encodings: `pqz-stmt` parse ⇒ encode, `decode_input`, bundle, opening, and the PQZL proof coder `pqz_decproof` ⇒ `encproof` |

Checked on every input: no panic (a panic hook aborts, so even the panics that status 3 and Ligero's own catch
would hide are counted), no status 3 / 4, deterministic, `…01` only for the unmodified honest inputs, arena peak ≤
96 MiB. Stable Rust sancov links with clang 18's libFuzzer (no nightly); the C core runs with ASan + UBSan
(`pqz-ffi` feature `fuzz`). No CI job (controller 2026-10-14): local runs only.

First campaigns [measured]:

| Target | Duration | Execs | Notes |
|---|---|---|---|
| `precompile` | 60 min | 1,464,429 | pre-vector seeds |
| `precompile` | 45 min | 1,043,633 | vector seeds |
| `mutate` | 45 min | 86,923 | 197 differentials |
| `codec` | 45 min | 367,237 | 56,597 PQZL proofs re-encoded byte-equal |

**No finding.** Arena high-water mark over all runs: 95,169,680 B, the adversarial peak already known (Open item 2).

## Spec: serialization v1, P6e Task 12 (branch `p6e-a6`; plan D2, D4, D7, D12, D14, D15)

Docs only, no code change; merged as `1783ea8` on 2026-10-14.
[pq-zero-knowledge.md §8.1 "Serialization v1"](../docs/contracts/pq-zero-knowledge.md#serialization) now specifies
every byte that this core, `pqz-stmt`, `pqz-ffi` and the Ligero crate exchange:

- the precompile framing and its check order; both ids and `MAX_PROOF(id)`;
- the 640-byte header word by word, with the decoder's rule per form;
- every statement body with offsets (checked against `pqz_kat.py`'s `parse` on the vector statements);
- objects, bundle, opening, `entryRef`, `authDigest`, the witness layouts (prover API);
- the PQZL coder format (field order, widths, `D` and `log2(stdev/1.55)` per relation from
  `pqzl/params/pqz_<rel>_params.h`, end bit);
- the Ligero proof format and Merkle order; `OP_SELFTEST`.

Also: §5 states the transcripts as implemented (D7), §8 the bump rule (D4: any change to parameters, layout,
transcript, encoding or the accepted set needs a new id), §4.4 the proof sizes above. Where the spec text disagreed
with the code, the text was changed to match the code (list at the end of §8.1). decisions.md has the D2, D4, D7,
D12, D14 and D15 (proof half) lines.

## Op 7 `R_TXM` in `pqz-stmt` / `pqz-ffi`, P6-ANON S3 (branch `p6-anon-s3`; plan D3, D13, §5.4; CTR-PQZ-10 L-3)

P6-ANON step S3: the multi-recipient transfer (`R_TXM`, op 7) is decoded by `pqz-stmt` and verified through
`pqz-ffi`, and the sizes to build are chosen. Merged as `d7b22ec` on 2026-10-16. Shapes are written (M, auditorOn):
M recipient legs, with or without the auditor.

- `pqz_stmt::parse(7, …)` / `decode_input` return the multi-recipient statement as `Stmt::Multi` (step S2's interim
  `Reject::Op` removed).
- `pqz-ffi` needed no new dispatch (PQZL `pqz_verify_fast(7, …)`, Ligero `verify(7, …)`); the `OVERSIZE` const
  assert keeps PQZH M = 8 / M = 16 out.
- **Arenas:** `ARENA_SMALL` 512 MiB (owner 2026-10-16), `ARENA_BIG` 1 GiB native; one 512 MiB arena on wasm32,
  where `prove` refuses PQZL multi-recipient transfers with M > 4 (`Statement(Legs)`) (controller proposals).
- **Feature `prove`:** `pqzl::enc_group_seed` / `enc_multi` (D13: per-group Enc randomness), `fixture::multi_case`
  (`R_TXM` witness layout, `recipientsHash`, memo hash), `memo::{seal, open}` (§5.4; labels in decisions.md
  CTR-PQZ-23).

Run `scripts/capped pqz-core/ffi/run.sh s3a` [measured] (`ffi/runs/s3a-*`). Every test green:

- round trip of the 8 forms + 8 multi-recipient shapes (PQZL) and 8 + 6 (PQZH);
- 1,012 rejection cases (for the multi-recipient transfer: every S2 rule through the precompile,
  `recipientsHash` / `memoHash` changed, `(1, on)` relabelled `(2, off)`, op 1 ↔ op 7);
- PQZL differential SV vs generic: 112 cases, 16 accepted, 0 disagreements;
- the PQZH (4, on) boundary: input = `MAX_INPUT` ⇒ `…00`, + 1 B ⇒ revert;
- oversize M refused; memo round trip;
- self-test `ed910a2c…d205` unchanged; C ABI smoke, symbol scan, 0 GMP / libm, clippy `float_arithmetic` clean.

`tests/verify_only.rs`: 30 honest inputs, corpus 11,281 (10,240 from the generator), 188 valid = the unedited
honest ones, status 3 / 4 never, 8 threads and a 1 MiB caller stack equal to serial, 5,000 mixed calls equal,
`arena_used` 265,693,696 B after every call.

- **Verify-only peak 268,240,256 B = 2.00 × margin in 512 MiB** (144 MiB would not hold it).
- Fill determinism 0x00 / 0xA5 / 0x5A: 3,118 lines identical.
- **Prove arena peak with every relation loaded: 853,679,872 B in 1 GiB (1.26 ×)**.
- wasm32: the prove harness proves the 8 forms and the 6 multi-recipient shapes with M ≤ 4 of each id; 29 digest
  lines = native (fixtures, proofs, verdicts, self-test); 36.3 s; linear memory 594,739,200 B (was 631 MB); PQZL
  M = 8 prove refused.
- The six P6e forms' digest lines (statements, witnesses, proofs) equal `ffi1f2`'s.

| Multi-recipient transfer through the FFI [measured], native, n = 200 | statement B | proof B | input B | worst-case input B | prove ms | verify p50 / p99 ms | adversarial p99 ms |
|---|---|---|---|---|---|---|---|
| PQZL (1, on) / (1, off) | 83,072 / 66,560 | 42,766 / 42,409 | 125,843 / 108,974 | 181,381 / 164,869 | 848 / 966 | 8.19 / 11.27; 8.58 / 11.11 | 12.76 / 11.43 |
| PQZL (2, on) / (2, off) | 99,712 / 83,072 | 43,603 / 42,951 | 143,320 / 126,028 | 198,021 / 181,381 | 1,109 / 1,846 | 8.63 / 10.80; 8.75 / 11.84 | 11.76 / 11.20 |
| PQZL (4, on) / (4, off) | 132,992 / 116,096 | 45,274 / 43,922 | 178,271 / 160,023 | 231,301 / 214,405 | 2,050 / 915 | 9.59 / 14.78; 9.23 / 12.16 | 14.06 / 12.11 |
| PQZL (8, on) / (8, off) | 215,936 / 198,528 | 61,802 / 58,998 | 277,743 / 257,531 | 314,245 / 296,837 | 2,641 / 2,093 | 13.81 / 16.87; 13.10 / 16.54 | 17.54 / 18.12 |
| PQZH (1, on) / (1, off) | 83,072 / 66,560 | 232,174 / 230,968 | 315,251 / 297,533 | 318,547 / 301,309 | 623 / 724 | 9.95 / 12.33; 9.81 / 11.93 | 1.27 / 2.16 |
| PQZH (2, on) / (2, off) | 99,712 / 83,072 | 232,174 / 231,918 | 331,891 / 314,995 | 335,187 / 318,547 | 672 / 714 | 9.99 / 10.49; 10.45 / 12.85 | 1.37 / 2.38 |
| PQZH (4, on) / (4, off) | 132,992 / 116,096 | 232,708 / 230,904 | 365,705 / 347,005 | 369,193 / 351,571 | 647 / 701 | 10.83 / 13.07; 10.74 / 12.74 | 2.13 / 2.52 |

Worst-case input = 5 + statement + the id's bound (PQZL `MAX_PROOF` 98,304; PQZH Ligero's exact bound).

**Size verdict (D3: build, per id, every power of two M that fits `MAX_INPUT`, `MAX_PROOF` and the time limit;
`pqzl/params/anon/anon-sizes-s3.txt`):**

- PQZL: M ∈ {1, 2, 4, 8} built. M = 16 does not fit: input 474,161 / 449,947 B > `MAX_INPUT`.
- PQZH: M ∈ {1, 2, 4} built. M = 8 does not fit: bound 281,208 B > `MAX_PROOF_PQZH`, input 497,149 B >
  `MAX_INPUT`; M = 16 is also over the gas cap.
- The largest multi-recipient worst-case input is 369,193 B (PQZH (4, on)) ≤ 393,216.

Frozen vectors (`ffi/vectors/runs/s3a-*`): `pqz_kat.py --check` ok, tamper 179 / 179, wasm32 replay 34 / 0
fails. `pqz-vectors --check` differs only in the reason of the two `TRANSFER: under op 7` rows of
`negative.json` (`Op` → `OpTag`; output `…00` unchanged; `s3a-negative-diff.txt`); the file was left as frozen for
S4.

## Op 7 vectors, P6-ANON S4 (branch `p6-anon-s4`; plan D15, LH-2)

P6-ANON step S4: test vectors for the multi-recipient transfer (`R_TXM`, op 7), plus the LH-2 check that the C and
Rust statement builders agree. Merged as `59522d6` on 2026-10-16. (D15 of the P6-ANON plan lists the vector files.)

What was added to `smartcontracts/vectors/pqz/` (README there):

- **`statement_transfer_multi.json`**: 11 multi-recipient statements. Every built `(M, auditorOn)` of each id with
  one real leg at a position that varies by shape; a two-real-leg row; an all-decoy row with fee 0; a
  group-boundary row with real legs 3 and 4. Each with multi-group Enc (each group's `seed_enc_g` and counter),
  `recipientsHash`, the §5.4 sender memo and its `memoHash`; plus 9 `memo_open` rows.
- `R_TXM` rows appended to `proof_pqzl.json` (11) and `proof_pqzh.json` (8, M ≤ 4).
- 342 multi-recipient rows appended to `negative.json` (pqzl 177, pqzh 165). By reason: `verify` 143, `OpTag` 70,
  `Length` 41, `Op` 28, `ProofSystemId` 14, `Legs` 11, `ProofLength` 11, `Coefficient` 10, `Salt` 4, two each of
  `AuditorOn`, `MustBeZero(amount)`, `Amount`, `Fee`, `Input`; two reverts at `MAX_INPUT + 1`.
- `pqz_kat.py` gained multi-recipient decoding (reason `Legs`), `enc_group_seed` / `enc_multi`, the memo (stdlib
  HMAC-SHA256) and a checker per new row; `replay_wasm.mjs` gained the multi-recipient rows.

**Frozen files regenerated, and why:** S3 made the multi-recipient statement (op 7) decode, so the two
`TRANSFER: under op 7` rows of `negative.json` (pqzl, pqzh) now fail at the opTag: reason `Op` → `OpTag`, with the
output `…00` and the input bytes unchanged (S3's `s3a-negative-diff.txt`). Everything else S4 changed is appended:
the P6e rows of `proof_pqzl.json`, `proof_pqzh.json` and `negative.json` are byte-identical, the 12 other P6e files
are byte-unchanged, and the self-test hash `ed910a2c…d205` is unchanged (decisions.md CTR-PQZ-09, Change
2026-10-16).

Run `scripts/capped pqz-core/ffi/vectors/run.sh s4a write` [measured] (`ffi/vectors/runs/s4a-*`):

- generation 150.0 s, 998 MB RSS;
- `pqz-vectors --check` (second generation) byte-identical, 16 / 16 files, 19,650,288 B;
- every proof row and every negative through `pqz_precompile`, PQZL also through the generic verifier (they
  agree);
- `pqz_kat.py --check` ok in 42.7 s; `tamper.py` 191 / 191; `pqz-ffi` tests ok (including `selftest_vectors`);
- wasm32 replay: 53 cases, 0 fails. 50 were proved byte-equal with native; the 3 PQZL M = 8 rows are verify-only,
  because wasm32 does not prove PQZL multi-recipient transfers above `WASM_PQZL_MAX_LEGS` = 4 (`s4a-wasm.txt` was
  re-run once after a counter fix in the script's summary line).

**LH-2: C and Rust build the same multi-recipient statements** (`ffi/vectors/lh2.sh`, `examples/lh2.rs`, run
`s4a-lh2.txt`).

- Inputs: pqz_bench.c's multi-recipient statements (C, every TXB shape, `research/upstream/dump_setup.c` mode
  `txm`, opTag and recipientsHash set) and the Ligero crate's `setup_multi` ones (default, fee 0 all decoys, two
  real legs), under each id that builds M.
- Each one: `pqz-stmt` parse + encode byte-equal; proved (PQZL by the C core, PQZH by Ligero); `…01` through the
  precompile; the PQZL generic verifier agrees; a `recipientsHash` bit flip gives `…00`.
- Result: 50 cases (C 14, Ligero 36), 0 failures. `kat_multi.py` (pqz_kat.py) rebuilds the 6 C statements with the
  PQZH id and re-encrypts every ciphertext from the C witnesses: ok.

| Multi-recipient proof bytes [measured] | (1, on) | (1, off) | (2, on) | (2, off) | (4, on) | (4, off) | (8, on) | (8, off) |
|---|---|---|---|---|---|---|---|---|
| PQZL | 42,716 | 42,426 | 43,604 | 42,919 | 45,275 | 43,932 | 61,794 | 58,975 |
| PQZH (exact bound) | 232,494 (235,470) | 232,248 (234,744) | 231,256 (235,470) | 232,078 (235,470) | 232,708 (236,196) | 232,494 (235,470) | — | — |

Open: no multi-recipient disclosure-bundle (§5.4) vectors yet; `pqz-stmt` has no codec for that bundle yet (S7 /
P6g).

## Op 7 in the reproducibility package, P6-ANON S6 (branch `p6-anon-s6b`; plan D14, D21)

P6-ANON step S6: the multi-recipient transfer (`R_TXM`, op 7) joins the reproducibility package and its expected
results. Merged as `926a481` on 2026-10-17. (D14: `R_TXM` in the default reproduction plus a `multi-bench` stage;
D21: `R_TXM` joins the frozen set.)

- `artifact/reproduce.sh` replays every built `R_TXM` of both ids in its default stages and has a new
  `--multi-bench` mode: the multi-recipient measurement table, PQZL by `research/pqzl-measure/txm-bench.sh`, PQZH by
  `ligero_bench` / `run_wasm.mjs` txm.
- `expected-results.json` was regenerated once (`results.py freeze-txm`: only `txm` and `ffi.digest_lines`).
- Docker on the new layout (2026-10-17, AMD Ryzen 5 7235HS): quick PASS, 199 ok after the regeneration;
  `--multi-bench` PASS (29 checks, 44 min).
- Results with the auditor: PQZL proof max 42,784 / 43,616 / 45,295 / 61,822 B for M = 1 / 2 / 4 / 8, SV p99
  portable 7.8–13.6 ms, wasm32 13.2–23.1 ms; PQZH proof max 233,102 / 232,526 / 233,604 B for M = 1 / 2 / 4, verify
  p99 native 9.9–10.9 ms, wasm32 18.5–20.4 ms.
- Full table: `artifact/README.md`; logs `artifact/runs/s6-docker-{quick,multi}/`.

## Op 7 live in the `PQZ` precompile on chain 7622, P6-ANON S8 (branch `p6-anon-s8`; plan D19)

P6-ANON step S8: the multi-recipient transfer (`R_TXM`, op 7) is live on chain 7622 with its own gas table. Merged
as `63e672f` on 2026-10-17. (D19: op 7 verified by the one `PQZ` precompile through `pqz-ffi`, priced by a table.)

- `Nethermind.Pqz` prices the multi-recipient transfer per `(proofSystemId, M, auditorOn)` (header words 320 /
  448): 14 calibrated rows, 3,625,000–6,177,000 gas. Image `pqz2`.
- On chain 7622 since T = 1792205116 (2026-10-17 02:45:16Z), through a second `engine.Pqz` schedule ("path A":
  chain data kept).
- Harness 60 min CLEAN; the copy-chain and live probes and the end-to-end tests pass (`nethermind/runs/2026-10-17-*`).
- The rows are in plan S8's results and in `nethermind/chain/engine-pqz.json`.

## Gates A / B and the freeze (2026-10-17)

Both proof systems passed their release gates (gate A: PQZL; gate B: PQZH), both ids were frozen, and the full
reproducibility run that fixes the expected results passed.

**Gates passed:** `gate.sh 2026-10-17` (`runs/gate/2026-10-17-*`):

- KAT 19/19; `check_tbox_fixes`, `check_sv_fixes` ok;
- differential 6,486 cases, 0 mismatches (portable + x86-64-v3); z21 differential 406, 0 disagreements;
- `pqz-vectors --check` 16 files byte-identical; `pqz_kat.py --check` ok; tamper 191 / 191; wasm32 replay 53 cases,
  0 fails;
- `pqz-ffi`, `pqz-stmt`, Ligero tests green; STARK-backup cross-check equal; fuzz smoke 3 × 60 s, no finding.
- Gate B also: every built PQZH op ≤ 236,196 B and p99 ≤ 10.9 / 20.4 ms native / wasm32 (S6 multi-bench); the
  Ligero ZK review (`docs/research/pqzh-ligero.md` §12).
- CI `pqz` job added (green). Both proofSystemIds frozen (decisions CTR-PQZ-09).

**Freeze:** `artifact/reproduce.sh --full` (host toolchain, machine lock): **PASS, 233 ok, 0 FAIL**
(`artifact/runs/freeze-2026-10-17/`). `artifact/expected-results.json` = `results.py freeze "frozen 2026-10-17"`
of that run: proof hashes, sizes and digest lines are equal to the provisional file; only the informational times
changed. The frozen tables are README §5.0.

## C core hardening (2026-10-18, branch `pqzl-c-hardening`; owner 2026-10-18)

The Rust port of PQZL (crate `pqzl`, branch `pqzl-rust`) found three latent defects in the C core, now the reference.
All three are fixed in C with **no output change on honest or reachable inputs**, and the C now computes what the Rust
port computes, so the port needs no change:

1. **`poly_auto_self` wrote past its buffer** (`pqzl/lazer/poly.c`). In the NTT domain (`crt == 1`) it looped over
   the ring's two former CRT moduli, but the fork keeps one residue vector of 64 words, so the second pass swapped
   the 64 words after it. Now it reverses the one vector, as the Rust port's first pass does. No relation reaches this
   branch. The reversal is also not the automorphism X → X⁻¹ in the fork's incomplete NTT (the test prints `no`).
   Upstream LaZer sizes the buffer per modulus, so this is a fork defect, not an upstream one.
2. **Signed overflow in the fixed-point exp and the rejection tests** (prover only). `pqz_fixexp.h` `pqz_exp_fp`
   now makes its clamp comparisons in 128 bits: the same result on [−64, 64), and outside it saturates as intended
   (as the Rust port's `fixexp.rs` does). `rejection.c` now does `t2 − 2·t1`, `t − ln M`, `a − |y| − ln M`, `|a|`
   in `_quot_q56` and `_int2i128` in unsigned arithmetic, so the values wrap as the Rust port's `wrapping_*` calls do.
   Only exponents far beyond ±64 get there, and no honest prover produces them.
3. **Signed overflow in `pqz_rel.c` `rd_poly`** on a non-canonical word v ∈ [2^63, 2^63 + q). It now computes
   `(int64_t)(v − q)`, the value the Rust port's `keys.rs` `rd_poly` gives. Further UB of the same kind was found and
   fixed: `int_set_i64` (`pqzl/lazer/lazer-in2.h`, upstream code; reported as [lazer#27](https://github.com/lazer-crypto/lazer/issues/27), 2026-10-18) overflowed on `INT64_MIN`, which `rd_poly` produces
   from the word 2^63 + q. Its magnitude is now computed in unsigned arithmetic, giving the same limbs for every input.

**Verifier path.** None of the fixes changes what a verifier computes. `pqz_exp_fp` and `rejection.c` are prover
only. Three touched functions are reached by a verifier:
- `int_set_i64`, from both verifiers;
- `rd_poly`, from the generic `pqz_verify`, not from `pqz_verify_fast`, which parses with its own `rd_coeffs`;
- `poly_auto_self`, from the generic tbox verify, but only in its coefficient branch, which did not change.

`int_set_i64` and `rd_poly` give the same bits for every input. `proofSystemId`, the transcript, honest proofs and the
accepted set are all unchanged.

**Evidence.**
- `pqzl/test/ub_test.sh` (`pqzl/test/pqz_ub_test.c`, clang 18, `-fsanitize=undefined,address
  -fno-sanitize-recover=all`, libc heap) has three parts: (a) fixexp / rejection, (b) encrypt / decrypt,
  (c) `poly_auto_self`.
  - On the unfixed sources (`a0dd89a`) every part aborts: `pqzl/test/runs/ub-before.txt`.
    `ub-before-recover.txt` lists every UB site (`pqz_fixexp.h` 52 and 54, `rejection.c` 34, 83, 99 and 126,
    `pqz_rel.c` 230, `int_set_i64`).
  - After the fix: PASS (`ub-after.txt`). Only `pointer-overflow` is off, because of the known upstream nit in
    `aes256ctr.c:339` (Open 4).
  - Before the fix, the verdict on huge exponents depended on the compiler. With plain wraparound (the recover run)
    the old clamp sent x ≥ 64 to −64 and rejected. On the four test inputs, the fixed C and the Rust port both accept.
- Proof hashes, in `research/pqzl-measure/runs/hard1-*`:
  - `pqz_bench 5 5 63`: the six `proofs_fnv` rows equal `tx0c-fnv-native.jsonl`. With arena peaks, they equal the
    unfixed `a0dd89a` byte for byte (`hard1-unfixed-a0dd89a-fnv-native.jsonl`). The one R_BURN arena-peak difference
    against `tx0c` (2,176 B) was already there on `a0dd89a`.
  - `pqz_bench 2 2 16320`: the eight R_TXM `proofs_fnv` rows equal `l3a-native-fast.jsonl`.
- `scripts/capped pqz-core/gate.sh hard1`: **PASS**, every step ok (`runs/gate/hard1-*`):
  - KAT 19/19; `check_tbox_fixes` and `check_sv_fixes` ok.
  - Differential: 6,486 cases, 0 mismatches; z21 differential: 406 cases, 0 disagreements. The log equals
    `2026-10-17-diff.txt` apart from `closest_z2sq_over_bsq`.
  - `pqz-vectors --check`: 16 files ok; `pqz_kat.py --check` ok; tamper 191 / 191; wasm32 replay 53 cases, 0 fails.
  - `pqz-ffi` tests green, with the self-test hash `ed910a2c…d205` unchanged.
  - Symbol scans ok (`/gmp|mpfr|hexl/`: 0); cargo tests green; STARK-backup cross-check equal.
  - Fuzz smoke 3 × 60 s: no finding, corpora restored.

**Follow-ups (2026-10-18, owner; Rust port Task 10b, branch `pqzl-rust`).** The hardening review asked for two more
changes, made in the C core and the Rust crate alike. Outputs are unchanged: honest proofs, `proofs_fnv`,
`proofSystemId`, the vectors and the self-test hash.
1. **`poly_auto_self` in the NTT domain computes X → X⁻¹.** It converts to coefficients (`_fromcrt`) and applies the
   coefficient automorphism, as `poly_auto` does; the result is in the coefficient domain. Item 1's reversal was not
   the automorphism, so the branch returned a wrong value had anything reached it. Still no relation reaches it.
   Rust `poly.rs` `auto_self` does the same. The oracle shim's double-size residue block, which only absorbed the
   old out-of-bounds write, is gone (`tests/oracle_shim.c`, `src/testkit.rs`).
2. **The rejection exponents saturate instead of wrapping.** `rejection.c` computes `t2 − 2·t1`, `t − ln M` and
   `a − |y| − ln M` with `pqz_sat_sub128` / `pqz_sat_sub64`, constant-time helpers added to `pqz_fixexp.h`; Rust
   `rejection.rs` uses `saturating_sub`. An exponent below −2^63 now stays the most negative one and rejects, so a
   dishonest-size exponent fails closed through the prover's `PQZ_REJ_MAX` retry cap, where wrapping made it accept.
   `num` above 2^127 (only for ⟨z,v⟩ near −2^126) stays the largest value and accepts, the exact value's verdict.
   Honest exponents stay within ±64 (Q56) and never reach either edge.

Evidence:
- `pqzl/test/ub_test.sh t10b`: PASS (`pqzl/test/runs/ub-t10b.txt`). Part a checks both helpers on every pair of
  range-edge values and six rejection inputs with exponents near ±2^63; the two negative-side inputs that accepted in
  `ub-after.txt` now reject. Part c checks that the NTT branch equals the coefficient-domain automorphism.
- Rust: the unit test `rand::rejection::tests::saturation_near_2_63` (the same six inputs) and the oracle test
  `oracle_rand::rejection_saturation_eq_c` (the five one-limb inputs on 200 streams, C = Rust and the expected
  verdict; the shim takes one-limb entries only, so the two-limb input is in the unit and C tests). The existing
  oracle tests (`rejection_eq_c`, the arithmetic vector with `poly_auto_self` in the NTT domain) stay equal.
- `pqzl/rust/run.sh t10b`: every test green, `proofs_fnv` equal to the C core's (native and wasm32).
- `scripts/capped pqz-core/gate.sh t10b`: **PASS** (`runs/gate/t10b-*`), with `pqz-vectors --check` and the
  self-test hash unchanged.

## PQZL v3: Fiat–Shamir fix (branch `pqzl-fs3`)

Plan `docs/superpowers/plans/2026-10-19-pqzl-fs3.md`; decisions CTR-PQZ-09 F1–F10 (owner rulings of Task 0 recorded
`2fff733`); spec pq-zero-knowledge.md §5 "Transcripts" and §8; analysis `docs/research/pqz-tbox-soundness.md` §8.
Closes Open item 11. Not merged yet: the reproduction package and fuzz on v3, the gate, reviews A / B (Tasks 6, 7,
9–12); the roll-out on 7622 follows the merge (Task 13).

What changed, in the C prover and generic verifier (`lazer/lnp-tbox.c`), the C specialised verifier (`src/pqz_sv.c`),
the Rust prover and generic verifier (`rust/src/proof/tbox.rs`) and the Rust specialised verifier (`rust/src/sv.rs`):

- **Two transcript rounds** (P6-FS, [lazer#28](https://github.com/lazer-crypto/lazer/issues/28)). `hz =
  SHAKE128(cseed ‖ grandom3(z3) ‖ grandom3(z4))`, after the verifier's norm checks on z3 / z4, seeds V3 / V4 and the
  tg round; the JL rows R / R' stay on `cseed` (the one deviation from the plan, F1: the Schwartz–Zippel
  accumulators now take two seeds). `hash2 = SHAKE128(hash1 ‖ urandom3(h))` seeds `μ` and the final challenge; γ
  stays on `hash1`. Encoding: the proof's own (F2), buffers sized exactly (F3).
- **Prover-side zero-knowledge fixes** (review D). D-2: z2 now uses Rej1, the one-time-commitment rejection the
  parameters were generated for (F7); D-3: the β3 / β4 sign bits read distinct bits (F8). They change honest proofs,
  not verifier rules; no parameter change.
- **`proofSystemId` v3** = `keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v3")` = `0x8079d65b…16baef` (F6) in `pqz.h`,
  the Rust crate, `pqz-stmt`, `pqz_kat.py`, the Nethermind harness and `engine-pqz.json` (ids only), `add-schedule.py`,
  `PqzRegistryBase.sol`, `stark-backup/src/rel.rs`. **v2 is retired** (forgeable): not accepted, no constant kept.
- **Tests:** the P6-FS binding test, `sz/fs_bind.c` (fourth check of `check_tbox_fixes.sh`) and
  `rust/tests/fs_bind.rs`, with mutate kind 14 (z3 ± 1, test-only; F10); unit tests of `rej_onetime` in C and Rust.

| Task | Commits | Run label |
|---|---|---|
| 1 binding tests (FAIL expected) | `c5b2c99`, review fixes `c0bd890`, Rust run `b3cc772` | `fs1` |
| 2 C transcript fix, id v3 | `6d83208`, review fix `2789314` | `fs2` |
| 3 Rust transcript fix, id v3 | `420f409`, `13a8f8e`, run `41c708b` | `fs3` |
| 4 D-2, D-3 in both cores; cheating fixtures re-exported | `c57381b`, review notes `0dc869d` | `fs4` |
| 5 the id everywhere, vectors regenerated | `8af584b` | `fs5` |
| 8 documents | `ec4d243` and this commit | — |

**Runs** [measured]:

- **fs1** (before the fix): P6-FS **FAIL**, 10 of 12 checks, in C (`pqzl/runs/fs1-before.txt`, `fs1-review-fix.txt`)
  and Rust (`pqzl/rust/runs/fs1-test.txt`): the `μ` seed of the h-changed proof and the V3 / V4 seeds of the z3- and
  z4-changed proofs equal the honest proof's, in `verify` and `verify_fast`. Everything else green.
- **fs2** (C fix): `check_tbox_fixes` ok with P6-FS 0 of 12 (`pqzl/runs/fs2-tbox.txt`); `check_sv_fixes` ok;
  `sv/diff.sh fs2` 4,328 portable + 2,158 x86-64-v3 cases, 0 mismatches, 0 PRG mismatches; z21 differential 406
  cases, 0 disagreements (its rc 1 is the both-verdicts flag on `R_TXM8` / `R_TXM8_0`, as on main since 2026-10-17)
  (`pqzl/runs/fs2-sv-*`); `relfix.sh fs2` KAT 19/19, `fails 0` native, wasm32 and ASan + UBSan (only the known UBSan
  notes), native = wasm32 (`research/pqzl-measure/runs/fs2-*`).
- **fs3** (Rust fix): `fs_bind` ok; the Rust bench `proofs_fnv` = the C fs2 values, native and wasm32; `oracle_prove`
  Rust = C on all 14 relation codes (with its assert on the committed v2 vector disabled locally)
  (`pqzl/rust/runs/fs3-*`).
- **fs4** (D-2, D-3): `relfix.sh fs4` KAT 19/19, `fails 0` native, wasm32 and ASan + UBSan, `check_tbox_fixes` ok
  (P6-SZ, P6-L2, P6-Z21, P6-FS); C `pqz_bench 2 2 16320` `fails 0` (`research/pqzl-measure/runs/fs4-*`);
  `pqzl/test/ub_test.sh fs4` PASS with the `rej_onetime` test: acceptance 11,624 / 65,536 = 0.17737 against
  1/(2·M2) = 0.17628 (`pqzl/test/runs/ub-fs4.txt`; Rust `onetime_rej1` the same counts); `rust/run.sh fs4` every FNV
  line equal, `export.sh` rc 0 (every production verifier rejects the re-exported cheating fixtures;
  `pqzl/rust/runs/fs4-*`); the harness patches still apply (`z34poc.sh` 5 edits, `l2dom` 1, `review.sh` 1 each).
- **fs5** (id, vectors): `ffi/vectors/run.sh fs5` and `fs5-c` (`pqz-vectors --check` 16 files byte-identical on both
  backends, `pqz_kat.py --check` ok, tamper 191 / 191, wasm32 replay 53 cases, 0 fails; `ffi/vectors/runs/fs5-*`);
  `ffi/run.sh fs5` and `fs5-c` (native = wasm32 29 digest lines, C backend = Rust backend; `ffi/runs/fs5-*`);
  `rust/run.sh fs5` (19 test binaries, 0 failed, every FNV line equal, native = wasm32 387 digest lines with M = 8
  proved in wasm32; `pqzl/rust/runs/fs5-*`); C KAT 19/19 (`pqzl/runs/fs5-kat.txt`); `stmt` 11 + 1, `pqzh/ligero`
  13 + 17 + 8, `xcheck` equal, Nethermind 41 / 41 (`nethermind/runs/2026-10-19-fs5-test.txt`), `forge test`
  `test/pqz` 37 / 37. `negative.json` 731 → 744 rows (+16 "retired PQZL v2 proofSystemId", −3 coder-padding rows the
  generator adds only when a proof ends below 0x80). **Self-test hash unchanged** `ed910a2c…d205` on both backends.
  The fuzz input `regress/valid/crash-b9881…` (v2) is re-proved as `fixture-disclose-receiver-rnd33`
  (`fuzz/runs/2026-10-19-fs5-regress-valid.txt`).

`proofs_fnv`, v2 → after the transcript fix (Tasks 2 / 3) → final v3 (with D-2 / D-3; C = Rust). The C core's runs
(`research/pqzl-measure/runs/`): v2 `tx0c-*` and `l3a-native-fast`, then `fs2-*`, `fs4-*`; the op 7 middle column is the
Rust `fs3` bench (no C run of those shapes in Task 2). `rust/run.sh` pins the final values.

| `proofs_fnv` | native 5 seeds (`5 5 63`; = wasm32 5 seeds) | wasm32 3 seeds (`3 1 63`) | native 10 seeds (relfix) |
|---|---|---|---|
| `R_REG` | `8bd69f2d` → `b76964d5` → `b935013d` | `e70b5dc4` → `df9c238e` → `c5d0e8c6` | `b82d49f8` → `c36b3c42` → `acfd0e0e` |
| `R_TX` | `b9bbf854` → `78417d42` → `258418fb` | `9304299b` → `27653466` → `da580d8a` | `0b786555` → `f2c9029d` → `96bc4cff` |
| `R_BURN` | `0a5976da` → `6c959845` → `85ab8aa8` | `0ea1c7a6` → `5850b6d7` → `581fda3e` | `c7e99b6b` → `c7904de4` → `a6690b16` |
| `R_DS` | `b4aa2e26` → `ba3698fc` → `cd5eccf7` | `f39a8e64` → `6a168a2c` → `12c24f8f` | `5429242c` → `4a3d88dd` → `a4c5cd87` |
| `R_DR` | `c800f2c6` → `619971bf` → `b3cb29a2` | `96a6e906` → `85759c97` → `1fc860f7` | `e53ad440` → `9d03b294` → `1449cf10` |
| `R_TX0` | `a29a5747` → `25062de9` → `06c6a4a5` | `a0afafc7` → `78ed03a7` → `3ff37043` | `a2759b37` → `698f8483` → `b10dc839` |

| op 7, `pqz_bench 2 2 16320` | v2 → Tasks 2 / 3 → v3 |
|---|---|
| `R_TXM1` / `R_TXM2` | `ee87e7a4` → `70cf13e6` → `e839a31e` / `4294a892` → `ec51bb4b` → `4c63cef7` |
| `R_TXM4` / `R_TXM8` | `4ff8974f` → `06fd0b71` → `e88b6a9f` / `cd21b056` → `5761601e` → `62e81d1d` |
| `R_TXM1_0` / `R_TXM2_0` | `bba9cd96` → `2dd19206` → `40131675` / `2fef961b` → `112a0f93` → `ad7a159c` |
| `R_TXM4_0` / `R_TXM8_0` | `74c6be73` → `ebecbd5c` → `024ffaf8` / `90c8fc70` → `653b03b1` → `f22cc134` |

Sizes, arena peaks, times (C core, native, 10 proofs, v2 `tx0c-native.jsonl` → v3 `fs4-native.jsonl`). Proof sizes
move within the `rnd32` noise; arena peaks are equal (apart from `R_BURN`'s known 2,176 B); verify times are within the
host's noise (about ± 20 %). Prove time follows the rejection attempts (both loops), which D-2 about doubles; `R_BURN`'s
did not move in this sample. The full v3 tables (both cores, wasm32, the specialised verifier) are to be re-measured
(plan Tasks 6 and 13).

| | proof bytes max | rejection attempts per proof | prove p50 (ms) | generic verify p50 (ms) |
|---|---|---|---|---|
| `R_REG` | 28,113 → 28,105 | 7.4 → 14.0 | 295 → 287 | 161 → 164 |
| `R_TX` | 42,785 → 42,792 | 12.1 → 18.5 | 965 → 1,125 | 648 → 677 |
| `R_BURN` | 41,938 → 41,949 | 10.9 → 10.1 | 874 → 840 | 556 → 574 |
| `R_DS` | 28,995 → 28,979 | 9.2 → 13.2 | 331 → 316 | 200 → 208 |
| `R_DR` | 28,996 → 29,001 | 10.2 → 12.6 | 395 → 365 | 206 → 217 |
| `R_TX0` | 42,441 → 42,452 | 11.0 → 23.0 | 827 → 1,140 | 577 → 585 |

**Not done in this round:** the package's `expected-results.json` (Task 6) and the fuzz campaign on v3 (Task 7; three
small `corpus/precompile` inputs still carry the v2 id and now reject on it); the gate and reviews A / B (Tasks 9–11);
the merge (Task 12); the roll-out on 7622 with a new image and gas re-calibration (Task 13). The external
cryptographic audit before mainnet 22776 remains open.

## Transcript B-1 / A-2 (5h Task 8a, branch `pqz-16k`, 2026-10-21)

Plan `docs/superpowers/plans/2026-10-20-pqz-state-redesign.md` Task 8 (sub-task 8a), spec §6.4; reviews B
(`research/code-review-2026-10-19/X-review-b-transcript.md`, B-1 P0, B-2) and A (`W-review-a-pqzl-rust.md`, A-1 = B-1,
A-2 P3); analysis `docs/research/pqz-tbox-soundness.md` §8.6. On today's parameters (n = 2048, q = 2^42 − 215) and
under the v3 id: the one `proofSystemId` bump for 16k + B-1 + A-2 is Task 8d's (D23), so this diff isolates the
transcript change. Commits `de249614` (tests, RED), `4adea55c` (fix, GREEN, regeneration).

- **B-1** (all four verifiers, both provers): V3 / V4 from the hash after `tg` (`hash1`, which seeds γ), no longer
  from `hz`; `hz` is now only the tg round's input. C `lazer/lnp-tbox.c` (prover, verifier), `src/pqz_sv.c` (`g0`
  gone, V on `g1`), Rust `proof/tbox.rs` (`accumulate_all` takes one seed for γ and V) and `sv.rs`.
- **A-2**: υ `M + 2(d−1) + 1` (it shared `M + 2(d−1)` with the last β4 row), binary `+ 2`, exact ℓ2 `+ 3 + i`, V4
  `+ 3 + Z`, V3 `+ 3 + Z + 256`, in all four.
- **`R_REG` / UA-6** (controller ruling 2026-10-21): the message stays opaque (relation, statement, verifier,
  vectors unchanged, UA-6 §9 / U13); `pqz-stmt`'s `Register` documents its pre-image
  `uaMessage(0x0142, POP, popDigest(ua, keyHash(0x0142, pk)))`; `UAPqzVerifier.PROBE_PQZL` re-pinned
  (`0x6c4573ab…5b04` → `0x517488fa…23f3`, the probe's message unchanged); `PqzSafety.SELFTEST` unchanged (it hashes
  verdicts).
- **Tests:** review A's cheating prover as `rust/tests/cheat_b1.rs` (the `set_cheat` test hook in `tbox::prove`,
  feature `test-hooks`; gate step rust); `test_mutate` kind 15 (tg +1 mod q, C and Rust; `oracle_codec` kinds 0..15)
  in `sz/fs_bind.c` and `rust/tests/fs_bind.rs` (18 checks: the V seeds must change with tg, the tg-changed proof is
  rejected); A-2 as the fifth check of `check_tbox_fixes.sh` (`sv/review/review.sh dom`, no shared dom).
- **Regenerated:** `proof_pqzl.json`, `fee0.json`, `worstcase_noise.json`, `negative.json` (744 → 745: the
  coder-padding rows follow the proofs' last byte; PQZL 367 → 368, `tests/vectors.rs`), `selftest.json`'s
  `proof_keccak`; the cheating fixtures (`export.sh`); the fuzz `regress/valid` input (re-proved,
  `fuzz/runs/2026-10-21-t8a-regress-valid.txt`); the pinned `proofs_fnv` of `rust/run.sh`. PQZH files unchanged.

Runs [measured]:

- **RED** (`de249614`, before the fix): `cheat_b1` modes 1 / 2 **accepted by all four verifiers** (Rust `verify`,
  `verify_fast`, C `pqz_verify`, `pqz_verify_fast`) on all 14 relation codes, 28 forgeries; the control (mode 3)
  rejected (`pqzl/rust/runs/t8a-red-test.txt`). fs_bind: 4 failed checks of 18 in C and in Rust, the tg-changed
  proof's V4 / V3 seeds equal to the honest ones in `verify` and `verify_fast` (`pqzl/runs/t8a-red-fsbind-c.txt`,
  `pqzl/rust/runs/t8a-red-fsbind.txt`).
- **GREEN**: `cheat_b1` every mode rejected by all four on all codes, mode 0 = the vectors; fs_bind 0 of 18 in both
  cores (`pqzl/runs/t8a-green-fsbind-c.txt`, `pqzl/rust/runs/t8a-green-fsbind.txt`); `review.sh dom`: 129 calls, 0
  shared doms (`pqzl/runs/t8a-dom-trace.txt`).
- `ffi/vectors/run.sh t8a write` and `PQZL=c … t8a-c`: `pqz-vectors --check` 16 files, 19,656,112 B, ok on both
  backends; `pqz_kat.py --check` ok; tamper 191 / 191; wasm32 replay 53 cases, 0 fails (`ffi/vectors/runs/t8a-*`).
- `rust/run.sh t8a`: every test binary ok but `negative_rows_reject` (the count, fixed in the same commit; the gate
  re-runs it); KAT 19/19; keys KAT ok; `to_rust.py --check` equal; native = wasm32 388 digest lines; `fails 0`.
  `proofs_fnv`, Rust = C (C: `research/pqzl-measure/runs/t8a-fnv-*`):

| `proofs_fnv` | native `5 5 63` (`R_REG`, `R_TX`, `R_BURN`, `R_DS`, `R_DR`, `R_TX0`) | wasm32 `3 1 63` |
|---|---|---|
| v3 → 8a | `b935013d 258418fb 85ab8aa8 cd5eccf7 b3cb29a2 06c6a4a5` → `84892d1b dd395fa2 19abd011 113c7085 e2c45af4 db4848a0` | `c5d0e8c6 …` → `4d60c711 559f032d b53e89fb dcd2be04 0dede50c c2b772e9` |
| op 7 `2 2 16320` | `e839a31e … f22cc134` → `f4f4963b 01ed81bc 5b7fe45d 2ee1dbf5 2c099a2a 36dceac2 4f6ca003 77c19a3d` | |

- `forge test` (Foundry 1.8.5): 1,331 passed, 0 failed, 9 skipped (`smartcontracts/evm/runs/2026-10-21-t8a-forge.txt`).
- `gate.sh t8a`: `scripts/capped pqz-core/gate.sh t8a` on `4adea55c` (clean tree): **PASS**, every step ok (kat, tbox with A-2, sv, diff, vectors, ffi, rust with `cheat_b1` and `fs_bind`, cargo, xcheck, fuzz; `pqz-core/runs/gate/t8a-*`).

**Not in 8a:** the 16k parameters (8b), PQZH at the new q (8c), the id bump, `PqzCt`, contracts and the 16k vectors
(8d); `artifact/expected-results.json` (the package, fs3 Task 6, frozen 2026-10-17 before v3); `pqz-core/nethermind/`
(not touched; another branch upgrades it).

## PQZH review fixes (branch `rev2-pqzh`, plan Task 5c; review round 2)

Findings and triage P-A…P-I: `research/code-review-2026-10-19/I`, `J`, `K` (Codex, agy, Claude; no P0 / P1 in the
live path). Rule: no PQZH proof byte or verdict changes, so the PQZH `proofSystemId`, vectors and gas rows stay.
Decisions: CTR-PQZ-19 (P-A, P-B, P-C, P-G) and CTR-PQZ-10 (P-D, P-E, P-F, P-H, P-I) in `docs/decisions.md`.

- **P-A** (sparse FFT on witness values): the radix stage's sparse path is chosen from the structural zero padding,
  never from values; the inverse transform (the witness rows) is always dense (`fft.rs`).
- **P-B** (secret-dependent work): branch-free field arithmetic, `Fq::from_i64` / `modq` without `rem_euclid`,
  `dot_int` without the zero skip, rounding by a fixed-step division, the honest prover's checks as one verdict per
  error; a ctgrind check `pqzh/ligero/runs/ct.sh` (feature `ctgrind`, test only). Inventory, runs and the wasm32
  code check: `research/code-review-2026-10-19/O-pqzh-constant-time.md`.
- **P-C** (no wiping): `Wiped` drop guards on every secret buffer of the witness builder and the prover, the SHAKE256
  reader replaced in place on drop (Open item 8).
- **P-D** (verifier OOM aborts): `pqzh_ligero::try_verify` reserves the parameter-sized buffers fallibly and returns
  `Err(Oom)`; `pqz-ffi` reports it as `NodeFault` (status 4); `tests/oom.rs`; pq-zero-knowledge.md CTR-PQZ-10 text.
- **P-E**: `#![forbid(unsafe_code)]` in `pqzh-ligero` (deny only under `ctgrind`); the raw-pointer exports of the two
  wasm harnesses (`pqzh/ligero/wasm`, `ffi/wasm`) are `unsafe extern "C"` with their contracts.
- **P-F, P-G, P-H** (`stark-backup`, not live): minimal varints only (`81 00` for `01` rejected), the mask seed
  hedged with op, statement and witness (`rel::mask_seed`; hiding backup proofs change), the MV layout from
  structural indices (matches the `(op, Params)` cache key). Tests in `enc.rs`, `rel.rs`, `air.rs`.
- **P-I**: no code; Open item 12.

Evidence (all under `scripts/capped`, tag `rev2`, on `50e5dbc`):
- **PQZH proof bytes unchanged.** Native `ligero_bench` FNVs of all twelve relations (six forms at seeds 0 and 1,
  six op 7 shapes at seed 0) equal the base run on `b1c4de5` (`pqzh/ligero/runs/rev2-fnv-compare.txt`);
  `ffi/vectors/run.sh rev2`: `pqz-vectors --check` 16 files ok (byte for byte), `pqz_kat` ok, tamper 191 / 191,
  ffi tests ok, wasm32 replay 53 cases, 0 fails; `ffi/run.sh rev2`: native = wasm32, 29 digest lines equal (and equal
  to `fs5`'s), self-test hash `ed910a2c…d205` unchanged, `c_abi` ok, no C core / GMP / libm in the cdylib.
- `pqzh/ligero/runs/gateb.sh rev2`: tests 15 + 17 + 8 + 1 (`oom`) passed, `--no-default-features` lib 13 passed (full
  `--no-default-features` test run `rev2-nobench-all.txt` ok), wasm32 1,000 verifies per form with `fails 0` and
  wasm32 `fnv_last` = native; `xcheck/ligero.sh`: all twelve statement / witness files Rust = C, `kat_stmt` ok
  (`rev2-xcheck.txt`).
- `pqzh/ligero/runs/ct.sh rev2`: 0 memcheck reports over the twelve relations, every proof verifies
  (`ct-rev2.txt`); negative control with the old arithmetic 21 contexts (`ct-rev2-control.txt`); wasm32: no 64-bit
  division left on secrets (`rev2-wasm-div-*.txt`).
- `stark-backup` `cargo test --release`: 9 + 7 + 1 + 3 passed (`stark-backup/runs/rev2-tests.txt`).

## Second code review: the PQZL C core (2026-10-19, branch `rev2-pqzl`)

Plan `docs/superpowers/plans/2026-10-19-pqzl-fs3.md` Task 5e; reports `research/code-review-2026-10-19/L-codex-pqzl-c.md`,
`M-agy-pqzl-c.md` (triage Q-A…Q-I), `N-claude-pqzl-c.md`; decisions CTR-PQZ-09 (the Q-A…Q-I entry, the Rust-port
minors entry) and CTR-PQZ-26. No P0 / P1 on the verifier path, no C = Rust verdict divergence. No fix changes a proof
byte, an arena peak or a verdict on a valid input.

| # | Change | Test |
|---|---|---|
| Q-A | `pqz_bernoulli_fp` / Rust `bernoulli_fp`: `mant + (mant & −(sh & 1))` instead of a u128 shift by the secret `sh & 1` (a branching `__ashlti3` libcall in Rust wasm32 builds) | `ub_test` part d, Rust `bernoulli_masked_add_eq_shift` (equal on e ∈ [−70, 4]) |
| Q-B | wipe on every exit (Open item 8): `pqz_arena_wipe_release` in `pqz_prove` and the key / encryption helpers, `wipe_vec` of the secret vectors, `explicit_bzero` of the seeds and stack arrays | `ub_test` part g: the arena above the mark is zero after keygen, enc, dec, prove |
| Q-C | a failed LaZer allocation traps (no write after it); sink and `pqz_arena_realloc` removed; the SV's checked allocations use `pqz_arena_try_alloc` (Open item 2) | `ub_test` part h under ASan: `pqz_init` 16 B short of A and `pqz_verify` without room for the keys trap (SIGILL), no ASan report; `ffi/tests/fault.rs` 18 MiB band still status 4 |
| Q-D | `coder_dec_ghint` / `coder_dec_grandom` stop at the first failed read; `pqz_decproof` through `err` | `ub_test` part e: the input pointer stays in the buffer; 10,552 zero proof bytes rejected by both verifiers |
| Q-E | the bounds asserts of `spolyvec` / `spolymat_insert_elem`, `coder_dec_urandom5/6` return before the write | `ub_test` part f |
| Q-F | `aes256ctr.c` NULL + 0, never-zero-length `INTVEC_T` / `Z` arrays, `canonical()` `n % 8`, `pqz__div` `nn ≥ dn ≥ 1` (Open item 4) | `ub_test` with pointer-overflow on; part f; relfix ASan + UBSan stderr empty |
| Q-G | `pqz_ct_barrier` on the masks of `pqz_int_set_centred`, `dec_w`, `debit_witness`; compiler in `ct.sh`'s summary and in `pqz-ffi`'s build log (`pqz_csubq` left without: CTR-PQZ-09) | `ct.sh rev2` |
| Q-H | `check_symbols.sh` refuses test-hook symbols; the statement-length comment | `test/check_symbols_neg.sh` |
| Q-I | global state (Open item 6): recorded, no code | — |

Rust-port minors (TODO "PQZL Rust port follow-ups" item 5): `ffi/tests/fault.rs` (Rust backend: `Ctx` allocation
denied, cache allocations denied end to end, panic path through the hook `TEST_PANIC`), the Rust heap check in
`ffi/tests/verify_only.rs` (review C-M5), the two-limb S3 rejection case compared C = Rust (`pqz_shim_rej_limbs`),
`tests/memory.rs` echoing its `PQZL_MEM_*` settings, `gate.sh`'s `runs/gate/<label>-summary.txt`.

Commits: `ea4b00d` (Q-A), `d08e3f9` (Q-B…Q-H), `d5bcc33` (Rust-port minors), `c5c8dfd` (C runs).

**Runs** [measured] (label `rev2`):

- The new tests on the pre-fix core (`cfea904`) fail: UBSan `NULL + 0` (aes256ctr) and the M = 0 VLA (`lnp-tbox.c`),
  ASan heap-buffer-overflow (`spolyvec_insert_elem`) and global-buffer-overflow (the sink, `pqz_init`), the decoder
  pointer past the buffer, a non-zero arena after keygen / enc / dec / prove (`pqzl/test/runs/ub-before-rev2*.txt`).
  After the fixes `pqzl/test/ub_test.sh rev2` PASS, parts a–h (`ub-rev2.txt`).
- `research/pqzl-measure/relfix.sh rev2`: KAT 19/19; `fails 0` native, wasm32 and ASan + UBSan, whose stderr is now
  empty (fs4: the four Open item 4 reports); `proofs_fnv` and arena peaks equal to `fs4` in every file (native 5 and
  10 seeds, wasm32, each relation alone) (`research/pqzl-measure/runs/rev2-*`).
- `check_tbox_fixes` ok (P6-SZ, P6-L2, P6-Z21, P6-FS 0 of 12); `sv/check_sv_fixes.sh` ok; the portable SV differential
  `pqz_sv_diff 20 10 2 1 10`: 4,328 cases, 0 mismatches, PRG 0, `bad_length_before_keys` 0 (the x86-64-v3 and z21
  passes run in the Task 9 gate); `check_symbols_neg` ok (`pqzl/runs/rev2-*`, `pqzl/sv/runs/rev2-portable.jsonl`).
- `pqzl/test/ct.sh rev2 383 3 2` (the arguments of `ct2`): 0 memcheck reports in C (clang 18.1.3) and Rust (rustc
  1.97.1), every proof verifies (`pqzl/test/runs/ct-rev2.txt`).
- `pqzl/rust/run.sh rev2`: fully green (19 test binaries, 0 failed, incl. `bernoulli_masked_add_eq_shift`, the two-limb
  `rejection_saturation_eq_c`, `tests/memory.rs` with its settings line); every FNV line equal (bench 5 5 63, 2 2 16320,
  wasm32 3 1 63 and the fast variants); native = wasm32 387 digest lines; keys KAT, `to_rust.py --check`, clippy ok
  (`pqzl/rust/runs/rev2-*`).
- `ffi/vectors/run.sh rev2`: `pqz-vectors --check` 16 files byte-identical, `pqz_kat.py --check` ok, tamper 191 / 191,
  wasm32 replay 53 cases, 0 fails (`ffi/vectors/runs/rev2-*`).
- `ffi/run.sh rev2` (Rust backend) and `PQZL=c ffi/run.sh rev2-c`: all tests green (the new fault and heap checks
  included), native = wasm32 29 digest lines on each, the C backend's digest lines equal the Rust backend's,
  **self-test hash unchanged** `ed910a2c…d205` on both; C backend: verify-only arena used 265,693,696 B after every
  call and peak 268,297,200 B, as in `fs5-c`; fill determinism 3,118 lines identical; symbol scan "no test hook"; the
  build log names clang 18.1.3 (`ffi/runs/rev2-*`, `rev2-c-*`).

## Measured (2026-10-13, this machine, single thread)

The spike's measurement record: P6d-2 against the unoptimised spike, and the verdict against the kill criteria
(the limits that would stop the PQZL approach). The verify verdict here is for the generic verifier; the
specialised verifier above later brought verify to ≤ 16 ms p99 (wasm, the five original relations).

Native: clang -O2, `pqz_bench 5 5` under `scripts/capped` (5 proves, 5 + 5 honest verifies, 10 adversarial).
wasm32: node v26.8.1, `run_wasm.mjs 3 1`. Medians. P6d-2 (`b8767b4`) against main (`fd8600f`), same session:

| | proof bytes | prove native | verify native | prove wasm | verify wasm | arena peak native / wasm |
|---|---|---|---|---|---|---|
| R_REG main | 28,070–28,107 | 1.30 s | 1.02 s | 3.30 s | 2.61 s | 144 MB / 113 MB |
| R_REG P6d-2 | same bytes | **0.25 s** | **0.17 s** | **0.38 s** | **0.23 s** | 112 MB / 87 MB |
| R_TX main | 42,734–42,770 | 17.0 s | 14.9 s | 39.6 s | 34.5 s | 612 MB / 476 MB |
| R_TX P6d-2 | same bytes | **1.10 s** | **0.72 s** | **1.59 s** | **0.82 s** | 316 MB / 241 MB |

- Adversarial verifies (P6d-2): rejected in ~3 ms (`R_REG`) / ~16 ms (`R_TX`) when the decoder or the hash check
  fails, otherwise after a full verify (`R_TX` max 0.67 s).
- Init (A expansion + ABDLOP keys): 0.11 s native, 0.15 s wasm.
- Rejection iterations (both loops, mean over the 5 seeds): 5.0 `R_REG` / 12.6 `R_TX`.

**Kill criteria:**

- **Prove: met.** `R_TX` prove 1.10 s native meets the 6 s limit (and the former 3 s).
- **Verify: missed** by the generic verifier. p99 adversarial / honest verify ≈ 0.7 s against 50 ms, ≈ 14× over
  (was ≈ 300×). Upstream LaZer verifies the same `R_TX` in 6.6 s (xcheck), so P6d-2 is ~9× faster than upstream
  there.

**Browser budgets** (pq-zero-knowledge.md CTR-PQZ-18; measured in node, not a browser; medians, not p95):

- `R_TX` wasm prove 1.59 s against 5 s desktop / 15 s phone / 30 s hard limit: inside.
- wasm arena peak 241 MB = 230 MiB against the 128 MiB budget (1.8× over) and the 256 MiB hard limit (inside, 10 %
  margin).
- `pqz.wasm` 333 KB. wasm/native ratio now 1.1–1.5×.
- No decision taken on these (owner).

**Profile after P6d-2** (gprof, `R_TX` 1 prove + 1 verify, `research/opt/runs/9-z3-gprof.txt`): flat. LaZer's
generic sparse-matrix and integer bookkeeping (`intvec_set` 17 %, `spolymat_insert_elem` 9 %, `int_mod` /
`int_redc` 15 %, `polymat_alloc` 9 %), the base multiplication 7 %, AES ~4 %. The E-S1 profile (main) was ~55 %
ring arithmetic, 8 % insertion sort, the rest bookkeeping; the zero entries of the selection matrices' Gram
matrices were most of that bookkeeping.

## Open

Numbered open items; other sections refer to them as "Open item N". Struck-through items are closed and kept for
the record.

1. **Verify (generic verifier).** After P6d-2, `R_TX` verifies in ≈ 0.7 s native (prove 1.1 s meets the 6 s
   limit); the 50 ms p99 criterion is missed by ≈ 14×. What is left is LaZer's generic sparse-matrix bookkeeping
   (flat profile). Further levers, not done: fewer `R_TX` equations (for example, merge the 16 per-digit evaleqs),
   restructuring the Schwartz–Zippel accumulation (typed dense / structured matrices instead of `spolymat`
   copies), verifier-side reuse; each is a larger change than P6d-2's. This was input for the owner's kill
   decision. wasm arena `R_TX`: 221 MiB per op since the fix-ups (230 MiB after P6d-2), under the 256 MiB hard
   limit, 1.7× the 128 MiB budget.
   *Since then:* the precompile path verifies with the specialised verifier (section "Specialised verifier P6-SV",
   rule R5), which meets the limit for the five original relations and `R_TX0` (p99 ≤ 16 ms wasm, ≤ 12.2 ms native
   through the FFI); the generic verifier stays the reference.
2. **Arena exhaustion is not graceful.** On exhaustion the sink block is shared by every later allocation; sparse
   structures in it then hold garbage pointers, and the call can crash instead of returning `PQZ_ERR_ARENA`. Fix
   options: size the arena from the measured peaks (the bench uses 768 MiB; P6d-2 peaks at 316 MB native), or make
   exhaustion abort the call.
   - `pqz-ffi` (P6e Task 7) sizes both arenas from measurement (verify-only 144 MiB = 1.59 × the
     adversarial-corpus peak 95.2 MB; prove 448 MiB).
   - Its first run `ffi1` used 64 MiB for verify-only: the core, out of arena, rejected honest proofs
     (`ffi/runs/ffi1-bench.jsonl`, `all_valid: false`) without crashing.
   - `ffi/runs/ffi1d-arena-probe.txt` shows the crash: a 4–12 MiB arena (exhaustion in the relation's key
     generation) segfaults.
   - `pqz-ffi` reports the exhaustion the core survives as a node fault (status 4). The core's behaviour is
     unchanged.
   - The fuzz targets (P6e Task 10) check the peak on every input against 96 MiB (144 MiB / 1.5): over ≈ 3 M
     inputs the maximum seen is the known adversarial 95,169,680 B; no input raised it.
   - (The multi-recipient transfer later raised the verify-only arena to 512 MiB; see the S3 section.)
   - **Second code review (2026-10-19, Q-C; branch `rev2-pqzl`):** no write follows a failed allocation any more.
     LaZer's allocator traps when a block does not fit (the process stops; the sink is gone); the specialised
     verifier's own allocations fail gracefully (`PQZ_ERR_ARENA`, `pqz-ffi` status 4, `tests/fault.rs`'s 18 MiB
     band). Exhaustion inside LaZer is no longer a node fault but a stop of the process: not reachable from input,
     the arenas are sized from measurement. Test: `pqzl/test/ub_test.sh` part h under ASan.
3. **wasm.** Proofs are equal byte for byte with native (P6d-2, seeds 0..2). No browser run yet (node only).
   `R_TX` needs ~0.23 GB of the 4 GiB wasm32 memory (fix-ups, one op per process).
4. **UBSan nits left as upstream:** zero-length VLAs when M = 0 / nbin = 0 (`lnp-tbox.c` 223, 875, 3451), and
   null + 0 in `aes256ctr.c:339` (P6d-2 `research/opt/asan.sh`: nothing else). **Fixed in the second code review
   (2026-10-19, Q-F; branch `rev2-pqzl`)**: the relfix ASan + UBSan stderr is empty (`research/pqzl-measure/runs/rev2-asan-stderr.txt`) and `ub_test.sh` runs with pointer-overflow on again. What stays: LSan on the malloc path reports the
   relation layer's statement objects (`pqz_rel.c` frees them by arena release), on main as well;
   `research/opt/asan.sh` runs with `detect_leaks=0`. **Fuzz builds (owner 2026-10-19):** `vla-bound` and
   `pointer-overflow` on again in `ffi/build.rs` (feature `fuzz`) and `pqzl/sv/fuzz.sh` (`7aab1fe`); validated by the
   plan Task 7 campaigns `fs7` (`pqzl-diff`, 2 h each, three at once): precompile 766,921 runs, mutate 86,955, codec
   287,503, no finding (`fuzz/runs/fs7-*.txt`).
5. ~~Docs: README, research note, roadmap P6d row + TODO P6 row, docs_check.~~ (done)
6. **Global library state (SV review finding 8, for P6f).** `pqz_sv.c` keeps per-call bookkeeping in statics
   (`svb`, `nsvb`) and its tables in `SR` / `SA`; `pqz_rel.c` has one arena, one base mark and the sticky
   `pqz_err`; `pqz.h` says single-threaded. The node can enter the precompile concurrently (eth_call, tracing,
   parallel import). Two concurrent calls would release each other's arena and reset each other's error (expected
   failure: a crash or a wrong reject; a wrong accept would still need the final hash to match). The P6f cgo
   wrapper must serialise every libpqz call (one process-wide lock) or move to per-thread contexts.
   Status: **closed at the `pqz-ffi` layer** (P6e Task 7: one process-wide lock around every libpqz call, one
   worker thread; P6f calls `pqz_precompile` and needs no lock of its own). Per-thread contexts are not done.
   Second code review (2026-10-19, Q-I): recorded again, no code (the node uses the Rust crate, which has no globals).
7. ~~`keygen.json` "one seed with ≥ 1 resample (searched)" cannot be searched (≈ 2^-70 per seed).~~ Settled
   (controller 2026-10-14): the row is dropped from the plan's Task 11; the resample path and the counter-64 error
   are pinned by the test-hook KATs of Task 3 (`pqzl/test/runs/keys2-*`).
8. **Secret material in the arena is not zeroed** (project-wide). The witness copies in `s1`, the masks `y`, `s2`
   and the keys `pqz_keygen` writes live in the arena (or the caller's buffers) until overwritten;
   `pqz_arena_release` does not clear them. `do_prove` zeroes its seeds, and `pqz_keys.c` its SHAKE state, bit
   buffer and `w`. Zeroing on release (or per call) is open, for P6f / P6h (cost: one memset of the used arena per
   prove).
   **Rust core, review G/H fix B (2026-10-19, branch `pqzl-fs3-fixad`):** the crate `pqzl` now clears, on every
   exit (`?` included, a drop guard `Wiped`), the prover's explicit secret copies and mask seeds: `s1`, `s2`, `m`,
   `t_a2` and the seeds `wh` / `ex` (`rel.rs`), the 96-byte expanded mask seed and the copy `sv` (`proof/tbox.rs`),
   `s`, `yseed`, `c·s1`, `c·s2` (`proof/quad.rs`). Platform boundary: `wipe` is plain stores plus `black_box`; a
   volatile write needs `unsafe` (forbidden outside `c-oracle`) and `zeroize` would be a dependency (D1), so the
   compiler is not bound to keep the stores, and its own copies (moves, register spills, stack temporaries) are
   never cleared; the masks y and the other intermediates are not cleared. ~~The C core has the same gap and keeps
   it here: `lnp-tbox.c` `expseed[96]`, `lnp-quad.c` `yseed[32]` are not cleared, and the copies `sv`, `s`, `m`,
   `tA2` live in the arena (above).~~
   **C core, second code review (2026-10-19, Q-B; branch `rev2-pqzl`):** closed for C. `pqz_prove` and the key /
   encryption helpers zero, before releasing, the arena above the mark up to the high-water mark and every freed block
   below it (`pqz_arena_wipe_release`), plus `s1`, `s2`, `m`, `tA2`, the secret key and the encryption randomness
   wherever they sit, the seeds `expseed` / `yseed`, the sampler buffers and the witness stack arrays (volatile
   stores). Test: `pqzl/test/ub_test.sh` part g. Same boundary as Rust for register / spill copies.
   **PQZH (Ligero), review round 2 fix P-C (2026-10-19, branch `rev2-pqzh`):** the same pattern (`Wiped`, `Wipe` in
   `pqzh/ligero/src/lib.rs`) clears on every exit the witness values (`cs::Wit` wipes itself on drop) and every
   secret buffer of `cs::witness` (the decryptions, the recomputed A s + e / u / v, the polynomial copies, the
   products in `ring::dot_int`, `keypair`, `encrypt`) and of `ligero::prove_once` (rows, row polynomials, masks
   u_0, u_lin, h_0, u_quad, encodings, salts, columns, the test accumulators and the quotient remainder), and the
   FFT's scratch copies; the SHAKE256 reader whose state yields every mask is replaced in place on drop (sha3 0.10.8
   has no `zeroize` and no `Drop`). Same platform boundary as the PQZL crate, plus: by-value `rnd32` copies
   (`prove`, `prove_inner`, `Rng::new`, pqz-ffi's `*rnd32`) and the sha3 hasher state before `finalize_xof` are not
   cleared (`research/code-review-2026-10-19/O-pqzh-constant-time.md` §Wiping).
9. ~~**`pqzl/check_symbols.sh` passes when its files are missing**~~ (found in P6e Task 7, run `ffi1`; seen again
   in the reproducibility package, `artifact/runs/art2-docker-quick-1-probe-*`). The script `cd`'d to its own
   directory, so relative paths from elsewhere named nothing; `llvm-nm` errors were lost in the pipe, and the script
   still printed "symbols ok".
   **Closed 2026-10-15 (branch `pqz-artifact2`):** paths are now relative to the caller (it `cd`s only for its
   default object list), every given file must exist, and `nm`'s exit status is checked. Evidence:
   `pqzl/test/check_symbols_neg.sh` (a missing file and a non-object exit non-zero; the library objects named from
   another directory pass) and `pqzl/build.sh native` + `glic/absence.sh` on the real files:
   `artifact/runs/art2-check-symbols.txt`, `glic/runs/absence-2026-10-15.txt`.
10. **Rust core: wasm32 verify_fast is about 2× the C core's time** (PQZL Rust port, D6 run `d6`, 2026-10-18):
    1.7–2.0× over the 14 relations; `R_TXM8` p99 51.0 ms against the 60 ms limit, about 15 % margin on the
    reference CPU (C: 29.0 ms). Likely cause: `pqzl/rust/src/arith/ntt.rs` multiplies 64 × 64 → 128 bits (`mulq`,
    `red128`, the basemul `u128` accumulator) on every target, and wasm32 has no wide multiply (each is a
    `__multi3` call); the C core uses its 21-bit-limb path there (`pqz_ntt.c`, `PQZ_MUL128 0`). Neither wasm32 build
    uses simd128. Follow-up, not done in the port: a `cfg(target_arch = "wasm32")` limb path in `ntt.rs` (it must give
    the same residues; `run.sh`'s native = wasm32 replay and proofs_fnv checks pin that). Native verify is unaffected (the
    Rust core is faster there), and the chain verifies natively.
11. ~~**P0: Fiat–Shamir transcript omissions in the toolbox protocol (whole-code review 2026-10-19).**
    `h` is not absorbed before the challenge `mu` that combines the quadratic equations, and `z3`, `z4` are not absorbed
    before their Schwartz–Zippel challenges; `h` is not in the final challenge either. In the C generic verifier
    (`lazer/lnp-tbox.c`, `lnp-quad-many.c`), the C specialised verifier (`src/pqz_sv.c`), the Rust core (`rust/src/proof/`,
    `rust/src/sv.rs`) and the provers; inherited from upstream LaZer, reported as
    [lazer#28](https://github.com/lazer-crypto/lazer/issues/28). On code reading a cheating prover forges a proof for any
    PQZL statement by a linear solve for `h`. Reports and controller verification:
    `research/code-review-2026-10-19/`. Owner 2026-10-19: fix now (cheating-prover PoC first, then the transcript in all
    four implementations, new `proofSystemId`, vectors, spec); the Rust roll-out on 7622 is stopped and the chain stays on
    `pqz2` until the fix. PQZH (Ligero) is not affected.~~
    **Closed 2026-10-19 on branch `pqzl-fs3`** (merge after the gate and reviews A / B, plan Tasks 9–12): lazer#28 is
    fixed in all four implementations and both provers (section "PQZL v3: Fiat–Shamir fix"): C generic verifier and
    prover (`lazer/lnp-tbox.c` `_lnp_tbox_hash_z34` / `_lnp_tbox_hash_h`) and C specialised verifier (`src/pqz_sv.c`)
    in `6d83208` (review fix `2789314`), Rust generic verifier and prover (`rust/src/proof/tbox.rs` `hash_z34` /
    `hash_h`) and Rust specialised verifier (`rust/src/sv.rs`) in `420f409` (`13a8f8e`, run `41c708b`); PQZL
    `proofSystemId` v3 in every pin and the regenerated vectors in `8af584b`. The owner replaced "cheating-prover PoC
    first" with binding tests that only observe the challenge seeds (`c5b2c99`, `c0bd890`, `b3cc772`): 10 of 12 checks
    FAIL before the fix, 0 of 12 after, in both cores. Chain 7622 stays on `pqz2` (v2) until plan Task 13.

12. **STARK backup promotion gate (review round 2, P-I; B-F1, B-F5, I-1, I-8).** `pqzh/stark-backup` is not
    reachable (pqz-ffi never dispatches to it) and stays a record. Before it is ever promoted to a live proof system
    it must have: (1) a reviewed **hiding** preset (`Params::DEFAULT` is `zk: false`: 28 queries against 16-row
    amount / new-balance columns let a proof reader interpolate them; its 71.9 bits are below target); (2) a size
    bound that admits the hiding proofs (`MAX_PROOF` 163,840 B is below them; `tests/smoke.rs` lifts the cap) or a
    smaller hiding configuration; (3) statement decoding by `pqz-stmt` with the op tag, id, auditorOn and zero-word
    checks (today only the fee word is read, `rel.rs` `parse_tx`); (4) a distinct `proofSystemId`; (5) every
    relation (today R_REG and R_TX only); (6) a verifier that rejects non-hiding configurations (`zk == false`) and
    a preset at 128-bit proven soundness; (7) the salt-form check (B-F5); (8) the prover hygiene Ligero got in this
    review (constant-time pass, wiping); (9) the verifier fault handling (OOM as `NodeFault`, panic containment;
    wasm32 traps on a panic); (10) vectors / KAT, tamper and xcheck runs, fuzzing, gas rows and its own review round.
    Status: recorded, no code; **owner ruling 2026-10-19: accepted** (decisions CTR-PQZ-10).

Scratch (not needed to resume, re-creatable): the LaZer and lattice-estimator clones, the upstream tbox harness and
debug builds under the session scratchpad `p6d/`.

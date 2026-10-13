> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQ Zether proof engine: the E-S1 `pqz-core` spike (P6d)

Written 2026-10-13 for P6d of the P6 roadmap (`docs/superpowers/plans/2026-10-12-p6-roadmap.md`): LaZer `3330e48`
forked into `pqz-core/` with its six arithmetic layers rewritten (CTR-PQZ-09), the arithmetic-layer KAT against
upstream, `R_REG` and a first `R_TX` proved and verified natively and as freestanding `wasm32`, and the result held
against the kill criteria. Nothing here changes a rule; the relations and parameters are those of
`docs/contracts/pq-zether.md` (CTR-PQZ-03, CTR-PQZ-09, §7.2 step 6, §7.4). Branch `p6d-pqz-core` (commits `c91b3ab` …
`70314c8`); state and reruns: `pqz-core/STATUS.md`, `pqz-core/README.md`.

**[measured]** marks a number from a run in this spike (machine and settings in §2). **[estimate]** marks a number
from the codegen or the estimator, not a run. **[inference]** marks a conclusion drawn here.

## 1. Result

**Two of the roadmap's four kill criteria are missed: verify by ≈ 300× and prove by ≈ 2.8× (the owner raised the prove limit from 3 s to 6 s on 2026-10-13; ≈ 6× against 3 s). The kill decision is pending
(owner).** **Update P6d-2 (§11, pure implementation changes, proofs byte-identical): `R_TX` prove 1.10 s native now
meets the 6 s limit; verify 0.72 s is ≈ 14× over 50 ms.** The table below is the spike's state (main `fd8600f`). The upstream timing cross-check the owner ordered is done (§10): upstream LaZer runs the same `R_TX` 2.3–2.6×
faster than the fork and still misses both time criteria (prove 6.6 s, verify 6.6 s). The proof size and the forbidden-symbol scan pass. The
browser budgets of CTR-PQZ-18 are missed too: `R_TX` wasm prove time and wasm memory are both above the hard limits
(§7).

| Kill criterion (CTR-PQZ-09, roadmap P6d row) | Limit | `R_TX` | |
|---|---|---|---|
| Transfer proof size | ≤ 96 KB (98,304 B, `PQZ_MAX_PROOF`) | 42,738–42,770 B [measured] | pass |
| p99 adversarial verify | ≤ 50 ms (chain host) | 15.2 s native, 33.4 s wasm (median honest verify) [measured] | **miss, ≈ 300×** |
| Prove | ≤ 6 s desktop (3 s until 2026-10-13, owner) | 17.0 s native, 39.3 s wasm (median) [measured] | **miss, ≈ 2.8×** |
| GMP / MPFR / float / `abort` / `malloc` on prove or verify paths | none | none [measured] | pass |
| Arithmetic-layer KAT equal to upstream (CTR-PQZ-09) | equal | 19/19 cases [measured] | pass |

The verify row uses the honest verify time: an adversarial proof that passes the decoder and the hash check runs the
full verify before it is rejected, so the p99 over adversarial inputs is about the honest verify time [inference]. The
spike ran on a desktop, not the chain host; a 300× gap does not depend on that difference [inference].

The size criterion has room: 42.7 KB is inside the spec's 30–50 KB estimate and under half the kill line. The time
criteria are where the spike fails. Whether the gap comes from the fork's rewrite (portable C, a 128-bit reduction
per product term) or is inherent to the statement under LaZer's protocol (§8: verify costs as much as prove) is not
known yet; that is what the upstream cross-check decides.

## 2. What ran

| Item | Value |
|---|---|
| Upstream | LaZer <https://github.com/lazer-crypto/lazer> commit `3330e487228f633eceb322807b13a596b516770f` (main, 2026-09-28), MIT, IBM |
| Fork | `pqz-core/lazer/` (subset, pristine in `c91b3ab`, changes marked `PQZ:`), `pqz-core/src/` (rewritten layers, C ABI `pqz.h`) |
| Codegen | LaZer's `lnp-tbox-codegen.sage` in `sagemath/sagemath:10.7` (pinned digest), `--network none` |
| Estimator | lattice-estimator `53da598`, `RC.ADPS16` (as P6b) |
| Machine | AMD Ryzen 5 7235HS (8 threads, no AVX-512), single thread |
| Native | clang 18.1.3 `-O2`, no `-march` (portable, pq-zether.md §10); `build/native/pqz_bench 7 7` under `scripts/capped` |
| wasm32 | clang 18 `--target=wasm32-unknown-unknown`, `wasm-ld-18`, freestanding, 8 MiB stack; node v26.8.1, `test/run_wasm.mjs 3 1` |

The six rewritten layers, for the fixed parameters only (q = 2^42 − 215, d = 64, l = 4):

| LaZer layer | Upstream | `pqz-core` |
|---|---|---|
| Integers | GMP `mpz` / multi-limb `int_t` | `src/pqz_mpn.h`, constant-time limb operations, no GMP |
| Ring arithmetic | CRT over several moduli, HEXL NTT (C++) | `src/pqz_ntt.c`: incomplete negacyclic NTT mod q, 4 × 16 base multiplication, portable C |
| Discrete Gaussian | `double` | integer sampler (`lazer/grandom.c`, `src/pqz_fixexp.h`) |
| Rejection | MPFR | fixed-point exp (`lazer/rejection.c`, `src/pqz_fixexp.h`) |
| Memory | `malloc` | caller arena (`src/pqz_arena.c`, `lazer/memory.h`) |
| Errors | `ERR` / `ASSERT` → `abort` | sticky error code with file:line (`src/pqz_rt.h`) |

Also: AES-NI replaced by a bitsliced software AES-256-CTR (bit-exact), no stdio in the library, capped rejection
loops, and a bounded proof decoder.

## 3. Arithmetic-layer KAT

CTR-PQZ-09's only cross-check against upstream is the arithmetic layer, because the samplers and the PRNG change the
transcripts. `kat/lazer_dump.c` is one source with two backends: built against upstream it writes the golden file,
built against `pqz-core` it writes the same cases, and `kat/check.py` compares them.

**The AVX-512 runner became a one-shot golden dump.** No AVX-512 machine was available. `kat/build-lazer-dump.sh`
builds upstream statically (HEXL's AVX-512 kernels forced in, GMP / MPFR / libstdc++ static) and the binary ran once
under Intel SDE 9.48.0 `-spr` (Sapphire Rapids emulation). The output is checked in as `kat/lazer-3330e48.json`; an
AVX2 (`v3`) build of upstream was checked too. The comparison then runs on any machine, with no SDE and no upstream
build. A one-time run of the `v4` binary on real AVX-512 hardware is still recommended, to exclude an emulator
artefact.

**19/19 cases equal** [measured]: inputs, ring product, add / sub / neg / scale, automorphism, CRT-domain
multiply-add and multiply-sub, ℓ2² and ℓ∞ norms, matrix-vector and dot products, vector ℓ2², decompose, power2round,
the AES-256-CTR stream, and the uniform and binomial samplers. Re-run after every later change: still 19/19.

**Upstream finding: strict aliasing in `aes256ctr-amd64.c`.** The AES-NI init reads the `uint64_t` nonce through an
`unsigned long long` pointer. gcc 13 at `-O2` then drops the rng domain separator: every domain gives the domain-0
stream. The golden build uses `-fno-strict-aliasing`. The fork does not carry this file (software AES).

## 4. Parameters

LaZer's tbox needs `nprime > 0`: with `nprime = 0` its layout is wrong upstream (β is placed at `l + 2·256/d`, tβ at
`l + loff`), and the fork's codegen refuses it. Both relations therefore carry a one-polynomial approximate ℓ∞ proof
as filler: `R_REG` selects `s[0]` (coefficients in [−1, 1], `Bprime` 1), `R_TX` selects `e2_t` (|coefficient| ≤ 20,
`Bprime` 64), `u = 0`.

LaZer's codegen sizes the ranks from a root-Hermite target. `params/e_s1_proof.sage` runs the real codegen with
floors and raises them until lattice-estimator `53da598` (`RC.ADPS16`) gives β ≥ 450 on both instances (CTR-PQZ-03's
target); `pqz_delta = 1.00366`. Record: `pqz-core/params/estimator-e-s1.txt` [estimate].

| | kmsis | kmlwe | m2 | MSIS β (classical / quantum) | MLWE uSVP β (best: dual hybrid β) | codegen proof size | expected attempts |
|---|---|---|---|---|---|---|---|
| `R_REG` | 22 | 33 | 67 | 452 (132.0 / 119.8) | 470 (462, 134.9 / 123.0) | ≈ 29,188 B | 6.46 |
| `R_TX` | 23 | 33 | 68 | 456 (133.2 / 120.8) | 470 (462, 134.9 / 123.0) | ≈ 44,638 B | 10.15 |
| Kyber-512 (P6b) | | | | | 406 | | |

Both instances are above the 450 target and above Kyber-512's 406.

**LaZer's real constants** (from the generated headers, replacing P6b's recalled ones):

| Constant | P6b (recalled) | LaZer `3330e48` |
|---|---|---|
| Challenge coefficients ω (P6b: κ) | κ ≥ 8 | 8 |
| Challenge bound η | 137 (operator norm, 99 % quantile) | 140 (`√ℓ1(σ₋₁(c)·c)`), \|C\| = 2^129 |
| `Z_q` repetitions λ | ≥ 4 | 4 |
| Binding bound | `8η·√(B1² + B2²)` | `4η·√(B1² + B2²)`, bimodal `s2` |
| Rejection width γ1 | 11 | 14 |
| Modular JL constant | 41 [unverified] | 41 |

P6b sized the MSIS rank at n ≥ 24, m2 ≥ 66 under conservative choices (binding factor 8η, no bimodal rejection). With
LaZer's 4η and bimodal `s2`, rank 22 / 23 already reaches β 452 / 456, so the β ≥ 450 target is met directly; P6b
noted that bimodal rejection lowers both [inference]. m2 = 67 / 68 is above P6b's 66.

## 5. Arena, upstream leaks, ILP32

**Arena exhaustion, not overflow.** Under the arena the upstream tbox test crashed. The first hypothesis, an
`nelems_max` overflow in the Schwartz–Zippel accumulators, was wrong: there `np = 2(m1 + Z + quad_many->l)` exceeds
`n_ = 2(m1 + Z + quad_eval->l)`, so `nelems_max` is lowered, and ASan on the `malloc` path is clean. gdb showed
`PQZ_ERR_ARENA` (512 MiB exhausted), after which the sink block handed out garbage pointers. Cause: LaZer allocates
CRT representations lazily, so a long-lived polynomial converted in the middle of a call (for example a caller's `Ds`
in `polyvec_addmul`) pinned every block freed below it in the LIFO arena; one 512-byte crtrep pinned 67 MB after one
prove. Fix (`b3ebf33`): freed inner blocks go on per-size free lists (at most 32 sizes; LaZer uses about 6) and are
reused. The arena peak is now within 2 % of the live set [measured]: `R_REG` 141 MB live / 144 MB peak, `R_TX`
603 / 612 MB.

**Two upstream leaks**, fixed in the fork: `poly_free` freed the crtrep only when `crt = 1` (a polynomial set back to
coefficients leaked it), and `_lnp_tbox_compute_z34` leaked `tmp_polyvec`. Upstream's `lnp-tbox-test.c` on
q = 2^42 − 215 passes with the arena (peak 43 MB over one prove and 30 verifies) and with `malloc` under
ASan / LSan / UBSan, no leaks [measured].

**Two ILP32 bugs**, found by the `wasm32` build: `int_lshift`'s loop index was `long` and compared unsigned, so on
ILP32 it wrote below the limbs (a trap in `int_binexp`); the coder's `grandom` used `long`, so decoded values above
2^31 would differ between native and wasm verifiers. Both now use fixed-width types.

Other fixes on the way to a valid `R_TX`: A1 / A2' / B' converted to NTT form at init (below the arena mark), the
verifier's asserts accept NULL `Es` / `Em` / `v` arrays (as the prover's do), `__evaleq` allocates scratch only for a
quadratic part, `z4` coded with `log2stdev4`.

## 6. Measurements

Medians [measured]; native 7 proves and 7 + 7 honest verifies, wasm 3 proves and 1 verify. Native times vary by
±20 % between runs on this machine (`R_TX` prove 13.7–17.0 s).

| | proof bytes | prove native | verify native | prove wasm | verify wasm | arena peak native / wasm | rejection-loop iterations (mean) |
|---|---|---|---|---|---|---|---|
| `R_REG` | 28,070–28,107 | 1.20 s | 0.99 s | 3.27 s | 2.61 s | 144 MB / 113 MB | 4.3 |
| `R_TX` | 42,738–42,770 | 17.0 s | 15.2 s | 39.3 s | 33.4 s | 612 MB / 476 MB | 13.0 |

- Proofs are smaller than the codegen estimate (`R_TX` 42.7 KB against ≈ 44.6 KB). `R_REG` is above the spec's
  15–25 KB estimate for the registration proof.
- Init (expansion of A and the ABDLOP keys) takes 0.33 s native, 0.49 s wasm.
- Adversarial verifies (bit flip, random bytes, a changed statement coefficient, truncation, a long unary run) are all
  rejected: in ≈ 3 ms (`R_REG`) / ≈ 15 ms (`R_TX`) when the decoder or the hash check fails, otherwise after a full
  verify.
- Iterations count both rejection loops (z3 / z4 and z1 / z2), so they are not the codegen's "expected attempts".
- wasm gives the same proof lengths as native for the same seeds; honest proofs verify and tampered ones are rejected
  under both. Byte equality of the proofs was not checked.
- Library objects, native and wasm, reference only `memcpy`, `memset`, `__stack_chk_fail` (and `__stack_pointer`)
  outside themselves (`check_symbols.sh`). The native x86-64 objects contain no SSE scalar or x87 floating-point
  instructions, and the wasm objects no `f32` / `f64` operations (llvm-objdump 18 prints the untyped `select`, opcode
  0x1b, as `f32.select`).

## 7. Browser budgets (CTR-PQZ-18)

The spec's prover budgets (`docs/contracts/pq-zether.md` §11, CTR-PQZ-18; p95 per transfer on reference devices) are
not kill criteria; the spike's wasm numbers against them [measured; node, not a browser; medians, not p95]:

| Budget | Desktop browser | Phone | Hard limit | Measured (wasm32) | |
|---|---|---|---|---|---|
| Prove `R_TX` | ≤ 5 s | ≤ 15 s | 30 s ⇒ fallback | 39.3 s | above the hard limit; ≈ 8× the desktop budget |
| Peak WASM memory | ≤ 128 MiB | ≤ 128 MiB | 256 MiB (iOS WebKit) | `R_TX` arena peak 476 MB (`R_REG` 113 MB) | `R_TX` ≈ 1.8–1.9× the hard limit |
| Module size | ≤ 1.0 MB gzip | same | — | `pqz.wasm` 337 KB uncompressed (with the bench steps) | inside |

**wasm / native ratio 2.3–2.7×** [measured]: prove `R_TX` 39.3 / 17.0 s = 2.3, `R_REG` 3.27 / 1.20 s = 2.7; verify
2.2 and 2.6. At that ratio the engine exit target of prove ≤ 6 s native (CTR-PQZ-18) maps to ≈ 14–16 s in wasm, above
the 5 s desktop-browser budget [inference]. The spike's wasm build has no `-msimd128` (the spec's build target names
it); the phone was not measured.

## 8. Where the time goes

gprof on `R_TX` (native):

| Share | Where |
|---|---|
| ≈ 55 % | ring arithmetic: `pqz_red128` (3.6·10^9 calls) and `basemul16` (5.9·10^7), a 128-bit reduction per product term |
| ≈ 8 % | `spolymat_sort`: insertion sort in `pqz_qsort` |
| rest | LaZer's sparse-matrix bookkeeping of the Schwartz–Zippel accumulation |

**Verify costs about as much as prove.** The verifier redoes the same Schwartz–Zippel accumulation over sparse
matrices of dimension `2(m1 + Z + l)`; `R_TX` has 64 quadratic and 80 evaluation equations. A verifier 300× faster
needs more than a faster ring multiply: at most about half of the time is in the ring arithmetic [inference].

Candidate work, not done and not to start before the cross-check: lazy reduction in `basemul16`, a proper sort in
`pqz_qsort`, fewer `R_TX` equations (for example merging the 16 per-digit evaluation equations), and reuse of the
accumulated matrices on the verifier side.

## 9. Open

- **Kill decision (owner).** The upstream cross-check is done (§10); the decision and any optimisation wait for the
  owner.
  What the hash-based fallback would mean (STARK, Ligero) and the other options: `pqz-proof-alternatives.md`.
- **Browser budgets.** `R_TX` wasm prove (39.3 s) and wasm memory (476 MB) are above CTR-PQZ-18's hard limits; no
  browser or phone run yet (§7).
- **Golden dump on real AVX-512.** One run of the `v4` dump binary on AVX-512 hardware, diffed against
  `kat/lazer-3330e48.json`.
- **Arena exhaustion is not graceful.** Once the arena is exhausted the sink block is shared by every later
  allocation; sparse structures in it then hold garbage pointers and the call can crash instead of returning
  `PQZ_ERR_ARENA`. Size the arena from the measured peaks (the bench uses 768 MiB) or make exhaustion end the call.
- **wasm.** Proof byte equality with native not checked; node only, no browser run; `R_TX` needs ≈ 0.5 GB of the
  4 GiB wasm32 memory.
- **Knowledge error.** The generated headers state a knowledge error ≤ 2^-127.0 (the codegen's bound for the whole
  protocol). P6b's gate is per Fiat–Shamir round; the per-round figures were not recomputed with LaZer's
  \|C\| = 2^129 and η = 140.
- UBSan findings left as upstream: zero-length VLAs when M = 0 or nbin = 0 (`lnp-tbox.c` 223, 875, 3358), null + 0
  in `aes256ctr.c:212`.

## 10. Upstream cross-check

Done 2026-10-13 at the owner's request, before any optimisation. Scripts, shim and the full write-up:
`pqz-core/xcheck/` (`RESULTS.md`; the scripts name the session scratch paths they ran from).

**Method.** The fork's own statement builder (`src/pqz_rel.c`) and bench, at `b2402b5`, compiled unchanged in logic
against upstream LaZer `3330e48` through a small shim (malloc instead of the arena, no bounded decoder). Same params
headers (q = 2^42 − 215; upstream accepts them as is, they carry its 2 × 50-bit CRT moduli), same 64 quadratic + 80
evaluation equations, same witness and seeds. Upstream built offline with its Makefile flags (gcc 13.3 `-O3
-march=native`, AVX2 here, no AVX-512), HEXL scalar path, static GMP / MPFR, AES-NI, asserts off, plus
`-fno-strict-aliasing`. Every upstream proof verifies; proof sizes match the fork's.

Medians of 5, ms [measured]:

| | upstream | fork as shipped (clang -O2, asserts on) | fork / upstream | fork `-O3 -march=native`, asserts off | fork / upstream |
|---|---|---|---|---|---|
| `R_REG` prove | 622 | 1,302 | 2.1× | 985 | 1.6× |
| `R_REG` verify | 566 | 992 | 1.75× | 784 | 1.4× |
| `R_TX` prove | 6,623 | 17,110 | 2.6× | 13,497 | 2.0× |
| `R_TX` verify | 6,621 | 15,027 | 2.3× | 12,076 | 1.8× |
| `R_TX` proof bytes | 42,736–42,755 | 42,734–42,770 | same | | |

Microbenchmarks, fork as shipped against upstream [measured]:

| Operation | upstream | fork | fork / upstream |
|---|---|---|---|
| Ring multiplication, coefficient form in and out | 6.9 µs | 3.3 µs | 0.48× (fork faster) |
| Pointwise product, operands already in NTT form | 0.31 µs | 1.79 µs | 5.8× |
| 23 × 153 matrix × vector (`R_TX` size) | 1.42 ms | 6.61 ms | 4.6× |
| AES-256-CTR per MiB | 0.13 ms | 61 ms | 480× |

**Where the fork's extra time goes** (gprof, one `R_TX` prove + verify, 13.3 s upstream against 27.6 s fork; `perf`
is blocked on this host) [measured]:

- ≈ 75–80 % of the gap: pointwise multiplication. The fork's NTT mod q splits X^64 + 1 into 4 factors only, so each
  product is four degree-16 schoolbook multiplications (`basemul16`, 12.7 s); upstream's complete CRT NTT does
  2 × 64 modular multiplications (2.15 s).
- ≈ 25 %: sparse-matrix sorting (`spolymat_sort` 4.5 s + `spolymat_insert_elem` 1.0 s, insertion sort) against
  upstream's libc `qsort`.
- ≈ 1.5 %: software AES (480× slower per MiB, little PRG output used).
- Asserts ≈ 4 %; clang `-O2` generic against `-O3 -march=native` ≈ 18 %.
- No GMP, the arena, the integer Gaussian and the fixed-point rejection cost nothing or help (upstream: `int_mod`
  1.9 s against the fork's 1.0 s, plus ≈ 1.5 s in malloc).

**What is inherent.** In upstream's own profile pointwise multiplication is ≈ 16 %; most of its time is LaZer's
generic sparse-matrix / Schwartz–Zippel bookkeeping over the 153-dimensional quadratic forms, integer arithmetic and
malloc, on prover and verifier alike [measured]. Against the thresholds on this machine, upstream `R_TX` prove 6.6 s
is ≈ 1.1× over 6 s (≈ 2.2× over the former 3 s) and verify 6.6 s ≈ 130× over 50 ms; `R_REG` prove 0.62 s meets 6 s, verify 0.57 s is ≈ 11× over
50 ms [measured]. So the fork's rewrite explains a factor of ≈ 2–2.6; the remaining gap to 50 ms is in the
statement as LaZer proves it [inference].

Caveats: no AVX-512 on this CPU (HEXL's IFMA kernels would only shrink upstream's ≈ 2.2 s of pointwise / NTT time,
not the bookkeeping) [inference]; compilers differ (the `-O3 -march=native` fork column removes most of it); a noisy
host (upstream ±5 % across seeds, fork ±20 % run to run) and 5 samples, so medians, not p99; proofs not
byte-identical (MPFR against integer samplers change rejection counts; ≈ 0.15 s per extra try); upstream leaks in
this harness (max RSS 2.1 GB against the fork's 612 MB arena) and its malloc time is included; adversarial verifies
skipped on both sides (upstream has no bounded decoder).


## 11. Optimisation (P6d-2)

Done 2026-10-13 at the owner's request ("optimise the fork"), branch `p6d2-opt`. Pure implementation changes: the
parameters, the relations, the proof format and `proofSystemId` are unchanged. The bench now hashes the proofs
(FNV-1a over the seeds): **every step left the proofs byte-identical** to main for the same seeds, and native and
wasm proofs are equal byte for byte (seeds 0..2) [measured]. KAT 19/19, the symbol scan (native and wasm) and the five
tamper kinds pass after every step; ASan + UBSan on the malloc path find nothing beyond the four known upstream
UBSan nits [measured]. Steps, numbers and raw runs: `pqz-core/STATUS.md`, `pqz-core/opt/`.

Medians, same session, the setup of §2 [measured]:

| | main: prove / verify native | P6d-2 | main: prove / verify wasm | P6d-2 | arena peak native / wasm, main → P6d-2 |
|---|---|---|---|---|---|
| `R_REG` | 1.30 s / 1.02 s | 0.25 s / 0.17 s | 3.30 s / 2.61 s | 0.38 s / 0.23 s | 144 → 112 MB / 113 → 87 MB |
| `R_TX` | 17.0 s / 14.9 s | **1.10 s / 0.72 s** | 39.6 s / 34.5 s | **1.59 s / 0.82 s** | 612 → 316 MB / 476 → 241 MB |

What gave what (`R_TX` prove native, cumulative) [measured]:

| Change | `R_TX` prove | Why it was slow |
|---|---|---|
| Base multiplication mod X^16 − ρ: one u128 column sum per output against a twisted operand (ρ·b), 64-bit-only reduction; on wasm32 21-bit limbs with 64-bit products | 17.0 → 12.1 s (wasm 39.6 → 18.4 s) | separate low / high sums, three reductions and a multiplication by ρ per output; on wasm32 every 64 × 64 → 128 product was a `__multi3` call |
| Heapsort for the sparse-matrix sort | → 8.4 s | insertion sort, O(n²) |
| Accumulators swapped, not copied | → 7.7 s | a full copy of the accumulated sparse matrix per equation |
| Gram terms of the ℓ2 / binary equations skip the zero columns of the public selection matrices | → 1.74 s (arena 612 → 325 MB) | `R_TX` selects 32 of 146 witness polynomials per ℓ2 equation; LaZer built all 146² entries of o(Es)ᵀEs (all but 32 zero) and carried them through every later sparse-matrix sum, sort and copy |
| Bitsliced AES with the Boyar–Peralta S-box and transposed bit planes | → 1.24 s | the S-box was an inversion chain of four bitsliced GF(2^8) multiplications; 1 MiB 60 → 8.8 ms |
| Zero columns skipped in `polyvec_mul2`, zero products in the Gram dots, the z3 term accumulated in int64 | → 1.10 s (verify 0.88 → 0.72 s) | the same zero structure, and 2-limb integer adds for sums below 2^51 |

Tried and dropped: a `poly_scale` fast path (no measurable gain once the zero columns were gone), Karatsuba on the
degree-16 products (slower than the column kernel with u128 sums, microbench) [measured]. Not done: asserts off
(pq-zether.md §10 keeps the invariant checks in release builds; the cross-check measured ≈ 4 %), `-O3` /
`-march=native` (pq-zether.md §10: portable `-O2`), an AVX2 backend and an integer CRT multiplication (the base
multiplication is ≈ 7 % of the `R_TX` profile now).

**Against the kill criteria.** `R_TX` prove 1.10 s meets the 6 s limit (and the former 3 s) [measured]. Verify
0.72 s honest, 0.67 s adversarial maximum, is ≈ 14× over 50 ms (was ≈ 300×) [measured]; the profile is now flat
LaZer bookkeeping (`intvec_set`, sparse inserts, `int_mod`), so reaching 50 ms needs structural work (fewer
equations, typed accumulation instead of generic sparse matrices), not more kernel tuning [inference]. §10's "what is
inherent" overstated the statement's share: most of LaZer's bookkeeping was spent on zero entries of the selection
matrices' Gram matrices, which upstream computes as well (upstream verifies `R_TX` in 6.6 s, the fork now in 0.72 s)
[measured / inference]. Browser budgets (CTR-PQZ-18, node): wasm `R_TX` prove 1.59 s is inside the 5 s desktop budget;
the wasm arena peak 230 MiB is under the 256 MiB hard limit but 1.8× the 128 MiB budget [measured].

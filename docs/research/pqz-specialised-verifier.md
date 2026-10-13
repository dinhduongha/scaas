> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZL specialised verifier: `R_REG` / `R_TX` without LaZer's generic machinery (P6-SV)

Written 2026-10-13 for the owner's P6-SV spike (TODO P6-SV), after the verifier-floor analysis
(`pqz-verifier-floor.md`). Question: can a verifier written for our two fixed statements accept exactly the proofs
LaZer's generic `tbox` verifier accepts, and how close does it get to the floor and to the 50 ms p99 verify limit
(CTR-PQZ-09)? Branch `pqz-sv` (not merged); code `pqz-core/src/pqz_sv.c`, tests `pqz-core/test/pqz_sv_diff.c`,
`pqz-core/test/pqz_sv_fuzz.c`, runs `pqz-core/sv/`. **No decision is recorded here.**

**[measured]** marks a number from a run in this note (machine in §2). **[estimate]** marks a number computed from
counts or a rough figure. **[inference]** marks a conclusion drawn here.

## 1. Result

**The specialised verifier accepts exactly what the generic one accepts on every case tried (8,782 differential
cases, 0 disagreements) and verifies `R_TX` in 7.9 ms (p50) / ≤ 10.4 ms (p99, adversarial) with the portable `-O2`
build: 84× faster than the generic verifier and ≈ 5× under the 50 ms limit [measured].** It is below the floor
estimate for portable C (9.1 ms, `pqz-verifier-floor.md`) because the JL fold, the largest floor term, came out 9×
cheaper than the floor's prototype (§5). The optional x86-64-v3 + AES-NI build takes `R_TX` to 4.5 ms; wasm32 under
node to 11.9 ms. A verify needs 1.7 MB of working arena instead of 273 MB, plus 9.1 MB of tables built once at
`pqz_init`.

| `R_TX` verify, ms [measured] | p50 honest | p99 honest | p99 adversarial | generic verifier p50 | floor (`pqz-verifier-floor.md`) | vs 50 ms |
|---|---|---|---|---|---|---|
| native portable (`-O2`, the reference) | **7.85** | 12.6 ¹ | **10.4** (bench) / 9.5 (diff, n = 1,917) | 660 | 9.1 (SHAKE PRG), ≈ 11 (table AES) [estimate] | ≈ 5× under |
| native x86-64-v3 + AES-NI (optional) | 4.54 | 5.5 | 4.7 (bench) / 5.6 (diff, n = 957) | — | 2.5 (hand AVX2) [estimate] | ≈ 9× under |
| wasm32, node, no SIMD | 11.9 | 14.4 | 13.4 (n = 1,000) | 741 | 12.8 [estimate] | ≈ 3.5× under |
| wasm32 with `-msimd128` (auto-vectorised only) | 12.0 | 15.5 | 13.1 | — | ≈ 7–9 [estimate] | |

| `R_REG` verify, ms [measured] | p50 honest | p99 honest | p99 adversarial | generic p50 |
|---|---|---|---|---|
| native portable | 3.97 | 4.5 | 4.7 (bench) / 4.9 (diff, n = 3,717) | 166 |
| native x86-64-v3 + AES-NI | 2.38 | 2.7 | 2.9 / 3.0 | — |
| wasm32 (node) | 5.9 | 6.8 | 6.5 | 204 |

¹ One noisy stretch of the busy host (the 200-run mean is 7.98 ms); the diff harness's 20 honest `R_TX` verifies give
p99 8.2 ms. "Adversarial" in the bench is its five tamper kinds (most are rejected by the decoder in < 1.2 ms; a
changed statement coefficient runs the whole verify); in the diff harness it is ≈ 2,000 / 3,700 mutated proofs, most
of which pass the decoder and are rejected only by the final hash check, i.e. full verifies. The work does not depend
on the proof's content beyond the decoder, so p99 adversarial ≈ the honest time plus noise [inference].

**Gas** at the 0.12 M gas/ms conversion (`pqz-proof-alternatives.md` §6) [estimate]: `R_TX` p99 ≈ 10 ms portable →
≈ 1.2 M gas (p50 ≈ 0.95 M); x86-64-v3 ≈ 5.6 ms → ≈ 0.7 M; `R_REG` portable ≈ 4.9 ms → ≈ 0.6 M.

## 2. What ran

| Item | Value |
|---|---|
| Machine | AMD Ryzen 5 7235HS (Zen 3+, AVX2, AES-NI, no AVX-512), single thread, other services running |
| Toolchain | clang 18.1.3, wasm-ld 18, node v26.8.1 |
| Builds | **portable** (`build.sh native`: clang `-O2`, generic x86-64, the reference); **x86-64-v3** (`build.sh native-x86v3`: the same library with `pqz_sv.c` alone at `-O3 -march=x86-64-v3 -maes`, AES-NI intrinsics, otherwise compiler auto-vectorisation); **wasm32** (`build.sh wasm`: freestanding, no SIMD, as main; `WASM_SIMD=1` adds `-msimd128`) |
| Runs | `sv/bench.sh` (bench, under `scripts/capped`), `sv/diff.sh` (differential test), `sv/fuzz.sh` (ASan + UBSan, libFuzzer); raw JSON lines in `sv/runs/` |
| Statistics | p50 / p99 over the stated number of verifies, one machine, busy host |

## 3. Design

**Same transcript, same checks, different arithmetic.** `lnp_tbox_verify` turns every equation of the statement
and of the norm proofs into a sparse quadratic form over the 2 (m1 + l) interleaved slots (s, o(s)), folds them
with the Schwartz–Zippel challenges into λ = 4 accumulators, applies the automorphism step
(R ↦ (R + o(R) + X^{d/2}(R′ + o(R′)))/2), folds all of them again with the ring challenges μ_k and only then
evaluates the one form at the proof: v = zᵀR2z + c·r1ᵀz + c²·r0 − f. Every step is linear in the equations. So v is
the same element of R_q when each equation is evaluated on z directly and the values are combined with the same
scalars and μ_k; that is what `pqz_sv.c` does. With z's odd slots equal to o(even slots) (true by construction in
`lnp_quad_verify`) and o(c) = c, the shuffled automorphic form evaluates to o(value), so the automorphism step is
applied to evaluated polynomials [inference; confirmed by the differential test, §4].

| Generic `tbox` step | Specialised evaluation (`R_TX`; `R_REG` is the subset) |
|---|---|
| ℓ2 equation i: o(Es_i)ᵀEs_i Gram matrix (146 × 146, all but 32 entries zero) | Σ o(z_p)·z_p over the 32 (or 1) selected slots + c·o(2^j powers)·υ_i − c²·B_i² |
| binary equation: o(Ps)ᵀPs | Σ_b o(z_b)·(z_b − c·J), J the all-ones polynomial, 15 slots |
| υ binary equation | Σ_j o(υ_j)·(υ_j − c·J), Z products |
| β3 / β4 coefficient equations (63 + 63) | one product each, the 63 challenges folded into one polynomial Σ γ_i X^i |
| `R_TX` evaluation equations (80) | Σ_t Γ_t·(pk_tᵀr + e2_t) + Γ_3·u_Tᵀs_f + Σ_b A_b·bits_b, with Γ_t = Σ_i γ X^−i and A_b the challenge-weighted bit coefficients |
| z3 / z4 (JL) equations, λ rows each | inv2·(β + o(β))·Σ_p o(z_p)·W_{k,col(p)} + c·Σ V_k·o(y3) − ⟨z3, V_k⟩c², W = V·R the JL fold |
| quad-many fold, `polyvec_mulsparse`, `spolymat_*` sorts / copies | v = Q + c·L + c²·R: the μ_k-weighted equation values grouped by the power of c, three reductions |
| ABDLOP part | w = A1·z1 + A2′·z21 − c·2^D·tA1, then LaZer's `dcompress_use_ghint` rule |

**What is reused, unchanged:** the bounded proof decoder (`pqz_decproof`, LaZer's coder), `abdlop_hashcomm`, the
coder + SHAKE128 rounds over ty3 ‖ ty4 ‖ tβ, tg and t ‖ v ‖ w1, `poly_urandom_autostable` for c′ and the comparison.
The statement is parsed with the same rule as `pqz_rel.c` (every coefficient < q). So the transcript bytes are
LaZer's own encoder output; only v and w1 are computed differently, and they are canonical values in [0, q) / [0, m).

**Challenges.** Every Fiat–Shamir-derived challenge is drawn with LaZer's derivation, re-implemented over the same
PRG: AES-256-CTR with key = seed, nonce = le64(dom) ‖ 0⁸, 128-bit big-endian counter (`rng.c`), `_urandom_i64`'s
42-bit LSB-first fields with rejection, `intmat_urandom`'s row domains (dom ≪ 32 | i·256), `polyvec_urandom`'s
(dom ≪ 32 | i + 1), `_brandom`'s plus / minus bit halves. The evaluation-equation challenges come from one function,
`sz_eval_challenges`, which mirrors `lnp-tbox.c`'s `__schwartz_zippel_accumulate2` derivation; the domains are those
`lnp_tbox_verify` passes. A test hook checks this PRG against LaZer's on random seeds, domains and lengths, plus the
FIPS-197 AES-256 vector.

**Arithmetic.** Ring products through a complete negacyclic NTT of degree 64 over **four** NTT-friendly 30-bit primes
(P ≈ 2^120), 32-bit Montgomery, Montgomery form throughout, mixed-radix CRT (Garner) back to Z_q. Four, not the floor's
three: with three primes (P ≈ 2^90) a sum is exact only while one operand is short (|z1| < 2^21 in the floor's
estimate), and the verifier must be exact on adversarial inputs before any bound is checked (z21 has no norm check at
all). With four primes every sum below stays under 2^106 for any input (inputs are values mod q or small integers;
bounds next to each sum in the code), against P/2 ≈ 2^119 [inference]. Cost: 4/3 of the three-prime products and
NTTs [estimate].

**Precomputed** at `pqz_init`, below the arena base mark: A (32 × 32, shared), A1, A2′, B′ of both relations in
4-prime NTT form (9.1 MB), the CRT constants, the automorphism as a permutation of the NTT slots, the o(2^j powers)
polynomials of the ℓ2 bounds. Public keys are not cached: 160 forward NTTs per `R_TX` verify cost ≈ 0.1 ms
[estimate], below the noise of the rest.

**PRG and JL fold.** The 627 KB of JL matrix bytes per `R_TX` verify are public (derived from the transcript), so the
portable build uses a table-based AES (four 1 KB round tables; the key schedule is expanded once per seed, not once
per row as LaZer's `rng_init` does); the prover keeps the constant-time bitsliced AES. The x86-64-v3 build uses
AES-NI for the same stream. The fold vR_k = Σ_i V_k[i]·R_i takes eight JL rows at a time: a 256-entry table of the
subset sums of their eight challenges per k, indexed by each column's transposed plus / minus bits (one 8 × 8 bit
transpose per byte column), so 10 M signed adds become ≈ 0.6 M lookups of 4-wide table rows.

**C ABI.** `pqz_verify_fast` next to `pqz_verify` in `pqz.h`, same arguments, same result (1 valid, 0 anything
else), same arena: a second entry point rather than a backend switch, so the generic verifier stays callable as the
reference in the same process (the differential test needs both) and no global mode can be left set by mistake.
No malloc, GMP, MPFR, float or `abort` on the path; working memory (≈ 1.1 / 1.7 MB) from the arena, freed at the end of
the call; every invariant (dimensions, arena exhaustion, PRG limits) is an error return; `check_symbols.sh` passes on
the native, x86-64-v3 and wasm objects [measured].

## 4. Equivalence testing

**Differential test** (`test/pqz_sv_diff.c`, `sv/diff.sh`). Each honest proof is made on a fresh statement (new
keys, message and prefix for `R_REG`; new keys, balance < 2^48, amount and fee for `R_TX`) from a seeded generator,
then verified by both verifiers, then mutated. Per proof and round: one random bit flipped; one byte set; random bytes
of the same length; truncated (one byte to all); extended by 1–16 zero / random bytes; a statement coefficient
changed (still < q); a statement coefficient set ≥ q; a prefix byte changed; the fee changed (`R_TX`); the previous
proof against this statement; the bench's long unary run; and 14 decoded-field mutations re-encoded with LaZer's
encoder (a test-only hook, so the proof is well formed and reaches the full verify): two z1 / z21 polys swapped, a
z3 and a z4 poly swapped, z1 ± 1, z1 large (norm), z4 at / over its ℓ∞ bound, z3 large, h (including its
coefficients 0 and d/2), hint, c (to another value in [−8, 8]), tB, tA1, z21 ± 1, the two h polys swapped. Plus a
re-encode without change (must be accepted) and 20 random multi-edit fuzz proofs (1–8 bit flips, byte sets, byte
inserts / deletes, chunk copies) per proof. Two runs of the final code, deterministic seeds [measured]:

| Run (`sv/runs/`) | Build | Honest proofs `R_REG` / `R_TX` | Cases | Generic accepts | Disagreements |
|---|---|---|---|---|---|
| `d2-portable` | portable | 40 / 20 | 5,694 | 129 (60 honest, 60 re-encoded, 9 no-op mutations) | **0** |
| `d2-x86v3` | x86-64-v3 + AES-NI | 20 / 10 | 2,844 | 61 | **0** |
| `b2-wasm-both` | wasm32 (`PQZ_VERIFY=both`) | 2 / 2 (each verified, then 20 verifies and 5 × 20 tamper cases per relation) | 244 | 44 | **0** |

The same harness on the previous commit (`d1-*`) gave the same 8,538 cases, 0 disagreements. "Generic accepts"
beyond the honest and re-encoded proofs are mutations that left the decoded proof unchanged (a poly swapped with
itself or with an equal one, a byte set to its own value); both verifiers accepted them.

**PRG check** (test hook, 200 random seeds / domains / lengths): `_urandom_i64` for moduli q (42 bits), 17 (5 bits)
and 1000 (10 bits), `_brandom` rows of 16–1,608 entries, against LaZer's `intvec_urandom` / `intvec_brandom`, plus
the FIPS-197 AES-256 vector: 0 mismatches [measured]. This covers the rejection branch of `_urandom_i64`, which
honest runs with modulus q essentially never reach.

**Sanitizers and fuzzing** (`sv/fuzz.sh`) [measured]: the bench with the specialised verifier under ASan + UBSan on
the libc-heap path (the verifier frees its blocks at the end of each call, so ASan sees each one): no reports. The
libFuzzer target (`test/pqz_sv_fuzz.c`: edit scripts over honest proofs and statements, both verifiers must agree,
ASan + UBSan): 748 executions in 10 minutes (the generic verifier dominates), 2,218 coverage edges, no crash, no
disagreement. A long fuzz campaign would need the fast verifier alone (or a faster reference).

**What the tests cannot reach.** A proof whose final hash check passes but which fails only a norm check (z1, z3,
z4, w − γ·w1, hint ℓ∞, h's zero coefficients) can only come from a cheating prover; mutated proofs fail the hash
first. Those checks were written against `_lnp_tbox_check_z34` / `lnp_quad_verify` line by line (same representatives,
same ≤ / < at the bound); the hint bound is unreachable within `PQZ_MAX_PROOF` (|hint| = m needs 2m bits).

## 5. Measurements

**Where the time goes**, `R_TX`, ms per full verify (40 honest verifies, phase timers in a scratch build of the same
source) [measured]:

| Phase | Portable | x86-64-v3 + AES-NI |
|---|---|---|
| Decode (LaZer's bounded decoder) + do_verify's reductions | 0.59 | 0.64 |
| Hash rounds (tA1, ty3 ‖ ty4 ‖ tβ, tg) | 0.12 | 0.13 |
| Input NTTs; the y3 / y4 / β / g slots (c·tB − B′·z21, 11 × 45 products) | 0.43 | 0.35 |
| υ / binary / ℓ2 / `R_TX` evaluation polynomials | 0.27 | 0.19 |
| JL rows: AES-256-CTR 627 KB | 2.40 | ≈ 0.1 |
| JL fold (subset-sum tables) | 0.66 | ≈ 0.8 |
| z3 / z4 terms (616 W NTTs, 640 products) | 1.08 | 0.73 |
| Schwartz–Zippel halves, automorphism step | 0.20 | 0.15 |
| μ, input rows (64 × 32 products), β quadratic equations, v | 0.97 | 0.67 |
| w = A1 z1 + A2′ z21 − c 2^D tA1 (4,577 products), UseHint | 0.89 | 0.58 |
| Final round (encode t ‖ v ‖ w1, SHAKE, c′) | 0.08 | 0.08 |
| **Total** | **7.8** | **4.6** |

The JL fold is 0.66 ms where the floor's branchless prototype took 5.75 ms for the same 10 M signed adds: eight rows
share one 256-entry subset-sum table per challenge row, so each column costs two table lookups per eight rows. AES is
now the largest portable term (≈ 15 cycles/byte with tables); SHAKE128 as the JL PRG would save ≈ 1.3 ms but changes
the protocol on both sides [estimate]. The x86-64-v3 build gets AES-NI and whatever the compiler vectorises;
hand-written AVX2 for the NTTs and products (≈ 3 ms of the 4.6 ms) is what the floor's 2.5 ms assumes [inference].

**Arena** [measured]: working set of one verify above the base mark: `R_REG` 1.06 MB, `R_TX` 1.67 MB (generic 81 MB
and 273 MB). The tables add 9.1 MB at `pqz_init` (A 1 MB, `R_REG` keys 3.0 MB, `R_TX` keys 5.1 MB; arena base
36.2 MB with LaZer's own copies). Init time 112 → 118 ms native.

**Prover unchanged:** the bench's proof hash over seeds 0..2 is `3bc7e9b3` / `834d6853` as on main; arithmetic KAT
19/19 [measured].

## 6. Risks and open points

- **Second implementation.** The specialised verifier re-states LaZer's equations (`lnp-tbox.c`, `pqz_rel.c`) by
  hand. The differential test covers what honest and mutated proofs reach; it cannot construct a proof that passes
  the final hash check and fails only a norm check (that needs a cheating prover), so those checks (z1, z3, z4,
  w − γw1, hint, h coefficients 0 and d/2) rest on reading the code against `lnp_quad_verify` /
  `_lnp_tbox_check_z34` line by line. An independent review of `pqz_sv.c` against `lnp-tbox.c` is still due before any
  use.
- **The statement is hard-wired.** The selection blocks, the `R_TX` evaluation equations and the input rows are
  re-stated from `pqz_rel.c` (`build_reg`, `build_tx`). A change to a relation must change both files; the
  differential test catches a mismatch on the first honest proof.
- **Upstream LaZer's transcript is mirrored as it is** (domains, PRG, encodings). Any change to the protocol or
  its transcript has to be made in both verifiers and bumps `proofSystemId` (CTR-PQZ-09).
- Not done: hand-written AVX2 for the NTT and the products (the x86-64-v3 build relies on auto-vectorisation),
  wasm SIMD tuning, a run on the chain host or a phone.

## 7. Files and reruns

```sh
cd pqz-core
./build.sh native            # libpqz with pqz_verify_fast, pqz_bench, pqz_sv_diff (test hooks)
./build.sh native-x86v3      # optional backend: pqz_sv.c for x86-64-v3 + AES-NI
./build.sh wasm              # pqz.wasm (WASM_SIMD=1 B=build/wasm-simd ./build.sh wasm: -msimd128)
sv/diff.sh <label>           # differential test, portable + x86-64-v3 -> sv/runs/<label>-*.jsonl
sv/bench.sh <label>          # p50 / p99, generic vs specialised, native / x86-64-v3 / wasm -> sv/runs/
sv/fuzz.sh <label> [secs]    # ASan + UBSan bench (malloc path) and the libFuzzer target
PQZ_VERIFY=fast build/native/pqz_bench 2 200                   # the bench with the specialised verifier
PQZ_VERIFY=both node test/run_wasm.mjs 2 20                     # wasm: both verifiers on every input, must agree
```

> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZL specialised verifier: the five PQZ relations without LaZer's generic machinery (P6-SV)

Written 2026-10-13 for the owner's P6-SV spike (TODO P6-SV), after the verifier-floor analysis
(`pqz-verifier-floor.md`). Question: can a verifier written for our fixed statements accept exactly the proofs
LaZer's generic `tbox` verifier accepts, and how close does it get to the floor and to the 50 ms p99 verify limit
(CTR-PQZ-09)? Code on branch `pqz-sv-relfix` (not merged yet; history `pqz-sv` → `pqz-sv-rel3` → `pqz-sv-relfix`):
`pqz-core/src/pqz_sv.c`, tests `pqz-core/test/pqz_sv_diff.c`, `pqz-core/test/pqz_sv_fuzz.c`,
`pqz-core/sv/check_sv_fixes.sh`, runs `pqz-core/sv/runs/`. **No decision is recorded here.**

**Current state (§0): the fixed transcript, `proofSystemId` v2, all five relations.** §1–§8 below were written on
the pre-fix transcript (v1) and keep their numbers as the "before"; where the v2 run changed something, §0 says so.

## 0. On the fixed transcript (`proofSystemId` v2), all five relations

`pqz-sv-relfix` = `pqz-sv-rel3` + main (the relation fix-ups: `R_TX` on the pq-zether.md §7.7 layout, the 32-byte
disclosure `kind` word, ABDLOP keys built at an op's first use; and `pqz-v2`: the two LaZer `tbox` Schwartz–Zippel
fixes, [lazer#24](https://github.com/lazer-crypto/lazer/issues/24) P6-SZ and
[lazer#25](https://github.com/lazer-crypto/lazer/issues/25) P6-L2, under `proofSystemId` v2). The specialised verifier
follows both fixes, each a one-line change: `sz_eval_challenges` draws λ × M challenge values from (seed, dom) and
gives half h of accumulator pair i row 2i + h (P6-SZ; v1 drew 2M values and gave every pair the same two rows), and
exact-ℓ2 equation i draws from domain dom + i (P6-L2; v1 used one domain for all Z equations, so only the sum of the
block norms was checked). It parses the v2 statements (header with the fee word for `R_TX`, `kind` word) as
`pqz_rel.c` does. Run `scripts/capped pqz-core/sv/rel3.sh v2` (`sv/runs/v2-*`), same machine as §2 [measured].

**Equivalence.** 0 disagreements in 4,420 cases; both fixes are needed and caught:

| Run (`sv/runs/`) | Build | Cases `R_REG` / `R_TX` / `R_BURN` / `R_DS` / `R_DR` | Generic accepts | Disagreements |
|---|---|---|---|---|
| `v2-diff-portable` | portable | 238 / 246 / 742 / 742 / 742 = 2,710 | 90 (44 honest, 44 re-encoded, 2 no-op) | **0** |
| `v2-diff-x86v3` | x86-64-v3 + AES-NI | 118 / 122 / 370 / 370 / 370 = 1,350 | 44 | **0** |
| `v2-wasm-both` | wasm32 (`PQZ_VERIFY=both`) | 72 each = 360 (2 honest, 10 verifies, 60 tamper cases) | 60 | **0** |
| `v2-sv-fixes-tree` | portable, the tree | 2 per relation = 10 (honest + re-encoded) | 10 | **0** |
| `v2-sv-fixes-sz-reverted` | P6-SZ line reverted in a copy of `pqz_sv.c` | 10 | 10 | **10** (every proof) |
| `v2-sv-fixes-l2-reverted` | P6-L2 line reverted | 10 | 10 | **10** (every proof) |

The last three are `sv/check_sv_fixes.sh` (exit 0 only if the tree agrees and each reverted copy disagrees), the SV
counterpart of `check_tbox_fixes.sh` (also ok in this run: the P6-SZ trace sees 4 independent evaluation-step tests,
the P6-L2 pooled-slack proofs are rejected by the production verifier and accepted with the fix undone). Before the
fixes were ported (the merge commit alone) the same harness gave 10 disagreements in 129 cases: exactly the honest
and re-encoded proofs, which v2's generic verifier accepts and a v1 transcript rejects. PRG check 0 mismatches,
KAT 19/19, ASan + UBSan bench clean, symbol scan clean on native, x86-64-v3, wasm and the SV=0 build.

**Speed** (`pqz_bench 2 200`: 200 honest and 246 adversarial verifies per relation; wasm `run_wasm.mjs 2 100`: 100
honest, 600 adversarial), ms, v1 (§1, runs `d2-*` / `r3-*`) → v2 [measured]:

| verify, ms | p50 honest | p99 honest | p99 adversarial (bench / diff) | generic p50 | vs 50 ms (worst p99) |
|---|---|---|---|---|---|
| `R_TX` portable | 7.85 → **8.00** | 12.6 → 11.1 | 10.4 / 9.5 → 9.3 / 10.1 | 638 | 4.5× under |
| `R_TX` x86-64-v3 | 4.54 → 4.65 | 5.5 → 5.9 | 4.7 / 5.6 → 5.9 / 5.0 | | |
| `R_TX` wasm32 | 11.9 → 13.5 | 14.4 → 16.0 | 13.4 → 15.7 | | 3.1× under |
| `R_BURN` portable | 7.69 → 7.74 | 9.8 → 9.7 | 10.0 / 10.9 → 9.3 / 9.8 | 535 | 5.1× under |
| `R_BURN` x86-64-v3 | 4.47 → 4.52 | 5.8 → 5.8 | 5.9 / 6.1 → 5.0 / 5.9 | | |
| `R_BURN` wasm32 | 13.2 → 13.0 | 20.4 → 15.3 | 16.3 → 15.5 | | 3.2× under |
| `R_REG` portable | 3.97 → 3.87 | 4.5 → 5.9 | 4.7 / 4.9 → 5.5 / 5.3 | 178 | 8.5× under |
| `R_REG` x86-64-v3 | 2.38 → 2.39 | 2.7 → 3.3 | 2.9 / 3.0 → 3.3 / 3.2 | | |
| `R_REG` wasm32 | 5.9 → 6.8 | 6.8 → 9.2 | 6.5 → 8.1 | | 5.4× under |
| `R_DS` portable | 4.17 → 4.35 | 5.7 → 5.9 | 5.7 / 6.5 → 4.7 / 5.5 | 213 | 8.5× under |
| `R_DS` x86-64-v3 | 2.82 → 2.68 | 3.6 → 3.6 | 3.7 / 3.8 → 3.7 / 3.8 | | |
| `R_DS` wasm32 | 7.2 → 7.1 | 8.9 → 8.8 | 9.3 → 8.4 | | 5.7× under |
| `R_DR` portable | 4.37 → 4.50 | 6.0 → 6.1 | 5.4 / 7.3 → 5.7 / 6.2 | 204 | 8.1× under |
| `R_DR` x86-64-v3 | 2.67 → 2.87 | 3.9 → 3.6 | 3.1 / 3.7 → 3.5 / 3.9 | | |
| `R_DR` wasm32 | 7.8 → 7.6 | 9.6 → 9.4 | 9.7 → 9.8 | | 5.1× under |

No change beyond the host's noise (±20 %, §1 ¹): the fixes draw (λ − 2)·M more challenge values per evaluation call
(a few hundred 42-bit values) and one more domain per ℓ2 equation, against ≈ 8 ms of NTTs, AES and folds [inference].
The wasm `R_TX` / `R_REG` p50 moved by +13 % / +15 %, inside the spread seen for the same v1 code across sessions
(`R_TX` wasm 11.9 in `d2`, 13.7 in `r3`). Every relation stays ≥ 3× under the 50 ms p99 limit on every build.

**Memory.** The tables are now built per op at its first `pqz_verify_fast` (after that op's ABDLOP keys, below the
arena base mark), not at `pqz_init` for all five (v1: 20.8 MB at init, arena base 54.5 → 75.3 MB). Sizes per op,
native [measured]: `R_REG` 4.10 MB (includes A, shared, 1 MB), `R_TX` 5.22 MB, `R_BURN` 5.10 MB, `R_DS` 3.10 MB,
`R_DR` 3.33 MB; working set per verify unchanged (1.06 / 1.67 / 1.64 / 1.08 / 1.12 MB; generic 81 / 273 / 258 / 85 /
92 MB). Init is A alone again (3.1 MB native, 2.5 MB wasm; 9–12 ms native, 24–30 ms wasm). Build option `SV=0`
(`build.sh`; the code is compiled only with `PQZ_SV`) leaves `pqz_sv.c` and `pqz_verify_fast` out: `pqz.wasm` 404,755
→ 350,585 B. Arena peak of one op alone (prove + one honest verify, one process per relation, `v2-alone.jsonl`):

| wasm32, MB (MiB) | `R_TX` | `R_BURN` | `R_DS` | `R_DR` | `R_REG` |
|---|---|---|---|---|---|
| `SV=0` (wallet prover) | **231.9 (221.1)** | 220.4 | 76.9 | 83.0 | 73.7 |
| with SV, generic verify | 231.9 | 220.4 | 76.9 | 83.0 | 73.7 |
| with SV, fast verify | 231.9 | 220.4 | 76.9 | 83.0 | 73.7 |

The prove sets the peak in all three; with the lazy tables a build with the specialised verifier costs a prover
nothing until it calls `pqz_verify_fast`, and then that op's tables (≤ 5.2 MB) plus 1.7 MB of working set, below
the prove's peak. `R_TX` prover: 221.1 MiB, 13.6 % under the 256 MiB hard limit (CTR-PQZ-18), as on main; the v1
branch with eager tables reached 284 MB. A wallet that fast-verifies first and proves afterwards carries the tables
under the prove: ≈ 221 + 5 = 226 MiB for `R_TX` [estimate]. Native `R_TX` alone 304 MB, as main.

**Proofs** unchanged by this branch: `proofs_fnv` 1-seed native = wasm (`R_REG` `a4477f23`, `R_TX` `6ffad36b`,
`R_BURN` `478eb819`, `R_DS` `10639246`, `R_DR` `82621a18`); the 5-seed hashes are main's v2 (`rel3/runs/v2-*`).

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

**`R_BURN`, `R_DS`, `R_DR`** (added on branch `pqz-sv-rel3`, after the relations themselves,
`pqz-relations-burn-disclose.md`; run `sv/runs/r3-*`, same machine) [measured]:

| verify, ms [measured] | p50 honest | p99 honest | p99 adversarial (bench / diff) | generic p50 | vs 50 ms |
|---|---|---|---|---|---|
| `R_BURN` native portable | **7.69** | 9.8 | 10.0 / 10.9 (n = 730) | 571 | ≈ 4.6× under |
| `R_BURN` x86-64-v3 + AES-NI | 4.47 | 5.8 | 5.9 / 6.1 (n = 364) | — | |
| `R_BURN` wasm32 (node) | 13.2 | 20.4 | 16.3 | 707 ¹ | ≈ 2.5× under |
| `R_DS` native portable | **4.17** | 5.7 | 5.7 / 6.5 (n = 730) | 219 | ≈ 7.7× under |
| `R_DS` x86-64-v3 + AES-NI | 2.82 | 3.6 | 3.7 / 3.8 | — | |
| `R_DS` wasm32 (node) | 7.2 | 8.9 | 9.3 | 286 ¹ | |
| `R_DR` native portable | **4.37** | 6.0 | 5.4 / 7.3 (n = 730) | 221 | ≈ 6.9× under |
| `R_DR` x86-64-v3 + AES-NI | 2.67 | 3.9 | 3.1 / 3.7 | — | |
| `R_DR` wasm32 (node) | 7.8 | 9.6 | 9.7 | 262 ¹ | |

Bench: `pqz_bench 2 200` (200 honest, 246 adversarial verifies per relation), wasm `run_wasm.mjs 2 100` (100 honest,
600 adversarial); diff: the differential harness's mutated proofs (§4). ¹ from `pqz-relations-burn-disclose.md`
(30 runs). In the same session `R_TX` gave 8.03 ms p50 / 11.5 p99 honest portable, 4.59 x86-64-v3, 13.7 wasm, as
before within the host's noise. `R_BURN` is `R_TX` without two row groups and costs the same; the disclosure
relations cost what `R_REG` costs [inference].

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
`lnp_tbox_verify` passes. Since v2 (§0) that derivation is the fixed one: λ × M values per call (P6-SZ, lazer#24) and
domain dom + i for exact-ℓ2 equation i (P6-L2, lazer#25). A test hook checks this PRG against LaZer's on random seeds, domains and lengths, plus the
FIPS-197 AES-256 vector.

**Arithmetic.** Ring products through a complete negacyclic NTT of degree 64 over **four** NTT-friendly 30-bit primes
(P ≈ 2^120), 32-bit Montgomery, Montgomery form throughout, mixed-radix CRT (Garner) back to Z_q. Four, not the floor's
three: with three primes (P ≈ 2^90) a sum is exact only while one operand is short (|z1| < 2^21 in the floor's
estimate), and the verifier must be exact on adversarial inputs before any bound is checked (z21 has no norm check at
all). With four primes every sum below stays under 2^106 for any input (inputs are values mod q or small integers;
bounds next to each sum in the code), against P/2 ≈ 2^119 [inference]. Cost: 4/3 of the three-prime products and
NTTs [estimate].

**Precomputed** (v1: at `pqz_init`; since v2 per op at its first `pqz_verify_fast`, §0), below the arena base mark: A (32 × 32, shared), A1, A2′, B′ of both relations in
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
| `r3-diff-portable` | portable, all five relations | `R_REG` 4, `R_TX` 4, `R_BURN` / `R_DS` / `R_DR` 12 each | 2,710 (`R_BURN`, `R_DS`, `R_DR` 742 each) | 90 (44 honest, 44 re-encoded, 2 no-op) | **0** |
| `r3-diff-x86v3` | x86-64-v3 + AES-NI, all five | 2 / 2 / 6 / 6 / 6 | 1,350 | 44 | **0** |
| `r3-wasm-both` | wasm32 (`PQZ_VERIFY=both`), all five | 2 per relation, then 10 verifies and 6 × 10 tamper cases | 360 | 60 | **0** |

For `R_BURN` / `R_DS` / `R_DR` the harness makes fresh statements the same way (new keys, balance < 2^48, amount,
fee, random header bytes; for the disclosures a fresh transfer leg and an amount of random size); its "public scalar"
mutation changes the fee or amount word, one time in four in a high byte, which makes it non-canonical (≥ 2^64), and
the `R_TX` fee as before. The bench's sixth tamper kind does the same. ASan + UBSan on the libc-heap path, the bench
with the fast verifier over all five relations (`sv/runs/r3-asan.jsonl`): no reports [measured].

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

With all five relations the tables are 20.8 MB native (arena base 54.5 → 75.3 MB) and 20.9 MB wasm (43.3 → 64.2 MB);
one verify of `R_BURN` / `R_DS` / `R_DR` needs 1.64 / 1.08 / 1.12 MB above the base [measured]. On wasm this pushes
the generic `R_TX` prove to an arena peak of 284 MB, above the 256 MiB hard limit of CTR-PQZ-18 (263 MB without the
tables): a browser prover build would leave out the specialised verifier's tables or build them lazily [inference].
Arena peaks of a long mixed run also depend on the history (the arena recycles freed blocks of at most 32 distinct
sizes): `R_BURN`'s prove peak was 443 MB after the other four relations had run and 348 MB alone [measured], so
per-relation peaks are read from a run of that relation alone.

**Prover unchanged:** the bench's proof hash over seeds 0..2 is `3bc7e9b3` / `834d6853` as on main; arithmetic KAT
19/19 [measured].

## 6. At a glance, coverage, maintenance, integration

**Generic vs specialised** (portable build unless stated; numbers from §1 and §5) [measured]:

| | Generic (`pqz_verify`, LaZer `tbox`) | Specialised (`pqz_verify_fast`) |
|---|---|---|
| How v is computed | every equation built as a sparse quadratic form over the (s, o(s)) slots, folded into accumulators, then evaluated once | every equation evaluated directly on z, combined with the same scalars (§3) |
| Ring products | ≈ 394× the mandatory count (dense Gram matrices of selection matrices, `pqz-verifier-floor.md`) | the mandatory ones only |
| Arithmetic | LaZer's generic integers and polynomials | complete NTT, degree 64, over 4 × 30-bit primes, exact for any input |
| JL matrix / fold | bitsliced AES / generic | table AES (AES-NI optional), 8-row subset-sum tables |
| `R_TX` verify, native / wasm | 660 / 741 ms | 7.85 / 11.9 ms (p50) |
| `R_REG` verify, native / wasm | 166 / 204 ms | 3.97 / 5.9 ms (p50) |
| Arena per verify, `R_REG` / `R_TX` | 81 / 273 MB | 1.06 / 1.67 MB (+ 9.1 MB tables once) |
| `R_BURN` / `R_DS` / `R_DR` verify, native p50 | 571 / 219 / 221 ms | 7.69 / 4.17 / 4.37 ms |
| Relations | any, from the generated parameters | the five of pq-zether.md §9.1, hand-written (§3) |

**Coverage of the precompile ops** (pq-zether.md §9.1). Rollover carries no proof.

| op | Relation | In `pqz-core` | Specialised verifier |
|---|---|---|---|
| `OP_REGISTER` | `R_REG` | yes | yes |
| `OP_TRANSFER` | `R_TX` | yes | yes |
| `OP_BURN` (also REFRESH) | `R_BURN` = `R_TX` rows 1, 2, 4, 6, 7 with `d` public | yes (branch `pqz-rel3`) | yes: the `R_TX` evaluation fold with the `R_BURN` bit layout |
| `OP_DISCLOSE_SENDER` | `R_DS` | yes (branch `pqz-rel3`) | yes |
| `OP_DISCLOSE_RECEIVER` (also auditor) | `R_DR` | yes (branch `pqz-rel3`) | yes (runs in `eth_call`, so speed matters less) |

**What a change costs** [inference, from `pqz_sv_setup` and the `R_TX` evaluation code]:

| Change | Example | Specialised verifier |
|---|---|---|
| Proof-system parameters | `l2Bsqr`, `Bz3sqr`, `Bz4`, `gamma`, `D`, `m`, `kmsis`, stdev, block sizes `n[i]` | read from the generated `*params.h` at `pqz_init`: regenerate, rerun `sv/diff.sh` |
| Structural assumptions | `d = 64`, `log2 q = 42`, λ = 4, ω = 8, number of blocks (2 / 7), `nprime = 1`, size totals | checked at `pqz_init`; a mismatch makes init fail (`PQZ_ERR_INTERNAL`), never a wrong accept; code change |
| Relation formulas | an `R_TX` row added or changed, Δ = 2^26 − 1, 16 digits × 4 bits, slot layout (`SLOT_M` 14 bits, `SLOT_C` 11, `SLOT_E` 25), `NPK` | hand-written from `pqz_rel.c` (`build_reg`, `build_debit`, `build_ds`, `build_dr`); not checked at init; the differential test fails on the first honest proof |

So the differential test (`sv/diff.sh`) should run in CI whenever `pqz_rel.c`, `params/` or `pqz_sv.c` changes.
Generating the evaluation code from the same relation spec (as LaZer's codegen does for parameters) would remove the
hand copy; with five fixed relations, hand-written code plus the differential test is enough [inference].

**Integration.** The verifier runs inside the node's precompile (`libpqz`, C), not in Solidity: the precompile would
call `pqz_verify_fast` instead of `pqz_verify`, and the op prices follow the measured time (CTR-PQZ-11). Contracts and
ABI do not change. Clients generate nothing new: the prover and the proof bytes are unchanged, and the specialised
verifier accepts the same proofs; a wallet (wasm) can check its own proof before sending in ≈ 12 ms instead of
≈ 0.8 s.

## 7. Risks and open points

- **Second implementation.** The specialised verifier re-states LaZer's equations (`lnp-tbox.c`, `pqz_rel.c`) by
  hand. The differential test covers what honest and mutated proofs reach; it cannot construct a proof that passes
  the final hash check and fails only a norm check (that needs a cheating prover), so those checks (z1, z3, z4,
  w − γw1, hint, h coefficients 0 and d/2) rest on reading the code against `lnp_quad_verify` /
  `_lnp_tbox_check_z34` line by line. An independent review of `pqz_sv.c` against `lnp-tbox.c` is still due before any
  use.
- **The statement is hard-wired.** The selection blocks, the `R_TX` evaluation equations and the input rows are
  re-stated from `pqz_rel.c` (`build_reg`, `build_debit`, `build_ds`, `build_dr`). A change to a relation must change both files; the
  differential test catches a mismatch on the first honest proof.
- **LaZer's transcript is mirrored as our fork runs it** (domains, PRG, encodings), since v2 with the two `tbox`
  fixes (§0). Any change to the protocol or its transcript has to be made in both verifiers and bumps
  `proofSystemId` (CTR-PQZ-09); `sv/check_sv_fixes.sh` shows the differential test catches a verifier left on the
  old transcript.
- Not done: hand-written AVX2 for the NTT and the products (the x86-64-v3 build relies on auto-vectorisation),
  wasm SIMD tuning, a run on the chain host or a phone.

## 8. Files and reruns

```sh
cd pqz-core
./build.sh native            # libpqz with pqz_verify_fast, pqz_bench, pqz_sv_diff (test hooks)
./build.sh native-x86v3      # optional backend: pqz_sv.c for x86-64-v3 + AES-NI
./build.sh wasm              # pqz.wasm (WASM_SIMD=1 B=build/wasm-simd ./build.sh wasm: -msimd128)
sv/diff.sh <label>           # differential test, portable + x86-64-v3 -> sv/runs/<label>-*.jsonl
sv/bench.sh <label>          # p50 / p99, generic vs specialised, native / x86-64-v3 / wasm -> sv/runs/
sv/fuzz.sh <label> [secs]    # ASan + UBSan bench (malloc path) and the libFuzzer target (R_REG / R_TX inputs)
../scripts/capped sv/rel3.sh <label>   # all five relations under one capped job: diff, bench, wasm both, ASan,
                                       #   KAT, check_tbox_fixes, check_sv_fixes, memory per op (SV=0 wasm too)
sv/check_sv_fixes.sh                   # each tbox fix reverted in a copy of pqz_sv.c must give disagreements
SV=0 B=build/wasm-nosv ./build.sh wasm # without the specialised verifier (wallet prover)
PQZ_VERIFY=fast build/native/pqz_bench 2 200                   # the bench with the specialised verifier
PQZ_VERIFY=both node test/run_wasm.mjs 2 20                     # wasm: both verifiers on every input, must agree
```

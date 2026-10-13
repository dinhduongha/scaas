> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZL verifier floor: what a specialised LNP22 verifier for R_REG / R_TX must cost

Written 2026-10-13 at the owner's request, after the upstream cross-check (`pqz-core-e-s1.md` §10). Question: LaZer's
generic `tbox` verifier takes 6.6 s (upstream) / 15 s (fork) on `R_TX`. Could a verifier written for our fixed
statements get near the 50 ms p99 verify limit (CTR-PQZ-09), or is the floor of the protocol itself far above it? If
the floor is far above, PQZL is off-chain / aggregation only and PQZH becomes the on-chain kind
(`pqz-proof-alternatives.md` §6). **No decision is recorded here.** Branch `pqz-verifier-floor`; code
`pqz-core/floor/`.

**[measured]** marks a number from a run in this note (machine in §2). **[estimate]** marks a number computed from
counts and measured unit costs, or a rough figure. **[inference]** marks a conclusion drawn here. **[unverified]**
marks a number from the literature that was not reproduced.

## 1. Result

**The floor is far below 50 ms on native code: ≈ 2.5 ms (AVX2) and ≈ 9 ms (portable C) for `R_TX`, ≈ 13 ms in wasm32
without SIMD [estimate].** The AVX2 floor is about 2,600× below upstream's 6.6 s (also native), and the portable
floor about 1,600× below the fork's 15 s (also portable C).
The generic machinery, not the protocol, is what costs seconds. A specialised verifier is not the same thing as the
fork's code made faster: it has to drop LaZer's quadratic-form bookkeeping entirely (§6). It also needs two other
changes. Ring products must go through a complete NTT (CRT over NTT-friendly primes) instead of the fork's 4-block
incomplete NTT mod q. And the PRG that expands the JL matrix must be fast: SHAKE128, or AES with tables or AES-NI.
The fork's bitsliced AES alone costs ≈ 44 ms on `R_TX`.

Floor per verify, ms, `R_TX` / `R_REG`, from operation counts (§3) × unit costs measured on this machine (§4)
[estimate]:

| Build | `R_TX` | `R_REG` | `R_TX` vs 50 ms |
|---|---|---|---|
| AVX2 (CRT NTT 4 lanes, AES-NI, JL fold AVX2) | **2.5** | **1.0** | 20× under |
| AVX-512 IFMA | ≈ 1.5–2 [estimate, no AVX-512 here] | ≈ 0.7 | |
| Portable C, CRT NTT, SHAKE128 as PRG | **9.1** | **4.2** | 5.5× under |
| Portable C, CRT NTT, AES-256-CTR kept but table-based (public data) | ≈ 11 [estimate] | ≈ 5 | 4.5× under |
| Portable C, CRT NTT, the fork's bitsliced AES | 52 | 26 | 1.04× (just over) |
| Portable C, the fork's own primitives (incomplete NTT, bitsliced AES) | 65 | 33 | 1.3× over |
| wasm32 (node, no SIMD), CRT NTT, SHAKE128 | **12.8** | **6.0** | 3.9× under |
| wasm32 (node, no SIMD), the fork's own primitives | 115 | 60 | 2.3× over |
| Measured: upstream LaZer (`xcheck`) / fork verify (`floor/count.c`) | 6,621 / 14,553 [measured] | 566 / 1,076 [measured] | 130× / 290× over |

The floor work does not depend on the proof's content: same counts for honest and adversarial proofs. So the p99
adversarial verify is about the floor, plus noise [inference]. At the 0.12 M gas/ms conversion of
`pqz-proof-alternatives.md` §6, 2.5 ms is ≈ 0.3 M gas and 9 ms ≈ 1.1 M gas [estimate].

**Top three terms** (`R_TX`, portable C with SHAKE128, 9.1 ms):

1. **JL fold** `vR = Vᵀ R`: 4 challenge rows × 256 JL rows × 9,792 ternary entries = 10.1 M signed adds. 5.7 ms
   portable, 1.4 ms AVX2 [measured prototype]. 63 % of the portable floor.
2. **JL matrix expansion**: 256 rows × 2,448 B = 627 KB of PRG output, derived from this proof's transcript, so it
   can never be precomputed. 1.1 ms with SHAKE128, 0.07 ms AES-NI, **36.5 ms with the fork's bitsliced AES**.
3. **ABDLOP commitment mat-vec** `w = A1 z1 + A2′ z21 − c·2^D·tA1`: 23 × 199 = 4,577 ring products.
   0.59 ms portable (CRT), 0.42 ms AVX2 (memory-bound), 8.3 ms with the fork's pointwise product [measured prototype].

Everything else together is < 1.5 ms portable. That covers the statement's own equations (2,264 products), the
norm-proof terms (156), the hashing (101 KB), the challenges, decoding and norm checks.

## 2. What ran

| Item | Value |
|---|---|
| Machine | AMD Ryzen 5 7235HS (Zen 3+, AVX2, AES-NI, SHA-NI, **no AVX-512**), single thread, other services running |
| Fork | `pqz-core` at `main` (`06320d5`): `build.sh native` (clang 18 -O2 generic) and `build.sh wasm` |
| Code | `pqz-core/floor/`: `kern.c` (unit costs and prototypes), `kern_core.h` (shared scalar kernels), `wasm.c` + `run_wasm.mjs` (the portable kernels in wasm32), `count.c` (operation counts of the fork's verifier), `model.py` (counts × unit costs → the tables here), `build.sh` |
| Runs | `scripts/capped floor/build.sh run` → `floor/runs/{kern_portable,kern_native,kern_wasm,count}.json`, `floor/runs/model.md` |
| Builds | `kern_portable`: clang -O2 generic x86-64, the fork's flags. `kern_native`: -O3 -march=native, AVX2 intrinsics, OpenSSL 3.0.13 (`libcrypto`, AES-NI). `kern.wasm`: clang 18 wasm32 freestanding, no SIMD, node v26.8.1 |
| Statistics | Median of 7 repetitions per kernel. One machine, busy host |

Every kernel is checked against an oracle before it is timed (`assert`). CRT NTT against the schoolbook product mod
p. Both mat-vec prototypes against the fork's mod-q arithmetic. AVX2 against scalar. JL fold against its definition.
`KERN_QUICK=1` runs the checks only.

## 3. The verifier's mandatory work

Derived from the protocol (LNP22 as LaZer's `tbox` instantiates it, `lnp-tbox.c` `lnp_tbox_verify` →
`lnp_quad_many_verify` → `lnp_quad_verify`), not from LaZer's code paths. Parameters from
`params/pqz_{tx,reg}_params.h`: d = 64, q = 2^42 − 215, λ = 4. Witness s1 has m1 = 146 + Z = 7 polys for `R_TX` and
64 + 2 for `R_REG`; m2 − kmsis = 45; kmsis 23 / 22. The B part has l + lext = 12 rows. JL dimension nex·d = 153·64 /
66·64. The ℓ∞ filler has nprime = 1.

**The statement is linear.** The 64 "quadratic" equations of `R_TX` (`A s_f + e_f = pk_f`, `Aᵀ r + e1 = u`) have no
quadratic part (`R2 = NULL`, `pqz_rel.c`). The 80 evaluation equations are Z_q-linear too: `ct(X^-i·(pk_xᵀ r)) + e2 +
Δ·digit − v = 0`, `ct(X^-i·u_Tᵀ s_f) + …`, and the carry rows over Z. The only quadratic terms come from the tbox's
own norm proofs: exact ℓ2 via `o(x)ᵀx`, binary, β, υ, and the JL cross terms β·Rs. All of them are short sums over
**selected blocks** of the witness. The `Es`, `Ps`, `Ds` matrices are 0/1 selections (`new_sel`).

Verifier checks, in transcript order. P = ring products in the NTT domain, F / I = forward / inverse NTTs,
G = PRG bytes, H = hashed bytes, J = ternary multiply-adds, S = scalar mod-q multiplies, C = coefficients decoded.

| # | Check (what the protocol requires) | Formula | `R_TX` | `R_REG` |
|---|---|---|---|---|
| 1 | Decode π; norm checks: ‖z1‖², ‖z3‖², ‖z4‖∞, ‖h‖∞, ‖w1 − γ·hint‖², h coefficients 0 and d/2 = 0 | C = (m1 + m2r + 8 + lB + 2·kmsis + 3)·d | C 17,088 | C 11,392 |
| 2 | Fiat–Shamir: statement digest, then 4 transcript rounds (tA1 ‖ tB; ty3 ‖ ty4 ‖ tβ; tg; t ‖ v ‖ w1); 4 PRG seeds | H = stmt + transcript; G = Z_q challenges + ~128 B per domain | H 100,840; G 98 K | H 35,088; G 96 K |
| 3 | ABDLOP / MSIS part: w = A1 z1 + A2′ z21 − c·2^D·tA1, then dcompress with the hint | P = kmsis·(m1 + m2r + 1); F = m1 + m2r + kmsis + 1; I = kmsis | P 4,577; F 222; I 23 | P 2,464; F 134; I 22 |
| 4 | B part: f = c·t − b′ext z21, zm = c·tB′ − B′ z21 (y3, y4, β, g, garbage) | P = lB·(m2r + 1); F = lB | P 552 | P 552 |
| 5 | Statement R_q-linear rows, evaluated on z: A·z_sf (+ Aᵀ·z_r) | P = rows·K² | P 2,048 | P 1,024 |
| 6 | Statement Z_q rows (evaluation equations): pk_tᵀz_r, pk_fᵀz_r, pk_aᵀz_r, u_Tᵀz_sf, then the challenge-weighted monomials and digit / bit coefficients per accumulator half | P = 4K + 4·(4 + 15 + 3); S ≈ M·4·d | P 216; S 20 K | — |
| 7 | Norm-proof quadratic terms: o(z_i)·z_i over the ℓ2 blocks (Σn_i) and the binary block, υ binary, β² / β·o(β) / o(β)² | P = Σn_i + nbin + Z + 3 | P 156 | P 69 |
| 8 | JL (approximate ℓ2, 256 rows, plus the 256-row ℓ∞ filler): expand R and R′ from the round-2 seed, fold vR_k = Σ_i V_ki R_i (k < λ), then ⟨vR_k, o(z)⟩·β | G = 256·2·(nex + nprime)·d/8; J = λ·256·(nex + nprime)·d; P = λ·(nex + nprime) + 2λ; F = λ·(nex + nprime) | G 631 K; J 10.1 M; P 624; F 616 | G 274 K; J 4.4 M; P 276; F 268 |
| 9 | Quad-many fold: v = Σ_k μ_k F_k(z) + c·r1ᵀz + c²·r0 − f over N_tot = λ/2 + 2 + N equations, μ expanded uniform mod q; then c′ = H(t, v, w1) must equal c | P = N_tot + N + 4; F = N_tot + 2; G = N_tot·d·6 | P 136; F 70; G 26 K | P 72; F 38; G 14 K |
| | **Total per proof** | | **P 8,309; F 1,112; I 24; G 755 KB; H 101 KB; J 10.1 M; S 24 K** | **P 4,457; F 484; I 23; G 385 KB; H 35 KB; J 4.4 M; S 3 K** |

**What is precomputable** [inference]:

- **Per parameter set (once, at node start):** A and Aᵀ (32 × 32) in NTT form. The ABDLOP keys A1 (23 × 153),
  A2′ (23 × 45) and B′ (12 × 45) in NTT form: 3.5 MB in a 3 × 30-bit CRT form. The constant polynomials
  (binary expansions of B_i², monomials), and the whole evaluation plan (which blocks each norm term selects).
- **Per account (cacheable):** each public key in NTT form, 32 NTTs per key, 96 for `R_TX`. That is ≈ 0.1 ms
  portable, so the cache barely matters.
- **Per proof, never precomputable:** everything else. The JL matrices and every challenge come from this proof's
  commitments (Fiat–Shamir). z1, z21, c and the commitments are the proof. The two biggest terms (JL, A1·z1) are
  per proof by construction.

## 4. Unit costs

Medians of 7, ns [measured]. "per product" = one ring product in the NTT domain (degree 64, mod q or all CRT residues).

| Primitive | Portable C (-O2) | Native (-O3, AVX2) | wasm32 (node, no SIMD) | wasm / portable |
|---|---|---|---|---|
| Fork pointwise product (incomplete NTT, 4 × 16×16 schoolbook, u128) | 1,795 | (lib is -O2) 1,779 | 6,784 | 3.8 (u128 emulated) |
| Fork LaZer `poly_mul` (API level, same op) | 1,792 | 1,770 | | |
| Fork NTT forward / inverse (2 layers) | 191 / 351 | 183 / 351 | 671 / 1,182 | 3.5 / 3.4 |
| CRT 30-bit prime: pointwise multiply-accumulate, per prime | 42.7 | 17.0 scalar; **8.25** AVX2 (33.0 per 4) | 74.5 | 1.7 |
| CRT 30-bit prime: NTT forward / inverse, per prime | 198 / 188 | 168 / 197 scalar; **58 / 58** AVX2 | 400 / 485 | 2.0 / 2.6 |
| → ring product in CRT form (3 primes) | **128** | **25** (AVX2) | 224 | |
| JL fold, `R_TX` (4 × 256 × 9,792) | 5.75 ms | 1.41 ms AVX2 | 7.40 ms | 1.3 |
| JL fold, `R_REG` (4 × 256 × 4,224) | 2.42 ms | 0.58 ms AVX2 | | |
| AES-256-CTR, per MiB | 61.0 ms (fork, bitsliced) | **0.114 ms** (OpenSSL, AES-NI) | 69.4 ms (fork) | 1.1 |
| AES key schedule + 16 B (fork `rng_init`) | 15.5 µs | | 17.1 µs | 1.1 |
| SHAKE128 squeeze, per MiB | 1.84 ms (fork) | 1.55 ms (OpenSSL) | 2.10 ms (fork) | 1.1 |
| SHAKE128 absorb, per KiB | 1.73 µs (fork) | 1.58 µs (OpenSSL) | 2.02 µs | 1.2 |
| Scalar mod-q multiply (u128 + `pqz_red128`, dependent chain) | 6.2 | 6.2 | | |

Observations [measured unless marked]:

- **Representation beats tuning.** A ring product through 3 NTT-friendly 30-bit primes (complete negacyclic NTT,
  32-bit Montgomery) costs 128 ns in portable C. That is 14× less than the fork's 1,795 ns in its incomplete NTT mod q.
  q = 2^42 − 215 ≡ 9 mod 16, so X^64 + 1 splits into only 4 factors mod q. Lazy u128 accumulation in the fork's
  representation only reaches 1.4–2.3× (prototype below). 3 × 30 bits = 90 bits holds every product with one short
  operand exactly: |A|·|z|·64·199 < 2^76 for |z1| < 2^21. The ≈ 140 full × full products per verify (μ_k · F_k)
  need a fourth prime or one reduction each, which is negligible [estimate].
- **wasm/native is 1.1–2.6×** for the kernels the floor uses (SHAKE, AES, JL fold, CRT NTT). That is below the
  2.2–2.7× of E-S1. It is 3.4–3.8× for the fork's u128 kernels, because wasm32 emulates 64×64→128 multiplies.
- **The fork's software AES dominates any build that keeps it.** It runs at 58 ns/B, ≈ 35× slower than its own
  SHAKE128, plus 15.5 µs per key schedule. The JL matrix is public data (it is derived from the transcript). The
  verifier therefore needs no constant-time AES: a table-based AES at ≈ 15–20 cycles/B (≈ 4–5 ns/B) would keep
  LaZer's transcript and cost ≈ 3 ms for `R_TX` [estimate; not measured here].

**Prototypes of the two biggest terms** [measured], to check the count × unit model:

| Prototype (`R_TX` / `R_REG`, NTTs and CRT reconstruction included, A pre-transformed) | Portable | Native | Model (count × unit) |
|---|---|---|---|
| ABDLOP mat-vec 23 × 198 / 22 × 111, fork pointwise per product | 8.28 / 4.48 ms | 8.25 / 4.44 ms | 8.27 / 4.47 ms |
| same, fork representation, lazy u128 accumulation over each row | 6.03 / 3.26 ms | 3.63 / 1.96 ms | |
| same, CRT 3 × 30-bit scalar | **0.587 / 0.347 ms** | 0.414 / 0.246 ms | 0.775 / 0.450 ms (model 30 % high) |
| same, CRT 3 × 30-bit AVX2 (4 lanes in 64-bit containers) | | **0.417 / 0.166 ms** | 0.170 / 0.102 ms |
| JL fold, scalar branchless / AVX2 (nibble LUT, L1 tiles) | 5.75 / 2.42 ms | 1.41 / 0.58 ms (AVX2) | = the unit |

The scalar model is conservative: the measured CRT mat-vec beats it by 25 %. The AVX2 mat-vec is memory-bound.
It streams A1 as 7 MB of 64-bit lanes, out of L3 (8 MB) on a busy host, so it gains nothing over -O3 scalar (3.5 MB of
32-bit words). Packing 8 × 32-bit lanes would halve the traffic. The floor uses the measured prototype for this term
in every column where one exists.

## 5. The floor

Per term, ms, `R_TX` [estimate: §3 counts × §4 unit costs; the ABDLOP row is the measured prototype]. Full table
with all columns and `R_REG`: `pqz-core/floor/runs/model.md`.

| Term | Fork primitives, portable | Portable CRT + SHAKE128 | wasm32 CRT + SHAKE128 | AVX2 |
|---|---|---|---|---|
| ABDLOP mat-vec (P 4,577) | 8.28 | 0.59 | 1.40 | 0.42 |
| B part (P 552) | 0.99 | 0.08 | 0.14 | 0.02 |
| Statement R_q-linear rows (P 2,048) | 3.68 | 0.26 | 0.46 | 0.05 |
| Statement evaluation rows (P 216, S 20 K) | 0.51 | 0.15 | 0.27 | 0.13 |
| Norm-proof quadratic terms (P 156) | 0.29 | 0.03 | 0.05 | 0.01 |
| **JL: PRG 631 KB + fold 10.1 M + P 624, F 616** | **43.7** | **7.35** | **9.61** | **1.62** |
| Quad-many fold, μ (P 136, G 26 KB) | 1.78 | 0.11 | 0.17 | 0.02 |
| Fiat–Shamir: hashing 101 KB, challenges, 4 key schedules | 5.95 | 0.34 | 0.40 | 0.17 |
| Decode, norm checks (17 K coefficients, 10 / 17 / 3 ns each) | 0.17 | 0.17 | 0.30 | 0.05 |
| **Total `R_TX`** | **65.4** | **9.1** | **12.8** | **2.5** |
| **Total `R_REG`** | **33.3** | **4.2** | **6.0** | **1.0** |
| + statement NTTs if public keys are not cached (192 / 32 NTTs) | +0.04 | +0.11 | +0.23 | +0.03 |

`R_REG` costs half of `R_TX`: its A1 is 22 × 66 instead of 23 × 153, it has a 4,224-wide JL and no evaluation
equations.

**AVX-512 IFMA** [estimate]: 8 × 52-bit lanes would take the CRT products to two 50-bit primes (as upstream's HEXL
does) and halve the JL fold. That is ≈ 1.5–2 ms `R_TX`. There is no AVX-512 here to check it.

**wasm with SIMD128** [estimate]: not built. i64x2 lanes give at most 2× on the JL fold, and i32x4 extending
multiplies help the CRT products. So ≈ 7–9 ms `R_TX` is plausible. Measuring it is the next step if PQZL is
considered for the browser.

## 6. Sanity check against reality: where the 6.6 s / 15 s go

`floor/count.c` wraps the fork's four ring entry points and counts what one honest verify executes [measured,
fork as shipped, after one prove; times include the counters]:

| | `R_TX` fork | `R_TX` floor | ratio | `R_REG` fork | `R_REG` floor | ratio |
|---|---|---|---|---|---|---|
| Verify time | 14,553 ms | 9.1 ms (portable) | 1,600× | 1,076 ms | 4.2 ms | 260× |
| Ring products | 3,274,603 | 8,309 | 394× | 296,277 | 4,457 | 66× |
| Forward NTTs | 111,111 | 1,112 | 100× | 22,240 | 484 | 46× |
| Inverse NTTs | 194,693 | 24 | 8,100× | 13,706 | 23 | 600× |
| Scalar 128-bit reductions mod q (outside the NTT) | 160.5 M | ≈ 24 K multiplies + 10 M adds | | 11.4 M | | |
| Statement build + decode (truncated proof, rejected at the decoder) | 13.1 ms | ≈ 0.2 ms | | 3.9 ms | ≈ 0.15 ms | |

**95 % of the fork's ring products are Gram matrices of selection matrices** [inference, from the code and the
counts]. For each exact-ℓ2 equation `__schwartz_zippel_accumulate_l2` builds `o(Es)ᵀ·Es` densely: m1 × m1 entries,
each a length-n_i dot product. The binary proof builds `o(Ps)ᵀ·Ps` the same way. For `R_TX` that is
(Σn_i + nbin)·m1² = 146 · 146² = 3,112,136 products. For `R_REG` it is 64 · 64² = 262,144 products. Both match the
counts (3.27 M and 0.30 M) once the ABDLOP and JL terms are added. These matrices depend on the statement only, and
for 0/1 selections they are identity blocks. The factored form Σ o(z_i)·z_i over the selected block needs 156 / 69
products. The same quadratic-in-m1 shape explains a third-party measurement of LaZer's LNP22 verify (§7): 88× more
cycles for 10× more witness.

**The rest is moving those dense matrices around.** Each Schwartz–Zippel step (`__schwartz_zippel_accumulate2`,
called once per evaluation equation, 126 times for β3 / β4 alone) copies, scales, adds and reduces the whole
accumulator. After the binary and ℓ2 steps each accumulator holds ≈ m1² ≈ 21,000 polynomials. Then come automorphism
shuffles with re-sorting, a ring-element scaling of every entry in quad-many (`spolymat_scale2`), and the final
`polyvec_mulsparse`. In time, for the fork `R_TX`: products ≈ 3.27 M × 1.79 µs ≈ 5.9 s, scalar reductions
≈ 0.5–1 s, NTTs ≈ 0.1 s, the remaining ≈ 7 s is sparse-matrix copy / add / sort / insert and int_t limb arithmetic
[estimate]. Upstream does the same 3.27 M products at 0.31 µs (≈ 1.0 s); its other ≈ 5.6 s is the same
bookkeeping plus GMP and malloc, as `xcheck/RESULTS.md` found.

So the gap between 6.6 s and ≈ 2.5–9 ms is generic machinery, not protocol work [inference].

## 7. Literature

| Source | Number | Status |
|---|---|---|
| LaZer paper (ePrint 2024/1846, CCS 2024), Table 1 | Anonymous credentials (BLNS23) on LaZer: issuance 0.117 s, showing 0.198 s, Intel Tiger Lake-H, single core, AVX-512 | [unverified]; whole protocols, no separate LNP verify time |
| Douteau, JC2 2025 talk (an addon to LaZer) | LaZer's LNP22: verify **18.5 M cycles** (p ≈ 2^60, witness m = 12) and **1,629 M cycles** (p ≈ 2^80, m = 120). That is 88× for 10× the witness, i.e. quadratic. Prove 324 / 4,462 M cycles | [unverified]; at 4 GHz 4.6 ms and 407 ms. The m = 120 point is in the same range as our `R_TX` at m1 = 153: upstream 6.6 s |
| LNP22 paper (ePrint 2022/284) | Proof sizes only, as far as known; no verify timings | [unverified]: the ePrint PDF could not be fetched here |
| Lantern, Lether | No verify timings found | not checked |

No published LNP22 verifier specialised to a fixed statement was found. The floor here is computed, not compared.

## 8. What a specialised verifier would have to do

1. **Evaluate, don't build matrices.** For each equation the protocol aggregates, compute its value on z
   directly in factored form: o(z_i)·z_i over the selected block, A·z, pkᵀz, monomial shifts. Then combine with the
   challenges (Z_q scalars, then the μ_k). No sparse matrices, no sorting, no Gram matrices. The equations, their
   aggregation and the order of every hash and challenge must match LaZer's `tbox` exactly, because the prover is
   unchanged.
2. **Complete-NTT ring arithmetic.** CRT over 3 NTT-friendly 30-bit primes (portable, wasm-friendly: 32×32→64
   only), or 2 × 50-bit with IFMA. Keep A1, A2′, B′, A, Aᵀ pre-transformed (3.5 MB in CRT form).
3. **A fast PRG for the JL matrix (627 KB per `R_TX` verify).** Keeping LaZer's AES-256-CTR (transcript-compatible):
   AES-NI natively. In portable / wasm code use a table-based AES, which is safe here because the data is public.
   Or switch prover and verifier to SHAKE128, a protocol change on both sides. Expand the AES key once per seed
   (4 seeds), not once per domain (≈ 650 domains).
4. **The JL fold.** 10.1 M signed adds is the largest term in every build. It vectorises well: 4 × 64-bit lanes
   on AVX2 give 1.4 ms. A bit-sliced / table method over groups of R rows could cut it further [estimate, not tried].
5. **Prove equivalence.** Differential testing against the generic verifier on honest and mutated proofs (accept /
   reject must agree), plus an audit. This is a second implementation of a soundness-critical check.

## 9. Risks and caveats

- **Second implementation risk.** A specialised verifier that omits or mis-orders one check is a soundness bug
  that honest-proof tests will not catch. It needs the differential tests above and a review of every equation
  against LNP22 / the `tbox` derivation.
- **Two challenge-derivation bugs in LaZer's `tbox` were found during this work and are fixed** (correction
  2026-10-13; this caveat first said only that a protocol-level point was under review). (1)
  `__schwartz_zippel_accumulate2` drew one pair of Z_q challenge rows and reused it for all λ/2 evaluation
  accumulators: 2 independent Schwartz–Zippel tests instead of λ = 4, soundness ≈ 2^-84 instead of the stated 2^-127
  ([lazer#24](https://github.com/lazer-crypto/lazer/issues/24), `pqz-tbox-soundness.md`). (2)
  `__schwartz_zippel_accumulate_l2` gave all exact-ℓ2 equations one domain, so only the sum of the block norms was
  checked ([lazer#25](https://github.com/lazer-crypto/lazer/issues/25), `pqz-l2-domain.md`). Both are fixed in
  `pqz-core` under `proofSystemId` v2 (merged `98695de`) and in the specialised verifier (merged `dcf0da3`). The
  counts in this note are for the v1 transcript; the fixes do not change the floor: (1) adds (λ − 2)·M challenge
  values per evaluation call, (2) changes only a domain index (measured on v2: `pqz-specialised-verifier.md` §0).
- **Counts are this R_TX.** A different relation (more evaluation equations, larger witness, a second JL) changes
  them linearly. The model (`floor/model.py`) takes the dimensions as inputs.
- **The model is not an implementation.** Only the two biggest terms were prototyped. The smaller ones use counts ×
  unit cost; on the ABDLOP term that method was 30 % pessimistic (scalar) and 2.5× optimistic (AVX2,
  memory-bound). Decode and norm checks (10 ns per coefficient portable) and a table AES (4–5 ns/B) are rough
  [estimate].
- **One machine, busy host, medians of 7.** Zen 3+ without AVX-512. The 50 ms limit is for the chain host; a server
  core is at least as fast [inference]. Memory bandwidth for the 3.5 MB of pre-transformed keys may matter under
  load.
- **Chain integration is out of scope**: precompile or native verifier, gas pricing, wasm in a browser.

## 10. Files and reruns

```sh
cd pqz-core
../scripts/capped floor/build.sh run   # builds (fork native + wasm if missing), runs all, writes floor/runs/*
python3 -I floor/model.py              # the floor tables from floor/runs/*.json
python3 -I floor/model.py --check      # self-check of the counts
KERN_QUICK=1 build/floor/kern_native   # every kernel's oracle check, no timing
```

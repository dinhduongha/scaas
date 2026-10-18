# Review D: the LaZer fork (`pqz-core/pqzl/lazer/`), static and read-only, 2026-10-19

Scope: `abdlop.c`, `lnp-quad*.c`, `lnp-tbox.c`, `coder.c`, `int.c` / `intvec.c` (plus `src/pqz_mpn.h`, `src/pqz_int.h`),
`rejection.c`, the samplers, `rng.c`, and the parameter headers (`pqz-core/pqzl/params/pqz_*_params.h`). Compared
against the pristine upstream copy in commit `c91b3ab` (`pqz-core/lazer/*`) and against the Rust port
(`pqz-core/pqzl/rust/src`). Nothing was built or run.

## Findings

### D-1 (P0): the z3 / z4 responses are never hashed before the challenge V that checks z = y + βRs

- **Where:** C `lazer/lnp-tbox.c:1825` (prover: hash = cseed, with cseed = H(hash ‖ ty3 ‖ ty4 ‖ tbeta) at `:1712`),
  `:397` (prover `hash0`), `:1967`/`:1985` and `:1155` (verifier `hash0`), `:678`, `:688`, `:1255`, `:1264` (z4 / z3
  equations seeded with `hash0`), `:3195` and `:3508` (`intmat_urandom (V, …, seed = hash0, dom)`). The specialised verifier
  does the same: `src/pqz_sv.c:1458–1481` (hash0 = H(hash ‖ ty3 ‖ ty4 ‖ tbeta)), `:1541`, `:1583–1590`. Rust (now the
  production core) does the same: `rust/src/proof/tbox.rs:274–314` (`check_z34`), `:751`, `:764`, `:688`, `:691`
  (generic verifier), `:1032–1033` (prover), and `rust/src/sv.rs:1303–1314` (hash0), `:1429–1436` (V3 / V4 from hash0).
  Upstream has the same order (`c91b3ab:pqz-core/lazer/lnp-tbox.c`), so this is an upstream LaZer issue that is not
  in lazer#24–#27.
- **Defect:** The λ × 256 matrices V3 and V4 compress the 256 Z_q equations z3 = y3 + β3·R·s3 and z4 = y4 + β4·R′·s4
  into λ = 4 equations each. They are derived from `hash0`, and `hash0` is fixed before z3 and z4 exist. z3 and z4 are
  never absorbed into the transcript: not into hash0, not into the tg round, and not into the final `t ‖ v ‖ w1` round.
  They only reach `v` through r0, and by then the equations they must satisfy are already fixed. In LNP22 the
  linear-check challenge comes after the prover sends z. Here the prover knows V before it picks z.
- **Failure scenario (a cheating prover):**
  1. Commit honestly to y3, β and an s1 whose s3 block is out of bound.
  2. Compute R and V from cseed.
  3. Instead of z3* = y3 + β3·R·s3 (large), publish any short z3′ with V3·z3′ ≡ V3·z3* (mod q). This is an
     inhomogeneous SIS instance with only 4 rows mod q ≈ 2^42 and 256 unknowns (lattice determinant 2^168). Babai on
     an LLL basis of a 20–40-dimensional sublattice gives entries of a few hundred, far below Bz3 = √444,049,040,871 ≈
     666k (z4: Bz4 = 101,580).
  4. Every tbox equation now holds exactly on the committed values, so the rest of the proof is honest and both
     verifiers accept.

  What this breaks:
  - **(i) The approximate ℓ∞ proof** on s4 = Ds·s1 (the nprime = 1 filler: `s[0]` in R_REG / R_DR, `e2_t` in R_DS /
    R_TX…). On its own this has little impact, because those polys also sit in an exact-ℓ2 block.
  - **(ii) The anti-wraparound guarantee of every exact-ℓ2 proof (the main impact).** LNP22 needs ‖s3‖ small so that
    ‖e‖² + ‖υ‖² ≡ B² (mod q) implies equality over Z. Without the z3 bound only the slack left by the z1 norm check
    limits s1:
    - ‖z1‖ ≤ σ1·√(2·m1·d). A cheater may take y1 = 0. With ‖c‖ ≈ 39 this allows ‖e‖ up to about 1.46·10^6 for R_TX
      (σ1 = 1.55·2^18, m1 = 153), and about 3.7·10^6 for R_TXM8 / 16 / 80 / 160 (σ1 = 1.55·2^19, m1 = 238–426).
    - A wrap needs ‖e‖² ≥ q − B² ≈ 4.4·10^12, that is ‖e‖ ≳ 2.1·10^6.
    - So the R_TXM shapes with log2stdev1 = 19 can prove a noise block with ‖e‖² = B² − ‖υ‖² + q directly.
    - The other relations can still get there by putting e along one canonical-embedding direction and grinding c over
      fresh masks. For a symmetric c the embedding |σ_j(c)| ≤ 27 holds for roughly half of all challenges; each try
      costs one A·y and one hash.
    - Result: per-credit noise about 2·10^6 (ℓ2) against the proven bound √l2Bsq ≤ 164. That breaks the noise budget
      and the mint margin (pq-zero-knowledge.md §4.3, threat T5), well beyond what lazer#25 allowed.

  The exploit chain is my analysis and was not run. The code fact (V is fixed before z3 / z4) is certain.
- **Suggested fix:**
  - Absorb the coder encodings of z3 and z4 into the transcript after R is derived and before V is derived, e.g.
    hash0 := H(cseed ‖ enc_grandom(z3) ‖ enc_grandom(z4)), in both prover and verifier.
  - Apply it to every implementation: C generic (`_lnp_tbox_compute_z34` / `_lnp_tbox_check_z34`), C SV, Rust
    `proof/tbox.rs` and `sv.rs`.
  - Keep R derived from cseed.
  - This changes the transcript, so it needs a `proofSystemId` bump (v3), regenerated vectors and `proofs_fnv`, and an
    upstream report.
  - Before the fix, write a cheating-prover PoC in the style of `l2dom/` (honest commitments, out-of-range s3, z3′
    from CVP) and add it to `check_tbox_fixes.sh`.
- **Confidence:**
  - Defect: high (read in all four implementations, identical upstream).
  - Exploitability for R_TXM M ≥ 8 (log2stdev1 = 19): medium-high.
  - Exploitability for the log2stdev1 = 18 relations: medium (needs the grinding step).

### D-2 (P2, prover-only, ZK): the z2 rejection test gets z1's variance, and is a "bimodal" test with no sign (Codex lead (a): confirmed)

- **Where:** C `lazer/lnp-quad.c:274–275`: `rej_bimodal (…, z2coeffs, cs2coeffs, params->scM2, params->stdev1sqr)`.
  Rust `rust/src/proof/quad.rs:322`, ported as is (the comment at `:318` notes it). Upstream is the same
  (`c91b3ab:pqz-core/lazer/lnp-quad.c:266–268`). `abdlop.c:379` uses `rej_standard` with `stdev2sqr` instead, but
  `abdlop_prove` is not on the PQZ path.
- **Defect:**
  - Every parameter set has rej2 = 2 and log2stdev2 = 12, with log2stdev1 = 18 or 19. So σ1²/σ2² = 2^12 or 2^14. I
    checked numerically that stdevNsq = (1.55·2^log2stdevN)² in all 14 headers.
  - With σ1² in the formula, a = ‖v‖²/2σ1² ≈ 2.6·10^-4 and |y| = |⟨z,v⟩|/σ1² ≈ 4·10^-4, so the acceptance probability
    is 1/M2 ± 0.1 % and nearly independent of z2. The z2 rejection step is in effect a no-op that only costs a factor of
    M2 ≈ 2.9 in retries.
  - Even with σ2, the test is a bimodal test applied without a random sign. Upstream's own comment says so: "XXX sample
    sign with bimodal ?". Its output density is D_σ(z)·2/(1 + e^{−2⟨z,v⟩/σ²}), not D_σ.
- **Failure scenario:** the published z21 is distributed as D_σ2 + c·s21, not D_σ2, so it leaks the fresh commitment
  randomness s2. Size with the current parameters:
  - s2 is ternary, so ‖c·s2‖² ≈ 1536·2900 typically.
  - KL(real ‖ simulated) ≈ ‖c·s21‖²/2σ2² ≈ 0.04–0.06 nats per proof. The worst case is ln M2 ≈ 1.06 nats.
  - Without s2 the marginal is a Gaussian with relative variance +2.5·10^-5, which is negligible.
  - Practical leakage: under 0.1 bit about a 4352-trit secret that is fresh per proof. Not exploitable as far as I can
    see, but the ZK simulation argument (the hybrid that needs z independent of s2) does not hold as written.
- **Suggested fix:**
  - Passing `stdev2sqr` alone does not fix it: the sign-less bimodal test leaks about the same KL.
  - Either switch z2 to standard rejection (rej2 = 1 with M2 re-derived by the codegen for σ2 and ‖c·s2‖ ≤ η‖s2‖), or
    add the β-style random sign that the tbox uses for z3 / z4. The second option needs protocol support.
  - Both change honest proofs, and the first changes the parameters (proof size, MSIS β). Bundle it with the D-1 bump.
  - Report upstream.
- **Confidence:** high (code). The impact numbers are estimates.

### D-3 (P3, prover-only): the tbox sign sampler reads bit 8 of a `uint8_t`, which forces β4 = +1 on every fourth attempt (Codex lead (b): confirmed)

- **Where:** C `lazer/lnp-tbox.c:1654` (β3 reads bit 8 − nrbits) and `:1675` (β4 reads bit 8 − nrbits + 1 after
  nrbits was already decremented). Rust `rust/src/proof/tbox.rs:923` and `:935`, ported as is ("C's bit index, as
  is"). Upstream is the same.
- **Defect:** nex > 0 and nprime > 0 in every relation. Per attempt k = 0..3 inside one refill, β3 reads bit 2k and β4
  reads bit 2k + 2:
  - On k = 3, β4 reads bit 8 of `rbits`. That bit is always 0 after integer promotion, so β4 = +1.
  - β3 of attempt k + 1 reuses β4's bit from attempt k, and bits 1, 3, 5 and 7 are never used.
- **Failure scenario:**
  - A proof whose z3 / z4 loop accepts on attempt 3, 7, 11, … publishes z4 with a fixed sign. Then the bimodal test is
    biased toward ⟨z4, R′·s4⟩ > 0, with KL ≤ ln M4 = 0.017 nats.
  - The loop accepts with probability 1/(M3·M4) ≥ 0.94, so attempt ≥ 3 happens with probability ≈ 4·10^-5 to
    1.9·10^-4, depending on the relation.
  - Expected leakage is ≲ 3·10^-6 nats per proof.
  - The reused bit is harmless: only the accepted attempt is published, and the bimodal acceptance does not depend on
    the sign.
  - Negligible in practice; a correctness bug against LNP22.
- **Suggested fix:** take β3 from bit (8 − nrbits) and β4 from the next bit, both read before the decrements, or simply
  refill when nrbits < 2. This changes honest proofs (`proofs_fnv`), so fold it into the next bump. Also clear `rbits`
  at the end (it is a secret sign).
- **Confidence:** high.

## Areas checked and found sound

- **Decoder (`coder.c`, `pqz_decproof`):**
  - Every read goes through `RDB`, bounded by `in_len`.
  - The unary loops (grandom, ghint) stop when the error flag is set, so time is linear in the proof length.
  - The fixed-width decoder checks the length up front, and `_udecode` range-checks against the modulus.
  - The proof must be consumed exactly (`coder_dec_end` plus the length equality).
  - Decoded grandom magnitudes are below 393,216·2^20 + 2^19 < 2^39 < q/2 under `PQZ_MAX_PROOF` = 98,304, so the
    centred mod-q reduction in `do_verify` does not change the values the norm checks see.
  - Encodings are unique (bijective zig-zag unary plus a fixed two's-complement width).
  - c is decoded mod 17, centred, and compared with the recomputed challenge.
- **Final ABDLOP round (`lnp-quad.c` `lnp_quad_verify`):**
  - c is recomputed from H(hash ‖ t ‖ v ‖ w1) and compared.
  - z1 ℓ2 bound; the bound computation does not overflow.
  - ‖z21‖² + ‖w − γ·w1‖² ≤ B² (P6-Z21 present).
  - ‖hint‖∞ ≤ m.
  - The h coefficients 0 and d/2 are checked to be zero.
  - β ∈ {±1} is enforced by the β3 / β4 equations.
  - The z3 ℓ2 and z4 ℓ∞ norm checks run before any use.
- **Challenge and samplers:**
  - `_intvec_urandom_autostable`: 32 free coefficients in [−8, 8], σ₋₁-symmetric, 17^32 ≈ 2^130.8.
  - `_brandom` with k = 1 gives R entries in {−1, 0, 1}.
  - `_urandom_i64` is deterministic rejection from the PRF, with negligible rejection for q and 5/32 for mod 17; it
    has no attacker-controlled loop.
  - The rng domain is little-endian, so it does not depend on the platform.
- **`rejection.c`:** the inputs match the parameters (scM in [1, 64); stdevNsq consistent in all 14 headers). The
  tbox bimodal test for z3 / z4 gets the right variance (stdev3sqr / stdev4sq), v = R·s with β reverted, and a real
  random sign (apart from D-3). The saturating arithmetic is as documented.
- **Limb code (`src/pqz_mpn.h`, `int.c`):**
  - The schoolbook multiply carries correctly in 128 bits.
  - Restoring division returns the top quotient limb as GMP does.
  - `int_div` copies before an aliased use.
  - `int_set_i64` with INT64_MIN is fixed (lazer#27).
  - No `long`-width dependence was found in the kept LaZer `.c` files: the earlier `long` in `coder.c` became
    `int64_t`.
- **Worst-case verifier time and memory:** every loop is bounded by the parameters, not by the input. The decoder is
  linear in the proof length.

## Not covered or only partly covered

- `lnp-tbox.c`'s Schwartz–Zippel accumulators (`__schwartz_zippel_accumulate*`, `_auto`, upsilon / binary / ℓ2 /
  z3 equation algebra): I traced only the z4 path and the challenge seeding, not every coefficient.
- `poly*.c`, `spoly*.c`, `dcompress.c` (UseHint), `grandom.c` (the Gaussian's accuracy and tail), `shake128.c`,
  `aes256ctr.c`, the arena (`memory.c` / `src/pqz_arena.c`), and the NTT (`src/pqz_ntt.c`) were not read line by line.
  Native against wasm32 divergence was checked only at the type level.
- **Challenge set.** LNP22's challenge set requires √‖σ₋₁(c)·c‖₁ ≤ η (η = 140), and the sampler does not reject
  challenges that violate it. My estimate of the violation rate is about 6σ out (very rare), and its effect is on the
  extractor's MSIS bound, not a direct attack. I did not quantify it, so I list it here and not as a finding.
- **Cosmetic upstream copy-paste.** In the second allocation loop, `lnp-tbox.c:1023` (verifier) and `:536`
  (prover) set `r1prime_sz[i]->nelems_max` where `r1prime_sz2[i]` was meant. It only leaves sz2's capacity at np > n_. I found no
  accept/reject impact.
- `src/pqz_sv.c` / `rust/src/sv.rs` beyond the z3 / z4 transcript round (D-1) are left to the SV reviewer.

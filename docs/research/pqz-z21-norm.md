> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# LaZer `lnp-quad` / `abdlop` verify: `z21` is never norm-checked, only ‖w − γ·w1‖ is bounded (lazer#26, P6-Z21)

Written 2026-10-13 (TODO P6-Z21). Finding, proof of concept, impact on PQZ and fix for the third LaZer finding of the
PQZL verifier work; the first two are `pqz-tbox-soundness.md` (lazer#24) and `pqz-l2-domain.md` (lazer#25). Found by
the independent review of the specialised verifier (finding 1 of the review of `pqz_sv.c`, 2026-10-13; the review
document is kept locally, its reproducers are `pqz-core/sv/review/`). Upstream issue:
[lazer-crypto/lazer#26](https://github.com/lazer-crypto/lazer/issues/26) (public, filed 2026-10-13, owner). Fixed in
`pqz-core` on branch `pqz-z21` (not merged). **No decision is recorded here**; the `proofSystemId` question is a
recommendation (§6.3).

**[measured]** marks a number from a run (the run file is named). **[code]** marks a statement read in the source
at the given lines. **[paper]** marks a statement of LNP22 ([eprint 2022/284](https://eprint.iacr.org/2022/284),
full version). **[estimate]** marks a number computed from bounds or counts. **[inference]** marks a conclusion drawn
here.

## 1. Summary

- The proof carries `z1`, `z21` (the `A2′` part of the masked commitment randomness) and a hint. LaZer's verifier
  (`lnp_quad_verify`; `abdlop_verify` the same) checks ‖z1‖², ‖w − γ·w1‖² (the `z22` part, which is not sent but
  recovered) and ‖h‖∞. It **never bounds `z21`** [code].
- LNP22 (Fig. 18, Theorem A.2) and LaZer's own parameters bound the whole `z2 = (z21, z22)`: the verifier is to check
  ‖(z21, A1·z1 + A2′·z21 − c·2^D·tA,1 − γ·w1)‖ ≤ B, with B = `Bound_()` of the codegen; the extractor and the MSIS
  bound `Bound() = 4η·√(B1² + (2B)²)` rely on it; the honest prover rejects on exactly that sum [paper, code].
- PoC: a cheating `R_REG` prover with `y21 ≪ 7` and its z2 checks skipped gives an 85,105-byte proof with
  ‖z21‖² = 87.3 × Bsq; **both** PQZ verifiers (`pqz_verify`, `pqz_verify_fast`) accepted it; with the fix both reject
  it [measured].
- Impact before the fix: bounded only by `PQZ_MAX_PROOF`, `z21` raises the extracted MSIS bound from 2^35.3–2^36.0 to
  ≈ 2^41.0–2^41.3; the MSIS block size of the five relations falls from β 452–461 to **β 286–311** (core-SVP classical
  2^132–2^134.6 → **2^83.5–2^90.8**), below CTR-PQZ-03's β ≥ 450 and Kyber-512's 406 [estimate, pinned estimator].
  No known attack, nothing deployed; every PQZ statement-level guarantee (key uniqueness, noise budget, no mint) rests
  on this knowledge soundness and was weaker by that margin, none was broken outright [inference].
- Fix (verifier only, both verifiers): ‖z21‖² + ‖w − γ·w1‖² ≤ Bsq. Honest proofs, the transcript and the proof format
  are unchanged; KAT, the five relations' `proofs_fnv` and every honest verify are unchanged [measured, §7].
  Recommendation: no `proofSystemId` bump (§6.3).

## 2. Where

LaZer `3330e48` (vendored pristine in `c91b3ab`) and upstream head `b958e24` have the same `src/lnp-quad.c` /
`src/abdlop.c` logic [code]:

| What | `b958e24` | `pqz-core` (`pqz-z21`) |
|---|---|---|
| verifier checks ‖z1‖², ‖w − γ·w1‖² ≤ Bsqr, ‖h‖∞ ≤ m | [`lnp-quad.c` L484–L512](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-quad.c#L484-L512) | `lazer/lnp-quad.c` 489–533, the fix at 507–518 |
| same in `abdlop_verify` | [`abdlop.c` L525–L548](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/abdlop.c#L525-L548) | `lazer/abdlop.c` 522–560, the fix at 538–549 |
| `z21` enters the equations, no norm | [L415](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-quad.c#L415), [L425](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-quad.c#L425), [L437](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-quad.c#L437) | |
| prover: reject unless ‖y2‖² = ‖(z21, z22 − c·tA,2 − w0)‖² ≤ Bsqr | [L279–L285](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-quad.c#L279-L285) | `lazer/lnp-quad.c` 283–293 |
| codegen `Bound_()`, `Bound2() = 2·Bound_()`, `Bound() = 4η√(B1² + B2²)`, `Bsq = floor(Bound_()²)` | `scripts/lnp-tbox-codegen.sage` L30–L60, also `lnp-quad-codegen.sage`, `abdlop-codegen.sage` | `params/codegen/lnp-tbox-codegen.sage` 30–60, 510 |
| specialised verifier, last check | — | `src/pqz_sv.c` 1846–1850 (was ‖w − γ·w1‖² only) |

Every PQZ verify reaches the check through `lnp_tbox_verify` → `lnp_quad_many_verify` → `lnp_quad_verify`
(`lnp_quad_eval_verify` goes the same way); `abdlop_verify` is not on PQZ's path but has the same gap and gets the
same fix. No other LaZer verifier has a `z21` [code: every `*_verify` in `lazer/`].

## 3. What the verifier should check

LNP22, Appendix A.2, Fig. 18 (ABDLOP opening proof with Dilithium compression, A2 = [A2′ I_n]) [paper]:

- Prover: y1, y2,1, y2,2 Gaussian; w = A1·y1 + A2′·y2,1 + y2,2, (w1, w0) = Decompose(w, γ); after the challenge,
  z1 = y1 + c·s1, z2 = (z2,1, z2,2) = y2 + c·s2, rejection on both, then z2,2 := z2,2 − c·tA,2 − w0, and
  "**if ‖(z2,1, z2,2)‖ > B then abort**"; sends (z1, z2,1, h).
- Verifier: w1 = UseGHint(h, A1·z1 + A2′·z2,1 − c·2^D·tA,1), ‖z1‖ ≤ s1·√(2·m1·d),
  **‖(z2,1, A1·z1 + A2′·z2,1 − c·2^D·tA,1 − γ·w1)‖ ≤ B**, ‖h‖∞ ≤ (q − 1)/(2γ).
- Theorem A.2: B = s2·√(2·m2·d) + η·2^(D−1)·√(n·d) + γ·√(n·d)/2. Soundness: from two accepting transcripts with
  u^(i) := γ·w1 + c^(i)·2^D·tA,1 − A1·z1^(i) − A2′·z2,1^(i), "we have ‖(z2,1^(i), u^(i))‖ ≤ B for i = 0, 1", which gives
  ‖c̄·s̄2‖ ≤ 2B; the MSIS bound of the whole protocol is B̄ = 4η·√(B1² + B2²) (Theorem B.7) with B2 = 2B.

LaZer's codegen matches this exactly: `Bound_()` is that B term by term, `Bound2() = 2·Bound_()`, `Bound()` is B̄, and
the generated `Bsq = floor(Bound_()²)` [code]. The honest prover rejects on ‖(z21, z22 − c·tA,2 − w0)‖² ≤ Bsqr, and
`A1·z1 + A2′·z21 − c·2^D·tA,1 − γ·w1` is −(z22 − c·tA,2 − w0) [paper, the correctness part of Thm A.2; measured
in §7.2: the verifier's sum equals the prover's on all 290 + 145 z21-differential proofs, and the accept / reject boundary is exactly Bsq].

**The check, chosen: ‖z21‖² + ‖w − γ·w1‖² ≤ Bsq** (Bsq = `Bsqr` of the `quad_many` params). Reasons:

1. It is LNP22's verifier condition (one norm on the whole z2).
2. It is the bound the parameters assume: the extractor needs ‖(z21, u)‖ ≤ B per transcript to get 2B for the
   difference, i.e. `Bound2()`. A per-part check (each of ‖z21‖, ‖z22‖ ≤ B, or each ≤ 2·Bound_) would let the whole z2
   reach √2·B (or 2√2·B) and the MSIS instance would again be larger than the one the parameters were sized for.
3. Every honest proof satisfies it: it is literally the prover's rejection condition, so completeness is unchanged
   and the honest acceptance set is exactly the same [code; measured §7].

Side observation (not changed): LNP22 bounds the hint by (q − 1)/(2γ) = m/2; LaZer checks ‖h‖∞ ≤ m (its comment says
"2·linf(h) ≤ m", the code compares linf with m). The extraction does not use the hint bound, and UseGHint reduces mod m
anyway; a hint coefficient of magnitude above m/2 needs ≈ m bits in the unary hint code (m ≈ 2^25), far beyond
`PQZ_MAX_PROOF`, so the two bounds accept the same proofs here [inference; the review noted the same for |hint| = m].

## 4. Proof of concept

Harness `pqz-core/sv/review/` (imported from the review branch `pqz-sv-review`, `0aecc93`): `review.sh norm` builds a
copy of `lazer/lnp-quad.c` whose prover (lines 1–335 only) takes the hooks of `normpoc_hooks.h` and links it into a
library variant under `build/review/`; `./build.sh` never compiles the hooks. Modes: honest; `z1_over` (y1 ≪ 3, z1
rejection skipped); **`z21_big`** (y21 ≪ 7, the z2 rejection and the prover's ‖y2‖ check skipped); `w_over` (w1 + 2
mod m before the final hash, hint + 2). The `R_REG` proofs go to the production library and to controls with one check
removed from both verifiers.

| Proof (bytes) | before the fix: production generic / fast | after: production generic / fast | after: control, z21 term removed (= before) |
|---|---|---|---|
| honest (28,070) | ACCEPT / ACCEPT | ACCEPT / ACCEPT | ACCEPT / ACCEPT |
| z1_over (32,663) | REJECT / REJECT | REJECT / REJECT | REJECT / REJECT |
| **z21_big** (85,105; ‖z21‖² = 1.941·10^15 = 87.3 × Bsq) | **ACCEPT / ACCEPT** | **REJECT / REJECT** | ACCEPT / ACCEPT |
| w_over (28,262) | REJECT / REJECT | REJECT / REJECT | REJECT / REJECT |

Runs [measured]: before `pqz-core/rel3/runs/z21-before-norm.txt` (main `cd00ab2` + the harness, proof hashes
`z21-before-norm-proofs.sha256`); after `pqz-core/rel3/runs/z21full-norm.txt` (same proof bytes: the prover is
unchanged, `z21full-norm-proofs.sha256`). The full table with all three controls is in those files.

## 5. Impact on PQZ before the fix

### 5.1 The MSIS instance

With no z21 check the only bound on `z21` is the proof length. `z21` is coded by `coder_enc_grandom`: per coefficient
log2stdev2 + 1 = 13 binary bits, a final zero and a unary high part, so each spare bit adds 2^log2stdev2 = 2^12 to
one coefficient; for a fixed bit budget one coefficient maximises ‖z21‖. Budget E = 8·(`PQZ_MAX_PROOF` − smallest
honest proof) + 3 bits per Gaussian-coded coefficient (the unary bits of an honest proof, an over-estimate), so
Z21max = (E/2 + 1/2)·2^13 ≈ 2^30.9–2^31.2 (z21 is centred mod q, cap q/2 = 2^41, not reached). The z22 part stays
bounded by B (that check exists), so the extractor gets ‖c̄·s̄2‖ ≤ 2·√(Z21max² + B²) instead of 2B. Computed by
`pqz-core/params/z21_msis.sage` with the codegen itself and lattice-estimator `53da598` (`SIS.lattice`, `RC.ADPS16`,
the pinned Sage image; `SCRIPT=z21_msis.sage params/run_e_s1.sh …`); output `pqz-core/params/estimator-z21.txt`, raw
log `estimator-z21-raw.txt` [estimate]:

| Relation | Bsq (‖z2‖ ≤ B) | Z21max | Z21max² / Bsq | MSIS bound `Bound()` designed → no z21 check | δ (codegen formula) | MSIS β / log2 rop (classical core-SVP) |
|---|---|---|---|---|---|---|
| `R_REG` | 2^44.34 | 2^31.16 | 2.6·10^5 | 2^35.30 → 2^41.29 | 1.00366 → 1.00501 | 452 / 132.0 → **286 / 83.5** |
| `R_TX` | 2^48.45 | 2^30.88 | 1.0·10^4 | 2^35.97 → 2^41.01 | 1.00363 → 1.00473 | 456 / 133.2 → **311 / 90.8** |
| `R_BURN` | 2^48.45 | 2^30.90 | 1.0·10^4 | 2^35.95 → 2^41.03 | 1.00363 → 1.00473 | 457 / 133.4 → **311 / 90.8** |
| `R_DS` | 2^42.08 | 2^31.14 | 1.2·10^6 | 2^35.31 → 2^41.27 | 1.00366 → 1.00500 | 452 / 132.0 → **286 / 83.5** |
| `R_DR` | 2^50.41 | 2^31.14 | 3.8·10^3 | 2^35.84 → 2^41.27 | 1.00361 → 1.00479 | 461 / 134.6 → **306 / 89.4** |

The designed column reproduces `estimator-e-s1.txt` / `estimator-e-s1-rel3.txt` (β 452 / 456 / 457 / 452 / 461), so
the setup is the one the parameters were sized with. The review's rougher figure (δ 1.0047–1.0050) agrees.

### 5.2 What that means

- **Proof-system claim.** CTR-PQZ-03 asks every attack on the proof's MSIS / MLWE instances to cost at least
  Kyber-512's (β ≥ 450 in block-size terms). For the instance the v2 verifiers actually enforced before the fix that
  was β 286–311, core-SVP 2^83.5–2^90.8 classical — below Kyber-512 (406) and the target. The knowledge-soundness
  statement the parameters were sized for did not hold as written [estimate].
- **Not a known attack.** Knowledge soundness says: an accepting prover either knows a witness or yields an MSIS
  solution of norm ≤ `Bound()`. A larger bound makes the MSIS fallback easier; it does not by itself give a forgery.
  Turning an easier MSIS instance into a false proof would mean finding a short kernel vector of [A1 | A2] whose
  A1-part stays within B1 (z1 is still checked) and then using it to equivocate the commitment; a lattice reduction at
  block size ≈ 290 in dimension ≈ 3,300 is far beyond anything run today. Nothing was deployed (all chains are
  test-only; the precompile, P6f, is not built), so no state was ever accepted under the gap [inference].
- **Statement-level guarantees.** Key uniqueness (§4.3 kernel argument on registered keys), the noise budget
  B_FRESH / the 12.16 M cap and the 4.1× mint margin (T5), and "no mint" (T2) all use the witness norms that the
  extractor delivers. None of them uses z21 directly, and none was broken outright, unlike lazer#25 where the per-block
  bounds were not enforced at all; each held only under MSIS at the weakened instance above instead of the designed
  one. With the fix they rest on β ≥ 450 again [inference].
- **The specialised verifier** mirrored LaZer exactly (the review's equivalence result), so the two verifiers agreed
  on the gap; there was never a generic-rejects / fast-accepts case [measured: the PoC table].

## 6. The fix

### 6.1 Generic verifiers

`lazer/lnp-quad.c` `lnp_quad_verify` and `lazer/abdlop.c` `abdlop_verify`, marked `PQZ (P6-Z21)`:

```c
  polyvec_subscale (tmp1, gamma, w1, 0);
  polyvec_l2sqr (l2sqr, tmp1);
  polyvec_l2sqr (l2z21, z21);          /* new */
  int_add (l2sqr, l2sqr, l2z21);       /* new */
  b = int_le (l2sqr, params->Bsqr);
```

`l2sqr` is a 2-limb integer (128 bits); a decoded z21 is centred mod q (|·| < 2^41), so the sum cannot overflow.

### 6.2 Specialised verifier

`src/pqz_sv.c` `verify_body`, last check: `l2_sum (z21, …, Bsq)` (the old `l2_le` loop now returns the running sum)
and then ‖w − γ·w1‖² ≤ Bsq − that sum. Same integer quantity as the generic path: SV's `z21` array is the same
centred residue (both paths `polyvec_mod` + `polyvec_redc` the decoded z21), and any coefficient ≥ 2^31 is rejected by
both (its square alone exceeds every Bsq < 2^51) [code].

### 6.3 `proofSystemId`: recommendation, no bump

The fix changes the accepted set, not the transcript, the proof format, the parameters or any honest proof
(`proofs_fnv` unchanged, §7). pq-zether.md §8 bumps the id for "every parameter, relation, transcript or
serialization change"; this is none of those. A bump would also retire nothing: no verifier with the gap was ever
deployed (P6f not built), and every v2 proof an honest prover can make still verifies. If a verifier had been
deployed, the change would be a consensus change (an activation point), which an id bump would not solve either.
Recommendation: keep v2 and make the z21 check part of what "v2 verifier" means (the P6f precompile ships with it).
Owner decision.

## 7. Regression

### 7.1 The PoC as a check

`pqz-core/check_tbox_fixes.sh` (run by `rel3/relfix.sh`) now also runs `sv/review/review.sh norm` and requires: the
`z21_big` proof is produced, the honest proof verifies, `z21_big`, `z1_over`, `w_over` are rejected by both production
verifiers, and the control with the z21 term removed from both verifiers accepts `z21_big` (so a REJECT is the fix,
not a broken PoC). Run `pqz-core/rel3/runs/z21full-tbox-fixes.txt` [measured].

### 7.2 Differential test with z21-inflated proofs

Mutated proofs cannot reach the check (they fail the final hash first), so `sv/review/z21diff.c` (`review.sh zdiff`,
also run by `sv/diff.sh`) proves all five relations with the cheating prover in mode 4: the first polynomial of y21
times k, k = round(1.25^j), j = 0 … 31, z2 checks skipped; per proof both verifiers must agree, and must accept exactly
when the prover's ‖(z21, z22)‖² ≤ Bsq. Results (§7.3): 290 cases, 0 disagreements between the verifiers, 0 cases where the verdict differs from ‖(z21, z22)‖² ≤ Bsq, both verdicts for every relation, the closest case 1.0103 × Bsq.

### 7.3 Runs

All under `scripts/capped` on this machine, branch `pqz-z21` [measured]:

| Check | Result | Run file (`pqz-core/…`) |
|---|---|---|
| PoC before the fix (main `cd00ab2` + the harness) | `z21_big` ACCEPT / ACCEPT (generic / fast) | `rel3/runs/z21-before-norm.txt` |
| PoC after the fix | `z21_big` REJECT / REJECT; control without the z21 term ACCEPT / ACCEPT; honest ACCEPT / ACCEPT; `z1_over`, `w_over` REJECT / REJECT; the four PoC proofs byte-identical to the before run | `rel3/runs/z21full-norm.txt`, `z21full-norm-proofs.sha256` vs `z21-before-norm-proofs.sha256` |
| `check_tbox_fixes.sh` (P6-SZ trace, P6-L2 l2dom, P6-Z21) | `check_tbox_fixes: ok` | `rel3/runs/z21full-tbox-fixes.txt` |
| KAT | 19/19 | `rel3/runs/z21full-kat.txt` |
| `proofs_fnv`, all five relations (native 5 and 10 seeds, wasm 3 and 5 seeds) | unchanged from v2 (`R_REG` `5124b5f8` / `e2a4ba8d` / `e23b746d`, `R_TX` `fa87fff6` / `b69bb773` / `762dacd2`, `R_BURN` `8df6b744` / `626710cc` / `3d80d4a8`, `R_DS` `46c77f3e` / `f4b59d4b` / `216b75fc`, `R_DR` `84a15cd2` / `ea72ce2d` / `e0d2deda`; `pqz-core/STATUS.md` v2 table) | `rel3/runs/z21full-fnv-native.jsonl`, `z21full-fnv-wasm.jsonl`, `z21full-native.jsonl`, `z21full-wasm.jsonl` |
| bench: honest verifies and six tamper kinds, five relations | `fails 0` native, wasm, ASan + UBSan (only the upstream nits of STATUS Open 4, the same 4 reports as `v2full`) | `rel3/runs/z21full-native.jsonl`, `z21full-wasm.jsonl`, `z21full-asan.jsonl`, `z21full-asan-stderr.txt` |
| `sv/check_sv_fixes.sh` | tree 10 / 0 mismatches, SZ reverted 10 / 10, L2 reverted 10 / 10: ok | `rel3/runs/z21full-check-sv-fixes.txt` |
| z21 differential, probe (1 seed) | 145 cases, 0 disagreements, 0 expectation mismatches, both verdicts for every relation, closest ‖z2‖² / Bsq = 1.0103 | `rel3/runs/z21-probe-z21diff.jsonl` |
| differential test, portable, the v2-sized sample (`pqz_sv_diff 4 4 2 1 10 12 12 12`, as `sv/rel3.sh`): honest and mutated proofs, five relations | 2,710 cases, 0 mismatches, PRG check 0 mismatches | `sv/runs/z21s-diff-portable.jsonl` |
| z21 differential, 2 seeds (`review.sh zdiff 2 31`) | 290 cases (58 per relation: 29 values of k × 2 seeds), 0 disagreements, 0 expectation mismatches, 0 prove errors; accepted / rejected `R_REG` 36 / 22, `R_TX` 48 / 10, `R_BURN` 48 / 10, `R_DS` 27 / 31, `R_DR` 53 / 5; closest ‖z2‖² / Bsq = 1.0103 | `sv/runs/z21s-z21diff.jsonl` |
| z21 differential under ASan + UBSan (malloc path, 1 seed) | 145 cases (`R_REG`, `R_TX` from a five-relation process that was stopped at `R_BURN`, most likely at the 4 GB cap since the malloc path keeps the per-prove statement objects [inference]; `R_BURN`, `R_DS`, `R_DR` one process each), 0 disagreements, 0 expectation mismatches, no sanitizer report | `sv/runs/z21s-asan-z21diff-all-killed.jsonl`, `z21s-asan-z21diff-m{4,8,16}.jsonl`, their `-stderr.txt`, `z21s-rc.txt` |

A first attempt at `sv/diff.sh z21` with its defaults (40 / 20 proofs per relation, ten times the v2 sample) was
stopped after 29 min in the portable step (`rel3/runs/z21full-rc.txt`); the v2-sized sample above replaced it. The
x86-64-v3 and wasm differential builds were not re-run: `pqz_sv.c` changed only in the last norm check and setup
guards, both build-independent C.
Generic verify times are unchanged within host noise (the extra work is one ℓ2 norm of 45–46 polynomials): native
p50 `R_TX` 648 → 677 ms, `R_REG` 177 → 184 ms (`z21full-native.jsonl` against the v2 row of `pqz-core/STATUS.md`).
Command: `NP=10 NV=30 NPW=5 NVW=10 scripts/capped pqz-core/rel3/relfix.sh z21full`, then
`scripts/capped pqz-core/sv/check_sv_fixes.sh`, `ZN=2 pqz-core/sv/diff.sh z21`, and the ASan + UBSan z21
differential (`CC='clang -fsanitize=address,undefined … -DPQZ_DEBUG_MALLOC' sv/review/review.sh zdiff 1 31`).

## 8. SV hardening folded in (review findings 2, 4–7)

No effect on accept / reject at the generated parameters; each closes a precondition that held only by the current
numbers (`src/pqz_sv.c`):

| Finding | Change |
|---|---|
| 2 transcript buffer sized with a hard-coded 25-bit w1 width (`R_DS` has log2m = 27) | sized from `S->log2m` as the max of the final-round and ty encodings, + 64; `log2m ≤ 42` checked at setup |
| 4 `modq` comment said \|x\| < 2^62 | precondition stated: −q·2^20 ≤ x < 2^62 (every caller passes \|x\| < 2^51) |
| 5 z1bnd guard admitted t·2^(2·log2stdev1) > 2^64 | requires t < 2^(62 − 2·log2stdev1) |
| 6 `l2_le` needs bnd < 2^62, unchecked | Bz3sqr, Bsq, z1bnd < 2^62 asserted at setup |
| 7 unknown op cleared R_REG's slot on the fail path | returns before touching any slot |

Finding 8 (all library state global; the P6f precompile wrapper must serialise libpqz calls) is recorded in
`pqz-core/STATUS.md` Open 6 for P6f. Finding 3 (β4 i = d − 1 and υ share a domain) is harmless and stays a note
(`pqz-l2-domain.md` §8).

## 9. Files

- Fix: `pqz-core/lazer/lnp-quad.c`, `pqz-core/lazer/abdlop.c` (`PQZ (P6-Z21)`), `pqz-core/src/pqz_sv.c` (last check).
- PoC and differential: `pqz-core/sv/review/` (`review.sh norm | zdiff`, `normpoc.c`, `normpoc_hooks.h`,
  `z21diff.c`); `./build.sh` never compiles them.
- Regression: `pqz-core/check_tbox_fixes.sh` (run by `rel3/relfix.sh`), `pqz-core/sv/diff.sh` (runs `zdiff`).
- Estimate: `pqz-core/params/z21_msis.sage`, `estimator-z21.txt`, `estimator-z21-raw.txt`.
- Runs: `pqz-core/rel3/runs/z21-*`, `z21full-*`; `pqz-core/sv/runs/z21-*`.

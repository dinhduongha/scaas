> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# LaZer `tbox`: one Schwartz–Zippel challenge pair for all λ/2 evaluation accumulators (lazer#24, P6-SZ)

Written 2026-10-13 (TODO P6-SZ). Finding, fix and evidence for the first of two Schwartz–Zippel findings in LaZer's
`tbox` that came out of the PQZL verifier work. The second (exact-ℓ2 equations sharing one domain) is
`pqz-l2-domain.md`. Upstream issue: [lazer-crypto/lazer#24](https://github.com/lazer-crypto/lazer/issues/24),
confirmed by the LaZer maintainers. Fixed in `pqz-core` under `proofSystemId` v2 (fix `f1bae83`, merged with the
second fix in `5361946`; version bump and regression check merged in `98695de`). §8 (added 2026-10-19) covers a
third `tbox` finding of a different kind, prover messages missing from the Fiat–Shamir transcript
([lazer#28](https://github.com/lazer-crypto/lazer/issues/28), P6-FS, `proofSystemId` v3). **No decision is recorded
here.**

**[measured]** marks a number from a run (pointed to). **[code]** marks a statement read in the source at the given
lines. **[estimate]** marks a number computed from counts. **[inference]** marks a conclusion drawn here.

## 1. Summary

- `__schwartz_zippel_accumulate2` in `lnp-tbox.c` draws only `2·M` uniform Z_q challenges per call and gives that one
  pair of rows to every one of the λ/2 accumulator pairs. The evaluation step therefore performs **2** independent
  Schwartz–Zippel tests over Z_q, not λ = 4 [code].
- For PQZ's modulus (`q = 2^42 − 215`, prime, λ = 4) a cheating prover that violates one of the affected equations is
  accepted with probability ≈ q^-2 ≈ **2^-84** per Fiat–Shamir attempt instead of q^-4 ≈ 2^-168. That term then
  dominates the knowledge error: ≈ 2^-84 overall instead of the codegen's stated ≤ 2^-127 [estimate].
- Fix: draw the full λ × M challenge matrix and give accumulator pair i rows 2i and 2i + 1. It changes the transcript
  (PQZL `proofSystemId` v1 → v2); proof sizes and cost are unchanged [measured].
- Impact on PQZ: nothing was deployed on v1 (all chains are test-only); v1 is retired. The upstream bug is in LaZer
  itself, not introduced by the fork [code].

## 2. Where

| Copy | Function | Lines |
|---|---|---|
| LaZer `3330e48` (vendored pristine in `c91b3ab`, `pqz-core/pqzl/lazer/`) and upstream head `b958e24` (the file is unchanged between them) | `__schwartz_zippel_accumulate2`, `src/lnp-tbox.c` | [2333–2366](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L2333-L2366); `INTVEC_T (V, 2 * M, …)` at 2347 |
| `pqz-core` v2 | the same function, fixed | `pqz-core/pqzl/lazer/lnp-tbox.c` 2375–2416 (`PQZ (P6-SZ)` comment at 2389) |
| `pqz-core` specialised verifier | `sz_eval_challenges` | `pqz-core/pqzl/src/pqz_sv.c` (follows the fix, `pqz-specialised-verifier.md` §0) |

The unfixed code [code]:

```c
INTVEC_T (V, 2 * M, Rq->q->nlimbs);
intvec_t subv1, subv2;
...
intvec_get_subvec (subv1, V, 0, M, 1);
intvec_get_subvec (subv2, V, M, M, 1);
intvec_urandom (V, q, log2q, seed, dom);

for (i = 0; i < lambda / 2; i++)
  {
    __schwartz_zippel_accumulate (R2i[i], r1i[i], r0i[i], R2primei, r1primei,
                                  r0primei, M, subv1, params);
    __schwartz_zippel_accumulate (R2i2[i], r1i2[i], r0i2[i], R2primei,
                                  r1primei, r0primei, M, subv2, params);
  }
```

**Which equations.** Every evaluation-step aggregation goes through this function: the M input evaluation equations
(`R_TX` and the other debit / disclosure relations put their single-coefficient rows here), the β3 and β4 coefficient
equations of the approximate-range proof, the υ (ℓ2 slack) binary equation, the binary-witness equation and the
exact-ℓ2 equations [code]. Not affected: the JL / approximate-range steps `__schwartz_zippel_accumulate_z3` / `_z4`
(`INTMAT_T (V, lambda, 256, …)`, a `k = 0..λ−1` loop with `k % 2` choosing the pair, i.e. λ distinct rows;
[3043](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L3043),
[3355](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L3355))
and LaZer's other prover, `lnp-quad-eval.c::_schwartz_zippel_int` (a λ × M matrix, rows `2i` and `2i + 1`;
[172](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-quad-eval.c#L172),
[178](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-quad-eval.c#L178))
[code]. Those two correct paths are what made the reuse stand out.

**Not a fork change.** The pristine vendored copy (`c91b3ab`) has the same function byte for byte. The fork's earlier
`PQZ:` edits near it were `spolymat_set` → `spolymat_swap` in the callee `__schwartz_zippel_accumulate` and do not
touch the challenge derivation [code].

## 3. Why it reduces soundness

In LNP22 (aggregation of the polynomial-evaluation equations with vanishing constant coefficient, Fig. 8 / §4.4) the
challenge matrix Γ is λ × M and accumulator pair j uses its own rows 2j, 2j + 1 (the a / b halves that the
σ-trace and X^{d/2} lifting combine). Each pair is one independent Schwartz–Zippel test: if any of the aggregated
equations has a nonzero constant coefficient, a uniform row of Z_q challenges makes the combination vanish with
probability 1/q. With λ independent rows the escape probability is q^-λ. In the code, pairs i = 0 … λ/2 − 1 receive
the same two rows, so the λ/2 accumulator pairs are copies of one another and only **2** tests are independent,
whatever λ is [inference].

For PQZ's parameters, all five relations (`R_REG`, `R_TX`, `R_BURN`, `R_DS`, `R_DR`): one prime modulus
`q = 2^42 − 215` (log2 q ≈ 42), d = 64, λ = 4 [estimate]:

| | independent Z_q tests | escape probability for one violated equation |
|---|---|---|
| intended (LNP22, λ = 4) | 4 | q^-4 ≈ 2^-168 |
| LaZer `3330e48` / `b958e24`, PQZL v1 | 2 | q^-2 ≈ **2^-84** |
| PQZL v2 (fixed) | 4 | q^-4 ≈ 2^-168 |

The codegen headers state a knowledge error ≤ 2^-127 (under MSIS(23, 214, 2^35.97) for `R_TX`); that figure assumes
the intended λ tests. The overall error is roughly the sum of the MSIS / commitment term (≈ 2^-127) and this
Schwartz–Zippel term, so before the fix it was ≈ **2^-84**, about 43 bits below the claim; after the fix the
Schwartz–Zippel term (≈ 2^-168) is negligible next to 2^-127 and the stated figure holds [inference].

What a cheater could do with it: produce an accepted proof for a statement that violates one of the affected
equations — an out-of-range bit decomposition or digit carry in `R_TX`, a norm equation in `R_REG` — by grinding
≈ 2^84 Fiat–Shamir transcripts. That is far beyond practical cost, so no realistic attack follows, but it is
43 bits short of the soundness the parameters were chosen for, and it was fixed as a soundness defect, not a
performance item [inference].

## 4. The fix

Draw the full λ × M matrix from the same `(seed, dom)` and index two rows per pair (`pqz-core/pqzl/lazer/lnp-tbox.c`,
the change suggested in lazer#24):

```c
INTVEC_T (V, lambda * M, Rq->q->nlimbs);
intvec_t subv1, subv2;
...
intvec_urandom (V, q, log2q, seed, dom);

for (i = 0; i < lambda / 2; i++)
  {
    intvec_get_subvec (subv1, V, (2 * i) * M, M, 1);
    intvec_get_subvec (subv2, V, (2 * i + 1) * M, M, 1);
    __schwartz_zippel_accumulate (R2i[i], r1i[i], r0i[i], R2primei, r1primei,
                                  r0primei, M, subv1, params);
    __schwartz_zippel_accumulate (R2i2[i], r1i2[i], r0i2[i], R2primei,
                                  r1primei, r0primei, M, subv2, params);
  }
```

Prover and verifier share the function, so both re-derive the same enlarged Γ. No parameter changes: λ, q, d and the
dimensions stay; only the number of challenges drawn from each domain grows from 2·M to λ·M.

**Transcript change.** v1 and v2 proofs do not verify against each other (the challenges differ). The PQZL
`proofSystemId` moved to `keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")` together with the second fix
(`pqz-l2-domain.md`), one bump for both (pq-zero-knowledge.md §8, CTR-PQZ-09; `pqz-core/STATUS.md` "proofSystemId v2" has the
`proofs_fnv` table, v1 → v2, for all five relations) [measured]. The specialised verifier (`pqz_sv.c`) follows the
same derivation in `sz_eval_challenges` (`pqz-specialised-verifier.md` §0).

**Cost.** The extra work is (λ − 2)·M uniform samples and as many scalar multiply-adds per call; M is 0 or 1 for most
calls and at most the 80 evaluation equations of `R_TX`. Proof sizes and arena peaks are unchanged; prove / verify
times moved within the host's noise (`pqz-core/STATUS.md`, v2 section) [measured]. The verifier floor
(`pqz-verifier-floor.md`) does not change [inference].

## 5. Evidence

- **Trace harness** `pqz-core/pqzl/sz/` (`sz/README.md`): one honest `R_REG` prove with the `-DPQZ_SZ_TRACE` hook in
  `lnp-tbox.c` (compiled only with that macro; production builds do not define it), which records the Z_q challenge
  vector given to each of the four accumulator slots per transcript domain [measured]:
  - unfixed: in **all 127** evaluation domains slot 0 = slot 2 (`subv1` reused) and slot 1 = slot 3 (`subv2` reused),
    slot 0 ≠ slot 1: 2 distinct rows, verdict "2 independent tests";
  - fixed (v2): 128 domains (the two exact-ℓ2 equations now have one each, `pqz-l2-domain.md`), **0** reuse, all
    four rows distinct, verdict "4 → ok". Output of the v2 full-sample run: `pqz-core/research/pqzl-measure/runs/v2full-sz-trace.txt`.
- **Regression check** `pqz-core/pqzl/check_tbox_fixes.sh` (run by `rel3/relfix.sh`): exits 1 unless the trace reports
  λ = 4 independent tests **and** the ℓ2 check of `pqz-l2-domain.md` passes; with this fix reverted it reports 2
  tests and fails (`pqz-core/STATUS.md`). Last results `pqz-core/research/pqzl-measure/runs/v2-tbox-fixes.txt`,
  `v2full-tbox-fixes.txt`: `check_tbox_fixes: ok` [measured].
- **Specialised verifier**: `pqz-core/pqzl/sv/check_sv_fixes.sh` reverts this line in a copy of `pqz_sv.c`; every honest v2
  proof of the five relations then disagrees with the generic verifier (10 / 10), the tree agrees (0 / 10)
  (`pqz-specialised-verifier.md` §0, merged `dcf0da3`) [measured].
- Honest proofs verify and the bench's tamper cases are rejected on v2 (`fails 0`, KAT 19/19, ASan + UBSan, native
  and wasm proofs byte-identical; `pqz-core/STATUS.md` v2 section) [measured].

## 6. Impact on PQZ

- **Deployed:** none. PQZ has not been deployed on any chain; every SCaaS chain is test-only and redeploys. PQZL v1
  is retired; the precompile accepts only the ids it implements (CTR-PQZ-09) [code].
- **v1 proofs** were sound only to ≈ 2^-84 for the binary, digit, range, slack and norm equations of every relation,
  instead of ≈ 2^-127. No PQZ number other than the knowledge error depended on it: parameters, sizes and the noise
  budget (pq-zero-knowledge.md §4.3) are unchanged by this fix [inference].
- **v2** restores the stated knowledge error; the codegen's figure is now correct for the code that runs.

## 7. Files

- Fix: `pqz-core/pqzl/lazer/lnp-tbox.c` (`PQZ (P6-SZ)`), `pqz-core/pqzl/src/pqz_sv.c` (`sz_eval_challenges`).
- Harness: `pqz-core/pqzl/sz/` (`README.md`, `sz_trace.c`, `build.sh`); regression `pqz-core/pqzl/check_tbox_fixes.sh`,
  `pqz-core/pqzl/sv/check_sv_fixes.sh`.
- Runs: `pqz-core/research/pqzl-measure/runs/v2-*`, `v2full-*` (incl. `v2full-sz-trace.txt`).
- Rerun: `cd pqz-core && ../scripts/capped sh -c './build.sh native && ./check_tbox_fixes.sh'`.

## 8. lazer#28: prover messages absorbed after the challenges that check them (P6-FS, v3)

Added 2026-10-19 (plan `docs/superpowers/plans/2026-10-19-pqzl-fs3.md`, Task 8). Found by the whole-code review of
2026-10-19 (`pqz-core/research/code-review-2026-10-19/`, findings C-F1 and D-1), filed upstream as
[lazer-crypto/lazer#28](https://github.com/lazer-crypto/lazer/issues/28). Fixed under `proofSystemId` v3: C `6d83208`
(review fix `2789314`), Rust `420f409`; binding tests `c5b2c99` / `c0bd890`. Unlike §1–§7 this is not a challenge
that is too weak but one that comes too early.

### 8.1 What was not absorbed

In a Fiat–Shamir proof each challenge is a hash of everything the prover has sent before it. LaZer's `tbox` derives
two challenges from a hash that does not yet contain the message the challenge checks [code]:

| Prover message | Challenge that checks it | v2 (LaZer `3330e48`, upstream `b958e24`) | v3 |
|---|---|---|---|
| `z3`, `z4` (approximate-range responses, `z = y + β·R·s`, 256 Z_q coefficients each) | V3, V4: λ × 256 matrices that fold the 256 equations of each into λ = 4 | from `hash0 = cseed`, the hash of `ty3 ‖ ty4 ‖ tbeta`, fixed before `z3` / `z4` exist; `z3` / `z4` are never absorbed, not in the tg round and not in the final round | from `hz = SHAKE128(cseed ‖ grandom3(z3) ‖ grandom3(z4))` |
| `h` (the evaluation step's garbage polynomials, `h_i = g_i + ` the accumulated evaluation `i`) | `μ`, which folds all quadratic relations into one, and the final challenge `c` | `μ` (`lnp-quad-many.c`) and `c = H(hash ‖ t ‖ v ‖ w1)` (`lnp-quad.c`) from `hash1 = H(… ‖ tg)`, which `h` does not enter | from `hash2 = SHAKE128(hash1 ‖ urandom3(h))` |

Upstream sites [code]: `lnp-tbox.c`
[L441–L444](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L441-L444),
[L673–L708](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L673-L708),
[L748](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L748);
`lnp-quad-many.c`
[L34](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-quad-many.c#L34);
`lnp-quad.c`
[L458–L472](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-quad.c#L458-L472).
The fork had the same order in all four implementations (C generic `lazer/lnp-tbox.c`, C specialised `src/pqz_sv.c`,
Rust `rust/src/proof/tbox.rs`, Rust `rust/src/sv.rs`) and in both provers; the P6-SZ, P6-L2 and P6-Z21 fixes do not
touch these rounds. It also contradicts the spec's own rule that each prover message is absorbed
(pq-zero-knowledge.md §5, "Transcripts") [code].

### 8.2 Why it breaks soundness

A Schwartz–Zippel check (a random linear combination of equations) is sound because the prover fixes the values
before the random coefficients exist: a nonzero error survives a uniform row of Z_q coefficients except with
probability 1/q. The Fiat–Shamir transform keeps that order only if the challenge is hashed from a transcript that
already contains the values. When the message enters after the challenge, or never, the prover computes the challenge
first and then chooses the message as a function of it; the probability argument does not apply, and what remains
for the prover is a linear system it can solve, not a guess [inference].

- **`z3`, `z4` before V3, V4.** In LNP22's approximate range proof (the Johnson–Lindenstrauss projection) the prover
  commits to `y` and `β`, receives `R`, sends `z = y + β·R·s`, and the verifier checks that `z` is short and that it
  is consistent with the commitments. The `tbox` checks consistency only through the λ = 4 rows of V. With V known
  first, a prover has to match the honest `z` on those 4 combinations, not on all 256 coordinates, and 4 linear
  conditions mod q leave room for a short `z` even when the committed `s3` / `s4` is far out of range. The
  approximate bound on `s3` is what lets the exact-ℓ2 proofs conclude `‖e‖² + ‖υ‖² = B²` over Z rather than only
  mod q, so without it the per-block noise bounds of the encryption relations (pq-zero-knowledge.md §4.3) are no
  longer enforced (review D-1) [inference].
- **`h` before `μ`.** LNP22 (§4.4, Fig. 8; aggregation of relations with vanishing constant coefficient) has the
  prover send `h` and then receive `μ`. The verifier's only direct check on `h` is that two coefficients are zero.
  With `μ` known first, the one combined quadratic relation that ties the witness to the statement can be satisfied
  through `h`, so it constrains nothing that sits inside it: the linear rows of every relation, the encryption and
  balance rows, the binary, range, υ and exact-ℓ2 equations. Every PQZL statement form is affected (review C-F1)
  [inference].

Review C estimates the second gap alone as a forgery of any PQZL statement for about one proof's work. No forging
tool was written: the owner replaced the earlier "cheating-prover proof of concept first" with binding tests that only
observe which bytes seed which challenge (§8.4). Severity: P0, against the ≈ 2^-84 of §3 [inference].

### 8.3 The fix

Two rounds, the same pattern as LaZer's other rounds (`hash ← SHAKE128(hash ‖ coder encoding)`), in the prover, the
generic verifier and the specialised verifier, C and Rust (`PQZ (P6-FS, lazer#28)` comments) [code]:

1. **hz.** After `_lnp_tbox_compute_z34` (prover) and after a successful `_lnp_tbox_check_z34` (verifier, so the norm
   checks run first): `hz = SHAKE128(cseed ‖ enc)`, `enc` one coder session of `coder_enc_grandom3 (z3, log2stdev3)`
   and `coder_enc_grandom3 (z4, log2stdev4)` over centred copies (`fromcrt`, `mod`, `redc`), the proof's own encoding
   (`pqz_rel.c` `encproof`). V3 / V4 and the tg round chain from `hz`.
2. **hash2.** Right before `lnp_quad_many_prove` / `_verify`: `hash2 = SHAKE128(hash1 ‖ urandom3(h mod q ∈ [0, q),
   q, 42))`, h's proof encoding, on a copy reduced with `redp`. `μ` and `c` take `hash2` with no edit to the quad
   files; the specialised verifiers draw `μ` from `PRG(hash2)` and run the final round over `hash2`. The γ challenges
   stay on `hash1`: `h` is computed from them, so they must come before it.

**Why R and R' must stay on `cseed`.** `R` / `R'` are the JL challenge of the range proof and V is the check of its
response; LNP22 orders them commitment (`ty`, `tbeta`) → `R` → `z` → V. The prover builds `z3 = y3 + β3·R·s3` from
`R`, so `R` cannot depend on `hz` (it would depend on `z3`, which depends on `R`), and it must still follow the
commitment, which `cseed` does. Upstream drew V and the rows of `R` / `R'` from one seed in
`__schwartz_zippel_accumulate_z3` / `_z4`; v3 gives those functions two seeds, V's (`hz`) and `rseed` (`cseed`), and
the specialised verifiers fold the JL rows on `cseed` and V3 / V4 on `hz`. That split was the one deviation from the
plan's "no further edits" (decision F1) [code].

**Encoding and buffers.** Absorbing the proof encoding makes the round injective (the grandom decoding is bijective,
with one pad bit) and needs no labels: `h`'s length is fixed per relation and the z encoding is self-delimiting.
LaZer's coder writes without bounds checks, so the generic code sizes its buffer exactly (`coder_grandom3_nbits`,
moved from `pqz_rel.c` to `lazer/coder.c`), the C specialised verifier sizes its transcript buffer from `proof_len`
(z3 ‖ z4 is a bit range of the proof, and the buffer exists before the norm checks), and Rust grows a `Vec` with
`try_reserve` [code].

**Transcript change.** v2 and v3 proofs do not verify against each other; the proof layout, the parameters and the
relations are unchanged. PQZL `proofSystemId` v3 = `keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v3")` =
`0x8079d65b…16baef` (pq-zero-knowledge.md §8, CTR-PQZ-09; decisions.md CTR-PQZ-09, F1–F10). The same bump carries two
prover-side zero-knowledge fixes from review D (D-2, the z2 rejection; D-3, the β sign bits), implemented in the
plan's Task 4 (`c57381b`); they change honest proofs and no verifier rule, and their figures are in
pq-zero-knowledge.md §8 ("Prover-side zero-knowledge fixes") and decisions.md F7 / F8.

### 8.4 Evidence

- **Binding test** `pqz-core/pqzl/sz/fs_bind.c`, the fourth check of `check_tbox_fixes.sh` (`sz/README.md`), and
  `pqz-core/pqzl/rust/tests/fs_bind.rs`: one honest `R_REG` proof and three re-encodings with `h`, `z3` or `z4`
  changed by one coefficient; in `verify` and `verify_fast` the V3 / V4 seeds must differ for the z3 and z4 changes and
  the `μ` seed for the h change (12 checks; a missing seed record fails). Before the fix 10 of 12 fail in both cores,
  every checked seed equal to the honest one (`pqz-core/pqzl/runs/fs1-before.txt`, `fs1-review-fix.txt`,
  `pqz-core/pqzl/rust/runs/fs1-test.txt`); after it 0 of 12 (`pqz-core/pqzl/runs/fs2-tbox.txt`,
  `pqz-core/pqzl/rust/runs/fs3-test.txt`) [measured].
- **Specialised = generic**: `sv/check_sv_fixes.sh` ok; `sv/diff.sh fs2` 4,328 + 2,158 cases, 0 mismatches
  (`pqz-core/pqzl/runs/fs2-sv-*`) [measured].
- **Honest proofs** (`relfix.sh fs2`, `pqz-core/research/pqzl-measure/runs/fs2-*`): `fails 0` native, wasm32 and
  ASan + UBSan, KAT 19/19, native = wasm32; every `proofs_fnv` changed (`R_REG` `8bd69f2d` → `b76964d5`, bench
  `5 5 63`) [measured].
- **C = Rust**: the Rust bench gives the same `proofs_fnv`, and `oracle_prove` the same proof bytes on all 14 relation
  codes (`41c708b`) [measured].

These are the Task 2 / 3 values. The final v3 code (Tasks 4–5, with D-2 / D-3) was checked again [measured]:

- `relfix.sh fs4` (`pqz-core/research/pqzl-measure/runs/fs4-*`): `check_tbox_fixes` ok with P6-FS 0 failed checks of
  12, KAT 19/19, `fails 0` native, wasm32 and ASan + UBSan, native = wasm32; final `proofs_fnv` (bench `5 5 63`)
  `R_REG` `b935013d`, the six forms and the eight op 7 shapes in `pqz-core/STATUS.md` (section "PQZL v3");
- Rust (`pqz-core/pqzl/rust/runs/fs5-*`): `fs_bind` 0 of 12, every bench `proofs_fnv` = the C core's, native =
  wasm32 on 387 vector digest lines, `oracle_prove` Rust = C on all 14 relation codes against the v3 vectors;
- the vectors regenerated under v3 (`8af584b`, `pqz-core/ffi/vectors/runs/fs5-*`): `pqz-vectors --check`
  byte-identical on both backends, 16 negative rows for the retired v2 id, the self-test hash unchanged.

The gate before the merge (plan Tasks 9, 12) and the reviews A / B (Tasks 10, 11) follow.

### 8.5 Impact on PQZ

- **Deployed:** v2 runs on chain 7622 (image `pqz2`), a test chain; every SCaaS chain is test-only. v2 proofs are
  forgeable, so v2 is retired: removed from the accepted set and from `pqz-stmt`, and 7622 is reset from genesis at
  the v3 roll-out (owner 2026-10-19, path B), with the PQZ tokens and `UAPqzVerifier`, which hold the id immutably,
  redeployed. v1 had the same gap and is already retired [code].
- **Parameters, sizes, noise budget:** unchanged. With both rounds in place the extractor argument of LNP22 applies
  again to `z3` / `z4` and to the quadratic relations, and the numbers of §3 and of pq-zero-knowledge.md §4.3 hold
  for v3 [inference]; review B (the plan's Task 11) audits every prover message against LNP22's order.
- **Files:** fix `pqz-core/pqzl/lazer/lnp-tbox.c` (`_lnp_tbox_hash_z34`, `_lnp_tbox_hash_h`), `lazer/coder.c`
  (`coder_grandom3_nbits`), `pqz-core/pqzl/src/pqz_sv.c`, `pqz-core/pqzl/rust/src/proof/tbox.rs` (`hash_z34`,
  `hash_h`), `rust/src/sv.rs`; tests `pqz-core/pqzl/sz/fs_bind.c`, `rust/tests/fs_bind.rs`; runs `pqz-core/pqzl/runs/fs*`,
  `pqz-core/pqzl/rust/runs/fs*`, `pqz-core/research/pqzl-measure/runs/fs2-*`, `fs4-*`, `pqz-core/ffi/vectors/runs/fs5-*`.

### 8.6 B-1: V3 / V4 after `tg`; A-2: distinct υ domain (5h Task 8a)

Added 2026-10-21 (plan `docs/superpowers/plans/2026-10-20-pqz-state-redesign.md` Task 8, sub-task 8a). Review B
(`pqz-core/research/code-review-2026-10-19/X-review-b-transcript.md`, B-1, P0) and review A (`W-review-a-pqzl-rust.md`,
A-1 = B-1 confirmed by a cheating prover; A-2, P3). v3 closed "z after V" but not "g after V": V3 / V4 came from `hz`,
before the round over `tg`, the commitment to the masking polynomial g whose coefficients 0 and d/2 nobody checks. A
prover that knows V before committing g sets those two coefficients to minus the V-folded error of a false `z3` /
`z4`, so `h_i = g_i + acc_i(s)` still has zero coefficients 0 and d/2 and every other check holds [code; measured
below]. In LNP22's vanishing-constant-coefficient argument g is committed before the aggregation challenge; V is
that challenge for the JL rows.

| Prover message | Challenge combined with it | v3 | since 8a |
|---|---|---|---|
| `tg` (commitment to g) | V3, V4 | from `hz`, fixed before `tg` | from `hash1 = SHAKE128(hz ‖ urandom3(tg))`, as γ |

**Fix** [code]: V3 / V4 from `hash1` with the same row construction (`dom << 32 | 256 i`, disjoint from every γ
draw, dom < 2^32) in `lnp-tbox.c` (prover and verifier), `pqz_sv.c`, `proof/tbox.rs` (`accumulate_all` lost its
`hash0` seed) and `sv.rs`. **A-2** in the same change: the last β4 row (`M + d − 1 + (d − 1)`) and υ (`M + 2(d − 1)`)
shared a domain, so the accumulators enforced only their sum (not exploitable, review A); υ, binary, exact ℓ2, V4 and
V3 each move up by one (`M + 2(d − 1) + 1`, `+ 2`, `+ 3 + i`, `+ 3 + Z`, `+ 3 + Z + 256`). Transcript change, folded
into the 16k `proofSystemId` bump (plan D23, Task 8d); this step keeps today's parameters so the vector diff isolates
it.

**Evidence** [measured]:
- review A's cheating prover, now `pqz-core/pqzl/rust/tests/cheat_b1.rs` (test hook `set_cheat`, feature
  `test-hooks`; modes 1: `z4[0][0] + 1`, 2: `z3 = y3`, both cancelled through g with V guessed from `hz`; 3: the
  uncancelled control): before the fix modes 1 and 2 were **accepted by all four verifiers** (Rust `verify` /
  `verify_fast`, C `pqz_verify` / `pqz_verify_fast`) on all 14 relation codes, 28 forgeries
  (`pqz-core/pqzl/rust/runs/t8a-red-test.txt`; review A had not run the C verifiers); after it every mode is rejected
  by all four on all codes, mode 0 = the vectors (gate `t8a`, step rust);
- the binding tests with a `tg` mutation (test_mutate kind 15): before the fix the V4 / V3 seeds equalled the honest
  ones in both verifiers of both cores (4 failed checks of 18; `pqz-core/pqzl/runs/t8a-red-fsbind-c.txt`,
  `pqz-core/pqzl/rust/runs/t8a-red-fsbind.txt`), after it 0 of 18 (`t8a-green-fsbind*.txt`);
- A-2: `sv/review/review.sh dom` (a fifth check of `check_tbox_fixes.sh`) finds 0 shared domains in 129 calls.

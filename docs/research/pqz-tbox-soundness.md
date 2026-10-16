> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# LaZer `tbox`: one Schwartz–Zippel challenge pair for all λ/2 evaluation accumulators (lazer#24, P6-SZ)

Written 2026-10-13 (TODO P6-SZ). Finding, fix and evidence for the first of two Schwartz–Zippel findings in LaZer's
`tbox` that came out of the PQZL verifier work. The second (exact-ℓ2 equations sharing one domain) is
`pqz-l2-domain.md`. Upstream issue: [lazer-crypto/lazer#24](https://github.com/lazer-crypto/lazer/issues/24),
confirmed by the LaZer maintainers. Fixed in `pqz-core` under `proofSystemId` v2 (fix `f1bae83`, merged with the
second fix in `5361946`; version bump and regression check merged in `98695de`). **No decision is recorded here.**

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
| LaZer `3330e48` (vendored pristine in `c91b3ab`, `pqz-core/lazer/`) and upstream head `b958e24` (the file is unchanged between them) | `__schwartz_zippel_accumulate2`, `src/lnp-tbox.c` | [2333–2366](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L2333-L2366); `INTVEC_T (V, 2 * M, …)` at 2347 |
| `pqz-core` v2 | the same function, fixed | `pqz-core/lazer/lnp-tbox.c` 2375–2416 (`PQZ (P6-SZ)` comment at 2389) |
| `pqz-core` specialised verifier | `sz_eval_challenges` | `pqz-core/src/pqz_sv.c` (follows the fix, `pqz-specialised-verifier.md` §0) |

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

Draw the full λ × M matrix from the same `(seed, dom)` and index two rows per pair (`pqz-core/lazer/lnp-tbox.c`,
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

- **Trace harness** `pqz-core/sz/` (`sz/README.md`): one honest `R_REG` prove with the `-DPQZ_SZ_TRACE` hook in
  `lnp-tbox.c` (compiled only with that macro; production builds do not define it), which records the Z_q challenge
  vector given to each of the four accumulator slots per transcript domain [measured]:
  - unfixed: in **all 127** evaluation domains slot 0 = slot 2 (`subv1` reused) and slot 1 = slot 3 (`subv2` reused),
    slot 0 ≠ slot 1: 2 distinct rows, verdict "2 independent tests";
  - fixed (v2): 128 domains (the two exact-ℓ2 equations now have one each, `pqz-l2-domain.md`), **0** reuse, all
    four rows distinct, verdict "4 → ok". Output of the v2 full-sample run: `pqz-core/rel3/runs/v2full-sz-trace.txt`.
- **Regression check** `pqz-core/check_tbox_fixes.sh` (run by `rel3/relfix.sh`): exits 1 unless the trace reports
  λ = 4 independent tests **and** the ℓ2 check of `pqz-l2-domain.md` passes; with this fix reverted it reports 2
  tests and fails (`pqz-core/STATUS.md`). Last results `pqz-core/rel3/runs/v2-tbox-fixes.txt`,
  `v2full-tbox-fixes.txt`: `check_tbox_fixes: ok` [measured].
- **Specialised verifier**: `pqz-core/sv/check_sv_fixes.sh` reverts this line in a copy of `pqz_sv.c`; every honest v2
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

- Fix: `pqz-core/lazer/lnp-tbox.c` (`PQZ (P6-SZ)`), `pqz-core/src/pqz_sv.c` (`sz_eval_challenges`).
- Harness: `pqz-core/sz/` (`README.md`, `sz_trace.c`, `build.sh`); regression `pqz-core/check_tbox_fixes.sh`,
  `pqz-core/sv/check_sv_fixes.sh`.
- Runs: `pqz-core/rel3/runs/v2-*`, `v2full-*` (incl. `v2full-sz-trace.txt`).
- Rerun: `cd pqz-core && ../scripts/capped sh -c './build.sh native && ./check_tbox_fixes.sh'`.

> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# LaZer `tbox`: all exact-ℓ2 equations share one Schwartz–Zippel domain, so only the sum of block norms is checked (lazer#25, P6-L2)

Written 2026-10-13 (TODO P6-SZ). Finding, proof of concept, impact on PQZ and fix for the second of two
Schwartz–Zippel findings in LaZer's `tbox`; the first (one challenge pair for all λ/2 accumulators) is
`pqz-tbox-soundness.md`. The two are independent: this one is present with and without the first fix. Upstream issue:
[lazer-crypto/lazer#25](https://github.com/lazer-crypto/lazer/issues/25), confirmed by the LaZer maintainers. Fixed in
`pqz-core` under `proofSystemId` v2 (fix `633c3f3`, merged in `5361946`; version bump, PoC harness and regression
check merged in `98695de`). **No decision is recorded here.**

Why a separate note: the first finding weakens a probability (q^-4 → q^-2) and has no effect on PQZ's numbers beyond
the knowledge error; this one removes a statement outright (with probability 1) and breaks the per-block premise of
the PQZ noise budget, so it has its own PoC and impact analysis.

**[measured]** marks a number from a run (pointed to). **[code]** marks a statement read in the source at the given
lines. **[estimate]** marks a number computed from counts or bounds. **[inference]** marks a conclusion drawn here.

## 1. Summary

- `__schwartz_zippel_accumulate_l2` gives every one of the Z exact-ℓ2 equations the same `(seed, dom)`, so all of them
  get identical challenges in prover and verifier. The verifier checks only their **sum**,
  Σ_i (‖x_i‖² + ⟨pow2, υ_i⟩ − B_i²) = 0 [code].
- Because each term can be negative, that proves Σ_i ‖x_i‖² ≤ Σ_i B_i², not ‖x_i‖ ≤ B_i per block. Any one block can
  carry the whole budget. Nothing else in the proof bounds the blocks tightly [inference].
- PoC: a prover that pools the slack got over-bound `R_REG` and `R_TX` proofs accepted by the unmodified production
  verifier; with the fix the same proofs are rejected and honest proofs verify [measured].
- PQZ before the fix (v1): the §4.3 noise budget (pq-zero-knowledge.md) did not hold for accounts whose keys the attacker
  controls; the minting margin of threat T5 shrank from 4.1× to ≈ 1.12×. No theft and no mint at the current
  parameters; honest accounts unaffected [estimate]. Nothing was deployed.
- Fix: `dom + i` for equation i. With it, every exact-ℓ2 bound is checked on its own and the documented margins
  stand.

## 2. Where

LaZer `3330e48` (vendored pristine in `c91b3ab`) and upstream head `b958e24` have the same `src/lnp-tbox.c`; line
numbers are the same in both [code]:

| What | `b958e24` / `3330e48` | `pqz-core` v2 (`pqz-core/lazer/lnp-tbox.c`) |
|---|---|---|
| `__schwartz_zippel_accumulate_l2` | [2770](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L2770) | 2896 |
| loop `for (i = 0; i < Z; i++)` | [2823](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L2823) | — |
| inner call `__schwartz_zippel_accumulate2 (…, seed, dom, …)`, same `dom` for every i | [2990–2992](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L2990-L2992) | 3132–3141, `dom + i` (`PQZ (P6-L2)`) |
| prover / verifier caller, `dom = M + 2(d − 1) + 2` | [634](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L634) / [1211](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L1211) | 668 / 1246 |
| z4 domain `M + 2(d − 1) + 2 + Z` (Z domains reserved for ℓ2) | [647](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L647) / [1223](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L1223) | 678 / 1255 |

Domain layout of one proof under the seed `hash` [code]:

| Equations | Domain |
|---|---|
| M input evaluation equations | 0 |
| β3 coefficients i = 1 … d − 1 | M + i |
| β4 coefficients i = 1 … d − 1 | M + d − 1 + i (up to M + 2d − 2) |
| υ binary | M + 2(d − 1) |
| binary witness | M + 2(d − 1) + 1 |
| exact ℓ2, equation i < Z | **M + 2(d − 1) + 2 for every i** (v1); M + 2(d − 1) + 2 + i (v2) |
| z4, z3 (JL) | from M + 2(d − 1) + 2 + Z, under `hash0` |

With d = 64: `R_REG` (M = 0, Z = 2) has both ℓ2 equations at domain 128, `R_TX` (M = 80, Z = 7) all seven at 208.
That the z4 domain starts at the ℓ2 base + Z, and that β3 / β4 use `dom + i`, shows distinct domains were intended
[inference].

## 3. What is enforced

Equation i states ‖x_i‖² + u_i ≡ B_i² (mod q), with u_i = ⟨(2^0, …, 2^{b_i − 1}), υ_i⟩, υ_i binary and
b_i = bitlen(B_i²). With shared challenges the verifier learns only the sum over i. The other constraints do not
recover the per-block statement [inference]:

- **υ binary** (own domain): Σ υ(υ − 1) = 0. Sound as one sum because every term is ≥ 0 over the integers. Gives
  u_i ∈ [0, 2^{b_i}), but says nothing about which block the norm sits in.
- **JL approximate range (z3)** on the whole witness: its job is to rule out wrap-around mod q; its bound is several
  hundred times looser than the block bounds.
- **z4 filler**: an approximate bound on one polynomial (`R_REG` s[0], `R_TX` e2_t), loose.
- **No ℓ∞** on the ℓ2 blocks, and the relation rows are linear, so they fix no norms.
- Rejection sampling and the MSIS estimate use only the total α = √(Σ B_i²), so a pooled witness proves at the same
  rate as an honest one.

So the guarantee is Σ_i ‖x_i‖² ≤ Σ_i B_i² (plus the loose JL bound). Binary and υ terms are sign-definite and can be
batched; ℓ2 terms are not [inference].

| Relation (bounds) | Σ B_i² | one block may reach | vs its own bound |
|---|---|---|---|
| `R_REG` (s 36, e 164) | 28,192 | 167.9 | s 4.66×, e 1.02× |
| `R_TX` (s_f 36, e_f 164, r 36, e1 164, e2_t / e2_f / e2_a 64) | 68,672 | 262.1 | s_f, r 7.3×; e_f, e1 1.6×; e2_* 4.1× |

`R_BURN` (36, 164, 36, 164, 64), `R_DS` (36, 164, 64) and `R_DR` (36, 164) go through the same function and had
the same gap in v1 [code].

## 4. Proof of concept

Harness `pqz-core/l2dom/` (`pqz-core/sz/README.md`): under `-DPQZ_L2DOM_POC` (never defined by `./build.sh`),
`set_upsilon` in `pqz-core/src/pqz_rel.c` pools the slack Σ_z (B_z² − ‖x_z‖²) of all blocks and spreads it greedily
over the υ_z, and the PoC emits the proof even when the prover's own self-checks fail. `l2dom/build.sh` builds it
twice: on a copy of `lnp-tbox.c` with the fix undone (control) and on the tree; the proofs are verified in-process and
again by a separate binary linked against the production `build/native/libpqz.a` (`pqz_verify`). The honest prover
refuses every over-bound witness (rc 3), so this is a verifier-side gap only. Output of the v2 full-sample run:
`pqz-core/rel3/runs/v2full-l2dom.txt` [measured]:

| Case | Witness (‖·‖² against its own B²) | v1 verifier (fix undone) | v2 verifier (production lib) |
|---|---|---|---|
| `R_REG` `honest` | honest key, slack pooled into υ (2,012 ≤ 28,192) | ACCEPT | REJECT (block 0's own equation is off) |
| `R_REG` `s_over_A` | ‖s‖² 17,889 (B² 1,296, ‖s‖ 133.7), ‖e‖² 991; sum 18,880 | **ACCEPT** | REJECT |
| `R_REG` `s_over_B` | ‖s‖² 28,192 (‖s‖ 167.9 = 4.7× its bound), e = 0 | **ACCEPT** | REJECT |
| `R_TX` `tx_over` | ‖r‖² 59,933 (‖r‖ 244.8 = 6.8× its bound 36), ‖e1‖² 4,144, ‖s_f‖² + ‖e_f‖² 2,042; sum 66,119 ≤ 68,672 | **ACCEPT** | REJECT |

The three `R_REG` cases were also accepted on the code before the first fix (`0d596ba`), so the gap does not depend on
it [measured]. Proof sizes are those of honest proofs (28,071–28,085 B `R_REG`, 42,748 B `R_TX`).

`tx_over` is the case that matters for PQZ: the sender aligns `(r, e1)` with a colluding recipient's key. The
recipient's decryption noise on coefficient 0 is **36,861 = 3.10 × B_FRESH** (pq-zero-knowledge.md §4.3 worst case 11,872);
over 1,023 credits that is 37.7 M, above the 2^24 = 16.78 M debit range and Δ/2 = 33.55 M [measured, ×1,023 an
estimate].

## 5. Impact on PQZ before the fix (v1)

The PQZ noise budget (pq-zero-knowledge.md §4.3) is a worst case over **per-block** norms: registration proves ‖s‖ ≤ 36,
‖e‖ ≤ 164, every encryption ‖r‖ ≤ 36, ‖e1‖ ≤ 164, ‖e2‖ ≤ 64, which gives
B_FRESH = 164·36 + 36·164 + 64 = 11,872 per credit and ≤ 12.16 M over `K_MAX = 1024` units. In v1 only the sums
were bound [estimate]:

- **Attacker-controlled accounts (a colluding sender and recipient).** Worst-case per-credit noise
  ‖(e_t, s_t, 1)‖ · ‖(r, e1, e2_t)‖ ≤ √(28,192 + 1) · √68,672 ≈ **44,001 = 3.71 × B_FRESH** (measured 36,861 with an
  honest-shaped key). Over 1,023 noisy units (the plain term is noise-free): **≈ 45.0 M**, beyond the debit range
  2^24 and beyond Δ/2. The spec's "an accepted state never fails to decrypt" was false for such accounts: their own
  funds could become undebitable or decrypt wrongly. Self-harm only; a decryption-failure oracle
  ([2024/127](https://eprint.iacr.org/2024/127)) would touch only keys the attacker owns.
- **Minting stayed out of reach.** It needs |e| ≥ Δ − 2^24 ≈ 50.33 M (pq-zero-knowledge.md §4.3, "soundness depends on
  accounting"); 45.0 M is below it. The documented margin of threat T5, 4.1× (50.33 M / 12.16 M), shrank to
  **≈ 1.12×** (50.33 M / 45.0 M). `K_MAX` ≳ 1,145, or about 5.3 M of other unaccounted noise, would have made a mint
  reachable [estimate].
- **Honest victims.** A sender cannot align with a key it does not know. The best coherent strategy against an
  honest key (all budget in one coefficient of r, which multiplies one CBD(20) coefficient of e_t, |·| ≤ 20) gives
  ≤ 262 · 20 per credit, ≤ ≈ 5.4 M over 1,023 credits, inside 2^24: honest accounts still decrypt and debit
  [inference].
- **Registration.** A registered key could have ‖s‖ up to 167.9 (or ‖e‖ up to 167.9). Key uniqueness is unaffected:
  its kernel argument (pq-zero-knowledge.md §4.3) already uses the total 2·√(36² + 164²). The shared-randomness hint count
  (§4.5) is about the number of hints, not key shape, and is unchanged [inference].
- **Proof-system claims.** MSIS and knowledge-error estimates are unchanged; they already use the total α.

Assessment: no theft and no mint at today's parameters, but a documented soundness argument (§4.3, the T5 margin)
rested on per-block bounds the verifier did not enforce, with ≈ 12 % to spare before minting [inference].

**After the fix (v2)** each block's bound is proven on its own, so B_FRESH = 11,872, the 12.16 M cap bound and the
4.1× margin hold as written; no spec number changes. `K_MAX` stays 1024 (owner, 2026-10-13; to be revisited later,
TODO).

## 6. The fix

`lnp-tbox.c::__schwartz_zippel_accumulate_l2`: `seed, dom` → `seed, dom + i` in the inner call (the change suggested
in lazer#25):

```c
      __schwartz_zippel_accumulate2 (R2i, r1i, r0i, R2i2, r1i2, r0i2, R2tptr,
                                     r1tptr, r0tptr, 1, seed, dom + i,
                                     params->quad_eval);
```

Shared by prove and verify. The ℓ2 domains become M + 2(d − 1) + 2 … M + 2(d − 1) + 1 + Z under `hash`: no collision
(β3 / β4 / υ / binary are below; z4 / z3 use `hash0` and start at the reserved M + 2(d − 1) + 2 + Z) [code]. Cost: none
measurable, the number of calls is the same. It changes the transcript; it shipped with the first fix as one
`proofSystemId` bump to v2 (pq-zero-knowledge.md §8; `proofs_fnv` table in `pqz-core/STATUS.md`). The specialised verifier
does the same (`pqz_sv.c`, ℓ2 loop with `dom + i`; `pqz-specialised-verifier.md` §0).

## 7. Regression checks

- `pqz-core/check_tbox_fixes.sh`: for each of the four l2dom cases the control (fix undone) must accept and the
  production library must reject; exits 1 otherwise (and on the `pqz-tbox-soundness.md` trace). With this fix
  reverted, the production verifier accepts the four pooled-slack proofs and the check fails (`pqz-core/STATUS.md`).
  Last runs `pqz-core/rel3/runs/v2-tbox-fixes.txt`, `v2full-tbox-fixes.txt`: 4 / 4 accepted by the control, 4 / 4
  rejected by production, `check_tbox_fixes: ok` [measured].
- `pqz-core/sv/check_sv_fixes.sh`: with the ℓ2 line reverted in a copy of `pqz_sv.c`, every honest v2 proof of the
  five relations disagrees with the generic verifier (10 / 10) [measured].

## 8. Side observation: β4's last coefficient and υ share a domain (harmless)

β4's coefficient equations use M + d − 1 + i for i = 1 … d − 1, so the last one, M + 2(d − 1), is also the υ domain
(b958e24 [607](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L607),
[617](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/src/lnp-tbox.c#L617)).
The verifier learns only E_β4,d−1 + E_υ = 0 there [code]. This is harmless, and the reason is the σ-symmetry of the
β4 polynomial [inference]: it is b = X^{d/2}(σβ − β)/2 with σ: X ↦ X^{-1}; since σ(X^{d/2}) = −X^{d/2} and
σ(σβ − β) = −(σβ − β), σ(b) = b, i.e. b_{d−j} = −b_j. The check for coefficient i = d − 1 is therefore the same
constraint as the check for i = 1, which has its own domain M + d, so E_β4,d−1 = 0 is already forced and the shared
equation reduces to E_υ = 0. (An argument from "β4² = 1 forces β4 = ±1" does not work: X^64 + 1 splits into 4
factors mod q, so R_q has 16 square roots of 1.) The layout looks unintended; changing it would be another transcript
change for no security gain, so v2 leaves it.

## 9. Files

- Fix: `pqz-core/lazer/lnp-tbox.c` (`PQZ (P6-L2)`), `pqz-core/src/pqz_sv.c` (ℓ2 loop).
- PoC: `pqz-core/l2dom/` (`l2dom_poc.c` `R_REG`, `l2dom_tx.c` `R_TX`, `build.sh`), `set_upsilon` in
  `pqz-core/src/pqz_rel.c` under `-DPQZ_L2DOM_POC`; description `pqz-core/sz/README.md`.
- Regression: `pqz-core/check_tbox_fixes.sh`, `pqz-core/sv/check_sv_fixes.sh`.
- Runs: `pqz-core/rel3/runs/v2-*`, `v2full-*` (incl. `v2full-l2dom.txt`).
- Rerun: `cd pqz-core && ../scripts/capped sh -c './build.sh native && ./check_tbox_fixes.sh'`.

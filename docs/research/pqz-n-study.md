> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZ with a smaller ring dimension n (plan 5h Task 7c, 2026-10-21)

Owner 2026-10-21: "Cân nhắc theo hướng giảm n. Tìm hiểu xem." (consider reducing n; find out). Research only: the
approved 16k set (n = 2560, k = 40, q = 2^50 − 42,310,535, `K_MAX` 16,384) is unchanged. Full tables, logs, scripts
and reruns: [`pqz-core/pqzl/params/n-study/results-n-study.md`](../../pqz-core/pqzl/params/n-study/results-n-study.md).
Tags: [measured] = pinned tools (lattice-estimator 53da598, leaky-LWE-Estimator 0a9caf8, LaZer 3330e48, Sage 10.7);
[estimate] = a model on measured numbers; [inference] = a conclusion drawn here.

## What was done

- Grid n ∈ {2048, 2176, 2304, 2432, 2560} × `K_MAX` ∈ {1,024, 4,096, 8,192, 16,384}: the spec §6.1 budget, the smallest
  admissible prime per cell (q ≡ 9 mod 16, 2^3·19·43·431 | q − 1, mint margin ≥ 3.08× — the lowest the owner accepted,
  O3 — and, as a variant, the bare budget with margin 1.12–1.38×), encryption uSVP and DDGR20 worst-case hints at
  0 / 32 / 80 for all 41 rows [measured].
- For the six cells at the 450 boundary: LaZer proof ranks (MSIS, hiding MLWE uSVP and dual_hybrid ≥ 450, both models)
  and codegen proof sizes for reg, tx, tx0, burn, ds, dr, txm2 / txm4 with and without the auditor; full
  `LWE.estimate` and dual_hybrid on the 80-hint instance; the e_s0 gate (budget, exactness, Fiat–Shamir) [measured].
- Sizes from the pqz-stmt layout; gas from Task 7's (old rules) and Task 7b's (Amsterdam) measured slopes scaled by
  the `acc` word count [estimate].

## Findings

1. **`K_MAX` is the lever [measured].** q ≈ 2^(m + log2 E + 4) with m and E both growing one bit per doubling of
   `K_MAX`, so each doubling costs ≈ 2 bits of q and ≈ 24–31 β at 80 hints; −128 in n costs ≈ 32–40 β.
2. **At `K_MAX` 16,384 only n = 2432 (−5 %) stays ≥ 450 by DDGR20 (450.5) and it fails the dual_hybrid view (442.5)
   [measured / estimate].** Smaller n at the approved cap needs an exception (n = 2304: 417.6).
3. **Clean smaller sets (both models ≥ 450 at 80 hints):** n = 2432 / `K_MAX` 8,192 (476.4 / 466.4, −5 %) and
   **n = 2304 / `K_MAX` 4,096 (468.5 / 458.5, −10 %)**. n = 2304 / 8,192 (441.9) and n = 2176 / 4,096 (432.6) need new
   exceptions below the 446.0 precedent; n = 2048 / 1,024 (today's n and cap at q ≈ 2^41.69) passes DDGR20 by 0.5
   only.
4. **Proofs shrink much less than keys [measured]:** the hiding rank falls with q (39 → 36 at `K_MAX` 4,096) but
   `kmsis` rises, so R_TX goes 52,624 → 48,724 B (−7 %) at n = 2304 while keys, ciphertexts, statements and op blobs
   fall 9.9 %.
5. **Under Amsterdam a smaller n pays more than before [estimate]:** the rollover's fixed `acc` rewrite (EIP-8038,
   12,100 per word) and every SSTORE2 state-gas item (EIP-8037, 1,530 / byte) scale with n: n = 2304 gives `ROLL_MAX`
   96 instead of 80, ≈ 3.1 M less state gas per debit, and with `K_MAX` 4,096 a full `acc` needs 43 rollovers instead
   of 205.
6. **The margin is worth ≈ 10 β [measured]:** the bare-budget prime (margin 1.2–1.4×) adds +8 to +14 β; not
   recommended (today's design kept 4×; the v1 ℓ2 bug once took the margin to 1.12×).
7. **Tool pitfall [measured]:** LaZer's codegen loops forever when `log2q` rounds q up by ≈ 0.2 bit (q = 2^47.80 with
   `log2q` 48); the study rounds `log2q` down (conservative, +0.3 % proof).

## Recommendation [inference; the owner decides]

If a refresh interval of 4,096 credits is acceptable, **n = 2304, `K_MAX` 4,096, q = 61,275,424,977,257 ≈ 2^45.80**:
−10 % keys / ciphertexts / state, no security exception in either model, `ROLL_MAX` 96 (Amsterdam), 43 rollovers per
full `acc`. Otherwise keep the approved 16k set: n = 2432 at 16,384 saves only 5 % at 0.5 β of DDGR20 headroom and
fails the dual_hybrid view. Not recommended: any set needing a new exception below 446 (n = 2304 / 8,192, n = 2176 /
4,096), n = 2048 / 1,024, and the low-margin primes.

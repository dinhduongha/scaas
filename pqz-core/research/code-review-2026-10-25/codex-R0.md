Reviewed commit `008e196c` by static reading only. **Two findings: one P1 confidentiality break and one P3 soundness-gate defect.** No new P0 established.

## Findings

### R0-1 — P1 — Shared randomness exposes differences between auditor-encrypted amounts

**Locations**

- `docs/research/pqz-anonymity.md:275–297`
- `pqz-core/pqzl/src/pqz_rel.c:773–784`
- [PQZL Rust relation builder:538–544](pqz-core/pqzl/rust/src/rel.rs:538)
- `pqz-core/pqzh/ligero/src/cs.rs:398–405`

**Claim.** Any observer can recover the exact per-digit amount differences between auditor copies belonging to the same randomness group. This breaks amount confidentiality and receiver anonymity for ordinary audited multi-recipient payments, across all four parameter sets.

**Evidence.** The specified relation is:

```text
v_a,j[i] = (pk_aᵀ r_g)[i] + e2_a,j[i] + Δ d_j,i
```

The current builders use the same auditor key and `r_(j/4)` for every auditor copy in a group. For two legs `j,k` in that group:

```text
center_q(v_a,j[i] − v_a,k[i])
    = Δ(d_j,i − d_k,i) + e2_a,j[i] − e2_a,k[i].
```

Each current `e2` block has norm at most 64, so the residual has absolute value at most 128. The smallest set’s Δ is already `67,108,863`. Digits lie in `[0,15]`, so the difference does not wrap around the centered modulus. Consequently:

```text
round(center_q(v_a,j[i] − v_a,k[i]) / Δ) = d_j,i − d_k,i
```

This requires neither the auditor secret nor a lattice attack.

A concrete distinguishing input is an audited `M=2` payment with amounts `(1,0)`, compared with `(0,1)`. Both spend the same total, but the first auditor-coordinate difference rounds to `+1` versus `−1`. An observer identifies the real recipient. If one leg’s amount is known, every other amount in its group is recovered exactly.

The DDGR20 discussion counts repeated auditor forms as only 16 hints; that accounting does not address this direct cancellation. Increasing lattice dimensions or generating independent `e2` values does not remove it. I found no corresponding fixed finding in the prior-review directory.

**Suggested fix.** Give auditor copies independent encryption randomness and corresponding `u` components, with the relation still proving equality to each recipient amount. Audit every output pair for reuse of the same key/randomness with different plaintexts. Update both proof systems, disclosure layouts, parameters and identifiers. Pending that change, disable audited transfers containing multiple legs per group.

### R0-2 — P3 — E-S0 certifies a calculated repetition count instead of the generated one

**Locations**

- [E-S0 checker:68–79,130–138](pqz-core/params/sets/e_s0_set.py:68)
- `pqz-core/params/sets/n2304-kmax4096/e-s0.txt:47–64`
- `pqz-core/params/sets/n2304-kmax4096/pqz_reg_params.h:123`

**Claim.** The per-round soundness gate does not check the actual Schwartz–Zippel repetition count.

**Evidence.** The header reader extracts dimensions, widths, challenge parameters and the commented knowledge-error claim, but no λ. The gate then uses:

```python
LAM = math.ceil(128 / log2(q))
```

It checks `LAM * log2(q) >= 128`, which succeeds by construction.

There is already a visible discrepancy: the default set’s E-S0 record reports **λ=3**, while its generated parameter initializer and E-S1 record specify **λ=4**. The same discrepancy occurs at n2560 and n2816.

The current λ=4 is sufficient; this is an assurance defect, not a current forgery. However, a generated λ=2 would leave this gate’s calculation unchanged, despite giving approximately 91.6-bit amortization soundness at the default modulus.

**Suggested fix.** Read λ from each generated parameter structure, validate its required layout constraints, and calculate the soundness bound from that value. Regenerate the E-S0 records.

## Checked and sound

These conclusions concern the reviewed equations and committed parameter evidence. Qualifications identify invariants that cannot receive an unconditional sign-off.

| Invariant | Evidence and result |
|---|---|
| **R_REG ownership** | `rel.rs:335–349` enforces `pk=A·s+e` with separate secret/error norm blocks. |
| **R_REG bound to UA** | `stmt/src/lib.rs:362–365` defines the bound message; `UARegistry.sol:420–424` supplies it, and `UAKinds.sol:218–223` includes chain, registry, UA and key hash. The whole statement enters the proof transcript. |
| **R_DS / R_DR** | `rel.rs:602–647` respectively proves bounded encryption randomness, or bounded key ownership plus decryption to the public amount. |
| **R_TX / R_TX0 / R_BURN conservation** | `rel.rs:522–580` binds ciphertext digits and the carry identity, including public burn/fee digits and both carry endpoints. Summing with weights `16^i` gives conservation. |
| **R_TXM conservation and range** | The same builder subtracts every recipient’s four-bit digits from the carry identity; per-leg `e2` blocks are individually bounded in the current Sage specifications. Confidentiality fails as R0-1 describes. |
| **Exact norm interpretation** | Every set’s `e-s0.txt` records both extracted-norm no-wrap and modular-JL inequalities for all 14 parameter specifications. |
| **PQZL challenge soundness** | Current generated λ=4 gives about 168 / 183.2 / 200 / 216 bits across the four moduli; the recorded JL bound is 128 bits, ring aggregation is substantially stronger, and final-challenge sizing estimates 129.79 bits. R0-2 limits the automated certification. |
| **Prior transcript fixes** | The current order commits `tg` before aggregation (`tbox.rs:801–808,1155–1172`); the soundness note §8.6 records the corresponding four-verifier fix. No recurrence established. |
| **Rej1 and bimodal rejection** | `quad.rs:326–331` uses Rej1 with σ₂²; `tbox.rs:1038–1047` uses separate bimodal tests with σ₃²/σ₄². The prior review’s unresolved challenge-norm premise remains a qualification on complete PQZL ZK assurance. |
| **Hints leakage** | The recorded 80-hint DDGR20 estimates are 445.97 / 468.47 / 482.43 / 496.79. The frozen set has an explicit exception below 450. These estimates do not prevent R0-1. |
| **Encryption correctness through K_MAX** | All four budgets satisfy `K_MAX·B_FRESH < E < Δ/2`, digit capacity and centering; therefore bounded credits cannot cause decryption failure within the stated unit budget. |
| **Ligero fields, rates and t** | The three `PQZH.md` files specify extension fields of about 168 / 183.2 / 200 bits and presets `(32756,817,121)`, `(45752,952,120)`, `(32756,817,122)`, matching the unique-decoding model. |
| **Ligero stated soundness** | Reported totals are 127.23 / 127.40 / 127.55 classical bits after summing terms, consistent with the documented totals. They are not 128-bit post-quantum bounds; that limitation is already documented. |
| **Ligero ZK construction** | `ligero_params.py:119–120` leaves `k−ℓ=t+1`; the documented simulator uses full extension-field blinds and salted columns. This protects proof witnesses, not ciphertext leakage in R0-1. |
| **n2816 without PQZH** | `set.toml:11–13` disables it. `SET.md:30` correctly identifies the absent current FFT radices and the need for a new radix-1789 construction or another modulus. This supports the implementation decision, not mathematical impossibility of Ligero over that field. |

The committed proof-hardness estimates meet the 450 target:

| Set | MSIS β | Hiding MLWE uSVP β | Hiding dual_hybrid β, classical / quantum |
|---|---:|---:|---:|
| n2048 | ≥452 | 470 | 462 / 464 |
| n2304 | 462–472 | 472 | 465 / 466 |
| n2560 | 455–468 | 470–475 | 462 / 463 |
| n2816 | 454–478 | 477–483 | 462 / 463 |

Evidence: the sets’ E-S1 summaries and the frozen set’s `estimator-e-s1*.txt` records. In particular, n2816 now uses rank **42**, correcting the historical rank-41 dual-hybrid shortfall.

## Not covered

- Full implementation review of the arithmetic, samplers, specialized verifiers, FFI, Nethermind plugin or contracts.
- Independent reconstruction of the external LNP22/LNS21/DDGR20/BCIKS20 proofs, or a new concrete-security reduction for hinted dual-hybrid attacks.
- Every generated header/Rust parameter body and every historical estimator-output line; these were inspected selectively alongside the scoped specifications and summaries.

No files were changed and no builds, tests, benchmarks or timing runs were performed. The principal remaining risk is public disclosure of audited multi-recipient amount differences under R0-1.
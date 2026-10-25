# R0-1 — auditor copies of an R_TXM group leak the differences of the leg amounts (P1)

**Found by:** Codex, unit R0 ([codex-R0.md](codex-R0.md)), 2026-10-25, at `008e196c`. agy's R0 pass did not report it
([agy-R0.md](agy-R0.md)); the Claude UltraCode pass is pending. **Verified by the controller** from the spec and the
code (below). **Status:** confirmed; fix direction chosen by the owner 2026-10-25 (direction 2); hint study done (section "Hint study (2026-10-25)" below).
No deployment is affected: the SCaaS testnet has no PQZ contracts yet and no customer chain runs PQZ.

## The defect

R_TXM (`docs/research/pqz-anonymity.md` §8.1, rows 3 and 5) with the auditor on:

```
v_j[i]     = (pk_jᵀ r_{g(j)})[i] + e2_j[i]     + Δ·d_{j,i}      i < 16, leg j < M
v_{a,j}[i] = (pk_aᵀ r_{g(j)})[i] + e2_{a,j}[i] + Δ·d_{j,i}      one auditor copy per leg
```

Legs share the encryption randomness `r_g` in groups of up to four (`g(j) = ⌊j / 4⌋`, CTR-PQZ-04). All auditor copies of
a group use the **same key `pk_a`, the same `r_g` and the same 16 coefficients**, so for two legs `j, k` of a group

```
v_{a,j}[i] − v_{a,k}[i] = Δ·(d_{j,i} − d_{k,i}) + (e2_{a,j}[i] − e2_{a,k}[i])
```

The mask cancels. `|e2| ≤ 64` per coefficient, so the residual is at most 128, while Δ ≥ 67,108,863 at every set;
digits lie in `[0, 16)`, so rounding `center_q(v_{a,j} − v_{a,k}) / Δ` gives `d_{j,i} − d_{k,i}` exactly. Anyone who reads
the statement (in state and in calldata) learns every digit difference of the legs of a group:

- a decoy leg (amount 0) is told apart from the real leg — `(1, 0)` vs `(0, 1)` — so receiver anonymity of audited
  multi-recipient transfers is lost;
- one known leg amount gives every other amount of its group.

No secret and no lattice attack are needed. The recipients' copies `v_j` are not affected (different keys `pk_j`: the
masks do not cancel); R_TX (one leg) and R_TXM without the auditor are not affected. Both proof systems prove this
relation (PQZL `pqzl/src/pqz_rel.c:779–784` and `pqzl/rust/src/rel.rs:538–544`, index `2K + 2K·(j / 4)`; PQZH
`pqzh/ligero/src/cs.rs:398–405`), at all four parameter sets. The hint analysis of §8.2 counted the repeated auditor
forms as 16 hints on `(r_g, e1_g)` and did not consider the direct difference.

## Options (analysis 2026-10-25)

Packed key / `u` size under P46: 10,752 / 13,248 / 16,000 / 19,008 B (n2048 / n2304 / n2560 / n2816), ≈ 16.5 / 20.3 /
24.5 / 29.1 M state gas per extra `u` at ≈ 1,530 per stored byte.

**Direction 1 — own randomness per leg when the auditor is on (G = M).** Removes the cancellation and gives each `r` 32
hints (as R_TX). Cost: one more `u` per leg — R_TXM M = 8 at n2304 +6 `u` ≈ +122 M state gas, M = 4 +3 `u` ≈ +61 M,
both over a 60 M block; larger proofs (more `r` in the witness). It would end audited R_TXM in practice.

**Direction 2 — distinct coefficients of one `pk_aᵀ r_g` per leg (chosen).** `pk_aᵀ r_g` has 64 coefficients; leg `j` of
its group uses coefficients `[16·(j mod s), 16·(j mod s) + 16)`, `s` = the group size. Each position has its own mask,
so differences no longer cancel — this is the standard LPR / Kyber use of one `r` for all coefficients of a ciphertext.
Statement, calldata and state sizes do not change (still 16 auditor coefficients per leg); contracts change only the
ids. The cost is the hint budget: the auditor now gives 16 **distinct** forms per leg instead of repeating 16, so a
group of `s` legs has `16s + 16s = 32s` worst-case hints (today `16s + 16` = 80 at `s = 4`).

Rough β at 32s hints from the per-set slopes 0 → 80 hints in each `SET.md` [estimate, linear; to be replaced by the
measured DDGR20 and dual_hybrid values]:

| Set | today (80 hints) | s = 4 (128) | s = 3 (96) | s = 2 (64) |
|---|---|---|---|---|
| n2048-kmax1024 | 446 (owner exception) | ≈ 428 | ≈ 440 | ≈ 452 |
| n2304-kmax4096 | 468.5 | ≈ 452 (dual_hybrid ≈ 442) | ≈ 463 (dual ≈ 453) | ≈ 474 |
| n2560-kmax16384 | 482.4 | ≈ 467 (dual ≈ 459) | | |
| n2816-kmax65536 | 496.8 | ≈ 483 | | |

A smaller `s` adds `u` vectors for large M (n2304, s = 3: R_TXM M = 8 needs G = 3 instead of 2, ≈ +20 M state gas), so
`s` becomes a per-set parameter in `set.toml`, the largest that keeps uSVP (DDGR20) **and** dual_hybrid ≥ 450 at `32s`
hints.

**Direction 3 — interim: no audited R_TXM with M > 1.** Not needed now (nothing deployed).

## Decision and next steps

**Owner 2026-10-25: direction 2; compute the hints first.** Steps:
1. Hint study: DDGR20 worst-case β (leaky-LWE-Estimator, the `anon/hints.sage` model with the auditor's forms made
   distinct) and dual_hybrid (lattice-estimator) per set at 64 / 96 / 128 hints, reproducing today's 80-hint values
   first; results in `pqz-core/pqzl/params/anon/`; choose `s` per set.
2. Then the fix: relation rows (C `pqz_rel.c`, the specialised verifier `pqz_sv.c`, Rust `rel.rs` / `sv.rs`, PQZH
   `cs.rs`), provers and the auditor's decryption, `s` in `set.toml` / `gen_set`, one proofSystemId bump per set,
   vectors, full gates at the four sets, Nethermind corpus, a new node image, spec §8.1 / §8.2 and CTR-PQZ-04.

## Hint study (2026-10-25)

Step 1 of the fix: [`pqzl/params/anon/hints_s.sage`](../../pqzl/params/anon/hints_s.sage) (new, beside `hints.sage`,
which stays) → raw output [`pqzl/params/anon/hints-s.txt`](../../pqzl/params/anon/hints-s.txt), one container per set
(`SET=<set> SCRIPT=hints_s.sage run_hints.sh <lk> <le> >> hints-s.txt`, `--memory 6g --cpus 4`).

**Method.** `hints.sage`'s instance per set: `u = Aᵀ r + e1`, `r` CBD(1) (var 1/2), `e1` CBD(20) (var 10), m = n + 16,
the set's n and q (`set.toml`) and `BETA_S` / `BETA_E` (`pqz_set.h`: 36/164, 38/173, 40/182, 42/189). With direction 2 a
group of s legs gives 16·s hints from the recipient keys plus 16·s **distinct** auditor forms = **32·s** with the
auditor on (today's model: 16·s + 16), 16·s without (unchanged). Same three hint kinds as `hints.sage` (unit on `r`,
unit on `e1`, orthogonal maximal-norm mixed forms with V_max = var_s·BETA_E² + var_e·BETA_S², the worst case); DDGR20 =
leaky-LWE-Estimator `DBDD_predict_diag` + `integrate_q_vectors` [measured]. dual_hybrid: lattice-estimator has no
hints, so h hints = h removed secret dimensions, `LWE.dual_hybrid` on LWE(n − h, m = n + 16) under ADPS16 classical /
quantum [measured on that instance], minus the offset (primal uSVP of n − h minus the DDGR20 mixed β at h) as the
worst case [estimate] — the method of `n-study/enc_n.sage` and `p16k/dual_hints16k.sage`.

**Reproduction first.** DDGR20 worst case at 80 hints: n2048 445.97, n2304 468.47, n2560 482.43, n2816 496.79 = the
`SET.md` values exactly; dual_hybrid − offset at 80: n2304 458.47 / 461.47, n2560 474.43 / 476.43 = `SET.md` exactly
(n2048 / n2816 had no earlier value). n2560 at 128 also equals `p16k/hints-16k-n2560.txt` (467.60; 458.60 / 460.60).

**Results** (worst-case mixed hints; dual = dual_hybrid − offset, classical / quantum; bold = below 450):

| Set | hints | 0 | 32 (s = 1) | 64 (s = 2) | 96 (s = 3) | 128 (s = 4) | today 80 |
|---|---|---|---|---|---|---|---|
| n2048-kmax1024 | DDGR20 | 475.83 | 463.85 | 451.92 | **440.03** | **428.20** | **445.97** |
| | dual | 465.83 / 468.83 | 454.85 / 456.85 | **443.92 / 444.92** | **432.03 / 433.03** | **420.20 / 423.20** | **437.97 / 438.97** |
| n2304-kmax4096 | DDGR20 | 495.77 | 484.82 | 473.91 | 463.04 | 452.21 | 468.47 |
| | dual | 486.77 / 488.77 | 474.82 / 477.82 | 463.91 / 466.91 | 453.04 / 456.04 | **443.21 / 445.21** | 458.47 / 461.47 |
| n2560-kmax16384 | DDGR20 | 507.31 | 497.34 | 487.39 | 477.48 | 467.60 | 482.43 |
| | dual | 498.31 / 499.31 | 488.34 / 491.34 | 478.39 / 480.39 | 468.48 / 471.48 | 458.60 / 460.60 | 474.43 / 476.43 |
| n2816-kmax65536 | DDGR20 | 519.74 | 510.54 | 501.37 | 492.22 | 483.09 | 496.79 |
| | dual | 510.74 / 511.74 | 502.54 / 503.54 | 493.37 / 494.37 | 484.22 / 486.22 | 475.09 / 478.09 | 488.79 / 490.79 |

The rough linear table above was close for DDGR20 (n2304 s = 4: 452.2 vs ≈ 452) and slightly pessimistic for dual
(443.2 vs ≈ 442; s = 3: 453.0 vs ≈ 453).

**Group size s** (largest s ∈ {4, 3, 2} with DDGR20 **and** dual ≥ 450 at 32·s hints, auditor on) and the cost.
Today G = ⌈M / 4⌉ = 1 / 1 / 2 for R_TXM M = 2 / 4 / 8; each extra `u` = the packed `u` size × ≈ 1,530 state gas per
byte (n2048 10,752 B ≈ 16.45 M, n2304 13,248 B ≈ 20.27 M, n2560 16,000 B ≈ 24.48 M, n2816 19,008 B ≈ 29.08 M):

| Set | s | G for M = 2 / 4 / 8 | extra `u` vs today (M = 2 / 4 / 8) | extra state gas M = 2 / 4 / 8 |
|---|---|---|---|---|
| n2048-kmax1024 | **none of 4 / 3 / 2** (s = 1 is the largest: 463.85 / 454.85) | s = 1: 2 / 4 / 8 | +1 / +3 / +6 | +16.45 / +49.35 / +98.70 M |
| n2304-kmax4096 | **3** (463.04; 453.04 / 456.04) | 1 / 2 / 3 | 0 / +1 / +1 | 0 / +20.27 / +20.27 M |
| n2560-kmax16384 | **4** (467.60; 458.60 / 460.60) | 1 / 1 / 2 | none | none |
| n2816-kmax65536 | **4** (483.09; 475.09 / 478.09) | 1 / 1 / 2 | none | none |

- **n2048-kmax1024** (frozen set, today the owner exception at DDGR20 446): no s ≥ 2 meets both bounds. s = 2 meets
  DDGR20 (451.92) but not dual (443.92 / 444.92); s = 2 is also above the 446 exception on DDGR20 alone. **The owner
  decides** (s = 1, or s = 2 with the exception widened to dual ≈ 444). New at this set: dual − offset was not
  measured before, and today's R_TXM is already below 450 on it — 437.97 / 438.97 at 80 hints (group of 4 + auditor) and
  443.92 / 444.92 at 64 (group of 4, auditor off).
- **n2304-kmax4096**: s = 3 (s = 4 fails dual: 443.21 / 445.21). R_TXM M = 4 and M = 8 each need one more `u`.
- **n2560-kmax16384, n2816-kmax65536**: s = 4, nothing changes beyond the relation rows.
- Auditor off (16·s hints, unchanged by the fix): s = 4 holds at n2304 / n2560 / n2816 (64 hints: n2304 473.91;
  463.91 / 466.91); at n2048 s = 4 fails dual (above), s = 2 holds (454.85 / 456.85), s = 3 (48 hints) has DDGR20
  457.88 and no dual value (not computed; between 454.85 at 32 and 443.92 at 64). Whether `s` applies only with the
  auditor on (G then depends on the auditor flag) or to every R_TXM is for the controller / owner.

**Pins.** SageMath image `sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528`
(10.7, Python 3.12.5), leaky-LWE-Estimator `0a9caf8bf0f80097724e0c6147194c52c6b90f86`, lattice-estimator
`53da5982597709ba0fdf94ea37a84d822310fd84` (both checked by `run_hints.sh`); Kyber-512 calibration in every run: DDGR20
405.53, estimator 406.

**Controller analysis (2026-10-25).** At n2304-kmax4096 with s = 3, an audited R_TXM M = 8 (state ≈ 45.6 M with P46,
spike PACK estimate) gains one `u` (+20.27 M) to ≈ 66 M of state gas: over a 60 M block, within the SCaaS testnet's
200 M; M = 4 audited stays ≈ 50 M [estimates; 2b measures]. n2560 / n2816 pay nothing. Proposals put to the owner:
(1) `s` applies only with the auditor on (auditor off keeps s = 4: 16·s = 64 hints hold at n2304 / n2560 / n2816), so
non-audited R_TXM keeps its sizes and gas; G = ⌈M / s_aud⌉ or ⌈M / 4⌉ by the auditor flag. (2) n2048-kmax1024 (the
frozen set): no R_TXM there (R_TX only), since no group size ≥ 2 meets both bounds with the auditor and today's R_TXM is
already below 450 on dual_hybrid with or without it; alternatives s = 1 (≈ +99 M state gas at M = 8) or a widened
exception. Pending the owner's answers.

**Owner ruling 2026-10-25 (group sizes).** (1) The group size `s` changes only with the auditor on: audited R_TXM uses
`s_aud`, R_TXM without the auditor keeps groups of 4 (G = ⌈M / s_aud⌉ or ⌈M / 4⌉ by the auditor flag). (2)
n2048-kmax1024: the exception is widened to dual_hybrid ≈ 444 (measured 443.92 classical / 444.92 quantum at 64 hints;
DDGR20 451.92), so `s_aud = 2` there; R_TXM without the auditor at s = 4 is the same 64-hint instance and falls under
the same exception. Resulting `s_aud`: n2048 2, n2304 3, n2560 4, n2816 4; without the auditor 4 everywhere. Extra `u`
vs today for audited R_TXM M = 2 / 4 / 8: n2048 0 / +1 / +2, n2304 0 / +1 / +1, n2560 and n2816 none.

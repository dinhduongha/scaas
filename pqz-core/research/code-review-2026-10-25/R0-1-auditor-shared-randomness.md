# R0-1 — auditor copies of an R_TXM group leak the differences of the leg amounts (P1)

**Found by:** Codex, unit R0 ([codex-R0.md](codex-R0.md)), 2026-10-25, at `008e196c`. agy's R0 pass did not report it
([agy-R0.md](agy-R0.md)); the Claude UltraCode pass is pending. **Verified by the controller** from the spec and the
code (below). **Status:** confirmed; fix direction chosen by the owner 2026-10-25 (direction 2); hint study running.
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

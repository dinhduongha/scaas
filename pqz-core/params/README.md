# pqz-core/params — E-S0 parameter spike and E-S1 codegen

`estimator.txt` is the recorded output of `e_s0.py`: lattice-estimator runs under `RC.ADPS16` (core-SVP, classical
`0.292β` and quantum `0.265β`) on the encryption MLWE instances, the proof's ABDLOP MSIS/MLWE instances and Kyber-512;
the DDGR20 hint estimate on the shared `(r, e1)`; the proof challenge space; the exactness checks of the norm proofs;
and the soundness of each Fiat–Shamir round. Spec: `docs/contracts/pq-zether.md` CTR-PQZ-03, CTR-PQZ-04 and §5;
write-up: `docs/research/pqz-parameters-e-s0.md`. The E-S1 files (P6d) are the codegen `codegen/` with
`reg_params.sage` / `tx_params.sage` (rerun `codegen/run.sh`), the generated `pqz_{reg,tx}_params.h`, and the rank sizing
`e_s1_proof.sage` → `estimator-e-s1.txt` (rerun `run_e_s1.sh`); write-up `docs/research/pqz-core-e-s1.md`.
`burn_params.sage`, `ds_params.sage`, `dr_params.sage` → `pqz_{burn,ds,dr}_params.h` are the `R_BURN` / `R_DS` / `R_DR`
specs (`docs/research/pqz-relations-burn-disclose.md`); `run_e_s1.sh <LaZer> <estimator> burn ds dr` sizes them
(`estimator-e-s1-rel3.txt`). `tx0_params.sage` → `pqz_tx0_params.h` is `R_TX0`, the transfer without the auditor
(CTR-PQZ-24, P6e plan D8: `R_TX` without `pk_a` / `v_a` / `e2_a`, row 5 skipped; op 1 with the 66,560-byte statement),
sized by `run_e_s1.sh <LaZer> <estimator> tx0` (`estimator-e-s1-tx0.txt`).

## Codegen reproducibility (P6e D1, 2026-10-14)

`regen.sh <LaZer 3330e48> <out dir> tx0 reg tx burn ds dr` reruns LaZer's codegen (`codegen/run.sh`, pinned Sage image,
no network) on every spec and compares each output with the checked-in header. Run under `scripts/capped`, output
`codegen-tx0.txt`: the five existing headers (`reg`, `tx`, `burn`, `ds`, `dr`) came out **byte-identical**; `tx0` is
new (copied from the run, sha256 `bdf886541e7fafac…`). About 30 s per spec.

| Relation | kmsis | kmlwe | m1 + m2 | MSIS β (classical / quantum) | MLWE uSVP β (dual_hybrid β) | knowledge error | codegen proof estimate |
|---|---|---|---|---|---|---|---|
| `R_TX0` (`estimator-e-s1-tx0.txt`) | 23 | 33 | 145 + 68 | 457 (2^133.4 / 2^121.1) | 470 (462) | ≤ 2^−127 | ≈ 44,286 B |
| for reference `R_TX` | 23 | 33 | 146 + 68 | 456 (2^133.2) | 470 (462) | ≤ 2^−127 | ≈ 44,638 B |

`R_TX0` meets CTR-PQZ-03's β ≥ 450 at LaZer's default `pqz_delta` 1.00366 and the MLWE rank floor 33 on the first
try, as the other relations did.

## Relations v2 (frozen, P6e plan R1)

The relation specification is the LaZer spec file, the generated header and `src/pqz_rel.c`'s builder (header comment),
frozen by the KATs (`smartcontracts/vectors/pqz/`) and the generic-vs-specialised differential test. Every relation
also hashes the whole statement into the transcript (`docs/contracts/pq-zether.md` §5, byte layouts §8.1). Columns
from the generated headers' comments and `pqz_rel.c`; `Z` = one slack polynomial per exact ℓ2 block.

| Relation (op) | Spec → header | Statement fields read | Witness slots in `s1` | Equations (pq-zether.md) | Exact ℓ2 blocks (polys: bound) | Binary polys | Approx. ℓ∞ filler | Knowledge error, MSIS |
|---|---|---|---|---|---|---|---|---|
| `R_REG` (3) | `reg_params.sage` → `pqz_reg_params.h` | `pk` | 0..31 `s`, 32..63 `e` (m1 64, Z 2) | `pk = A·s + e` (§7.2) | 32: 36, 32: 164 | — | 1 poly, bound 1 | ≤ 2^−127, MSIS(22, 131, 2^35.30) |
| `R_TX` (1, 83,072 B) | `tx_params.sage` → `pqz_tx_params.h` | `fee`, `auditorOn` (= 1), `pk_f`, `pk_t`, `pk_a`, `T`, `u`, `v_t`, `v_f`, `v_a` | 0..31 `s_f`, 32..63 `e_f`, 64..95 `r`, 96..127 `e1`, 128 `e2_t`, 129 `e2_f`, 130 `e2_a`, 131..145 bits (m1 146, Z 7) | rows 1–7 (§7.4) | 32: 36, 32: 164, 32: 36, 32: 164, 1: 64 (× 3) | 15 | 1 poly, bound 64 | ≤ 2^−127, MSIS(23, 214, 2^35.97) |
| `R_TX0` (1, 66,560 B) | `tx0_params.sage` → `pqz_tx0_params.h` | as `R_TX` without `pk_a`, `v_a`; `auditorOn` (= 0) | as `R_TX` without `e2_a`: 130..144 bits (m1 145, Z 6) | rows 1–4, 6, 7 | as `R_TX`, 1: 64 (× 2) | 15 | 1 poly, bound 64 | ≤ 2^−127, MSIS(23, 213, 2^35.96) |
| `R_BURN` (2: BURN, REFRESH) | `burn_params.sage` → `pqz_burn_params.h` | `fee`, `amount` (`d = digits(amount)` public), `pk_f`, `T`, `u`, `v_f` | 0..31 `s_f`, 32..63 `e_f`, 64..95 `r`, 96..127 `e1`, 128 `e2_f`, 129..142 bits (m1 143, Z 5) | rows 1, 2, 4, 6, 7 (§7.5) | 32: 36, 32: 164, 32: 36, 32: 164, 1: 64 | 14 | 1 poly, bound 64 | ≤ 2^−127, MSIS(23, 211, 2^35.95) |
| `R_DS` (4) | `ds_params.sage` → `pqz_ds_params.h` | `amount` (`d` public), `pk`, `u`, `v` | 0..31 `r`, 32..63 `e1`, 64 `e2_t` (m1 65, Z 3) | `u = Aᵀ·r + e1`, `v[i] = (pkᵀ·r)[i] + e2_t[i] + Δ·d_i` (§7.9) | 32: 36, 32: 164, 1: 64 | — | 1 poly, bound 64 | ≤ 2^−127, MSIS(22, 132, 2^35.31) |
| `R_DR` (5: RECEIVER, AUDITOR) | `dr_params.sage` → `pqz_dr_params.h` | `amount` (`d` public), `pk`, `u`, `v` | 0..31 `s`, 32..63 `e`, 64..70 bits (m1 71, Z 2) | `pk = A·s + e`, `v[i] − (uᵀ·s)[i] = Δ·d_i + e'_i`, `e'_i + 2^24 ∈ [0, 2^25)` (§7.9) | 32: 36, 32: 164 | 7 | 1 poly, bound 1 | ≤ 2^−127, MSIS(23, 139, 2^35.84) |

Bit slots (slot `k` = coefficient `k mod 64` of binary poly `k / 64`; `b` the bit index): `R_TX` / `R_TX0`: `d_i` at
`4i + b`, `d'_i` at `64 + 4i + b`, `M_i` at `128 + 14i + b`, `c_i + 64` at `352 + 11i + b` (`i < 15`), `e_T[i] + 2^24`
at `517 + 25i + b`; `R_BURN`: `d'_i` at `4i + b`, `M_i` at `64 + 14i + b`, `c_i + 64` at `288 + 11i + b`,
`e_T[i] + 2^24` at `453 + 25i + b`; `R_DR`: `e'_i + 2^24` at `25i + b`. PQZH (Ligero) implements the same six
relations as constraint systems in `pqz-core/pqzh/ligero/src/cs.rs` on the same statement and witness bytes.

| Pin | Value |
|---|---|
| lattice-estimator | <https://github.com/malb/lattice-estimator> commit `53da5982597709ba0fdf94ea37a84d822310fd84` (main, 2026-08-19) |
| Sage container | `sagemath/sagemath:10.7`, `sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528` |
| Estimator calls | `LWE.estimate(p, red_cost_model=ADPS16(mode), deny_list=("arora-gb", "bkw", "bdd_mitm_hybrid"), jobs=4)` (`bdd_mitm_hybrid` kept for Kyber-512 and the PQZ key, classical), `SIS.estimate(p, red_cost_model=ADPS16(mode))`, mode ∈ {classical, quantum}; sizing search with `LWE.primal_usvp` / `SIS.lattice` |

## Rerun

```sh
git clone https://github.com/malb/lattice-estimator /tmp/le && git -C /tmp/le checkout 53da598
pqz-core/params/run.sh /tmp/le > /tmp/estimator.txt     # one container, no network inside
diff pqz-core/params/estimator.txt /tmp/estimator.txt   # must be empty
```

`run.sh` refuses any other estimator commit and runs the pinned image with `--network none` and both mounts read-only.
The challenge-space sampling uses a fixed numpy seed and the estimator is deterministic, so the output should be
byte-identical on the pinned image (parts 0 and 2–5 matched between two runs; the full file has been produced once).
Runtime ≈ 1 h.

## What is not the estimator

- **Hints (DDGR20).** The leaky-LWE-Estimator is a separate repository, not part of lattice-estimator `53da598`.
  `e_s0.py` implements its predictive perfect-hint update (dimension −1, normalized log-volume `+½ ln vᵀΣv`) and the
  same ADPS16/GSA uSVP condition, calibrated against the estimator's `primal_usvp` on Kyber-512 and on the PQZ
  instance (both printed).
- **Proof instances.** The spec does not fix the ABDLOP ranks (LaZer's codegen does, in P6d). `e_s0.py` derives the
  smallest MSIS rank and randomness length that reach `β ≥ 450` for `R_TX` from the LNP22 bounds with conservative
  choices (Rej0 `γ = 11`, ternary randomness scored as CBD(1)); P6d's codegen must use at least these ranks.

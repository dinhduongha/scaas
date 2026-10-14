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

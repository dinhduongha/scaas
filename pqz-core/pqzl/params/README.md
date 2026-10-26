# pqz-core/pqzl/params — E-S0 parameter spike and E-S1 codegen

> **Parameter sets moved (owner 2026-10-21, plan 5h Task 8b).** The headers the cores build with now live in one
> directory per parameter set, [`pqz-core/params/sets/<set>/`](../../params/sets/README.md) (selected at compile time:
> C `PQZ_SET`, Rust feature `set-<set>`; one set per library build; how to add a set:
> [`pqz-core/params/README.md`](../../params/README.md)). Each set's specs, headers, Rust params and estimator logs
> (`e-s1.txt`, `e-s0.txt`) are generated there by `gen_set.py` / `make.sh <set> all`. The first-generation headers and
> Rust params moved unchanged to `sets/n2048-kmax1024/` (2026-10-21); since the R0 review fix (2026-10-25) that set is no
> longer frozen and its reg, dr and audited txm headers were regenerated (audited `R_TXM` legs in groups of `s_aud` =
> 2, not 4). **Everything below is therefore the history of the first specs** (the shapes and numbers before the
> parameter sets and before the R0 fix), kept as the record: this folder keeps those specs (`*.sage`), their estimator
> logs, `codegen/` (used by every set), `to_rust.py`, and the research records `n-study/` (the ring-dimension study),
> `p16k/` (the `n2560-kmax16384` study), `aprime/` (the `n2816-kmax65536` candidates), `anon/` (the op 7 sizing and hint
> studies, with the `s_aud` hint study `hints-s.txt`) and `pa-pack/` (the coefficient-packing spike). The `pqz_*_params.h`
> named below are the headers then checked in here (moved to `sets/n2048-kmax1024/` in `d68e0fc8`, 2026-10-21; git
> history has them). Current numbers: each set's `SET.md`, `e-s1.txt` and `codegen.txt`.

This folder holds the first security parameters of PQZL, the lattice proof system of PQZ, and the evidence that they
were secure. For each relation (what a proof shows: a transfer, a burn, a registration, …) it has a small
specification and the output of the lattice-estimator runs that sized it to at least 128-bit security; the C header
generated from it was checked in here until the parameter sets. The cores now build with the per-set headers;
reviewers re-checking the history and the method use this folder.
How PQZL fits into PQZ: the parent [pqz-core README](../../README.md), §3
["Two proof systems, one precompile"](../../README.md#3-two-proof-systems-one-precompile).

There were two stages. **E-S0** (the first parameter spike) estimated the security of the encryption and of the proof
in Python. **E-S1** (plan P6d) then used LaZer's own code generator to fix the exact proof dimensions and re-checked
them with the estimator.

**Words used here**

| Term | Meaning |
|---|---|
| lattice-estimator | the standard tool that estimates the cost of attacking a lattice problem (<https://github.com/malb/lattice-estimator>) |
| MLWE, MSIS | the two lattice problems PQZL's security rests on (Module Learning With Errors, Module Short Integer Solution) |
| β | the BKZ block size an attack needs; larger is harder. The target is β ≥ 450 (CTR-PQZ-03) |
| core-SVP, `ADPS16` | the cost model: an attack with block size β costs 2^(0.292β) classically and 2^(0.265β) on a quantum computer |
| ABDLOP | the commitment scheme inside the LNP22 proof; its ranks `kmsis` / `kmlwe` set the MSIS / MLWE instances |
| LaZer codegen, tbox | LaZer's code generator (`codegen/`) turns a relation spec (`*_params.sage`) into a C header (`pqz_*_params.h`); "tbox" is LaZer's proof toolbox that uses it |
| m1, m2 | the number of witness polynomials (secrets) and of randomness polynomials in the commitment |
| knowledge error | the chance that a cheating prover gets a false proof accepted; the target is ≤ 2^−127 |
| DDGR20 hints | a method (Dachman-Soled, Ducas, Gong, Rossi 2020) to account for extra information ("hints") an attacker learns, here because the transfer shares the randomness `(r, e1)` across ciphertexts |
| exact ℓ2 block | a group of witness polynomials whose Euclidean norm the proof bounds exactly |
| `R_TXM` | the multi-recipient transfer (precompile op 7): one proof for M recipients |

## Files

| Files | What |
|---|---|
| `e_s0.py` → `estimator.txt` | E-S0 (see below); rerun with `run.sh` |
| `codegen/` (`codegen.sage`, `lnp-tbox-codegen.sage`, `run.sh`) | LaZer's code generator in the pinned Sage image |
| `reg_params.sage`, `tx_params.sage` → `pqz_{reg,tx}_params.h` | E-S1 specs for `R_REG` and `R_TX` (rerun `codegen/run.sh`) |
| `e_s1_proof.sage` → `estimator-e-s1.txt` | E-S1 rank sizing (rerun `run_e_s1.sh`) |
| `burn_params.sage`, `ds_params.sage`, `dr_params.sage` → `pqz_{burn,ds,dr}_params.h` | the `R_BURN` / `R_DS` / `R_DR` specs, sized in `estimator-e-s1-rel3.txt` |
| `tx0_params.sage` → `pqz_tx0_params.h` | `R_TX0`, the transfer without the auditor, sized in `estimator-e-s1-tx0.txt` |
| `txm{2,4,8,16}[0]_params.sage` → `pqz_txm*_params.h` | `R_TXM`, sized in `estimator-e-s1-txm.txt` |
| `regen.sh`, `codegen-*.txt` | history (P6e D1): reran the codegen and compared with the headers then checked in here; the recorded runs. The headers left this folder (2026-10-21), so today it only reports "new"; per set: `make.sh <set> codegen` |
| `z21_msis.sage` → `estimator-z21.txt` | the z21 norm check (P6-Z21, `SCRIPT=z21_msis.sage ./run_e_s1.sh <LaZer> <estimator> reg tx burn ds dr`) |
| `anon/` | the P6-ANON sizing and hint scripts (`hints.sage` → `hints-anon.txt`, run by `run_hints.sh`) |

## E-S0: the first estimates

`estimator.txt` is the recorded output of `e_s0.py`. It contains:

- lattice-estimator runs under `RC.ADPS16` (core-SVP, classical `0.292β` and quantum `0.265β`) on the encryption MLWE
  instances, the proof's ABDLOP MSIS/MLWE instances and, for comparison, Kyber-512;
- the DDGR20 hint estimate on the shared `(r, e1)`;
- the proof's challenge space;
- the exactness checks of the norm proofs;
- the soundness of each Fiat–Shamir round.

Spec: `docs/contracts/pq-zero-knowledge.md` CTR-PQZ-03, CTR-PQZ-04 and §5; write-up:
`docs/research/pqz-parameters-e-s0.md`.

## E-S1: the generated headers (P6d and later)

- **`R_REG`, `R_TX`.** The E-S1 files (P6d) are the codegen `codegen/` with `reg_params.sage` / `tx_params.sage`
  (rerun `codegen/run.sh`), the generated `pqz_{reg,tx}_params.h`, and the rank sizing `e_s1_proof.sage` →
  `estimator-e-s1.txt` (rerun `run_e_s1.sh`). Write-up: `docs/research/pqz-core-e-s1.md`.
- **`R_BURN`, `R_DS`, `R_DR`.** `burn_params.sage`, `ds_params.sage`, `dr_params.sage` → `pqz_{burn,ds,dr}_params.h` are
  the specs of the burn and the two disclosure relations (`docs/research/pqz-relations-burn-disclose.md`);
  `run_e_s1.sh <LaZer> <estimator> burn ds dr` sizes them (`estimator-e-s1-rel3.txt`).
- **`R_TX0`.** `tx0_params.sage` → `pqz_tx0_params.h` is the transfer without the auditor (CTR-PQZ-24; P6e plan D8:
  `R_TX` without `pk_a` / `v_a` / `e2_a`, row 5 skipped; op 1 with the 66,560-byte statement), sized by
  `run_e_s1.sh <LaZer> <estimator> tx0` (`estimator-e-s1-tx0.txt`).

The scripts take a LaZer checkout at `3330e48` and a lattice-estimator checkout at `53da598`; `run_e_s1.sh` writes to
standard output, so redirect it into the `estimator-*.txt` file named above.

## Codegen reproducibility (P6e D1, 2026-10-14)

`regen.sh <LaZer 3330e48> <out dir> tx0 reg tx burn ds dr` reruns LaZer's codegen (`codegen/run.sh`, pinned Sage image,
no network) on every spec and compares each output with the checked-in header. The run (under `scripts/capped`, output
`codegen-tx0.txt`) found:

- the five existing headers (`reg`, `tx`, `burn`, `ds`, `dr`) came out **byte-identical**;
- `tx0` is new (copied from the run, sha256 `bdf886541e7fafac…`).

It takes about 30 s per spec.

The sizes of the transfer relations (MSIS β: the attack's block size, with its classical / quantum cost):

Rust (plan D8, the pure-Rust port `pqzl/rust`): `to_rust.py` (stdlib Python) converts every set's headers
`pqz-core/params/sets/<set>/pqz_*_params.h` into `pqz-core/params/sets/<set>/rust/<rel>.rs` (typed constants, the C
names lower-cased, lazer-in2.h's structs field for field; the structs are in `pqzl/rust/src/params/mod.rs`). After a
codegen run `python3 -I pqz-core/pqzl/params/to_rust.py [set ...]` (or `make.sh <set> rust`); `--check` (no Sage
needed) compares the committed `.rs` files with the regenerated text, and `regen.sh` and `pqzl/rust/run.sh` run it.

| Relation | kmsis | kmlwe | m1 + m2 | MSIS β (classical / quantum) | MLWE uSVP β (dual_hybrid β) | knowledge error | codegen proof estimate |
|---|---|---|---|---|---|---|---|
| `R_TX0` (`estimator-e-s1-tx0.txt`) | 23 | 33 | 145 + 68 | 457 (2^133.4 / 2^121.1) | 470 (462) | ≤ 2^−127 | ≈ 44,286 B |
| for reference `R_TX` | 23 | 33 | 146 + 68 | 456 (2^133.2) | 470 (462) | ≤ 2^−127 | ≈ 44,638 B |
| `R_TXM` M = 2, auditor on (`txm2`) | 23 | 33 | 149 + 68 | 456 (2^133.2 / 2^120.8) | 470 (462) | ≤ 2^−127 | ≈ 45,518 B |
| `R_TXM` M = 4, auditor on (`txm4`) | 23 | 33 | 155 + 68 | 454 (2^132.6 / 2^120.3) | 470 (462) | ≤ 2^−127 | ≈ 47,278 B |
| `R_TXM` M = 8, auditor on (`txm8`) | 25 | 33 | 231 + 70 | 458 (2^133.7 / 2^121.4) | 470 (462) | ≤ 2^−127 | ≈ 64,578 B |
| `R_TXM` M = 2, auditor off (`txm20`) | 23 | 33 | 147 + 68 | 456 (2^133.2 / 2^120.8) | 470 (462) | ≤ 2^−127 | ≈ 44,814 B |
| `R_TXM` M = 4, auditor off (`txm40`) | 23 | 33 | 151 + 68 | 455 (2^132.9 / 2^120.6) | 470 (462) | ≤ 2^−127 | ≈ 45,870 B |
| `R_TXM` M = 8, auditor off (`txm80`) | 25 | 33 | 223 + 70 | 459 (2^134.0 / 2^121.6) | 470 (462) | ≤ 2^−127 | ≈ 61,634 B |
| `R_TXM` M = 16, auditor on, oversize (`txm16`) | 25 | 33 | 383 + 70 | 452 (2^132.0 / 2^119.8) | 470 (462) | ≤ 2^−127 | ≈ 96,658 B |
| `R_TXM` M = 16, auditor off, oversize (`txm160`) | 25 | 33 | 367 + 70 | 453 (2^132.3 / 2^120.0) | 470 (462) | ≤ 2^−127 | ≈ 90,570 B |

`R_TX0` meets CTR-PQZ-03's β ≥ 450 at LaZer's default `pqz_delta` 1.00366 and the MLWE rank floor 33 on the first
try, as the other relations did.

**`R_TXM`** (the multi-recipient transfer, precompile op 7; plan P6-ANON L1):

- Specs: `txm{2,4,8,16}[0]_params.sage`; a trailing `0` means auditor off. M = 1 needs no spec of its own: it is
  `R_TX` / `R_TX0`.
- Sized by `run_e_s1.sh <LaZer> <estimator> txm2 txm4 txm8 txm20 txm40 txm80 txm16 txm160` (`estimator-e-s1-txm.txt`,
  which also lists each header's knowledge-error line).
- Headers by `regen.sh … txm2 … txm160 tx tx0 burn` (`codegen-txm-x1.txt`: `tx`, `tx0`, `burn` came out
  byte-identical).
- Every e2 vector (the noise of one recipient's ciphertext) is its own exact-ℓ2 block with `‖e2‖² ≤ 4,096` (owner
  decision 2026-10-15, X-1). The first L1 specs at `eded6fb` instead used one `64·√M` block per kind of leg noise.
- All eight meet β ≥ 450 on the first try. M = 16 (oversize, built only with `-DPQZ_TXM_OVERSIZE`) does not fit the
  precompile's `MAX_INPUT` (P6-ANON D3 / D20).

## Relations v2 (history: frozen in P6e plan R1, at the first specs)

**Where the relation is defined.** Each relation is defined by three things together: the LaZer spec file, the
generated header and the builder in `src/pqz_rel.c` (see its header comment). The KATs (known-answer tests,
`smartcontracts/vectors/pqz/`) and the differential test between the generic and the specialised verifier freeze
them. Every relation also hashes the whole statement into the transcript (`docs/contracts/pq-zero-knowledge.md` §5,
byte layouts §8.1).

The table is taken from the generated headers' comments and `pqz_rel.c`. `Z` = one slack polynomial per exact ℓ2
block; "exact ℓ2 blocks" lists each block as `polys: bound`.

| Relation (op) | Spec → header | Statement fields read | Witness slots in `s1` | Equations (pq-zero-knowledge.md) | Exact ℓ2 blocks (polys: bound) | Binary polys | Approx. ℓ∞ filler | Knowledge error, MSIS |
|---|---|---|---|---|---|---|---|---|
| `R_REG` (3) | `reg_params.sage` → `pqz_reg_params.h` | `pk` | 0..31 `s`, 32..63 `e` (m1 64, Z 2) | `pk = A·s + e` (§7.2) | 32: 36, 32: 164 | — | 1 poly, bound 1 | ≤ 2^−127, MSIS(22, 131, 2^35.30) |
| `R_TX` (1, 83,072 B) | `tx_params.sage` → `pqz_tx_params.h` | `fee`, `auditorOn` (= 1), `pk_f`, `pk_t`, `pk_a`, `T`, `u`, `v_t`, `v_f`, `v_a` | 0..31 `s_f`, 32..63 `e_f`, 64..95 `r`, 96..127 `e1`, 128 `e2_t`, 129 `e2_f`, 130 `e2_a`, 131..145 bits (m1 146, Z 7) | rows 1–7 (§7.4) | 32: 36, 32: 164, 32: 36, 32: 164, 1: 64 (× 3) | 15 | 1 poly, bound 64 | ≤ 2^−127, MSIS(23, 214, 2^35.97) |
| `R_TX0` (1, 66,560 B) | `tx0_params.sage` → `pqz_tx0_params.h` | as `R_TX` without `pk_a`, `v_a`; `auditorOn` (= 0) | as `R_TX` without `e2_a`: 130..144 bits (m1 145, Z 6) | rows 1–4, 6, 7 | as `R_TX`, 1: 64 (× 2) | 15 | 1 poly, bound 64 | ≤ 2^−127, MSIS(23, 213, 2^35.96) |
| `R_BURN` (2: BURN, REFRESH) | `burn_params.sage` → `pqz_burn_params.h` | `fee`, `amount` (`d = digits(amount)` public), `pk_f`, `T`, `u`, `v_f` | 0..31 `s_f`, 32..63 `e_f`, 64..95 `r`, 96..127 `e1`, 128 `e2_f`, 129..142 bits (m1 143, Z 5) | rows 1, 2, 4, 6, 7 (§7.5) | 32: 36, 32: 164, 32: 36, 32: 164, 1: 64 | 14 | 1 poly, bound 64 | ≤ 2^−127, MSIS(23, 211, 2^35.95) |
| `R_DS` (4) | `ds_params.sage` → `pqz_ds_params.h` | `amount` (`d` public), `pk`, `u`, `v` | 0..31 `r`, 32..63 `e1`, 64 `e2_t` (m1 65, Z 3) | `u = Aᵀ·r + e1`, `v[i] = (pkᵀ·r)[i] + e2_t[i] + Δ·d_i` (§7.9) | 32: 36, 32: 164, 1: 64 | — | 1 poly, bound 64 | ≤ 2^−127, MSIS(22, 132, 2^35.31) |
| `R_DR` (5: RECEIVER, AUDITOR) | `dr_params.sage` → `pqz_dr_params.h` | `amount` (`d` public), `pk`, `u`, `v` | 0..31 `s`, 32..63 `e`, 64..70 bits (m1 71, Z 2) | `pk = A·s + e`, `v[i] − (uᵀ·s)[i] = Δ·d_i + e'_i`, `e'_i + 2^24 ∈ [0, 2^25)` (§7.9) | 32: 36, 32: 164 | 7 | 1 poly, bound 1 | ≤ 2^−127, MSIS(23, 139, 2^35.84) |
| `R_TXM` (7, `M` legs, `G = ⌈M/4⌉` groups, auditor `A`) | `txm{M}[0]_params.sage` → `pqz_txm{M}[0]_params.h` (M = 1: `R_TX` / `R_TX0`'s) | header words `M` (320), `auditorOn` (448), `fee`; `pk_f`, `pk_j`, [`pk_a`], `T`, `u_g`, `v_j`, `v_f`, [`v_{a,j}`] (pq-zero-knowledge.md §8.1 op 7) | 0..31 `s_f`, 32..63 `e_f`, `64 + 64g` `r_g`, `96 + 64g` `e1_g`, `E = 64 + 64G`: `e2_j` at `E + j`, `e2_f` at `E + M`, `e2_{a,j}` at `E + M + 1 + j`, then ⌈(853 + 64M)/64⌉ binary polys (Z = 3 + 2G + M + A·M) | rows 1–7 of the P6-ANON plan §3 (row 2 per group, rows 3 / 5 per leg, row 7 with Σ_j d_j) | 32: 36, 32: 164, (32: 36, 32: 164) per group, 1: 64 per e2 vector (M + 1 + A·M) | ⌈(853 + 64M)/64⌉ | 1 poly (`e2_0`), bound 64 | ≤ 2^−127, `estimator-e-s1-txm.txt` |

**Bit slots.** The range proofs put each bit into one coefficient of a binary polynomial: slot `k` = coefficient
`k mod 64` of binary poly `k / 64`, and `b` is the bit index.

- `R_TX` / `R_TX0`: `d_i` at `4i + b`, `d'_i` at `64 + 4i + b`, `M_i` at `128 + 14i + b`, `c_i + 64` at
  `352 + 11i + b` (`i < 15`), `e_T[i] + 2^24` at `517 + 25i + b`;
- `R_BURN`: `d'_i` at `4i + b`, `M_i` at `64 + 14i + b`, `c_i + 64` at `288 + 11i + b`, `e_T[i] + 2^24` at
  `453 + 25i + b`;
- `R_DR`: `e'_i + 2^24` at `25i + b`.

PQZH (Ligero), the hash-based proof system, implements the same six relations as constraint systems in
`pqz-core/pqzh/ligero/src/cs.rs`, on the same statement and witness bytes.

**Pinned versions**

| Pin | Value |
|---|---|
| lattice-estimator | <https://github.com/malb/lattice-estimator> commit `53da5982597709ba0fdf94ea37a84d822310fd84` (main, 2026-08-19) |
| Sage container | `sagemath/sagemath:10.7`, `sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528` |
| Estimator calls | `LWE.estimate(p, red_cost_model=ADPS16(mode), deny_list=("arora-gb", "bkw", "bdd_mitm_hybrid"), jobs=4)` (`bdd_mitm_hybrid` kept for Kyber-512 and the PQZ key, classical), `SIS.estimate(p, red_cost_model=ADPS16(mode))`, mode ∈ {classical, quantum}; sizing search with `LWE.primal_usvp` / `SIS.lattice` |

## Rerun

This reruns E-S0 (`estimator.txt`). Run from the repository root; it needs docker and network access only for the
clone.

```sh
git clone https://github.com/malb/lattice-estimator /tmp/le && git -C /tmp/le checkout 53da598
pqz-core/pqzl/params/run.sh /tmp/le > /tmp/estimator.txt     # one container, no network inside
diff pqz-core/pqzl/params/estimator.txt /tmp/estimator.txt   # must be empty
```

- `run.sh` refuses any other estimator commit and runs the pinned image with `--network none` and both mounts
  read-only.
- The challenge-space sampling uses a fixed numpy seed and the estimator is deterministic, so the output should be
  byte-identical on the pinned image. Parts 0 and 2–5 matched between two runs; the full file has been produced once.
- It takes about 1 h.

## What is not the estimator

Two parts of the analysis are not plain lattice-estimator calls:

- **Hints (DDGR20).** The leaky-LWE-Estimator is a separate repository, not part of lattice-estimator `53da598`.
  `e_s0.py` implements its predictive perfect-hint update (dimension −1, normalized log-volume `+½ ln vᵀΣv`) and the
  same ADPS16/GSA uSVP condition, calibrated against the estimator's `primal_usvp` on Kyber-512 and on the PQZ
  instance (both printed). Later, P6-ANON S1 ran the leaky-LWE-Estimator itself (commit `0a9caf8`, pinned in
  `anon/run_hints.sh`) on the multi-recipient hint counts: `anon/hints.sage` → `anon/hints-anon.txt`.
- **Proof instances.** The spec does not fix the ABDLOP ranks (LaZer's codegen does, in P6d). `e_s0.py` derives the
  smallest MSIS rank and randomness length that reach `β ≥ 450` for `R_TX` from the LNP22 bounds with conservative
  choices (Rej0 `γ = 11`, ternary randomness scored as CBD(1)); P6d's codegen had to use at least these ranks.

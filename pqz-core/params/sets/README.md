# pqz-core/params/sets — PQZ parameter sets

Owner 2026-10-21: **parameter sets are per-directory, selected at compile time; one set per library build** (a
runtime choice between sets is deferred). Each directory `<set>/` holds every parameter-dependent input of the PQZL C
and Rust cores; the algorithm code uses only the named constants. Sets are named by n and `K_MAX`. PQZH adds its own
file per set in plan 5h Task 8c (`pqzh_set.rs`); until then PQZH exists for `n2048-kmax1024` only and is compiled out
of `pqz-ffi` / `pqz-vectors` for every other set. Adding a set: write `<set>/set.toml`, then `make.sh <set> all`.

| Set | n, k | q | `K_MAX` | Status | `SET.md` |
|---|---|---|---|---|---|
| `n2048-kmax1024` | 2048, 32 | 2^42 − 215 | 1,024 | the frozen v3 set: main's build, the committed vectors, the contracts until 8d | [SET.md](n2048-kmax1024/SET.md) |
| `n2304-kmax4096` | 2304, 36 | 61,275,424,977,257 (2^45.80) | 4,096 | owner 2026-10-21: the default of the `pqzl` crate and `gate.sh` | [SET.md](n2304-kmax4096/SET.md) |
| `n2560-kmax16384` | 2560, 40 | 2^50 − 42,310,535 | 16,384 | approved 2026-10-20 as the Task 8 set, superseded as the default by `n2304-kmax4096` 2026-10-21: shippable for customer chains; full vectors + gate | [SET.md](n2560-kmax16384/SET.md) |
| `n2816-kmax65536` | 2816, 44 | 2^54 − 327 | 65,536 | research record `pqzl/params/aprime/`, owner 2026-10-21: **core only** (`core_only = true`: C + Rust cores, KATs; no pqz-stmt / precompile / vectors / contracts) | [SET.md](n2816-kmax65536/SET.md) |

Older notes and plans use short names for three of these sets: "set (a)" = `n2304-kmax4096`, "16k" = `n2560-kmax16384`,
"A′" = `n2816-kmax65536`; new text uses the directory names only.

## What a set fixes: cryptography first, cost follows (owner question 2026-10-23)

A parameter set is not a gas or storage setting: it is the cryptographic instance itself. Every value below decides
security or correctness; gas, state and calldata only follow from the sizes they produce.

| Parameter | Cryptographic role |
|---|---|
| n (= k · 64), q | the ring and modulus of the lattice encryption (MLWE): the root of its security |
| `K_MAX` | how many credits (homomorphic additions of encrypted amounts) an account may receive between refreshes and still decrypt correctly: the summed noise of `K_MAX` fresh ciphertexts must stay below the noise ceiling E (`n2816-kmax65536`: 65,535 · B_FRESH = 1,044,627,900 < E = 2^30) |
| Δ, β_s / β_e, CBD widths | plaintext scale and noise distributions: correct decryption and encryption security |
| proof MLWE rank `kmlwe` | security of the zero-knowledge proofs (MSIS / MLWE); `n2816-kmax65536` needs 42, at 41 dual_hybrid gives β 447 / 448 < 450 |
| norm-proof exactness, Fiat–Shamir rounds (`e-s0.txt`) | soundness of the proofs, checked again for every set |

What is the same across sets: the target security bar — every set must reach β ≥ 450 (MSIS, hiding MLWE uSVP and
dual_hybrid, `e-s1.txt`). One recorded exception: `n2048-kmax1024`, encryption with 80 worst-case hints, DDGR20 β 446.0
(owner-accepted, CTR-PQZ-03, 2026-10-15); the larger sets clear 450 there without an exception.

What differs: the capacity `K_MAX`. A larger `K_MAX` needs a larger q (more noise room), and a larger q needs a larger n
to keep the same security; larger n and q make keys, ciphertexts and proofs larger, and that is where the cost comes
from (state gas per stored ciphertext, calldata, prover and verifier time).

| Set | `K_MAX` | q | proof rank `kmlwe` | encryption uSVP β (no hints) | pk / ciphertext (B) |
|---|---|---|---|---|---|
| `n2048-kmax1024` | 1,024 | 2^42 − 215 | 33 | 476 | 16,384 / 16,512 |
| `n2304-kmax4096` | 4,096 | 61,275,424,977,257 (2^45.80) | 36 | 496 | 18,432 / 18,560 |
| `n2560-kmax16384` | 16,384 | 2^50 − 42,310,535 | 39 | 508 | 20,480 / 20,608 |
| `n2816-kmax65536` | 65,536 | 2^54 − 327 | 42 | 520 | 22,528 / 22,656 |

Each set is a separate cryptographic instance: a proof made at one set does not verify at another, a deployment needs
its own `proofSystemId` (plan 5h Task 8d), and a cryptographic audit covers one set at a time. Choosing a set trades
capacity (`K_MAX`) against cost at the same target security; it never changes the cryptography's bar, only its instance.
Numbers: each set's `SET.md`.

## PQZL and PQZH in one set: what is shared, what is not (owner question 2026-10-23)

**Shared.** PQZL (lattice proofs, LaZer) and PQZH (hash-based backup, Ligero over F_q) prove the same statements over
the same ciphertexts mod q, so a set's q, n, `K_MAX`, Δ and the statement / object layout are one source for both; both
live in the same directory `params/sets/<set>/` and are built for one set per library build.

**Not shared.** The proof parameters are each system's own:

| | PQZL | PQZH |
|---|---|---|
| file in `<set>/` | `pqz_set.h`, `rust/set.rs`, `<rel>_params.sage`, `pqz_<rel>_params.h`, `rust/<rel>.rs` | `pqzh_set.rs` (plan 5h Task 8c) |
| proof parameters | proof MLWE rank `kmlwe`, norm bounds, codegen shapes per relation | the Ligero preset: domain radices, code length n, message length k, query count t |
| security measure | lattice estimator β ≥ 450 (MSIS, MLWE uSVP / dual_hybrid, `e-s1.txt`), norm-proof exactness and Fiat–Shamir rounds (`e-s0.txt`) | soundness bits of the preset (query and total soundness, `PQZH.md`; `n2304-kmax4096` preset B: 127.40 bits total) |
| size limit | `MAX_PROOF` 98,304 B | `MAX_PROOF_PQZH` 262,144 B; `n2560-kmax16384` only: 327,680 B (owner 2026-10-23, built in 8c part 2 / 8d) |

**Not every set has PQZH.** Ligero's evaluation domains need q − 1 to be divisible by small radices, so whether PQZH
exists at a set depends on q:

| Set | PQZH |
|---|---|
| `n2048-kmax1024` | built and running (`pqz-ffi`, vectors) |
| `n2304-kmax4096` | built on branch `pqz-8c` (owner 2026-10-22): the **radix-7/17 preset** (radices 2 / 7 / 17 / 19 / 43 / 431, n 45,752, k 952, t 120), debit proofs 251,608–253,048 B (9–10 KB under 262,144), soundness 127.40 bits; the two other options below stay as fallbacks (re-prove under the limit: Cargo feature `fallback-retry`, never in production builds; per-set limit raise: documented only); wiring into `pqz-ffi` / vectors / gate is Task 8c part 2 |
| `n2560-kmax16384` | sizes are a model until Task 8c part 2 builds the crate here: debit proofs ≈ 301.9–303.6 KB exceed 262,144; no set-specific preset exists (q − 1 = 2^3 · 19 · 43 · 431 · 5,659 · 70,627 has no other small radix) and re-proving cannot close a 37–41 KB gap → **owner 2026-10-23: `MAX_PROOF_PQZH` = 327,680 B (320 KiB) for this set only** (per-set limit raise; decisions CTR-PQZ-10) |
| `n2816-kmax65536` | none: q − 1 = 2^3 · 3 · 1,789 · 419,563,967,521 has none of the radices 19 / 43 / 431 of PQZH's domains; PQZH here would need other domains |

Details per set: `<set>/PQZH.md` (on branch `pqz-8c` until it merges).

### When a PQZH proof exceeds `MAX_PROOF_PQZH`: three options

Found at `n2304-kmax4096` (plan 5h Task 8c, 2026-10-22): with the Ligero layout every other set uses, its debit proofs
were 263,784–265,236 B, 1.6–3 KB above 262,144. Three ways out, usable for any set that hits the same limit (research
note `docs/research/pqzh-set-a-proof-limit.md`; 8c notes call them A, B, C — the letters say nothing, the names below
are used here):

| Option (8c letter) | What it does | Cost / limits | Where used |
|---|---|---|---|
| **re-prove under the limit** (A) | keep the preset; when a proof comes out over the limit, prove again with fresh randomness until it fits. The proof length depends only on the query indices (public), so dropping a long proof reveals nothing about the witness (ZK argument in the research note) | extra prover runs: at `n2304-kmax4096` 0.9 % of runs for most forms, 27.6 % for op 7 M = 4 with the auditor (average 1.38 runs, at most 7 in 200); useless when the gap is larger than the spread of honest proof lengths (a few KB) | `n2304-kmax4096` fallback: Cargo feature `fallback-retry`, never in default or production builds; tag `pqzh-set-a-fallback-A` |
| **set-specific preset** (B; at `n2304-kmax4096` the radix-7/17 preset) | a new Ligero preset whose evaluation domain uses extra small radices of q − 1 (there 7 and 17, through the existing generic FFT stage), so the code length / message length / query count fit under the limit | needs q − 1 to have such radices; soundness must stay at or above the old preset's | **`n2304-kmax4096` production** (owner 2026-10-22): debits 251,608–253,048 B, soundness 127.40 bits, prover 4–5 % fewer products |
| **per-set limit raise** (C) | keep the preset; raise `MAX_PROOF_PQZH` for that set only (one constant per set in `pqz-stmt` and the prover) | larger precompile inputs (`MAX_INPUT` must cover 5 + largest statement + limit) and calldata; every chain running the set must accept the larger limit | **`n2560-kmax16384`** (owner 2026-10-23): 327,680 B (320 KiB), largest bound 303,590 B (24,090 B headroom), largest input 493,445 B ≤ `MAX_INPUT` 512 KiB; `n2304-kmax4096` fallback (≥ 265,236 B, documented only) |

Picking an option for a new set: try a set-specific preset first (no limit change, no extra prover runs); re-proving
fits only a gap of a few KB; the per-set raise always works but changes the chain-facing limits. Whatever is chosen is
an owner decision recorded in `docs/decisions.md` (CTR-PQZ-10) and in the set's `PQZH.md`.

## Selecting a set

| Build | How |
|---|---|
| C core (`pqzl/build.sh`, `sz/build.sh`, harnesses) | `PQZ_SET=<set>` (default `n2304-kmax4096`); `pqzl/set.sh` copies the set's headers into `build/include` |
| Rust `pqzl` | cargo feature `set-<set>` (default `set-n2304-kmax4096`; another set: `--no-default-features --features sv,set-<set>`) |
| `pqz-stmt` | cargo feature `set-<set>` (default `set-n2048-kmax1024`, the contracts' set until 8d) |
| `pqz-ffi` (precompile, prover API, `pqz-vectors`) | cargo feature `set-<set>` (default `set-n2048-kmax1024`, forwarded to `pqz-stmt` and `pqzl`); PQZH (`pqzh-ligero`) only with `set-n2048-kmax1024` |
| gate | `PQZ_SET=<set> scripts/capped pqz-core/gate.sh <label>` |

Each build checks that exactly one set is chosen (C: `pqz_set.h` from one directory; Rust: a compile error otherwise).

## Files of a set

| File | What | Made by |
|---|---|---|
| `set.toml` | the set's only input: n, `K_MAX`, q, `pqz_delta`, `kmlwe_min`, description, approval, `core_only` / `pqzh` / `frozen` | by hand |
| `pqz_set.h`, `rust/set.rs` | n, k, q, log2 q, Δ, `K_MAX`, digit / carry / noise widths, norm bounds, NTT roots, Barrett constants, the specialised verifier's CRT prime count | [`gen_set.py`](gen_set.py) (`--check` in the gate) |
| `set.json` | every derived constant the Python tools read (`pqz_kat.py`, `e_s0_set.py`, the tests' `core_only`) | `gen_set.py` |
| `PqzSet.sol` | the set's Solidity constants; `PQZ_SOL_INSTALL=1 make.sh <set> sol` copies it to `smartcontracts/evm/src/pqz/` (the `n2048-kmax1024` one until 8d) | `gen_set.py` |
| `<rel>_params.sage` | LaZer codegen specs of the 14 relations (reg, tx, tx0, burn, ds, dr, txm2 / 20 / 4 / 40 / 8 / 80, bench-only txm16 / 160) | `gen_set.py` (v3's have the shapes of `pqzl/params/*.sage`, the record) |
| `pqz_<rel>_params.h`, `codegen.txt` | LaZer codegen headers and the codegen log (`codegen-check.txt` for the frozen `n2048-kmax1024`: the regenerated headers byte-identical) | `make.sh <set> codegen` (LaZer 3330e48, pinned Sage image) |
| `rust/<rel>.rs`, `rust/mod.rs` | the headers' Rust form | `pqzl/params/to_rust.py` (`make.sh <set> rust`) |
| `e-s1.txt` | lattice-estimator check of every spec (MSIS β, hiding MLWE uSVP and dual_hybrid ≥ 450) | `pqzl/params/n-study/e_s1_n.sage` |
| `e-s0.txt` | set budget checks, exactness of the norm proofs per relation, per-round Fiat–Shamir soundness | [`e_s0_set.py`](e_s0_set.py) (`SET=<set> scripts/capped …/run_e_s0_set.sh`) |
| `lazer-3330e48-kat.json` | upstream LaZer golden arithmetic KAT at the set's q (the gate's `kat` step: pqz-core = upstream) | `pqzl/kat/build-lazer-dump.sh` |
| `SET.md`, `PQZH.md` | the set's numbers, approval, conditions; PQZH's preset and sizes (from 8c) | by hand |

`gen_set.py --all --check` (the gate's `rust` step) fails on a file in a set directory that is not in this table.

Vectors: `smartcontracts/vectors/pqz/` for `n2048-kmax1024` (read by the contracts until 8d),
`smartcontracts/vectors/pqz/<set>/` for every other set (`pqz-ffi/vectors/run.sh`, `PQZ_SET=<set>`).

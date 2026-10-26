# pqz-core/params — PQZ parameter sets

PQZ's lattice parameters live in **parameter sets**, one directory per set under [`sets/`](sets/README.md)
(owner 2026-10-21): parameter sets are per-directory, selected at compile time; one set per library build. The PQZL C
and Rust cores, `pqz-stmt`, `pqz-ffi` (precompile, prover API, `pqz-vectors`), the fuzz targets and `pqz_kat.py` take
every parameter-dependent number from the chosen set, PQZH (`pqzh-ligero`, its `pqzh_set.rs`) too since plan 5h Task 8c
part 2 (every set whose `set.toml` says `pqzh`; the precompile limits `MAX_PROOF_PQZH` / `MAX_INPUT` per set). Each
set has its own `proofSystemId`s (PQZL `…/v5`, PQZH `…/v3` since the R0 review fix of 2026-10-25; the table in
[`sets/README.md`](sets/README.md#proofsystemids-per-set-plan-5h-task-8d-part-1-bumped-by-the-r0-review-fix-2026-10-25)).

| Set | n | `K_MAX` | q | Status |
|---|---|---|---|---|
| [`n2048-kmax1024`](sets/n2048-kmax1024/SET.md) | 2048 | 1,024 | 2^42 − 215 | not recommended (owner 2026-10-25); the reference set, frozen until the R0 review fix (2026-10-25); its vectors are the top level of `smartcontracts/vectors/pqz/`, the contracts' set until plan 5h Task 8d part 2 |
| [`n2304-kmax4096`](sets/n2304-kmax4096/SET.md) | 2304 | 4,096 | 61,275,424,977,257 | the default, owner 2026-10-21: of the `pqzl` crate, `pqz-ffi`, `gate.sh` and the contracts' committed `PqzSet.sol`; the SCaaS testnet's set (image `2.2.0-pqz5`) |
| [`n2560-kmax16384`](sets/n2560-kmax16384/SET.md) | 2560 | 16,384 | 2^50 − 42,310,535 | shippable (customer chains may choose it): its own vectors, PQZH since 8c part 2 (`MAX_PROOF_PQZH` 327,680, every PQZH set's since 2026-10-25) |
| [`n2816-kmax65536`](sets/n2816-kmax65536/SET.md) | 2816 | 65,536 | 2^54 − 327 | research record; a full PQZL set for customers since plan 5h Task 8d part 1b (owner 2026-10-24): pqz-stmt, precompile, vectors, gate; no PQZH (none of the current Ligero radices divides q − 1; a radix-1,789 preset is unexplored, not in scope) |

## Adding a set

1. Write `sets/<set>/set.toml` (the set's only input: `n`, `k_max`, `q`, `pqz_delta`, `kmlwe_min`, `s_aud`,
   `description`, `[approval]` date and what; `max_input`, `roll_max`, the `proofSystemId` label `pqzl_id`; `pqzh` and,
   with PQZH, `pqzh_id` and `[pqzh_preset]`; `[pqzl_c]`; `core_only = true` for a set without pqz-stmt / precompile /
   vectors). The directory name is `n<n>-kmax<k_max>`.
2. Run `pqz-core/params/sets/make.sh <set> all` (environment: `PQZ_TOOLS` with the pinned estimator / LaZer checkouts,
   `PQZ_WORK` for the KAT build; heavy steps go through `scripts/capped`). Steps: `specs` (gen_set.py: the 14 codegen
   specs, `pqz_set.h`, `rust/set.rs`, `set.json`, `PqzSet.sol`, `pqzh_set.rs` for a set with PQZH, the crates' per-set
   feature lists and the Nethermind plugin's `PqzSetIds.cs`), `e_s1` (MSIS /
   MLWE β ≥ 450 per spec; stops and prints the `pqz_delta` / `kmlwe_min` to put into `set.toml` when they differ),
   `codegen` (LaZer headers), `rust` (their Rust form), `e_s0` (exactness, Fiat–Shamir rounds per relation), `kat`
   (upstream LaZer golden KAT at the set's q), `fixtures` (the Rust suite's cheating fixtures), `vectors`, `sol`, `gate`. Each step also runs alone:
   `make.sh <set> <step> [step ...]`.
3. Write `sets/<set>/SET.md` by hand (numbers, approval, conditions).

Build with the set: C `PQZ_SET=<set>` (`pqzl/build.sh`), Rust feature `set-<set>` (`--no-default-features`), the
contracts `smartcontracts/evm/script/pqz/at-set.sh <set>`, the gate `PQZ_SET=<set> scripts/capped pqz-core/gate.sh
[label]` (more in [`sets/README.md`](sets/README.md#selecting-a-set)). The research records of how parameters were chosen stay
in `pqz-core/pqzl/params/` (n-study, p16k, aprime, …).

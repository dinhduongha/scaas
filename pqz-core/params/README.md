# pqz-core/params — PQZ parameter sets

PQZ's lattice parameters live in **parameter sets**, one directory per set under [`sets/`](sets/README.md)
(owner 2026-10-21): parameter sets are per-directory, selected at compile time; one set per library build. The PQZL C
and Rust cores, `pqz-stmt`, `pqz-ffi` (precompile, prover API, `pqz-vectors`), the fuzz targets and `pqz_kat.py` take
every parameter-dependent number from the chosen set, PQZH (`pqzh-ligero`, its `pqzh_set.rs`) too since plan 5h Task 8c
part 2 (every set whose `set.toml` says `pqzh`; the precompile limits `MAX_PROOF_PQZH` / `MAX_INPUT` per set).

| Set | n | `K_MAX` | q | Status |
|---|---|---|---|---|
| [`n2048-kmax1024`](sets/n2048-kmax1024/SET.md) | 2048 | 1,024 | 2^42 − 215 | the frozen set (contracts, vectors at `smartcontracts/vectors/pqz/` until 8d) |
| [`n2304-kmax4096`](sets/n2304-kmax4096/SET.md) | 2304 | 4,096 | 61,275,424,977,257 | the default, owner 2026-10-21; the `pqzl` crate's default |
| [`n2560-kmax16384`](sets/n2560-kmax16384/SET.md) | 2560 | 16,384 | 2^50 − 42,310,535 | shippable (customer chains may choose it): its own vectors, PQZH since 8c part 2 (`MAX_PROOF_PQZH` 327,680) |
| [`n2816-kmax65536`](sets/n2816-kmax65536/SET.md) | 2816 | 65,536 | 2^54 − 327 | research record; a full PQZL set for customers since plan 5h Task 8d part 1b (owner 2026-10-24): pqz-stmt, precompile, vectors, gate; no PQZH (none of the current Ligero radices divides q − 1; a radix-1,789 preset is unexplored, not in scope) |

## Adding a set

1. Write `sets/<set>/set.toml` (the set's only input: `n`, `k_max`, `q`, `pqz_delta`, `kmlwe_min`, `description`,
   `[approval]` date and what; `core_only = true` for a set without pqz-stmt / precompile / vectors). The directory name is
   `n<n>-kmax<k_max>`.
2. Run `pqz-core/params/sets/make.sh <set> all` (environment: `PQZ_TOOLS` with the pinned estimator / LaZer checkouts,
   `PQZ_WORK` for the KAT build; heavy steps go through `scripts/capped`). Steps: `specs` (gen_set.py: the 14 codegen
   specs, `pqz_set.h`, `rust/set.rs`, `set.json`, `PqzSet.sol`, the crates' per-set feature lists), `e_s1` (MSIS /
   MLWE β ≥ 450 per spec; stops and prints the `pqz_delta` / `kmlwe_min` to put into `set.toml` when they differ),
   `codegen` (LaZer headers), `rust` (their Rust form), `e_s0` (exactness, Fiat–Shamir rounds per relation), `kat`
   (upstream LaZer golden KAT at the set's q), `vectors`, `sol`, `gate`. Each step also runs alone:
   `make.sh <set> <step> [step ...]`.
3. Write `sets/<set>/SET.md` by hand (numbers, approval, conditions).

Build with the set: C `PQZ_SET=<set>` (`pqzl/build.sh`), Rust feature `set-<set>` (`--no-default-features`), the
gate `PQZ_SET=<set> scripts/capped pqz-core/gate.sh <label>`. The research records of how parameters were chosen stay
in `pqz-core/pqzl/params/` (n-study, p16k, aprime, …).

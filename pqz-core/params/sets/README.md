# pqz-core/params/sets — PQZ parameter sets

Owner 2026-10-21: **parameter sets are per-directory, selected at compile time; one set per library build** (a
runtime choice between sets is deferred). Each directory `<set>/` holds every parameter-dependent input of the PQZL C
and Rust cores; the algorithm code uses only the named constants. Sets are named by n and `K_MAX`. PQZH adds its own
file per set in plan 5h Task 8c (`pqzh_set.rs`); until then PQZH exists for `n2048-kmax1024` only and is compiled out
of `pqz-ffi` / `pqz-vectors` for every other set. Adding a set: write `<set>/set.toml`, then `make.sh <set> all`.

| Set | n, k | q | `K_MAX` | Status | `SET.md` |
|---|---|---|---|---|---|
| `n2048-kmax1024` | 2048, 32 | 2^42 − 215 | 1,024 | the frozen v3 set: main's build, the committed vectors, the contracts until 8d | [SET.md](n2048-kmax1024/SET.md) |
| `n2304-kmax4096` | 2304, 36 | 61,275,424,977,257 (2^45.80) | 4,096 | set (a), owner 2026-10-21: the default of the `pqzl` crate and `gate.sh` | [SET.md](n2304-kmax4096/SET.md) |
| `n2560-kmax16384` | 2560, 40 | 2^50 − 42,310,535 | 16,384 | the 16k set (approved 2026-10-20, superseded as the default 2026-10-21): shippable for customer chains; full vectors + gate | [SET.md](n2560-kmax16384/SET.md) |

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
| `pqz_set.h`, `rust/set.rs` | n, k, q, log2 q, Δ, `K_MAX`, digit / carry / noise widths, norm bounds, NTT roots, Barrett constants, the specialised verifier's CRT prime count | [`gen_set.py`](gen_set.py) (`--check` in the gate) |
| `<rel>_params.sage` | LaZer codegen specs of the 14 relations (reg, tx, tx0, burn, ds, dr, txm2 / 20 / 4 / 40 / 8 / 80, bench-only txm16 / 160) | the set's generator (v3: `pqzl/params/*.sage`, the record) |
| `pqz_<rel>_params.h`, `rust/<rel>.rs` | LaZer codegen headers and their Rust form | `regen.sh` (LaZer 3330e48, pinned Sage image), `pqzl/params/to_rust.py` |
| `e-s1.txt` | lattice-estimator check of every spec (MSIS β, hiding MLWE uSVP and dual_hybrid ≥ 450) | `pqzl/params/n-study/e_s1_n.sage` |
| `e-s0.txt` | set budget checks, exactness of the norm proofs per relation, per-round Fiat–Shamir soundness | [`e_s0_set.py`](e_s0_set.py) (`SET=<set> scripts/capped …/run_e_s0_set.sh`) |
| `lazer-3330e48-kat.json` | upstream LaZer golden arithmetic KAT at the set's q (the gate's `kat` step: pqz-core = upstream) | `pqzl/kat/build-lazer-dump.sh` |
| `SET.md` | the set's numbers, approval, conditions | by hand |

Vectors: `smartcontracts/vectors/pqz/` for `n2048-kmax1024` (read by the contracts until 8d),
`smartcontracts/vectors/pqz/<set>/` for every other set (`pqz-ffi/vectors/run.sh`, `PQZ_SET=<set>`).

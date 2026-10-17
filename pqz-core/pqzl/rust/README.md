# pqzl — PQZL in pure Rust

A pure-Rust port of the PQZL C core (`pqz-core/pqzl/src` + `pqzl/lazer`, a LaZer fork): the lattice proof system of
SCaaS PQZ (pq-zero-knowledge.md §4, §5, §8). Goal: byte-for-byte equal to the C core — same proofs for the same
`(op, stmt, wit, rnd32)`, same verdicts on every input, same keys / Enc / Dec, native and wasm32 — so other chains
and applications can use the proof system without the C build. Plan: `docs/superpowers/plans/2026-10-17-pqzl-rust-port.md`.

Status: **port in progress** (Tasks 1-2 of 12: crate skeleton, API, C oracle; the arithmetic layer). Every API
function that is not ported yet returns `Err(Error::Internal)` / `false`.

## Layout

Crate-internal layers in the C core's order: `src/arith/` (`pqz_mpn.h`; LaZer's ints and int vectors with the
`pqz_glue.h` reductions; R_q and its incomplete NTT, `pqz_ntt.c`; dense and sparse vectors and matrices of polys),
`src/rand/` (the AES-256-CTR PRNG and the samplers), `src/coder.rs` (`dcompress.c`). `src/testkit.rs` holds the test
entry points (`#[doc(hidden)]`, not API): the arithmetic KAT of `pqzl/kat/lazer_dump.c`, which `src/bin/kat_dump.rs`
prints, and the Rust halves of the oracle tests. The C half of the vector test drives `poly_auto_self` in the NTT
domain, whose second loop pass writes the 64 words after the residue buffer (a C-core defect, the core is read-only
here): the shim gives that poly a double-size residue block, so the write stays in scratch it owns.

## API

Mirrors the C ABI `pqzl/src/pqz.h` (sizes, layouts, return codes): `Ctx::{new, prove, verify, verify_fast}`,
`keypair_from_secret`, `keygen`, `enc_seed`, `enc_group_seed`, `encrypt`, `decrypt_raw`, `dec`, `test_mutate`
(feature `test-hooks`). `Error { Internal, Input, Reject, Memory }` = the C core's codes 1, 3, 4 and arena exhaustion.
`#![no_std]` + `alloc`, `#![forbid(unsafe_code)]` (relaxed to `deny` only for the dev-only `c_oracle` module), no
floating point.

## Features

| Feature | |
|---|---|
| `sv` (default) | the specialised verifier, `Ctx::verify_fast` |
| `oversize` | R_TXM with M = 16 (bench only) |
| `test-hooks` | `test_mutate`; with `c-oracle` the C core is built with `-DPQZ_TEST_HOOKS` |
| `c-oracle` | dev / test only: `build.rs` compiles the C core (`../src ../lazer ../params`, build.sh's flags) plus the test entry points `tests/oracle_shim.c`, and `c_oracle::{c_prove, c_verify, c_verify_fast, c_keygen, c_enc_seed, c_dec, c_test_mutate}` and the layer wrappers (`c_ntt_*`, `c_polyvec_ops`) call them |

A default build compiles no C.

## Checks

```sh
scripts/capped pqz-core/pqzl/rust/run.sh <label>    # from the repo root; logs in pqzl/rust/runs/<label>-*.txt
```

Tests (release, `c-oracle,test-hooks`), the arithmetic KAT (`kat_dump` against the upstream golden file
`pqzl/kat/lazer-3330e48.json`, `kat/check.py`), clippy `-D clippy::float_arithmetic`, the wasm32 build.

## Licence

The repository's Vegan Community License 1.0 (`../../../LICENSE`). The crate ports LaZer-derived code: LaZer's MIT
notice is in `NOTICE` and `LICENSE-lazer`, which travel with every distribution. `publish = false` until the owner
rules (plan D7).

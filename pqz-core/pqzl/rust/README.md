# pqzl — PQZL in pure Rust

A pure-Rust port of the PQZL C core (`pqz-core/pqzl/src` + `pqzl/lazer`, a LaZer fork): the lattice proof system of
SCaaS PQZ (pq-zero-knowledge.md §4, §5, §8). Goal: byte-for-byte equal to the C core — same proofs for the same
`(op, stmt, wit, rnd32)`, same verdicts on every input, same keys / Enc / Dec, native and wasm32 — so other chains
and applications can use the proof system without the C build. Plan: `docs/superpowers/plans/2026-10-17-pqzl-rust-port.md`.

Status: **port in progress** (Tasks 1-9 of 12: crate skeleton, API, C oracle; the arithmetic layer; hashing,
rng and samplers; keys, Enc, Dec; the proof codec and `test_mutate`; the generated parameters; the generic verifier
`Ctx::verify`; the prover `Ctx::prove`; the specialised verifier `Ctx::verify_fast`). Every API function is ported.

## Layout

Crate-internal layers in the C core's order: `src/arith/` (`pqz_mpn.h`; LaZer's ints and int vectors with the
`pqz_glue.h` reductions; R_q and its incomplete NTT, `pqz_ntt.c`; dense and sparse vectors and matrices of polys),
`src/rand/` (SHAKE128 / SHAKE256 and the keys' CBD stream, the AES-256-CTR PRNG, the uniform, binomial and
Gaussian samplers, the rejection tests on `pqz_fixexp.h`'s integer exp), `src/coder.rs` (`dcompress.c`; the proof codec: `coder.c`'s bounded decoder / encoder as `pqz_rel.c`'s `encproof` /
`pqz_decproof` drive them, serialization v1, and the `pqz_test_mutate` hook; `bytes.c` has no caller in the core),
`src/params/` (generated, plan D8: one module per `pqzl/params/pqz_*_params.h`, written by `pqzl/params/to_rust.py`;
do not edit; `txm16` / `txm160` only with feature `oversize`),
`src/keys.rs` (`pqz_keys.c` and the ring work of `pqz_rel.c` it calls: A, `pqz_keypair_from_secret`, `pqz_encrypt`,
`pqz_decrypt_raw`; A is expanded per call, as there is no `pqz_init`), `src/proof/` (the LaZer proof layers the
relations use, prover and verifier: `abdlop.c`'s keys, commitment and commitment hash, `lnp-quad.c` /
`lnp-quad-many.c`, `lnp-tbox.c` with the P6-SZ / P6-L2 fixes and the P6-Z21 norm check; only the forms `pqz_rel.c`
passes), `src/rel.rs` (`pqz_rel.c`: the one relation table, statement parsing, the relation builders, the witness
parsers, the hedged prover seeds of CTR-PQZ-19, `pqz_prove`'s and `pqz_verify`'s dispatch; A and each relation's
ABDLOP keys are cached in `Ctx` at first use), `src/sv.rs` (`pqz_sv.c`, feature `sv`: the specialised verifier,
`pqz_verify_fast`; its prime tables, A in its form and each relation's tables are built in `Ctx` at the relation's
first `verify_fast`). `src/bench.rs` (`#[doc(hidden)]`, not API) holds
`pqzl/test/pqz_bench.c`'s statements, witnesses and steps: `src/bin/bench.rs` times them natively (`bench [n_prove]
[n_verify] [rel]`, the C bench's JSON lines with `proofs_fnv`; `PQZ_VERIFY=fast` times `verify_fast`), `wasm/` (a cdylib, raw exports) exports them to
`wasm/run_wasm.mjs` (`node wasm/run_wasm.mjs [n_prove] [n_verify] [rel]` after `cargo build --release --target
wasm32-unknown-unknown` in `wasm/`). `src/testkit.rs` holds the test
entry points (`#[doc(hidden)]`, not API): the arithmetic KAT of `pqzl/kat/lazer_dump.c`, which `src/bin/kat_dump.rs`
prints, KeyGen / Enc with lowered norm thresholds for `src/bin/keys_kat.rs` (`pqzl/test/pqz_keys_kat.c`'s JSON
lines), and the Rust halves of the oracle tests (`tests/oracle_arith.rs`, `tests/oracle_rand.rs`; the CBD vectors
`smartcontracts/vectors/pqz/cbd.json`). The C half of the vector test drives `poly_auto_self` in the NTT
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
| `c-oracle` | dev / test only: `build.rs` compiles the C core (`../src ../lazer ../params`, build.sh's flags) plus the test entry points `tests/oracle_shim.c`, and `c_oracle::{c_prove, c_verify, c_verify_fast, c_keygen, c_enc_seed, c_dec, c_keypair_from_secret, c_encrypt, c_decrypt_raw, c_enc_group_seed, c_test_mutate}` and the layer wrappers (`c_ntt_*`, `c_polyvec_ops`, `c_int_ops`, the samplers' `c_rng` .. `c_autostable`, `c_params`, `c_ghint`) call them |

A default build compiles no C.

## Checks

```sh
scripts/capped pqz-core/pqzl/rust/run.sh <label>    # from the repo root; logs in pqzl/rust/runs/<label>-*.txt
```

Tests (release, `c-oracle,test-hooks`; `tests/vectors.rs` checks the frozen keygen / enc / matrix vectors,
re-encodes every PQZL proof to itself, re-proves every PQZL proof from its witness and rnd32 to the same bytes,
refuses non-canonical statements in `prove`, verifies every PQZL proof, rejects every PQZL row of negative.json and the
cheating provers' proofs of `check_tbox_fixes.sh` (`tests/fixtures/cheating`, exported once by its `export.sh`),
`tests/oracle_verify.rs` `verify` = `pqz_verify` on those, on out-of-range challenges and on `test_mutate` outputs
(`PQZL_MUTATED_N`, default 280), `tests/oracle_prove.rs` `prove` = `pqz_prove` (bytes or error code) on honest and
altered witnesses of every relation code, `tests/oracle_keys.rs` keys, Enc and Dec against C, `tests/oracle_codec.rs`
`test_mutate` = `pqz_test_mutate` on every relation code, malformed encodings, and the hint functions,
`tests/sv_diff.rs` `verify_fast` = `verify` and = `pqz_verify_fast` on the cases of `pqzl/test/pqz_sv_diff.c` (ported:
the sample of `pqzl/sv/rel3.sh`, 3,484 cases over the six forms + every R_TXM shape; `PQZL_SV_DIFF` for other
arguments), on the cheating fixtures and on the PQZL vectors), the arithmetic KAT (`kat_dump` against the upstream golden file
`pqzl/kat/lazer-3330e48.json`, `kat/check.py`), the keys KAT (`keys_kat 1000` against
`smartcontracts/vectors/pqz/pqz_kat.py --c-keys`), the generated params (`python3 -I ../params/to_rust.py --check`;
`tests/oracle_params.rs` compares every field with the C headers), the prover's `proofs_fnv` against the C core's
runs (`bench 5 5 63` = `research/pqzl-measure/runs/tx0c-fnv-native.jsonl`, `bench 2 2 16320` = `l3a-native-fast.jsonl`,
`node wasm/run_wasm.mjs 3 1 63` = `tx0c-fnv-wasm.jsonl`; the two bench runs again with `PQZ_VERIFY=fast`), clippy `-D clippy::float_arithmetic`, the wasm32 build.

## Licence

The repository's Vegan Community License 1.0 (`../../../LICENSE`). The crate ports LaZer-derived code: LaZer's MIT
notice is in `NOTICE` and `LICENSE-lazer`, which travel with every distribution. `publish = false` until the owner
rules (plan D7).

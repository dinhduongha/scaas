# pqzl — PQZL in pure Rust

A pure-Rust port of the PQZL C core (`pqz-core/pqzl/src` + `pqzl/lazer`, a LaZer fork): the lattice proof system of
SCaaS PQZ (pq-zero-knowledge.md §4, §5, §8). Goal: byte-for-byte equal to the C core — same proofs for the same
`(op, stmt, wit, rnd32)`, same verdicts on every input, same keys / Enc / Dec, native and wasm32 — so other chains
and applications can use the proof system without the C build. Plan: `docs/superpowers/plans/2026-10-17-pqzl-rust-port.md`.

Status: **port in progress** (Tasks 1-10 of 12, with Task 10b's hardening follow-ups; crate skeleton, API, C oracle; the arithmetic layer; hashing,
rng and samplers; keys, Enc, Dec; the proof codec and `test_mutate`; the generated parameters; the generic verifier
`Ctx::verify`; the prover `Ctx::prove`; the specialised verifier `Ctx::verify_fast`; no globals, memory, threads,
wasm32, the `Ctx` key methods). Every API function is ported. Owner 2026-10-18: this crate becomes the production
PQZL core of the `PQZ` precompile (pqz-ffi switches to it in Task 11).

## Layout

Crate-internal layers in the C core's order: `src/arith/` (`pqz_mpn.h`; LaZer's ints and int vectors with the
`pqz_glue.h` reductions; R_q and its incomplete NTT, `pqz_ntt.c`; dense and sparse vectors and matrices of polys),
`src/rand/` (SHAKE128 / SHAKE256 and the keys' CBD stream, the AES-256-CTR PRNG, the uniform, binomial and
Gaussian samplers, the rejection tests on `pqz_fixexp.h`'s integer exp), `src/coder.rs` (`dcompress.c`; the proof codec: `coder.c`'s bounded decoder / encoder as `pqz_rel.c`'s `encproof` /
`pqz_decproof` drive them, serialization v1, and the `pqz_test_mutate` hook; `bytes.c` has no caller in the core),
`src/params/` (generated, plan D8: one module per `pqzl/params/pqz_*_params.h`, written by `pqzl/params/to_rust.py`;
do not edit; `txm16` / `txm160` only with feature `oversize`),
`src/keys.rs` (`pqz_keys.c` and the ring work of `pqz_rel.c` it calls: A, `pqz_keypair_from_secret`, `pqz_encrypt`,
`pqz_decrypt_raw`; the free functions expand A per call, as there is no `pqz_init`; the `Ctx` methods use the
`Ctx`'s A), `src/proof/` (the LaZer proof layers the
relations use, prover and verifier: `abdlop.c`'s keys, commitment and commitment hash, `lnp-quad.c` /
`lnp-quad-many.c`, `lnp-tbox.c` with the P6-SZ / P6-L2 fixes and the P6-Z21 norm check; only the forms `pqz_rel.c`
passes), `src/rel.rs` (`pqz_rel.c`: the one relation table, statement parsing, the relation builders, the witness
parsers, the hedged prover seeds of CTR-PQZ-19, `pqz_prove`'s and `pqz_verify`'s dispatch; A and each relation's
ABDLOP keys are cached in `Ctx` at first use), `src/sv.rs` (`pqz_sv.c`, feature `sv`: the specialised verifier,
`pqz_verify_fast`; its prime tables, A in its form and each relation's tables are built in `Ctx` at the relation's
first `verify_fast`). `src/bench.rs` (feature `bench`, `#[doc(hidden)]`, not API) holds
`pqzl/test/pqz_bench.c`'s statements, witnesses and steps: `src/bin/bench.rs` times them natively (`bench [n_prove]
[n_verify] [rel]`, the C bench's JSON lines with `proofs_fnv`; `PQZ_VERIFY=fast` times `verify_fast`), `wasm/` (a cdylib, raw exports) exports them to
`wasm/run_wasm.mjs` (`node wasm/run_wasm.mjs [n_prove] [n_verify] [rel]` after `cargo build --release --target
wasm32-unknown-unknown` in `wasm/`; `PQZ_VERIFY=fast` for `verify_fast`), and `wasm/run_vectors.mjs` replays the
vectors in wasm32 (prove, verify, verify_fast; the digest lines equal the native ones; the shadow stack's use per
operation). `src/testkit.rs` (feature `test-hooks`, also built with `c-oracle`) holds the test entry points
(`#[doc(hidden)]`, not API): the arithmetic KAT of `pqzl/kat/lazer_dump.c`, which `src/bin/kat_dump.rs`
prints, KeyGen / Enc with lowered norm thresholds for `src/bin/keys_kat.rs` (`pqzl/test/pqz_keys_kat.c`'s JSON
lines), and the Rust halves of the oracle tests (`tests/oracle_arith.rs`, `tests/oracle_rand.rs`; the CBD vectors
`smartcontracts/vectors/pqz/cbd.json`).

## API

Mirrors the C ABI `pqzl/src/pqz.h` (sizes, layouts, return codes): `Ctx::{new, prove, verify, verify_fast}`,
`keypair_from_secret`, `keygen`, `enc_seed`, `enc_group_seed`, `encrypt`, `decrypt_raw`, `dec`, `test_mutate`
(feature `test-hooks`). `Ctx::{keygen, keypair_from_secret, encrypt, enc_seed}` take the same arguments and give
the same results as the free functions, with the `Ctx`'s A (expanded once; for servers that encrypt in bulk).
`Error { Internal, Input, Reject, Memory }` = the C core's codes 1, 3, 4 and arena exhaustion.
`#![no_std]` + `alloc`, `#![forbid(unsafe_code)]` (relaxed to `deny` only for the dev-only `c_oracle` module), no
floating point.

- No globals: a `Ctx` holds the caches (A, each relation's keys, the specialised verifier's tables). Every call
  takes `&mut self`; one `Ctx` per thread needs no lock, and a `Ctx` is `Send` (`tests/threads.rs`). With feature
  `sv` a `Ctx` is about 41 KB inline: keep it in a `Box`, a static or a thread-local.
- Memory: every buffer that scales with the input is reserved with `try_reserve`; running out is `Error::Memory`
  from `prove` and false from the verifiers, never a panic or an abort, and the `Ctx` stays usable
  (`tests/memory.rs`, a test-only counting / capping allocator). Peak heap (release, cold `Ctx`): R_TX prove 63 MB
  (the C arena: 312 MB), R_TXM8 prove 115 MB, R_TX verify 63 MB, R_TX verify_fast 11 MB (1.2 MB warm).
- wasm32: `prove` of op 7 with M > `WASM_MAX_LEGS` (4) is `Error::Input` (pqz-ffi's limit; whether the Rust
  backend can take 8 is the D6 question below).
- Secrets: the prover's seeds, the witness vector s1, the commitment randomness s2 and `dec`'s w are cleared after
  use (`fill` + `black_box`, where C calls `explicit_bzero`). Best effort, not guaranteed: without unsafe code and
  without a zeroize crate the compiler may elide the stores, and copies elsewhere are not cleared.

## Features

| Feature | |
|---|---|
| `sv` (default) | the specialised verifier, `Ctx::verify_fast` |
| `oversize` | R_TXM with M = 16 (bench only) |
| `test-hooks` | `test_mutate`, the `testkit` module (`kat_dump`, `keys_kat`); with `c-oracle` the C core is built with `-DPQZ_TEST_HOOKS` |
| `bench` | the `bench` module (`src/bin/bench.rs`, `wasm/`) |
| `wasm-m8` | bench builds only (implies `bench`): `WASM_MAX_LEGS` = `TXM_MAX_LEGS`, so wasm32 proves op 7 with M = 8 (16 with `oversize`); for the measurement of the wasm32 limit (D6 below), never in a production build |
| `c-oracle` | dev / test only: `build.rs` compiles the C core (`../src ../lazer ../params`, build.sh's flags) plus the test entry points `tests/oracle_shim.c`, and `c_oracle::{c_prove, c_verify, c_verify_fast, c_keygen, c_enc_seed, c_dec, c_keypair_from_secret, c_encrypt, c_decrypt_raw, c_enc_group_seed, c_test_mutate}` and the layer wrappers (`c_ntt_*`, `c_polyvec_ops`, `c_int_ops`, the samplers' `c_rng` .. `c_autostable`, `c_params`, `c_ghint`) call them |

A default build compiles no C and has neither test entry points nor the bench.

## Checks

```sh
scripts/capped pqz-core/pqzl/rust/run.sh <label>    # from the repo root; logs in pqzl/rust/runs/<label>-*.txt
```

Tests (release, `c-oracle,test-hooks`; `tests/vectors.rs` checks the frozen keygen / enc / matrix vectors,
re-encodes every PQZL proof to itself, re-proves every PQZL proof from its witness and rnd32 to the same bytes,
refuses non-canonical statements in `prove`, verifies every PQZL proof, rejects every PQZL row of negative.json and the
cheating provers' proofs of `check_tbox_fixes.sh` and of `tests/fixtures/cheating/z34poc.sh` (z3 / z4 over their bounds;
`tests/fixtures/cheating`, exported once by its `export.sh`),
`tests/oracle_verify.rs` `verify` = `pqz_verify` on those, on out-of-range challenges and on `test_mutate` outputs
(`PQZL_MUTATED_N`, default 280), `tests/oracle_prove.rs` `prove` = `pqz_prove` (bytes or error code) on honest and
altered witnesses of every relation code, `tests/oracle_keys.rs` keys, Enc and Dec against C, `tests/oracle_codec.rs`
`test_mutate` = `pqz_test_mutate` on every relation code, malformed encodings, and the hint functions,
`tests/sv_diff.rs` `verify_fast` = `verify` and = `pqz_verify_fast` on the cases of `pqzl/test/pqz_sv_diff.c` (ported:
the sample of `pqzl/sv/rel3.sh`, 3,484 cases over the six forms + every R_TXM shape; `PQZL_SV_DIFF` for other
arguments), on the cheating fixtures and on the PQZL vectors), `tests/keys.rs` the `Ctx` key methods = the free
functions (also after verify / verify_fast on the same `Ctx`), `tests/memory.rs` the peak heap per relation and
operation (`peak_per_op`) and exhaustion = `Error::Memory` / false with the `Ctx` usable after, under caps and single
denied allocations, for every relation, operation and the keys (`exhaustion_is_error`; `PQZL_MEM_SWEEP`,
`PQZL_MEM_THREADS`, `PQZL_MEM_TRACE`), `tests/threads.rs` 8 threads on separate `Ctx`s and on one handed-off `Ctx` =
the sequential results), the arithmetic KAT (`kat_dump` against the upstream golden file
`pqzl/kat/lazer-3330e48.json`, `kat/check.py`), the keys KAT (`keys_kat 1000` against
`smartcontracts/vectors/pqz/pqz_kat.py --c-keys`; again with `keys_kat 1000 ctx` through the `Ctx` methods, the same
lines), the generated params (`python3 -I ../params/to_rust.py --check`;
`tests/oracle_params.rs` compares every field with the C headers), the prover's `proofs_fnv` against the C core's
runs (`bench 5 5 63` = `research/pqzl-measure/runs/tx0c-fnv-native.jsonl`, `bench 2 2 16320` = `l3a-native-fast.jsonl`,
`node wasm/run_wasm.mjs 3 1 63` = `tx0c-fnv-wasm.jsonl`; the bench runs again with `PQZ_VERIFY=fast`, natively and
in wasm32), native = wasm32 on the vectors (`node wasm/run_vectors.mjs`: proofs, verify and verify_fast verdicts of
every PQZL vector and negative row; op 7 M = 8 prove refused; the shadow stack's use), clippy `-D
clippy::float_arithmetic` (production build, all features, `wasm/`), the wasm32 build.

## D6: Rust against C (plan D6, Task 12)

**Pending D6 (Task 12).** The figures below come from one run, `d6.sh`, that measures the C core and this crate in
the same session on the same machine. The earlier Rust runs (`runs/t8-*` to `runs/t10b-*`) and the frozen C runs
were measured at different times, so their times are **not comparable** and are not used here. D6 is reported, not a
gate: the owner uses it for the production choice.

Layout (`results.py d6` writes it to `runs/<label>/results-d6.md`; one C row and one Rust row per relation, for the
six forms and the eight built `R_TXM` shapes). Times are p50 / p99 in ms; verify p99 is the larger of the honest and
the adversarial p99, as in STATUS.md.

| relation | core | prove native | prove wasm32 | verify native | verify wasm32 | verify_fast native | verify_fast wasm32 | prove peak native (MiB) | prove peak wasm32 (MiB) |
|---|---|---|---|---|---|---|---|---|---|
| `R_REG` | C | pending D6 (Task 12) | pending D6 | pending D6 | pending D6 | pending D6 | pending D6 | pending D6 | pending D6 |
| `R_REG` | Rust | pending D6 (Task 12) | pending D6 | pending D6 | pending D6 | pending D6 | pending D6 | pending D6 | pending D6 |
| `R_TX`, `R_BURN`, `R_DS`, `R_DR`, `R_TX0` | C, Rust | pending D6 (Task 12) | | | | | | | |
| `R_TXM1` … `R_TXM8_0` (8 shapes) | C, Rust | pending D6 (Task 12) | | | | | | | |

- **Peak memory.** Native: the C core's arena peak against this crate's heap peak (the counting allocator of
  `tests/memory.rs`, cold `Ctx`). wasm32: the C arena peak (the prover build without the specialised verifier) against
  the module's linear memory after the proves, one relation per process. That memory also holds the bench's
  statements and witnesses for every relation, so it is an upper bound.
- Rust-only facts, which are not comparisons: the heap peaks of run `t10b` (2026-10-18, `peak_per_op`, prove from a
  cold `Ctx`, bytes) are R_REG 23,529,344, R_TX 62,903,248, R_BURN 60,519,936, R_DS 24,442,192, R_DR 25,597,312,
  R_TX0 62,006,944, M = 4 on 69,982,472, M = 8 on 115,489,848, M = 8 off 102,718,072.
- The run also checks that the C and Rust `proofs_fnv` are equal for each relation (the same n), so both sides timed
  the same proofs. It also runs `ffi_bench` on both `pqz-ffi` backends (C and `pqzl-rust`), for README §5.3.

### The wasm32 op 7 limit (owner 2026-10-18: "if it is enough, raise it")

wasm32 proves op 7 only up to M = 4: `pqzl::WASM_MAX_LEGS` and `pqz-ffi`'s `WASM_PQZL_MAX_LEGS`. That limit comes from
the C core's arena, where M = 8 peaks at 495.3 MiB, over the browser's 256 MiB. `d6.sh` measures this crate's wasm32
prove of M = 8, with the auditor on and off, in a bench build with the limit lifted (feature `wasm-m8`). It records
the p50 time and the linear-memory peak.

- **Enough** means both of these hold:
  - the M = 8 peak is ≤ 255.6 MiB (268,012,304 B, the C core's wasm32 M = 4 peak, `R_TXM4` auditor on,
    `artifact/runs/s6-docker-multi`; wasm32 already accepts that budget);
  - native = wasm32 on the M = 8 vector proofs (`run_vectors.mjs` with `PQZL_WASM_MAX_LEGS=8` against a native
    replay built with `wasm-m8`: the digest lines are equal and the M = 8 rows carry a proof digest).
- If enough: set both constants to 8 for the Rust backend (the C backend, now opt-in, keeps 4). The wasm32 replay
  then proves the three M = 8 rows instead of refusing them. Record the change in `docs/decisions.md` CTR-PQZ-09 with
  the measured figures.
- If not: keep 4, and record the figures and the reason.
- Outcome: **pending D6 (Task 12)**. `results-d6.md` prints it as the last check ("wasm32 op 7 M = 8 (Task 12)").

### How to run the D6 measurement

Run it after Task 11's fuzz campaign has finished, on an idle machine (no other capped jobs, builds or containers),
from the repository root. It is one capped job of about 1–1.5 h:

```sh
scripts/capped pqz-core/pqzl/rust/d6.sh d6      # -> pqz-core/pqzl/rust/runs/d6/ (results-d6.md, every raw file)
```

`d6.sh` builds the C core (`pqzl/build.sh all`, the wasm prover without SV), the native `bench` and the wasm32 module
(feature `wasm-m8`). Then, for each relation and in one process per relation, core and backend, it runs C and then
Rust in turn:

- native generic: `pqz_bench` / `bench`, NP = 10 proves, NV = 100 verifies;
- native `verify_fast`: 2 proves, NF = 200 verifies;
- wasm32 generic: `test/run_wasm.mjs` / `wasm/run_wasm.mjs`, NPW = 5 proves, NVW = 30 verifies;
- wasm32 `verify_fast`: 2 proves, 100 verifies;
- the C wasm32 arena peak.

These are the `reproduce.sh --full` counts; `NP= NV= NPW= NVW= NF=` override them. After that it runs
`ffi_bench 200` on both `pqz-ffi` backends (`FFI_C` / `FFI_RUST`: the feature lists, for after Task 11's default
switch), `tests/memory.rs peak_per_op` (heap peaks) and the M = 8 replay. Finally it runs
`python3 -I ../../artifact/results.py d6 runs/d6`. Commit `runs/d6/` (text files), then copy the table here, into
STATUS.md and into the Rust rows of README §5 and `artifact/README.md`. Label them "run `d6`, <date>".

## Licence

The repository's Vegan Community License 1.0 (`../../../LICENSE`). The crate ports LaZer-derived code: LaZer's MIT
notice is in `NOTICE` and `LICENSE-lazer`, which travel with every distribution. `publish = false` until the owner
rules (plan D7).

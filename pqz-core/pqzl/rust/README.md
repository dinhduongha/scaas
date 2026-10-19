# pqzl — PQZL in pure Rust

A pure-Rust port of the PQZL C core (`pqz-core/pqzl/src` + `pqzl/lazer`, a LaZer fork): the lattice proof system of
SCaaS PQZ (pq-zero-knowledge.md §4, §5, §8). Goal: byte-for-byte equal to the C core — same proofs for the same
`(op, stmt, wit, rnd32)`, same verdicts on every input, same keys / Enc / Dec, native and wasm32 — so other chains
and applications can use the proof system without the C build. Plan: `docs/superpowers/plans/2026-10-17-pqzl-rust-port.md`.

Status: **port done** (Tasks 1–12 and 10b of the plan, 2026-10-18/19): every API function is ported and checked
against the C core (vectors re-proved byte-equal, the C oracle tests, the 2 h fuzz differential, the package's
"Rust = C" stage). Owner 2026-10-18: this crate is the production PQZL core of the `PQZ` precompile; `pqz-ffi` builds
it by default (feature `pqzl-rust`, Task 11), the C core is the opt-in reference. Chain 7622 keeps the C-backed node
image until the live roll-out.

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
`lnp-quad-many.c`, `lnp-tbox.c` with the P6-SZ / P6-L2 fixes, the P6-Z21 norm check and the P6-FS transcript rounds
of PQZL v3, `hash_z34` and `hash_h` in `proof/tbox.rs`; only the forms `pqz_rel.c` passes), `src/rel.rs` (`pqz_rel.c`: the one relation table, statement parsing, the relation builders, the witness
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
`Ctx::{try_verify, try_verify_fast}` (the verdict, or `Error::Memory` when an allocation failed, kept apart from
false: a node must treat it as its own fault, not as an invalid proof; pqz-ffi maps it to a node fault),
`keypair_from_secret`, `keygen`, `enc_seed`, `enc_group_seed`, `encrypt`, `decrypt_raw`, `dec`, `test_mutate`
(feature `test-hooks`). `Ctx::{keygen, keypair_from_secret, encrypt, enc_seed}` take the same arguments and give
the same results as the free functions, with the `Ctx`'s A (expanded once; for servers that encrypt in bulk).
`Error { Internal, Input, Reject, Memory }` = the C core's codes 1, 3, 4 and arena exhaustion. `PROOF_SYSTEM_ID` =
`keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v3")` (`0x8079d65b…16baef`, = `PQZ_PROOF_SYSTEM_ID` of `pqz.h`; v2
retired 2026-10-19, pq-zero-knowledge.md §8).
`#![no_std]` + `alloc`, `#![forbid(unsafe_code)]` (relaxed to `deny` only for the dev-only `c_oracle` module), no
floating point.

- No globals: a `Ctx` holds the caches (A, each relation's keys, the specialised verifier's tables). Every call
  takes `&mut self`; one `Ctx` per thread needs no lock, and a `Ctx` is `Send` (`tests/threads.rs`). With feature
  `sv` a `Ctx` is about 41 KB inline: keep it in a `Box`, a static or a thread-local.
- Memory: every buffer that scales with the input is reserved with `try_reserve`; running out is `Error::Memory`
  from `prove`, `try_verify` and `try_verify_fast` and false from `verify` / `verify_fast`, never a panic or an
  abort, and the `Ctx` stays usable
  (`tests/memory.rs`, a test-only counting / capping allocator). Peak heap (release, cold `Ctx`): R_TX prove 63 MB
  (the C arena: 312 MB), R_TXM8 prove 115 MB, R_TX verify 63 MB, R_TX verify_fast 11 MB (1.2 MB warm).
- wasm32: `prove` of op 7 with M > `WASM_MAX_LEGS` (8) is `Error::Input` (= pqz-ffi's `WASM_PQZL_MAX_LEGS` on the
  Rust backend; raised from 4 in Task 12, see "The wasm32 op 7 limit" below; the C backend keeps 4).
- PQZL v3 (P6-FS, [lazer#28](https://github.com/lazer-crypto/lazer/issues/28)): `proof/tbox.rs` `hash_z34` absorbs
  `grandom3(z3) ‖ grandom3(z4)` (one `Coder` session over centred copies, the proof's encoding) after `compute_z34` /
  a successful `check_z34`; the result `hz` seeds V3 / V4 and the tg round, while the JL rows R / R' stay on `cseed`
  (`sz_z3` / `sz_z4` take both seeds). `hash_h` absorbs `urandom3(h mod q)` before `quad::many_prove` / `many_verify`,
  the seed of μ and the final challenge. `sv.rs` does the same (`hz` for V3 / V4, `cseed` for the JL rows, μ and the
  final round from `hash2`). Byte-equal to the C core's `_lnp_tbox_hash_z34` / `_lnp_tbox_hash_h` (run `fs3`).
- Secrets: the prover's seeds, the witness vector s1, the commitment randomness s2 and `dec`'s w are cleared after
  use (`fill` + `black_box`, where C calls `explicit_bzero`), and the AES-CTR key schedules and SHAKE sponges when
  they are dropped (re-keyed with zeros / replaced by an empty sponge, where C calls `_aes256ctr_clear` /
  `_shake128_clear`). Best effort, not guaranteed: without unsafe code and
  without a zeroize crate the compiler may elide the stores, and copies elsewhere are not cleared.

## Features

| Feature | |
|---|---|
| `sv` (default) | the specialised verifier, `Ctx::verify_fast` |
| `oversize` | R_TXM with M = 16 (bench only) |
| `test-hooks` | `test_mutate` (kind 14, z3 ± 1, for the P6-FS test), `fs_trace_take` (below), the `testkit` module (`kat_dump`, `keys_kat`); with `c-oracle` the C core is built with `-DPQZ_TEST_HOOKS` |
| `bench` | the `bench` module (`src/bin/bench.rs`, `wasm/`) |
| `wasm-m8` | bench builds only (implies `bench`): `WASM_MAX_LEGS` = `TXM_MAX_LEGS`, so wasm32 proves op 7 with M = 16 with `oversize` (without it, 8 = the default since Task 12; the D6 measurement of the limit was built with it), never in a production build |
| `c-oracle` | dev / test only: `build.rs` compiles the C core (`../src ../lazer ../params`, build.sh's flags) plus the test entry points `tests/oracle_shim.c`, and `c_oracle::{c_prove, c_verify, c_verify_fast, c_keygen, c_enc_seed, c_dec, c_keypair_from_secret, c_encrypt, c_decrypt_raw, c_enc_group_seed, c_test_mutate}` and the layer wrappers (`c_ntt_*`, `c_polyvec_ops`, `c_int_ops`, the samplers' `c_rng` .. `c_autostable`, `c_params`, `c_ghint`) call them |

A default build compiles no C and has neither test entry points nor the bench.

`fs_trace_take() -> Vec<(u8, [u8; 32], u64)>` (feature `test-hooks`) is the P6-FS trace, the Rust side of the C core's
`pqz_sz_trace_fn` under `-DPQZ_SZ_TRACE`: `(kind, seed, dom)` for each Fiat–Shamir challenge of this thread's
`prove` / `verify` / `verify_fast`, kind 2 / 3 = the seed and domain of V4 / V3, kind 5 = the seed of μ (generic code:
also of the final challenge), and `sv.rs` records kind + 10 (12 / 13 / 15). It returns the records since the last
call and clears them. The recorder (`fstrace`, a `thread_local!` vector) is **off until the thread's first
`fs_trace_take`**, which returns nothing, so other `test-hooks` builds (`pqz-ffi`'s `fuzz`, the fault hooks) never
record; a record whose allocation fails is dropped, and the test counts a missing record as a failure.

## Checks

```sh
scripts/capped pqz-core/pqzl/rust/run.sh <label>    # from the repo root; logs in pqzl/rust/runs/<label>-*.txt
```

Tests (release, `c-oracle,test-hooks`; `tests/vectors.rs` checks the frozen keygen / enc / matrix vectors,
re-encodes every PQZL proof to itself, re-proves every PQZL proof from its witness and rnd32 to the same bytes,
refuses non-canonical statements in `prove`, verifies every PQZL proof, rejects every PQZL row of negative.json and the
cheating provers' proofs of `check_tbox_fixes.sh` and of `tests/fixtures/cheating/z34poc.sh` (z3 / z4 over their bounds;
`tests/fixtures/cheating`, exported once by its `export.sh`),
`tests/fs_bind.rs` the P6-FS binding test (as `pqzl/sz/fs_bind.c`: one honest R_REG proof and its h- (kind 7), z3-
(kind 14) and z4-changed (kind 5 at the bound) re-encodings; in `verify` and `verify_fast` the V3 / V4 seeds change
with z3 and z4 and the μ seed with h, 12 checks, a missing record fails; observation only),
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
runs (PQZL v3 since 2026-10-19: `bench 5 5 63` = `research/pqzl-measure/runs/fs4-fnv-native.jsonl`, `bench 2 2 16320`
= `fs4-fnv-native-16320.jsonl`, `node wasm/run_wasm.mjs 3 1 63` = `fs4-fnv-wasm.jsonl`; under v2 they were
`tx0c-fnv-native`, `l3a-native-fast`, `tx0c-fnv-wasm`; the bench runs again with `PQZ_VERIFY=fast`, natively and
in wasm32), native = wasm32 on the vectors (`node wasm/run_vectors.mjs`: proofs, verify and verify_fast verdicts of
every PQZL vector and negative row, op 7 M = 8 proved too; the shadow stack's use), clippy `-D
clippy::float_arithmetic` (production build, all features, `wasm/`), the wasm32 build.

## D6: Rust against C (plan D6, Task 12)

Run `d6` (2026-10-18, `scripts/capped pqz-core/pqzl/rust/d6.sh d6`, files in `runs/d6/`, table `runs/d6/results-d6.md`)
measured the C core and this crate in the same session on the same machine (AMD Ryzen 5 7235HS, clang 18.1.3,
rustc 1.97.1, node v26.8.1). The earlier Rust runs (`runs/t8-*` to `runs/t10b-*`) and the frozen C runs were
measured at different times, so their times are **not comparable** and are not used here. D6 is reported, not a
gate: the owner uses it for the production choice. Every bench reported `fails 0`, and every relation's `proofs_fnv`
is the same for both cores (native n = 10, wasm32 n = 5), so both sides timed the same proofs. D6 measured
`proofSystemId` v2. PQZL v3 (2026-10-19) adds two hashes per proof and, with the z2 rejection fix D-2, about twice
the z1 / z2 rejection attempts, so the prove times above are v2 figures; the v3 times are to be re-measured (plan
`pqzl-fs3` Task 13; first C figures in `pqz-core/STATUS.md`, section "PQZL v3"). Verify does no rejection sampling.

Times are p50 / p99 in ms (verify p99: the larger of the honest and the adversarial p99, as in STATUS.md). Samples:
native 10 proves / 100 verifies, wasm32 5 / 30, verify_fast 200 native / 100 wasm32 (the `reproduce.sh --full`
counts), one process per relation, core and backend, the C core then the crate each time.

| relation | core | prove native | prove wasm32 | verify native | verify wasm32 | verify_fast native | verify_fast wasm32 | prove peak native (MiB) | prove peak wasm32 (MiB) |
|---|---|---|---|---|---|---|---|---|---|
| `R_REG` | C | 315.5 / 368.0 | 499.1 / 555.8 | 177.2 / 198.6 | 241.1 / 276.2 | 4.0 / 5.9 | 7.1 / 9.2 | 91.1 | 70.3 |
| `R_REG` | Rust | 202.8 / 213.5 | 507.4 / 765.5 | 80.9 / 95.5 | 179.8 / 201.2 | 3.2 / 4.7 | 13.1 / 16.4 | 22.4 | 27.8 |
| `R_TX` | C | 982.8 / 1,295.9 | 1,460.0 / 1,490.1 | 674.4 / 729.3 | 848.5 / 881.0 | 8.5 / 11.4 | 13.6 / 17.5 | 290.1 | 221.1 |
| `R_TX` | Rust | 529.4 / 835.6 | 1,344.0 / 1,635.2 | 277.9 / 309.6 | 525.1 / 561.0 | 6.3 / 8.9 | 26.7 / 32.0 | 60.0 | 68.9 |
| `R_BURN` | C | 900.5 / 1,196.4 | 1,368.6 / 1,404.5 | 577.2 / 646.3 | 747.5 / 864.4 | 8.0 / 11.0 | 13.0 / 16.1 | 275.5 | 210.2 |
| `R_BURN` | Rust | 515.6 / 800.1 | 1,316.5 / 1,629.9 | 237.6 / 270.1 | 473.9 / 501.7 | 6.1 / 8.4 | 26.3 / 31.9 | 57.7 | 67.1 |
| `R_DS` | C | 384.3 / 448.6 | 742.8 / 760.4 | 218.3 / 241.7 | 282.5 / 311.9 | 4.2 / 6.2 | 7.3 / 9.9 | 95.1 | 73.3 |
| `R_DS` | Rust | 230.1 / 276.4 | 904.0 / 954.9 | 102.5 / 127.3 | 213.2 / 233.3 | 3.4 / 5.1 | 13.6 / 16.5 | 23.3 | 28.6 |
| `R_DR` | C | 417.1 / 487.2 | 637.4 / 730.4 | 210.4 / 234.6 | 282.2 / 307.2 | 4.4 / 6.5 | 7.8 / 9.9 | 102.7 | 79.1 |
| `R_DR` | Rust | 261.9 / 322.2 | 631.3 / 989.9 | 102.1 / 125.6 | 213.8 / 226.3 | 3.5 / 5.5 | 14.4 / 18.6 | 24.4 | 29.7 |
| `R_TX0` | C | 934.1 / 1,164.3 | 1,484.9 / 2,010.5 | 623.9 / 725.3 | 930.0 / 998.2 | 8.2 / 11.1 | 13.4 / 17.8 | 284.2 | 216.7 |
| `R_TX0` | Rust | 471.8 / 716.5 | 1,821.6 / 2,793.7 | 236.7 / 388.3 | 521.3 / 684.7 | 6.2 / 8.6 | 27.1 / 37.1 | 59.1 | 68.4 |
| `R_TXM1` | C | 1,018.9 / 1,281.3 | 1,964.9 / 1,997.8 | 677.1 / 1,090.5 | 986.8 / 1,332.2 | 10.9 / 14.7 | 13.5 / 21.0 | 290.1 | 221.1 |
| `R_TXM1` | Rust | 572.2 / 860.9 | 1,744.1 / 1,768.5 | 339.1 / 467.6 | 524.4 / 777.5 | 9.0 / 11.7 | 26.7 / 29.8 | 60.0 | 68.9 |
| `R_TXM2` | C | 1,160.7 / 1,318.2 | 1,598.4 / 2,110.6 | 866.7 / 1,509.7 | 1,006.6 / 1,489.9 | 9.1 / 11.7 | 15.2 / 23.1 | 305.2 | 232.3 |
| `R_TXM2` | Rust | 543.6 / 830.8 | 1,407.2 / 2,679.0 | 317.7 / 467.7 | 616.2 / 656.2 | 6.9 / 9.5 | 28.6 / 36.4 | 62.1 | 70.9 |
| `R_TXM4` | C | 1,778.9 / 2,069.3 | 2,105.8 / 2,427.6 | 1,039.5 / 1,326.8 | 1,253.3 / 1,475.1 | 11.6 / 15.2 | 15.8 / 20.2 | 336.6 | 255.6 |
| `R_TXM4` | Rust | 799.3 / 926.3 | 2,549.2 / 2,882.0 | 411.0 / 529.6 | 743.1 / 853.3 | 7.3 / 10.0 | 30.4 / 38.8 | 66.7 | 77.2 |
| `R_TXM8` ¹ | C | 2,825.4 / 3,195.2 | 3,300.1 / 3,333.6 | 2,441.2 / 2,633.2 | 2,607.3 / 2,718.4 | 14.1 / 17.9 | 23.1 / 29.0 | 655.6 | 495.3 |
| `R_TXM8` ¹ | Rust | 1,127.5 / 1,386.3 | 2,393.3 / 2,672.7 | 830.3 / 899.4 | 1,350.6 / 1,393.1 | 10.5 / 13.9 | 44.7 / 51.0 | 110.1 | 117.4 |
| `R_TXM1_0` ¹ | C | 893.3 / 1,048.5 | 1,244.9 / 1,281.2 | 628.1 / 681.3 | 804.4 / 853.6 | 8.3 / 11.1 | 13.6 / 16.9 | 284.2 | 216.7 |
| `R_TXM1_0` ¹ | Rust | 448.6 / 617.8 | 1,237.3 / 1,304.7 | 243.2 / 288.7 | 506.0 / 519.4 | 6.2 / 8.7 | 26.7 / 34.3 | 59.1 | 68.4 |
| `R_TXM2_0` ¹ | C | 1,108.2 / 1,417.8 | 1,822.4 / 1,823.0 | 687.2 / 742.5 | 861.8 / 882.8 | 8.5 / 11.7 | 13.7 / 16.7 | 293.2 | 223.4 |
| `R_TXM2_0` ¹ | Rust | 639.4 / 941.1 | 2,171.3 / 2,252.6 | 287.2 / 315.6 | 542.6 / 572.3 | 6.4 / 8.9 | 26.9 / 34.8 | 60.3 | 69.1 |
| `R_TXM4_0` | C | 1,414.7 / 2,295.3 | 3,097.8 / 3,736.4 | 870.3 / 1,155.5 | 949.6 / 1,174.5 | 9.3 / 12.0 | 16.8 / 20.5 | 311.7 | 237.2 |
| `R_TXM4_0` | Rust | 711.2 / 1,347.4 | 4,031.9 / 5,698.1 | 322.0 / 406.0 | 664.1 / 700.7 | 6.9 / 9.1 | 28.9 / 38.0 | 62.9 | 73.9 |
| `R_TXM8_0` | C | 2,158.2 / 2,734.2 | 2,945.2 / 3,255.3 | 1,770.7 / 2,119.8 | 1,951.6 / 2,020.4 | 12.9 / 16.9 | 21.3 / 25.8 | 590.1 | 447.0 |
| `R_TXM8_0` | Rust | 911.1 / 1,062.6 | 2,827.1 / 2,829.6 | 604.0 / 746.2 | 1,060.1 / 1,097.1 | 9.8 / 12.9 | 41.1 / 50.1 | 98.0 | 105.9 |

¹ Re-run (owner ruling, 2026-10-18): the first pass of loop steps t = 9..11 (`R_TXM8`, `R_TXM1_0`, `R_TXM2_0`, about
14:06–14:47 UTC) overlapped external load (dotnet builds of another project on the same machine; the C `R_TXM8`
generic verify p50 was 3,616 ms there, p99 / p50 2.9). Those three relations were measured again on a quiet machine
at 15:18–15:44 UTC: `D6_T="9 10 11" d6.sh d6/rerun-t9-11`, and `results.py d6 runs/d6 runs/d6/rerun-t9-11` takes
their rows from the re-run. The first-pass files stay in `runs/d6/` for the record. Steps t = 0..8 and 12..13 stand.

- **Native:** the crate is faster on every relation: prove 1.6–2.5× (`R_TX` 529 against 983 ms), generic verify
  2.0–2.9× (`R_TX` 278 against 674 ms), verify_fast 1.2–1.6× (`R_TX` 6.3 against 8.5 ms).
- **wasm32:** prove is about level (C / Rust 0.8–1.4×; Rust slower for `R_REG`, `R_DS`, `R_TX0`, `R_TXM4`,
  `R_TXM2_0`, `R_TXM4_0`, faster for the others), generic verify is 1.3–1.9× faster, but **verify_fast is about 2× slower** than the C core (1.7–2.0×)
  (`R_TX` 26.7 / 32.0 against 13.6 / 17.5 ms; `R_TXM8` 44.7 / 51.0 against 23.1 / 29.0 ms). Every Rust wasm32
  verify_fast p99 is under the 60 ms limit, the largest being `R_TXM8` at 51.0 ms: about 15 % margin on this CPU,
  which a slower client CPU may not have. The chain's precompile verifies natively; wasm32 verify_fast is for
  clients. Likely cause: `arith/ntt.rs` multiplies 64 × 64 → 128 bits (`mulq`, `red128`, the basemul `u128`
  accumulator) on every target, and wasm32 has no wide multiply; the C core uses a 21-bit-limb path on wasm32
  (`pqz_ntt.c`, `PQZ_MUL128 0`). Neither build uses simd128. Follow-up, not done in this port: a
  `cfg(target_arch = "wasm32")` limb path in `ntt.rs` (STATUS.md "Open", item 10).
- **Peak memory:** native, the C arena peak against this crate's heap peak (the counting allocator of
  `tests/memory.rs`, prove from a cold `Ctx`): 4–6× less (`R_TX` 60.0 against 290.1 MiB, `R_TXM8` 110.1 against
  655.6 MiB). wasm32: the C arena peak (the prover build without the specialised verifier) against the module's
  linear memory after the proves, one relation per process (it also holds the bench's statements and witnesses for
  every relation): 2.5–4.2× less (`R_TX` 68.9 against 221.1 MiB). A process whose `Ctx` keeps every relation's
  keys (a wallet proving every form and shape, M = 8 included: `wasm/run_vectors.mjs` over all the vectors) reaches
  229,638,144 B = 219.0 MiB (`runs/d6/rust-m8-wasm-vectors-stderr.txt`).
- **pqz-ffi path** (`ffi_bench 200`, verify through the C ABI, both backends in the run): the Rust backend
  (`pqzl-rust`, the default) is faster on every PQZL form, `R_TX` 6.48 / 9.27 ms against 8.34 / 11.72 ms, op 7
  M = 8 10.76 / 14.86 ms against 14.83 / 21.42 ms; the largest Rust PQZL p99 is 14.9 ms (C 21.4 ms). Tables in
  `runs/d6/results-d6.md`.

### The wasm32 op 7 limit (owner 2026-10-18: "if it is enough, raise it")

wasm32 proved op 7 only up to M = 4 (`pqzl::WASM_MAX_LEGS` and `pqz-ffi`'s `WASM_PQZL_MAX_LEGS`). That limit came
from the C core's arena, where M = 8 peaks at 495.3 MiB, over the browser's 256 MiB. `d6.sh` measured this crate's
wasm32 prove of M = 8, with the auditor on and off, in a bench build with the limit lifted (feature `wasm-m8`).

- **Enough** means both of these hold:
  - the M = 8 peak is ≤ 255.6 MiB (268,012,304 B, the C core's wasm32 M = 4 peak, `R_TXM4` auditor on,
    `artifact/runs/s6-docker-multi`; wasm32 already accepts that budget);
  - native = wasm32 on the M = 8 vector proofs (`run_vectors.mjs` with `PQZL_WASM_MAX_LEGS=8` against a native
    replay built with `wasm-m8`: the digest lines are equal and the M = 8 rows carry a proof digest).
- **Outcome: enough.** The M = 8 wasm32 prove peaks at 123,076,608 B = 117.4 MiB (auditor on; p50 2,393 ms) and
  111,017,984 B = 105.9 MiB (auditor off; p50 2,827 ms); native = wasm32 on all 374 vector digest lines, the three
  M = 8 rows proved in wasm32 with the native proof's digest (`runs/d6/rust-m8-*`). Both peaks are for one
  relation per process; a `Ctx` holding every relation's keys (all the vectors, M = 8 included) reaches
  229,638,144 B = 219.0 MiB, still under 255.6 MiB.
- **Done (Task 12):** `pqzl::WASM_MAX_LEGS` = 8, and `pqz-ffi`'s `WASM_PQZL_MAX_LEGS` = 8 on the Rust backend; the C
  backend (opt-in) keeps 4. The wasm32 replays (`wasm/run_vectors.mjs`, `pqz-ffi`'s `vectors/replay_wasm.mjs`) prove
  the three M = 8 rows instead of refusing them. `pqz-ffi`'s digest lines keep their frozen M ≤ 4 set. Recorded in
  `docs/decisions.md` CTR-PQZ-09. The feature `wasm-m8` now only matters with `oversize` (M = 16, benches).

### How to run the D6 measurement

On an idle machine (no other capped jobs, builds or containers), from the repository root, one capped job of about
1 h 40 min:

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
`ffi_bench 200` on both `pqz-ffi` backends (`--no-default-features --features ...,pqzl-c` for C, the default for
Rust), `tests/memory.rs peak_per_op` (heap peaks) and the M = 8 replay, and finally
`python3 -I ../../artifact/results.py d6 runs/d6`. `D6_T="<t ...>"` re-runs only those loop steps into another
directory (see the re-run note above).

## Licence

The repository's Vegan Community License 1.0 (`../../../LICENSE`). The crate ports LaZer-derived code: LaZer's MIT
notice is in `NOTICE` and `LICENSE-lazer`, which travel with every distribution. `publish = false` until the owner
rules (plan D7).

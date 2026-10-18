# PQZL → Rust port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** plan only (owner 2026-10-16: "plan, no code"). Execution starts **after the freeze** (owner order 2026-10-16:
S5 → layout move → S6 ∥ this plan → S8 → S7 → gates A / B → freeze → the port). Decisions D1–D8 below are controller
proposals; the owner may override any of them.

**Owner 2026-10-17:** plan approved (D1–D8 as proposed); execution subagent-driven (superpowers:subagent-driven-development:
one implementer + one reviewer per task, then a whole-branch review), after the freeze.

**Goal:** A pure-Rust crate `pqzl` that is byte-for-byte equivalent to the PQZL C core (`pqz-core/pqzl/src` +
`pqzl/lazer`): same proofs for the same `(op, stmt, wit, rnd32)`, same verdicts on every input, same keys / Enc / Dec,
native and wasm32 — so other chains and applications can use the LaZer proof system without the C build.

**Architecture:** Port bottom-up in the C core's own layers (arithmetic → hashing / sampling → keys → proof codec →
generic verifier → prover → specialised verifier), each layer checked against the C core as the oracle (a test-only
`c-oracle` feature compiles the C core with `cc`, as `pqz-ffi/build.rs` does) and against the frozen vectors. No
globals: one `Ctx` value holds what the C core keeps in static storage (keys per relation, SV tables), so calls are
re-entrant and need no lock. `pqz-ffi` gains a `pqzl-rust` feature that swaps the backend. **Owner 2026-10-18: the Rust
crate is the production PQZL core for the precompile**: once Task 11's checks pass, `pqzl-rust` becomes `pqz-ffi`'s
default and the C core stays as the reference / differential oracle (kept, less maintained; decisions.md CTR-PQZ-09).

**Tech Stack:** Rust 1.97.1 (`no_std` + `alloc`), RustCrypto `sha3` / `aes` (D1), `cc` (dev / test only), Python 3
checkers already in the repository (`pqzl/kat/check.py`, `smartcontracts/vectors/pqz/pqz_kat.py`), node for wasm32.

**Spec:** [pq-zero-knowledge.md](../../contracts/pq-zero-knowledge.md) §4 (encryption, §4.2 algorithms), §5
(encodings), §8 / §8.1 (proof engine, serialization v1), §14 (vectors); the C ABI `pqz-core/pqzl/src/pqz.h` (every
size, layout and return code below is copied from it); `pqz-core/README.md` §3, §6.

## Global Constraints

- Location `pqz-core/pqzl/rust/`, crate `pqzl` (owner 2026-10-17); `publish = false` until the owner rules (D7).
- Licence: the repository's Vegan Community License 1.0 (`license-file = "../../../LICENSE"`, owner 2026-10-16);
  LaZer's MIT notice travels with the LaZer-derived code: `pqzl/rust/NOTICE` (copy of the LaZer part of
  `pqz-core/NOTICE`) and `pqzl/rust/LICENSE-lazer` (copy of `pqzl/lazer/LICENSE`).
- Rust 1.97.1 (`pqzl/rust/rust-toolchain.toml`, `targets = ["wasm32-unknown-unknown"]`), `#![no_std]` + `alloc`,
  `#![forbid(unsafe_code)]`, `clippy -D clippy::float_arithmetic` (no float anywhere, as `pqzh-ligero`).
- Byte parity: for every op and input, `prove` output = the C core's, `verify` / `verify_fast` verdict = the C core's;
  native = wasm32. No new `proofSystemId`, no format change (D5).
- Constants from `pqz.h`: `MAX_PROOF = 98,304`, `POLYVEC_BYTES = 16,384`, `V_BYTES = 128`, `PREFIX_BYTES = 64`,
  `HEADER_BYTES = 640`, ops 1 TRANSFER, 2 BURN, 3 REGISTER, 4 DISCLOSE_SENDER, 5 DISCLOSE_RECEIVER, 7 TRANSFER_MULTI;
  `TXM_MAX_LEGS = 8` (16 only with feature `oversize`); proofSystemId `0x2e07e6ed…798c2f` (v2).
- Return codes as `pqz.h` / `pqz_rt.h`: `ERR_INTERNAL = 1`, `ERR_INPUT = 3`, `ERR_REJECT = 4` (map to `Error`
  variants, D3).
- wasm32: PQZL op 7 prove only for M ≤ 4 (as `pqz-ffi` `WASM_PQZL_MAX_LEGS`).
- Heavy runs under `scripts/capped` (two slots), `cargo -j2`, never `timeout … scripts/capped`.

## Decisions (controller proposals)

| # | Decision | Proposal | Why |
|---|---|---|---|
| D1 | Dependencies | `sha3 =0.10.8` (already in `pqz-ffi`'s lock) for SHAKE128/256 and Keccak; `aes =0.8.4` (fixslice, constant time) + own CTR loop for AES-256-CTR; nothing else at run time | the C core's own `shake128.c` / bitsliced `pqz_aes_gen.h` are standard algorithms: any correct implementation gives the same stream, and audited crates are less to maintain |
| D2 | Memory | no arena: `Vec` with `try_reserve` on every buffer that scales with the input; failure → `Error::Memory` (never a panic / abort); peak measured per op by a counting allocator in tests | keeps the C core's "bounded, no abort" property without unsafe code |
| D3 | API | safe functions on `Ctx` mirroring `pqz.h` (below), `Result<_, Error>`; `Error { Internal, Input, Reject, Memory }` | one-to-one with the C ABI, so `pqz-ffi` swaps the backend without touching its callers |
| D4 | The C core during and after the port | stays the oracle (feature `c-oracle`, dev only) until the owner's production choice; no C file changes in this plan | parity is checked continuously, not once |
| D5 | Formats | no change: same `proofSystemId`, statements, witnesses, proofs | the crate is a second implementation, not a new proof system |
| D6 | Performance | measured and reported (prove / verify p50 / p99 native and wasm32, peak memory, vs C) — not a gate | the owner's production choice uses these numbers |
| D7 | Publication | `publish = false`; crates.io only on an owner ruling (licence VCL 1.0) | publication is outward-facing |
| D8 | Params | the generated `pqz_*_params.h` (14 headers) → Rust by a converter `pqzl/params/to_rust.py` (stdlib) into `pqzl/rust/src/params/*.rs`, checked in; `regen.sh` runs it; `--check` mode in the test run | one codegen source, no hand-copied constants |

## Review Focus

1. **Non-canonical or out-of-range encodings** (a coefficient ≥ q, a trailing coder bit, an over-long proof) must be
   rejected exactly where the C core rejects — pinned by Task 5's mutation-kind test and Task 11's fuzz differential.
2. **Statement length / op / M / auditorOn mismatches** (op 1 with 83,072 B but auditorOn 0, op 7 with M = 3 or 16
   in a default build) → `verify` false, `prove` `Error::Input` — pinned in Task 7 (`negative.json` PQZL rows).
3. **Memory exhaustion** (wasm32 M = 8 prove, a 4 GB-capped process) → `Error::Memory`, no panic — pinned in Task 10.
4. **Concurrent use** (two threads verifying different ops on one `Ctx` / two `Ctx`) → results equal to sequential,
   no lock needed — pinned in Task 10.
5. **Panics on hostile input** (any byte string as statement or proof) → never; `verify` returns false — pinned by
   Task 11's fuzz campaign (2 h per target, as P6e / S5).

---

## File Structure

```text
pqz-core/pqzl/rust/
  Cargo.toml  Cargo.lock  rust-toolchain.toml  build.rs (c-oracle only)  README.md  NOTICE  LICENSE-lazer  run.sh
  src/lib.rs            Ctx, Error, the public API (D3), re-exports
  src/arith/            mpn.rs (pqz_mpn.h), int.rs (int / intvec / intmat), mont.rs, poly.rs, ntt.rs (pqz_ntt.c),
                        polyvec.rs, polymat.rs, spoly.rs (spolyvec / spolymat)
  src/rand/             shake.rs (D1), aes_ctr.rs (D1), rng.rs, urandom.rs, brandom.rs, grandom.rs + fixexp.rs
                        (pqz_fixexp.h), rejection.rs
  src/keys.rs           pqz_keys.c
  src/coder.rs          coder.c, dcompress.c, bytes.c
  src/params/           generated (D8): reg, tx, tx0, burn, ds, dr, txm2, txm4, txm8, txm16, txm20, txm40, txm80, txm160
  src/proof/            abdlop.rs, quad.rs (lnp-quad, lnp-quad-eval, lnp-quad-many), tbox.rs (lnp-tbox: prover +
                        verifier, the P6-SZ / P6-L2 fixes, the z21 norm check)
  src/rel.rs            pqz_rel.c: statement parsing, relation builders, hedged masks (CTR-PQZ-19)
  src/sv.rs             pqz_sv.c (specialised verifier)
  src/bin/kat_dump.rs   arithmetic KAT (pqzl/kat/lazer_dump.c's cases and JSON)
  src/bin/keys_kat.rs   pqzl/test/pqz_keys_kat.c's JSON lines
  src/bin/bench.rs      pqzl/test/pqz_bench.c's setup() + timing + proofs_fnv
  tests/                oracle_*.rs (c-oracle), vectors.rs, sv_diff.rs, memory.rs, threads.rs
  wasm/                 node runner run_wasm.mjs + a cdylib wrapper (as ffi/wasm)
pqz-core/pqzl/params/to_rust.py   D8 converter
pqz-core/ffi/                     feature pqzl-rust (Task 11)
pqz-core/fuzz/                    target mode "pqzl-diff" (Task 11)
pqz-core/artifact/                stage "Rust = C" (Task 12)
```

## Public API (Task 1 defines it, later tasks fill it)

```rust
pub struct Ctx { /* caches: relation keys, SV tables; no globals */ }
pub enum Error { Internal, Input, Reject, Memory }
impl Ctx {
    pub fn new() -> Ctx;
    pub fn prove(&mut self, op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, Error>;
    pub fn verify(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> bool;        // pqz_verify: 1 / 0
    pub fn verify_fast(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> bool;   // pqz_verify_fast (feature sv, default)
}
pub fn keypair_from_secret(s: &[i8; 2048], e: &[i16; 2048]) -> Result<Box<[u8; 16384]>, Error>;
pub fn keygen(seed32: &[u8; 32]) -> Result<Key, Error>;            // Key { pk, s, e, ctr }
pub fn enc_seed(pks: &[&[u8; 16384]], msgs: &[[u8; 16]], seed_enc: &[u8; 32]) -> Result<Enc, Error>;
pub fn enc_group_seed(seed_enc: &[u8; 32], g: u32) -> [u8; 32];
pub fn encrypt(pks: &[&[u8; 16384]], msgs: &[[u8; 16]], r: &[i8; 2048], e1: &[i16; 2048], e2: &[[i16; 16]]) -> Result<Enc, Error>;
pub fn decrypt_raw(s: &[i8; 2048], u: &[u8; 16384], v: &[u8; 128]) -> Result<[i64; 16], Error>;
pub fn dec(s: &[i8; 2048], ct: &[u8; 16512]) -> Result<([i64; 16], [i64; 16]), Error>;   // (M, noise)
#[cfg(feature = "test-hooks")] pub fn test_mutate(rel: u8, proof: &[u8], kind: u32, r1: u64, r2: u64) -> Result<Option<Vec<u8>>, Error>;
```

`Enc { u: Box<[u8; 16384]>, vs: Vec<[u8; 128]>, r, e1, e2, ctr }` as `pqz_enc_seed`'s outputs. Features: `sv`
(default), `oversize` (M = 16, bench only), `test-hooks`, `c-oracle` (dev).

---

### Task 1: Crate skeleton and the C oracle

**Files:** Create `pqzl/rust/{Cargo.toml,rust-toolchain.toml,build.rs,src/lib.rs,README.md,NOTICE,LICENSE-lazer,run.sh}`,
`pqzl/rust/tests/oracle_smoke.rs`.

**Interfaces:** Produces `Ctx`, `Error`, the API signatures above (no `unimplemented!()`: an unported function
returns `Err(Error::Internal)` / `false` until its task);
`c_oracle` module (feature `c-oracle`): safe wrappers `c_prove`, `c_verify`, `c_verify_fast`, `c_keygen`, `c_enc_seed`,
`c_dec`, `c_test_mutate` over the C core built by `build.rs` from `../src ../lazer ../params` with `build.sh`'s flags
(copy the `cc` setup of `pqz-ffi/build.rs`), one process-wide `Mutex` + 16 MiB stack thread as `pqz-ffi::pqzl` does.

- [ ] Test `oracle_smoke::c_core_selftest_proofs_verify`: the REGISTER rows of `proof_pqzl.json` → `c_verify(3, …)` true;
  `oracle_smoke::rust_stub_rejects`: `Ctx::new().verify(3, …)` false.
- [ ] `run.sh <label>`: `cargo test -j2 --release --offline --features c-oracle,test-hooks`, clippy float lint, wasm32
  build; logs `runs/<label>-*` (as `ffi/run.sh`).
- [ ] Run `scripts/capped pqz-core/pqzl/rust/run.sh t1` → both tests pass. Commit.

### Task 2: Arithmetic layer (mpn, int, poly, NTT, polyvec / polymat / spoly)

**Files:** `src/arith/*.rs`, `src/bin/kat_dump.rs`, `tests/oracle_arith.rs`, `tests/oracle_shim.c` (C test entry
points into the core's layers, compiled by `build.rs` under `c-oracle`; extended by Tasks 3, 5, 6).

**Interfaces:** Produces `Poly`, `PolyVec`, `PolyMat`, `SPolyVec`, `SPolyMat`, `IntVec`, NTT `fwd` / `inv` / `basemul`
with the C layer's semantics (q = 2^42 − 215, d = 64, l = 4 incomplete NTT, CRT moduli of `pqz_ntt.c`).

- [ ] `kat_dump` writes `lazer_dump.c`'s 19 cases in its JSON shape (`meta.backend = "pqzl-rust"`).
- [ ] Verify: `python3 -I pqz-core/pqzl/kat/check.py pqz-core/pqzl/kat/lazer-3330e48.json <kat-rust.json>` →
  `19/19 cases equal`.
- [ ] `oracle_arith::{ntt_roundtrip_eq_c, basemul_eq_c, polyvec_ops_eq_c}`: 10,000 random inputs each (seeded), Rust
  = `c-oracle` output byte for byte (the C side through test entry points added to the oracle shim, not to the core).
- [ ] Commit.

### Task 3: Hashing, RNG and samplers

**Files:** `src/rand/*.rs`, `tests/oracle_rand.rs`.

**Interfaces:** Produces `Shake256::stream(tag, seed, ctr)`, `AesCtr::new(key)`, `cbd(eta, stream)`, the discrete
Gaussian sampler of `grandom.c` (integer-only, `fixexp`), `rejection` (the `rej` tests of `rejection.c`).

- [ ] `oracle_rand::cbd_eq_vectors`: every row of `smartcontracts/vectors/pqz/cbd.json` (stream, eta, bit offset →
  samples).
- [ ] `oracle_rand::{grandom_eq_c, rejection_eq_c, aes_ctr_eq_c}`: 1,000 seeds each, Rust = C.
- [ ] `clippy -D clippy::float_arithmetic` clean. Commit.

### Task 4: Keys, Enc, Dec

**Files:** `src/keys.rs`, `src/bin/keys_kat.rs`, `tests/vectors.rs` (keys part).

**Interfaces:** Consumes Task 2 / 3. Produces `keygen`, `enc_seed`, `enc_group_seed`, `encrypt`, `decrypt_raw`, `dec`,
`keypair_from_secret` as the API block.

- [ ] `vectors::{keygen_json, enc_json, matrix_json}`: every row of `keygen.json`, `enc.json`, `matrix.json` equal.
- [ ] `keys_kat 1000 > k.jsonl` then `python3 -I smartcontracts/vectors/pqz/pqz_kat.py --c-keys k.jsonl` →
  `pqz_kat: ok` (the C binary's JSON-lines shape, so the same checker serves both).
- [ ] Errors: a pk coefficient ≥ q → `Error::Input`; a digit > 15 → `Error::Input` (as `pqz_keys.c`). Commit.

### Task 5: Proof codec

**Files:** `src/coder.rs`, `tests/vectors.rs` (codec part), `tests/oracle_codec.rs`.

**Interfaces:** Produces `decode_proof(rel, bytes) -> Result<ProofParts, Error>`, `encode_proof(&ProofParts) -> Vec<u8>`
and, with `test-hooks`, `test_mutate` (the 14 mutation kinds of `pqz_test_mutate`).

- [ ] `vectors::codec_roundtrip`: every PQZL proof of `proof_pqzl.json` and `fee0.json` decodes and re-encodes to the
  same bytes.
- [ ] `oracle_codec::test_mutate_eq_c`: kinds 0..13 × 200 `(r1, r2)` seeds × every relation code (six forms and the
  eight `PQZ_REL_TXM` codes) — Rust output (or `None`) = C's (Review Focus 1). Commit.

### Task 6: Parameters from the codegen (D8)

**Files:** Create `pqzl/params/to_rust.py`, `pqzl/rust/src/params/*.rs`; modify `pqzl/params/regen.sh` (call it).

**Interfaces:** Produces one module per header with the same constant names (lower-snake) and the same values.

- [ ] `python3 -I pqzl/params/to_rust.py --check` exits 0 when the committed `.rs` files equal the regenerated ones;
  the test run calls it.
- [ ] `oracle_params::constants_eq_c`: the `_Bsq`, kmsis, m1 / m2, moduli of every relation read through the oracle
  shim equal the Rust constants. Commit.

### Task 7: Generic verifier (ABDLOP, quadratic proofs, tbox, relations)

**Files:** `src/proof/{abdlop,quad,tbox}.rs`, `src/rel.rs` (verify side), `tests/vectors.rs` (verify part),
`tests/fixtures/cheating/` (proof files), `tests/oracle_verify.rs`.

**Interfaces:** Produces `Ctx::verify`.

- [ ] `vectors::all_pqzl_proofs_verify`: every PQZL row of `proof_pqzl.json` (six forms, REFRESH, AUDITOR, 11 op 7
  rows) and `fee0.json` → true.
- [ ] `vectors::negative_rows_reject`: every row of `negative.json` whose id is PQZL → false (Review Focus 2).
- [ ] Cheating fixtures: export once from the C hooks the proofs that `check_tbox_fixes.sh` builds (`sz` trace input,
  `l2dom` s_over_A / s_over_B / tx_over, `z21_big`, `z1_over`, `w_over`) into `tests/fixtures/cheating/*.bin` with
  their statements; `vectors::cheating_proofs_reject` → all false.
- [ ] `oracle_verify::mutated_eq_c`: 20,000 `test_mutate` outputs over all relation codes → Rust verdict = C verdict.
  Commit.

### Task 8: Prover

**Files:** `src/rel.rs` (prove side, hedged masks CTR-PQZ-19), `src/proof/tbox.rs` (prove), `src/bin/bench.rs`.

**Interfaces:** Produces `Ctx::prove`; `bench` CLI = `pqz_bench`'s (`<np> <nv> [mask]`, JSON lines with `proofs_fnv`).

- [ ] `vectors::reprove_byte_equal`: every PQZL row of `proof_pqzl.json` / `fee0.json` re-proved from its witness and
  `rnd32` → identical bytes.
- [ ] `bench 5 5 63` → `proofs_fnv` of the six relations = `research/pqzl-measure/runs/tx0c-fnv-native.jsonl`
  (`8bd69f2d b9bbf854 0a5976da b4aa2e26 c800f2c6 a29a5747`); `bench 2 2 16320` (the eight op 7 shapes) = the L3 run's
  hashes (`research/pqzl-measure/runs/l3a-*`).
- [ ] wasm32: `node wasm/run_wasm.mjs 3 1 63` → the `tx0c-fnv-wasm` hashes (`e70b5dc4 9304299b 0ea1c7a6 f39a8e64
  96a6e906 a0afafc7`). Commit.

### Task 9: Specialised verifier

**Files:** `src/sv.rs`, `tests/sv_diff.rs`.

**Interfaces:** Produces `Ctx::verify_fast` (feature `sv`, default on).

- [ ] `sv_diff::sv_eq_generic`: the `pqz_sv_diff` sample of `pqzl/sv/rel3.sh` (`4 4 2 1 10 12 12 12 12 2`: 3,484 + op 7
  cases) → `verify_fast` = `verify`, 0 disagreements.
- [ ] `sv_diff::sv_eq_c_sv`: the same cases → Rust `verify_fast` = C `pqz_verify_fast`.
- [ ] `sv_diff::cheating_rejected`: Task 7's fixtures → false. Commit.

### Task 10: No globals, memory, threads, wasm32

**Files:** `tests/{memory,threads}.rs`, `wasm/`.

- [ ] `threads::concurrent_eq_sequential`: 8 threads × every op on separate `Ctx` and on one `Ctx` behind `&mut`
  hand-off → verdicts / proofs equal to a sequential run (Review Focus 4).
- [ ] `memory::peak_per_op`: counting allocator; peak per relation printed; R_TX prove ≤ 1.1 × the C arena peak
  (312,151,904 B, `layout-*` relfix run) — informational above, failing only above 2× (D6).
- [ ] `memory::exhaustion_is_error`: an allocator capped at 64 MiB → `prove` / `verify` of R_TX return
  `Error::Memory` / false, no panic (Review Focus 3).
- [ ] wasm32: native = wasm32 for every vector proof (as `ffi/wasm` digest lines); op 7 M = 8 prove refused on wasm32
  (`Error::Input`).
- [ ] Owner 2026-10-18: key methods on `Ctx` that reuse its cached A (for servers that encrypt in bulk):
  `Ctx::keygen`, `Ctx::keypair_from_secret`, `Ctx::encrypt`, `Ctx::enc_seed`, with the same arguments and results
  as the free functions, which stay unchanged (pqz-ffi binds them). Test `keys::ctx_eq_free`: each method byte-equal
  to its free function over several seeds, including after a `verify` on the same `Ctx`; the keys KAT
  (`pqz_keys_kat` / `pqz_kat.py --c-keys`, 1,000 seeds) also run through the methods. Commit.

### Task 10b: C / Rust follow-ups of the hardening review

- [ ] Owner 2026-10-18 (after the C-core hardening review, merged in `d10be79`; done after Task 10, before Task 11, on
  the branch rebased onto main, so Task 11's checks run on the final code), in both the C core and the Rust crate,
  honest proofs and `proofs_fnv` unchanged: (i) `poly_auto_self` in the NTT domain (`crt == 1`, unreachable today)
  computes the correct X → X⁻¹ by converting to coefficients first (`_fromcrt`, then the coefficient automorphism, as
  the fork's `poly_auto` does), so the branch can no longer return a wrong value; update `pqzl/test/pqz_ub_test.c`
  part c; (ii) `rejection.c` / `rejection.rs`: `t − lnM`, `t2 − 2·t1` and `a − |y| − lnM` saturate instead of
  wrapping, so a dishonest-size exponent rejects (fails closed through the `PQZ_REJ_MAX` retry cap) instead of
  accepting; a test with exponents near ±2^63 in both. Then `scripts/capped pqz-core/gate.sh <label>` passes and the
  C ↔ Rust oracle tests stay equal. Also update the Rust doc comments that describe the old C UB (`fixexp.rs`,
  `poly.rs`) and drop the now unneeded double-size residue block in `testkit.rs`.

### Task 11: `pqz-ffi` backend switch and fuzz differential

**Files:** Modify `pqz-core/ffi/{Cargo.toml,src/pqzl.rs}` (feature `pqzl-rust`: the same `pqzl::` functions over the
crate instead of the C core; the C core is not built under it), `pqz-core/fuzz/src/lib.rs` (mode `pqzl-diff`).
  Owner 2026-10-18: after the checks below pass, `pqzl-rust` becomes the default feature (the C core stays reachable
  through an opt-in feature for the differential and `pqzl-diff`).

- [ ] `scripts/capped pqz-core/ffi/run.sh rust1` with `--features pqzl-rust` (an env switch in `run.sh`) → every test
  passes; self-test `ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205`; native = wasm32 digest lines.
- [ ] `ffi/vectors/run.sh rust1` with the switch → `pqz-vectors --check` byte-identical.
- [ ] Fuzz: target `precompile` and `mutate` (and `codec`, owner 2026-10-18) with `pqzl-diff` (both cores in one binary: Rust verdict = C verdict,
  Rust proof re-encoding = C's) — 2 h per target under `scripts/capped`, no finding (Review Focus 5). Commit with the
  logs.

### Task 12: Package stage, documents

**Files:** Modify `pqz-core/artifact/{reproduce.sh,results.py,expected-results.json,README.md}`, `pqz-core/README.md`
(§5 comparison tables, §7 map row `pqzl/rust/`), `pqz-core/STATUS.md`, `docs/decisions.md` (D1–D8 as recorded rulings), `pqzl/rust/README.md`.

- [ ] `reproduce.sh` stage "Rust = C" (quick and `--full`): Task 8's `proofs_fnv`, Task 4's keys KAT, Task 11's
  `--check`; no re-run of the existing stages (owner 2026-10-16). Docker quick run passes.
- [ ] D6 table (Rust vs C: prove / verify / verify_fast p50 / p99 native and wasm32, peak memory) in `pqzl/rust/README.md`
  and STATUS, C and Rust measured in the same session on the same machine (the t8–t10 Rust runs and the older C runs
  are not comparable).
- [ ] Owner 2026-10-18: add the Rust figures to the existing comparison tables, keeping every C figure (a Rust row or
  column next to the C one, labelled with its run and date; the frozen C values stay as they are):
  `pqz-core/README.md` §5.0 (PQZL table), §5.1, §5.3 (`pqz-ffi` path, now the Rust backend), §5.4 (`R_TXM`), §5.5
  (Comparisons); `pqz-core/artifact/README.md` "Measurements of the multi-recipient transfer" (PQZL table, and
  `results.py` so `results-multi.md` carries the Rust rows); `pqz-core/STATUS.md` (current state). Peak memory:
  Rust heap peak (counting allocator, `tests/memory.rs`) against the C arena peak.
- [ ] Owner 2026-10-18 (ruling: "if it is enough, raise it"): the wasm32 op 7 prove limit M ≤ 4 (`pqz-ffi`
  `WASM_PQZL_MAX_LEGS`, `pqzl::WASM_MAX_LEGS`) dates from the C core's arena. Measure the Rust wasm32 prove of M = 8
  (auditor on and off; time p50 and the wasm32 linear-memory peak) in a bench build with the limit lifted. **Enough** =
  the M = 8 peak ≤ 255.6 MiB (the C core's wasm32 M = 4 peak, `artifact/README.md`, the budget wasm32 already
  accepts) and native = wasm32 for the M = 8 vector proofs. If enough: set both constants to 8 for the Rust backend
  (the C backend, opt-in, keeps 4), make the wasm32 replay prove the three M = 8 rows instead of refusing them, and
  record the change in `docs/decisions.md` CTR-PQZ-09 with the measured figures. If not: keep 4 and record the figures
  and the reason.
- [ ] `docs_check` 0 errors. Commit; stop at the branch (merge per the P6 mandate after review).

## Out of scope

The production choice C vs Rust and anything after it (owner, later); crates.io publication (D7); PQZH (already Rust);
any change to the C core.

# PQZH — the hash-based proof system

PQZH is one of PQZ's two proof systems (the other is [PQZL](../pqzl/README.md)). It proves the same statements as
PQZL, but its security rests on hash functions only (Keccak-256), not on lattice problems. That makes it the
conservative choice: if the lattice assumptions behind PQZL were ever weakened, PQZH would still hold. The price is
size: a transfer proof is about 232 KB instead of PQZL's 43 KB. Both verify in about 10 ms, and the same `PQZ`
precompile accepts both; the `proofSystemId` inside each statement says which system made the proof.

PQZH uses **Ligero** over the field F_q (q of the parameter set, the same q as the encryption: v3 2^42 − 215, set (a)
61,275,424,977,257), with radix-431 evaluation domains, a Keccak-256 Merkle tree and transcript, and zero knowledge. It is written in Rust. For the big picture read
the parent [pqz-core/README.md](../README.md) first; the design and every measurement are in
[pqzh-ligero.md](../../docs/research/pqzh-ligero.md).

## What is here

| Path | What it is |
|---|---|
| `ligero/` | **the PQZH backend**: crate `pqzh-ligero`, used by `pqz-ffi` for both verifying and proving |
| `xcheck/` | cross-checks that the Rust statement and witness bytes equal the C core's (`pqz_bench.c`) and `pqz_kat.py`'s |
| `stark-backup/` | a STARK backend (Plonky3) that was tried and rejected; kept as the record, never linked by `pqz-ffi` |

## The Ligero crate (`ligero/`)

- **Relations:** `R_REG`, `R_TX`, `R_TX0`, `R_BURN`, `R_DS`, `R_DR` and the multi-recipient transfer `R_TXM` (op 7)
  for M = 1, 2 and 4. M = 8 is not built: its proof (up to 281,208 B) would exceed PQZH's `MAX_PROOF` of 262,144 B.
- **Parameters:** one fixed preset per parameter set, `Params::proven()`: at v3 n = 32,756, k = 817, t = 121, 127.2
  bits of proven (unique-decoding) soundness; set (a) below. Parameters are fixed per `proofSystemId` and op, never read
  from the proof.
- **Statements** are decoded by the shared codec `pqz-stmt`, so the same canonical rules apply as everywhere else.
- **Parameter sets** (owner 2026-10-21, plan 5h Task 8c): one set per build, as PQZL — feature `set-<set>`
  (`set-n2048-kmax1024` = v3, `set-n2304-kmax4096` = set (a)), at most one; none = v3 (what `pqz-ffi` gets until it
  forwards a set). The constants come from `pqz-core/params/sets/<set>/rust/set.rs` (PQZL's) and `pqzh_set.rs`
  (generator, F_q^4 non-residue, radices, preset). v3 keeps its preset; **set (a) uses preset B** (owner 2026-10-22:
  radices 2 / 7 / 17 / 19 / 43 / 431, n = 45,752, k = 952, t = 120, 127.4 bits; every debit proof bound 251,608–253,048,
  under `MAX_PROOF_PQZH` 262,144). Its fallbacks are kept, not in production builds: A = feature `fallback-retry`
  (set (a) only: v3's preset, the prover re-proves until the proof is ≤ 262,144), C = raise `MAX_PROOF_PQZH` for the
  set (documented only); `docs/research/pqzh-set-a-proof-limit.md`. v3 proofs are byte-identical to before the
  change. What a chain needs to run PQZH at a set: `params/sets/<set>/PQZH.md`.
- **Dependencies:** `sha3` and `pqz-stmt` only.
- **Two builds:**
  - the default feature `bench` adds the reference presets, the float parameter model, soundness accounting and the
    test client — for research and tests;
  - the production build is `--no-default-features`: only the proven preset, no floating point (a clippy lint
    enforces it). `pqz-ffi` uses this build.
  - Feature `oversize` (bench only) also builds op 7 at M = 8 and 16, above `MAX_PROOF`.

| File | Role |
|---|---|
| `src/set.rs` | the parameter set of the build (feature `set-<set>`) |
| `src/fq.rs`, `src/fft.rs` | the field F_q of the set (Barrett; limbs for wasm32: 2 × 21 bits at v3, 3 × ⌈log2 q / 3⌉ above) and the radix-431 FFT |
| `src/cs.rs` | the constraint systems of every form: statement → constraints, witness |
| `src/ligero.rs` | the Ligero protocol: prove and verify |
| `src/merkle.rs`, `src/transcript.rs` | the Keccak-256 Merkle tree and Fiat–Shamir transcript |
| `src/ring.rs`, `src/client.rs` | ring helpers; the test client (feature `bench`) |
| `src/bin/ligero_bench.rs` | the benchmark: proof bytes, soundness per term, prove time, peak memory, verify p50 / p99 |
| `src/bin/ligero_export.rs` | fixtures for the Solidity Ligero verifier experiment (`smartcontracts/evm/test/pqzh/ligero/`) |
| `src/bin/ligero_kat.rs` | deterministic proof fingerprints, the vectors replay, sizes / soundness per relation (no timing) |
| `tests/attacks.rs`, `tests/multi.rs`, `tests/oom.rs` | mutation and negative-witness tests; op 7 tests; the verifier's out-of-memory path |
| `src/ct.rs`, `src/bin/ct.rs` | the constant-time marks and the memcheck driver (feature `ctgrind`, test only) |
| `wasm/` | the wasm32 module and its node runner |
| `ligero_params.py`, `evm_model.py` | the parameter model and the EVM gas model |
| `runs/` | one script per measurement round, with its raw results (`l<N>-*`) |

The round scripts in `runs/` (each runs alone under `scripts/capped`, from the repository root):

| Script | Round |
|---|---|
| `measure.sh` | every measurement of pqzh-ligero.md §8 |
| `evm.sh`, `forge.sh` | the EVM verifier experiment (§11): without a precompile, a proven `R_TX` costs about 530 M gas |
| `rel5.sh` | all five relations with the hedged prover (§12) |
| `gateb.sh` | the gate-B round: tests, production build, native hashes, wasm32 1,000 verifies (§12) |
| `limits.sh` | the frozen id, the exact proof-length bounds, prover retry (§13) |
| `stmt.sh` | the crate on `pqz-stmt`, the production build without floats (§14) |
| `tx0.sh` | `R_TX0`, the transfer without the auditor (§14) |
| `txm.sh` | the multi-recipient transfer: tests, cross-check, measurements (§15) |
| `bench.sh` | a plain native bench run |
| `ct.sh` | the constant-time check of the prover under valgrind memcheck (ctgrind, review P-B): 0 reports, every proof verifies |
| `c8.sh`, `c8-wasm.sh` | per parameter set: tests, production build, proof fingerprints (v3: = the baseline and the vectors replay), native = wasm32 (plan 5h Task 8c) |

## Build and test

Run from `pqz-core/`:

```sh
(cd pqzh/ligero && cargo test --release --offline)                        # all tests, with the bench feature
(cd pqzh/ligero && cargo test --release --offline --no-default-features)  # the production build
(cd pqzh/ligero && cargo test --release --offline --features set-n2304-kmax4096)  # another parameter set
scripts/capped pqz-core/pqzh/ligero/runs/c8.sh <tag> <set>      # from the repository root: one set's round
scripts/capped pqz-core/pqzh/ligero/runs/c8b.sh            # from the repository root: v3 + set (a) + fallback A rounds
scripts/capped pqz-core/pqzh/ligero/runs/gateb.sh <tag>   # from the repository root: the gate-B round
scripts/capped pqz-core/pqzh/xcheck/ligero.sh             # from the repository root: Rust bytes = C bytes, all six forms
scripts/capped pqz-core/pqzh/ligero/runs/ct.sh <label>    # from the repository root: the constant-time check (x86-64)
```

**Prover hygiene (review round 2, 2026-10-19).** The prover keeps no branch, table address or 64-bit division on
secret values (witness, `rnd32`, masks): `runs/ct.sh` builds the test-only feature `ctgrind`, proves all twelve
relations with the witness and `rnd32` marked secret under valgrind memcheck and must report nothing; the inventory,
the declassified points and the wasm32 code check are in
[O-pqzh-constant-time.md](../research/code-review-2026-10-19/O-pqzh-constant-time.md). Every secret buffer is wiped
on every exit (best effort, the platform boundary is stated there). The library is `#![forbid(unsafe_code)]` (only the
test-only `ctgrind` build has the two memcheck client requests). The verifier reserves its parameter-sized buffers
fallibly: `try_verify` returns `Err(Oom)`, which `pqz-ffi` reports as a node fault.

## Why Ligero (and not the STARK in `stark-backup/`)

Three backends were measured on the same `R_TX` statement, all zero knowledge with 128-bit proven security
([pqzh-backend-comparison.md](../../docs/research/pqzh-backend-comparison.md)):

| Backend | Proof | Prove | Prover memory | Verify p99 | Outcome |
|---|---|---|---|---|---|
| **Ligero over F_q** (`ligero/`) | ≈ 231 KB | 0.65 s | 43 MB | 10.5 ms | **chosen** |
| STARK (Plonky3, FRI + ZK, Goldilocks⁵) | 622 KB | 20.4 s | 2.8 GB | 19.1 ms | rejected |
| ZK WHIR (Plonky3 WHIR with hiding) | 1.95 MB | 43 s | 2.4 GB | 46.5 ms | rejected (reaches only ≈ 124 bits) |

`stark-backup/` keeps the STARK crate (`src/`: AIR, encryption, relations, the ZK WHIR adapter `whirpcs.rs`), its
runs, the Solidity and StarkEx cost models (`sol/`) and the design-study counts (`pqzh_count.py`, `counts.txt`).

## Status and open points

- Gate B passed on 2026-10-17; the PQZH `proofSystemId`
  `keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")` = `0x0a47a768…2fead4` is frozen.
- The modified zero-knowledge construction was reviewed (pqzh-ligero.md §12): sound and zero-knowledge in the
  classical random-oracle model. An external review comes before PQZH is used with real value (owner step).
- Open (owner): a 128-bit post-quantum soundness target (against Grover-style quantum search) would need a new
  parameter set and a new id (pqzh-ligero.md §5.1).

# pqz-core

**PQZ — Post-Quantum Zero-knowledge.** This directory is a post-quantum zero-knowledge proof engine: two independent
proof systems behind **one precompile**, everything needed to **prove and verify** PQZ statements. Its first application
is a confidential token in the Zether model, whose amounts and balances stay secret even against a quantum computer
("PQ Zether" was the historical name; Z stands for zero-knowledge). Each operation has its own fixed relation — it is
not a general-purpose ZK system.

> **Status:** built and measured, **unaudited, not for production funds**. Numbers are **frozen** (2026-10-17, after
> gates A / B: `artifact/runs/freeze-2026-10-17/`, `artifact/expected-results.json`). The dated log of every change and run is [STATUS.md](STATUS.md); the spec is
> [pq-zero-knowledge.md, "Proof engine"](../docs/contracts/pq-zero-knowledge.md#proof-engine).

## Contents

1. [At a glance](#1-at-a-glance) — the picture and the key numbers
2. [What PQZ is](#2-what-pqz-is) — encryption, accounts, what each proof shows
3. [Two proof systems, one precompile](#3-two-proof-systems-one-precompile) — PQZL, PQZH and the shared parts
4. [Statement forms, ids, limits](#4-statement-forms-ids-limits) — the operations and their sizes
5. [Measurements](#5-measurements-frozen-2026-10-17) — proof sizes, prove and verify times
6. [Build, test, run](#6-build-test-run) — commands
7. [Directory map](#7-directory-map) — what each folder holds
8. [Licences](#8-licences)
9. [Status and what's next](#9-status-and-whats-next)
10. [Further reading](#10-further-reading)

## 1. At a glance

```mermaid
flowchart LR
  N["Node / contract<br/>(PQZ precompile call)"] --> F["pqz-ffi<br/>one C ABI: pqz_precompile"]
  W["Wallet<br/>(prove, wasm32)"] --> F
  F --> S["pqz-stmt<br/>decode + canonical checks"]
  S -- "proofSystemId = PQZL" --> L["PQZL<br/>lattice proof, C<br/>(LaZer fork)"]
  S -- "proofSystemId = PQZH" --> H["PQZH<br/>Ligero, Rust"]
```

| `R_TX` (a transfer), proven 128 bits | PQZL (lattice) | PQZH (Ligero) |
|---|---|---|
| Proof size | ≈ 42.8 KB | ≈ 232 KB |
| Prove, native / wasm32 | ≈ 1.0 s / 1.3 s | ≈ 0.65 s / 1.3 s |
| Verify p99, native / wasm32 | 8.7 ms / 14.8 ms | 10.5 ms / 19.4 ms |
| Prover memory, native / wasm32 | 304 MB / 232 MB (arena peak) | 43 MB / 48 MiB (heap; wasm module with all six forms) |
| Verifier memory | 1.7 MB working set + 5.2 MB tables (specialised verifier) | 1.2 MB heap |
| Memory inside the precompile (`pqz-ffi`) | one 512 MiB arena reserved at start (owner 2026-10-16; measured peak 268 MB with keys and tables of every form and every op 7 shape kept, run `s3a`; 95 MB for the six forms alone) | ≈ 1.2 MB heap per verify, no arena |
| Security rests on | MSIS / MLWE (lattices) | hash functions only |

Both stay far under the 60 ms verify limit, and both provers fit the 256 MiB browser (wasm32) memory limit. One precompile verifies both, chosen by the `proofSystemId` in the
statement. **Live:** the precompile runs on chain 7622 (the testnet) since 2026-10-16 for ops 1–6
([§3](#3-two-proof-systems-one-precompile)). **op 7** (one proof for a transfer to M recipients,
[§4](#4-statement-forms-ids-limits), [§5.4](#54-op-7-r_txm-multi-recipient-transfer)) is built in both systems
and in `pqz-ffi`, with vectors, fuzzing and the package, and **live on chain 7622 since 2026-10-17** (gas rows per
`(id, M, auditorOn)`, P6-ANON S8).

## 2. What PQZ is

PQZ keeps the classical Zether shape — identities visible, **amounts and balances encrypted**, the fee a public number,
sender / receiver / auditor disclosure — but rebuilt on module-lattice assumptions, so a quantum adversary can neither
read balances later nor forge proofs and mint ([overview](../docs/contracts/pq-zero-knowledge.md#overview)).

- **Encryption** ([spec](../docs/contracts/pq-zero-knowledge.md#encryption)): additive module-LWE with BFV-style scaling Δ and digit-packed plaintext, over
  `R_q = Z_q[X]/(X^64 + 1)` with q = 2^42 − 215 and vectors of 32 ring elements. Public key 16,384 B, ciphertext
  16,512 B. KeyGen / Enc / Dec are deterministic from seeds (SHAKE256, [algorithms](../docs/contracts/pq-zero-knowledge.md#42-algorithms)): in C (`pqzl/src/pqz_keys.c`) and in Rust
  (`pqz-ffi` feature `prove`), checked against the independent Python `smartcontracts/vectors/pqz/pqz_kat.py`.
- **Accounts** ([protocol](../docs/contracts/pq-zero-knowledge.md#protocol)): one registered public key per `(UA, token)`; balances as ciphertext hashes in storage,
  ciphertext bytes in calldata and events.
- **Relations** ([protocol](../docs/contracts/pq-zero-knowledge.md#protocol)): each operation proves knowledge of the secrets behind a statement, with exact ℓ2 norms and
  bit ranges:
  - key well-formedness — `R_REG`;
  - a transfer's encryption, norms, digit carries and balance — `R_TX`, `R_TX0`;
  - burn / refresh — `R_BURN`;
  - decryption for disclosure — `R_DS`, `R_DR`;
  - a transfer to M recipients in one proof (decoys receive an encryption of 0) — `R_TXM` (op 7).

## 3. Two proof systems, one precompile

| | **PQZL** (lattice) | **PQZH** (hash-based) |
|---|---|---|
| Proof | LNP22 (ABDLOP + tbox) through a fork of [LaZer](https://github.com/lazer-crypto/lazer) `3330e48` (MIT, IBM), six layers rewritten | Ligero over F_q (radix-431 domains, Keccak-256 Merkle + transcript, zero knowledge) |
| Parameters | MSIS / MLWE, β ≥ 452 (`pqzl/params/estimator-e-s1*.txt`) | proven (unique-decoding) preset n = 32,756, k = 817, t = 121; 127.2 bits total ([pqzh-ligero.md](../docs/research/pqzh-ligero.md), "soundness") |
| Code | C — `pqzl/src/`, `pqzl/lazer/`, `pqzl/params/`; native and freestanding wasm32 | Rust crate `pqzh-ligero` — `pqzh/ligero/`; native and wasm32 |
| On-chain verifier | `pqz_verify_fast`, the specialised verifier (`pqzl/src/pqz_sv.c`); `pqz_verify` is the reference | `pqzh_ligero::verify` |
| Backup | — | the Plonky3 STARK crate `pqzh/stark-backup/`, kept as a record, never linked |

**PQZL without heavy dependencies.** Prover and verifier use **no GMP, MPFR, HEXL, floating point, `malloc`, `abort`
or stdio**. The six rewritten layers:

- integers without GMP — `pqzl/src/pqz_mpn.h`;
- an incomplete NTT mod q with l = 4 — `pqzl/src/pqz_ntt.c`;
- fixed-point exp for the sampler and rejection — `pqzl/src/pqz_fixexp.h`;
- an arena instead of `malloc` — `pqzl/src/pqz_arena.c`;
- sticky error returns instead of `abort` — `pqzl/src/pqz_rt.h`;
- bitsliced software AES-256-CTR — `pqzl/src/pqz_aes_gen.h`, generated by `gen_aes.py`.

The relations are in `pqzl/src/pqz_rel.c` (the prover mixes the secret witness into its random masks, so a weak random number generator cannot leak keys).

**Three soundness findings in upstream LaZer** were fixed here and reported:
[lazer#24](https://github.com/lazer-crypto/lazer/issues/24) and [#25](https://github.com/lazer-crypto/lazer/issues/25)
(the reason for `proofSystemId` v2) and [#26](https://github.com/lazer-crypto/lazer/issues/26) (z21 norm, verifier
only).

**Shared by both systems:**

- **`pqz-stmt`** (`stmt/`) — the one statement codec. Rust, `no_std` + `alloc`, no dependencies, builds for
  `wasm32-unknown-unknown`. Parses and builds every statement form of both systems with the canonical rules (exactly one accepted encoding per statement),
  plus `pk` / ciphertext, bundle, opening, and the precompile input (`MAX_PROOF(id)`, `MAX_INPUT`).
- **`pqz-ffi`** (`ffi/`) — **one `PQZ` precompile for both systems**, details in [ffi/README.md](ffi/README.md):
  - C ABI `pqz_precompile(input, len, out, out_len) -> status` (`ffi/pqz_ffi.h`, for the node's P/Invoke);
  - input `u8(op) ‖ be32(len(stmt)) ‖ stmt ‖ proof` → `pqz_stmt::decode_input` → dispatch on the statement's
    `proofSystemId` to PQZL's `pqz_verify_fast` or to the Ligero crate; ops 1–5 and op 7 (every built `(M, auditorOn)`
    of both ids; an unbuilt shape ⇒ `…00`); op 6 returns the cached self-test hash;
  - libpqz is built by `build.rs` with `pqzl/build.sh`'s flags; one process-wide lock; one worker thread with a fixed
    16 MiB stack; fixed arenas: verify-only 512 MiB, prove / generic verify 1 GiB (wasm32: one 512 MiB arena; P6-ANON S3);
  - status 0 ok (`…01` / `…00`), 1 revert (input over `MAX_INPUT`), 2 bad arguments, 3 input-caused panic ⇒ `…00`,
    4 node fault ⇒ no result;
  - feature `prove` adds keygen / enc / dec / prove of both systems, op 7 included with its multi-group encryption and
    the sender memo (HKDF-SHA256), wasm32 byte-equal with native (wasm32 proves PQZL op 7 only for M ≤ 4);
  - `src/bin/pqz-vectors.rs` generates the frozen vectors `smartcontracts/vectors/pqz/` (op 7: 11 PQZL + 8 PQZH proof
    rows, 342 negative rows).

**Live on chain 7622** (the testnet, reset 2026-10-16 with the precompiles from block 0; genesis hash unchanged
`0x24e43dcb…c464`): the Nethermind plugin `Nethermind.Pqz` ([nethermind/README.md](nethermind/README.md), image
`scaas/nethermind-pqz:1.39.0-pqz2`, built locally, never pushed) loads `libpqz_ffi.so` and adds three precompiles:

| Precompile | Address | Gas (calibrated once, 0.359 M gas / ms) |
|---|---|---|
| `PQZ` (ops 1–7, both systems) | `0x5caa500000000000000000000000000000000f01` | per (op, `proofSystemId`, statement length) row: 2,567,000–5,409,000 + 3 per input word; op 7 per (`proofSystemId`, M, auditorOn): 3,625,000–6,177,000 (since 2026-10-17); `OP_SELFTEST` 2,567,000; an input without a row pays the smallest row and gets `…00` without calling `pqz-ffi` |
| `MLDSA44` (EIP-8355 layout) | `0x5caa500000000000000000000000000000000012` | 49,000 + 6 per message word |
| `MLDSA65` (EIP-8355 layout) | `0x5caa500000000000000000000000000000000013` | 68,000 + 6 per message word |

The prices live in the chainspec section `engine.Pqz` (a re-price or op 7 = a new schedule at a future timestamp); status 4 (node fault) ⇒
log `PQZ-NODE-FAULT` and process exit 120, never a verdict. Live run: probes and e2e pass
(`nethermind/runs/2026-10-16-live.txt`); roll-out and rollback: [nethermind/chain/RUNBOOK.md](nethermind/chain/RUNBOOK.md).
Chain 22776 (the future mainnet) gets the same addresses only after the audit and the licence clearance.

## 4. Statement forms, ids, limits

Every statement starts with `opTag ‖ proofSystemId` (64 bytes) and a 640-byte header ([statement layout](../docs/contracts/pq-zero-knowledge.md#77-statement-layout)). Every byte
layout — statements, objects, both proof formats, the precompile input and `OP_SELFTEST` — is in
[pq-zero-knowledge.md, "Serialization v1"](../docs/contracts/pq-zero-knowledge.md#serialization).

| op | Form | Relation | Statement B | What it proves |
|---|---|---|---|---|
| 1 | TRANSFER (`auditorOn` = 1) | `R_TX` | 83,072 | sender debit, receiver and auditor credits, fee, balance digits |
| 1 | TRANSFER0 (auditor off; chosen by statement length) | `R_TX0` | 66,560 | `R_TX` without `pk_a`, `v_a`, `e2_a` |
| 2 | BURN, REFRESH | `R_BURN` | 50,048 | debit with a public amount |
| 3 | REGISTER | `R_REG` | 16,480 | key well-formedness |
| 4 | DISCLOSE-SENDER | `R_DS` | 33,184 | the sender's encryption of an amount |
| 5 | DISCLOSE-RECEIVER, DISCLOSE-AUDITOR | `R_DR` | 33,184 | decryption of a ciphertext |
| 6 | SELFTEST | — | 0 | input exactly `06 00000000`; returns the self-test hash `ed910a2c…1333d205` |
| 7 | TRANSFER-MULTI (M legs, auditor on / off) | `R_TXM` | 66,560–215,936 | sender debit, M leg credits (decoys receive Enc(0)), per-leg auditor copies, fee, balance digits |

**op 7 `R_TXM`** ([multi-recipient plan](../docs/superpowers/plans/2026-10-14-p6-anon.md), spec CTR-PQZ-23):

- **What it is:** one transfer, **one proof**, M legs. The sender is visible and debited once; the real recipient(s) are
  hidden among the M legs, and a decoy leg carries an encryption of 0. M counts legs, real and decoys: 7 real recipients
  ⇒ M = 8 with one decoy (owner 2026-10-16). Every e2 vector is bounded by 64 in ℓ2, per vector (owner 2026-10-15).
- **Header:** the op 1 header with word 320 = M, word 192 = `recipientsHash`, word 448 = `auditorOn`; the legs are
  encrypted in groups of up to 4 that share one `(r, e1)` (β 446 with the auditor, owner 2026-10-15). The sender memo is
  sealed with HKDF-SHA256.
- **Built shapes** (`pqz-stmt` refuses the others; statement bytes):

  | M | auditor on | auditor off | PQZL | PQZH |
  |---|---|---|---|---|
  | 1 | 83,072 | 66,560 | built | built |
  | 2 | 99,712 | 83,072 | built | built |
  | 4 | 132,992 | 116,096 | built | built |
  | 8 | 215,936 | 198,528 | built | not built: proof bound 281,208 B > `MAX_PROOF` 262,144 B, input > `MAX_INPUT` |
  | 16 | — | — | bench builds only (statement + proof > `MAX_INPUT`) | bench builds only |

  The length alone does not fix the shape: (1, on) and (2, off) are both 83,072 B, so the node prices op 7 by the
  `(proofSystemId, M, auditorOn)` header words (plan D19).
- **Wallet rules (owner 2026-10-16):** the user chooses the storage mode (BUNDLE / COMPACT) per transfer, the contract
  never switches; an auditor-on BUNDLE shape over the gas cap is offered as one M = 8 COMPACT transfer (default) or split
  into fitting BUNDLE transfers; PQZH op 7 takes at most 10 inline credits; wasm32 proves PQZL op 7 only for M ≤ 4.
- **Where it is:** PQZL (C) and PQZH (Rust) relations, `pqz-stmt`, `pqz-ffi` (S3), the frozen vectors (S4), fuzzing (S5,
  2 h per target, no finding), the reproducibility package (S6), **live on chain 7622 since 2026-10-17 (S8)**; the token
  entry points follow S7. Joins the frozen set before gates A / B.

| `proofSystemId` | keccak256 of | Value | Frozen at |
|---|---|---|---|
| PQZL v2 | `scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2` | `0x2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f` | gate A |
| PQZH | `scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1` | `0x0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4` | gate B |

| Limit (enforced by `pqz-stmt`) | Value |
|---|---|
| `MAX_INPUT` (larger input = revert) | 393,216 B |
| `MAX_PROOF`, PQZL | 98,304 B |
| `MAX_PROOF`, PQZH | 262,144 B (exact maximum at the proven preset: 235,470 B for `R_TX`, 236,196 B for op 7 M = 4 with the auditor) |
| Largest input | PQZH 369,193 B (op 7 M = 4 on: 5 + 132,992 + 236,196); PQZL 314,245 B (op 7 M = 8 on, at `MAX_PROOF`) |
| Proof length | `1 ≤ len(proof) ≤ MAX_PROOF(id)` |
| Verify time | **≤ 60 ms p99** on the chain host, also bounding wasm32 (owner decision 2026-10-14) |

## 5. Measurements (frozen 2026-10-17)

> **Frozen run** (`artifact/reproduce.sh --full` on the host toolchain under the machine lock, after gates A / B, with
> op 7): `artifact/runs/freeze-2026-10-17/` (`results.md`: 233 ok, 0 FAIL); `artifact/expected-results.json` is built
> from it. Proof hashes, sizes and checks are compared; times are informational. The subsections after the frozen
> tables keep the method and the earlier measurements.

### 5.0 The frozen tables

Machine: AMD Ryzen 5 7235HS (8 threads; flags aes vaes avx2), Ubuntu 24.04.4 LTS, kernel 7.0.0-34-generic, Ubuntu clang version 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3, node v26.8.1, Python 3.12.3, rustc 1.97.1 (8bab26f4f 2026-07-14), in Docker: False.

#### PQZL (the LaZer fork, C)

| | proof bytes (max) | prove p50 native / wasm | generic verify p50 native / wasm | SV p50 portable / x86-64-v3 / wasm | SV p99 portable / x86-64-v3 / wasm | wasm prove peak (one op, no SV) |
|---|---|---|---|---|---|---|
| `R_REG` | 28,113 | 290 / 509 ms | 159 / 276 ms | 3.89 / 2.42 / 6.8 ms | 5.2 / 3.4 / 9.7 ms | 70.3 MiB |
| `R_TX` | 42,785 | 898 / 1,255 ms | 625 / 946 ms | 7.94 / 4.59 / 14.2 ms | 10.7 / 5.7 / 20.4 ms | 221.1 MiB |
| `R_BURN` | 41,938 | 828 / 1,214 ms | 639 / 713 ms | 8.01 / 4.34 / 14.1 ms | 14.8 / 6.1 / 18.8 ms | 210.2 MiB |
| `R_DS` | 28,995 | 408 / 644 ms | 250 / 259 ms | 4.62 / 2.73 / 7.3 ms | 6.5 / 3.9 / 9.8 ms | 73.3 MiB |
| `R_DR` | 28,996 | 452 / 502 ms | 241 / 263 ms | 4.60 / 2.67 / 7.8 ms | 6.0 / 3.7 / 9.4 ms | 79.1 MiB |
| `R_TX0` | 42,441 | 1,010 / 1,391 ms | 721 / 745 ms | 7.96 / 4.67 / 13.4 ms | 9.9 / 6.6 / 15.8 ms | 216.7 MiB |

#### PQZH (Ligero, Rust; the proven preset)

| | proof bytes (max) | max_len_exact | prove p50 native / wasm32 | verify p50 / p99 native | verify p50 / p99 wasm32 | prove memory native heap / wasm32 linear | verifies native / wasm32 |
|---|---|---|---|---|---|---|---|
| `R_REG` | 187,674 | 190,458 | 400 / 891 ms | 7.20 / 8.65 ms | 12.22 / 15.06 ms | 25.9 / 29 MiB | 1,000 / 1,000 |
| `R_TX` | 232,302 | 235,470 | 695 / 1,445 ms | 10.32 / 12.05 ms | 18.64 / 23.80 ms | 43.2 / 46.8 MiB | 1,000 / 1,000 |
| `R_BURN` | 232,632 | 234,744 | 687 / 1,431 ms | 9.50 / 11.46 ms | 17.48 / 24.43 ms | 42.9 / 47.1 MiB | 1,000 / 1,000 |
| `R_DS` | 187,802 | 190,458 | 446 / 852 ms | 7.62 / 9.23 ms | 12.44 / 16.43 ms | 25.9 / 47.1 MiB | 1,000 / 1,000 |
| `R_DR` | 187,226 | 190,458 | 390 / 777 ms | 7.45 / 9.25 ms | 12.49 / 16.95 ms | 25.9 / 47.1 MiB | 1,000 / 1,000 |
| `R_TX0` | 231,800 | 234,744 | 651 / 1,555 ms | 9.92 / 12.19 ms | 17.73 / 22.47 ms | 42.9 / 48.6 MiB | 1,000 / 1,000 |

#### pqz-ffi (one precompile, both systems)

Self-test hash: `ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205`.

| system | form | proof bytes | verify p50 / p99 through the C ABI | adversarial p50 |
|---|---|---|---|---|
| PQZL | Transfer | 42,759 | 8.22 / 10.16 ms | 8.54 ms |
| PQZL | Transfer0 | 42,387 | 8.47 / 13.00 ms | 8.54 ms |
| PQZL | Burn | 41,914 | 8.39 / 11.16 ms | 8.28 ms |
| PQZL | Refresh | 41,902 | 8.19 / 10.88 ms | 8.74 ms |
| PQZL | Register | 28,068 | 4.21 / 6.58 ms | 4.19 ms |
| PQZL | DiscloseSender | 28,964 | 4.49 / 6.44 ms | 4.56 ms |
| PQZL | DiscloseReceiver | 28,990 | 4.82 / 7.42 ms | 4.73 ms |
| PQZL | DiscloseAuditor | 28,995 | 4.76 / 7.27 ms | 4.76 ms |
| PQZL | TransferMulti1 | 42,766 | 8.87 / 12.42 ms | 8.75 ms |
| PQZL | TransferMulti2 | 43,603 | 9.05 / 11.67 ms | 9.17 ms |
| PQZL | TransferMulti4 | 45,274 | 10.05 / 13.41 ms | 9.88 ms |
| PQZL | TransferMulti8 | 61,802 | 14.65 / 20.39 ms | 14.54 ms |
| PQZL | TransferMulti1_0 | 42,409 | 9.14 / 11.23 ms | 8.99 ms |
| PQZL | TransferMulti2_0 | 42,951 | 9.27 / 11.92 ms | 9.23 ms |
| PQZL | TransferMulti4_0 | 43,922 | 9.86 / 11.94 ms | 9.93 ms |
| PQZL | TransferMulti8_0 | 58,998 | 14.06 / 18.10 ms | 14.37 ms |
| PQZH | Transfer | 231,022 | 10.14 / 11.49 ms | 1.28 ms |
| PQZH | Transfer0 | 231,064 | 9.72 / 11.27 ms | 1.23 ms |
| PQZH | Burn | 231,320 | 9.62 / 12.85 ms | 0.59 ms |
| PQZH | Refresh | 231,928 | 9.64 / 11.71 ms | 1.21 ms |
| PQZH | Register | 187,738 | 7.17 / 8.57 ms | 0.38 ms |
| PQZH | DiscloseSender | 186,842 | 7.52 / 8.87 ms | 0.42 ms |
| PQZH | DiscloseReceiver | 187,098 | 7.39 / 8.53 ms | 0.42 ms |
| PQZH | DiscloseAuditor | 186,778 | 7.41 / 9.04 ms | 0.42 ms |
| PQZH | TransferMulti1 | 232,174 | 10.23 / 14.35 ms | 1.29 ms |
| PQZH | TransferMulti2 | 232,174 | 10.55 / 12.27 ms | 1.32 ms |
| PQZH | TransferMulti4 | 232,708 | 11.22 / 12.99 ms | 1.44 ms |
| PQZH | TransferMulti1_0 | 230,968 | 9.75 / 11.07 ms | 1.23 ms |
| PQZH | TransferMulti2_0 | 231,918 | 10.28 / 11.98 ms | 1.29 ms |
| PQZH | TransferMulti4_0 | 230,904 | 10.49 / 12.48 ms | 1.38 ms |

**How the numbers were measured**

| | |
|---|---|
| Machine | AMD Ryzen 5 7235HS (Zen 3+, AVX2, AES-NI, no AVX-512), 8 threads, 23 GB RAM, Linux 7.0 |
| Threads | one (every operation is single-threaded) |
| Native build | clang 18 `-O2`, portable (no CPU-specific instructions) unless a column says x86-64-v3 (AVX2 + AES-NI) |
| wasm32 | node v26.8.1 (as a browser would run it) |
| Conditions | every run under `scripts/capped`, other services running on the machine: expect about ± 20 % noise |

**How to read the tables**

- Units are in every column header: bytes, ms (milliseconds), MB.
- p50 = median; p99 = 99th percentile (1 run in 100 is slower) — the limits apply to p99.
- "native / wasm" in one cell = the native value, then the wasm32 value.
- Each table has a short version first; the full version with every column and its source files is in the
  expandable block under it.

### 5.1 PQZL (runs `tx0c`, 2026-10-14)

"SV" = the specialised verifier `pqz_verify_fast`; "generic" = `pqz_verify`.

| Relation | Proof size, max (bytes) | Prove, native / wasm (ms) | SV verify p99, portable / x86-64-v3 / wasm (ms) |
|---|---|---|---|
| `R_REG` | 28,113 | 295 / 484 | 4.48 / 3.10 / 6.91 |
| `R_TX` | 42,785 | 965 / 1,304 | 8.73 / 5.40 / 14.76 |
| `R_TX0` | 42,441 | 827 / 1,398 | 8.49 / 5.53 / 14.73 |
| `R_BURN` | 41,938 | 874 / 1,158 | 8.35 / 4.74 / 14.21 |
| `R_DS` | 28,995 | 331 / 646 | 4.94 / 3.91 / 8.70 |
| `R_DR` | 28,996 | 395 / 504 | 4.89 / 2.82 / 7.92 |

<details>
<summary>All PQZL columns (generic verify, SV p50, arena) and sources</summary>

Sources: `research/pqzl-measure/runs/tx0c-native.jsonl` (10 proves, 30 honest verifies per relation), `research/pqzl-measure/runs/tx0c-wasm.jsonl`
(5 / 10), `research/pqzl-measure/runs/tx0c-alone.jsonl` (one relation per process, arena peak), `pqzl/sv/runs/tx0c-native-fast.jsonl`,
`pqzl/sv/runs/tx0c-x86v3-fast.jsonl` (200 honest verifies), `pqzl/sv/runs/tx0c-wasm-fast.jsonl` (100).

| Relation | Proof size, max of 10 seeds (bytes) | Prove p50, native / wasm (ms) | Generic verify p50 / p99 native; p50 wasm (ms) | SV p50 / p99, portable (ms) | SV p50 / p99, x86-64-v3 (ms) | SV p50 / p99, wasm (ms) | Arena peak, one op, native / wasm (MB) |
|---|---|---|---|---|---|---|---|
| `R_REG` | 28,113 | 295 / 484 | 161 / 169; 223 | 3.85 / 4.48 | 2.37 / 3.10 | 6.61 / 6.91 | 95.5 / 73.7 |
| `R_TX` | 42,785 | 965 / 1,304 | 648 / 760; 762 | 7.98 / 8.73 | 4.76 / 5.40 | 13.36 / 14.76 | 304.2 / 231.9 |
| `R_TX0` | 42,441 | 827 / 1,398 | 577 / 627; 760 | 8.03 / 8.49 | 4.68 / 5.53 | 13.36 / 14.73 | 298.0 / 227.3 |
| `R_BURN` | 41,938 | 874 / 1,158 | 556 / 584; 693 | 7.75 / 8.35 | 4.63 / 4.74 | 12.88 / 14.21 | 288.9 / 220.4 |
| `R_DS` | 28,995 | 331 / 646 | 200 / 214; 270 | 4.42 / 4.94 | 2.86 / 3.91 | 7.27 / 8.70 | 99.8 / 76.9 |
| `R_DR` | 28,996 | 395 / 504 | 206 / 218; 254 | 4.50 / 4.89 | 2.69 / 2.82 | 7.52 / 7.92 | 107.7 / 83.0 |

- Adversarial SV p99 (246 native / 600 wasm mutated inputs per relation): ≤ 8.9 ms portable, ≤ 5.7 ms x86-64-v3,
  ≤ 14.4 ms wasm.
- The largest wasm prove peak (`R_TX`, 231,858,048 B = 221.1 MiB) is 13.6 % under the 256 MiB hard limit.
- Native and wasm proofs are equal byte for byte.
- `pqz.wasm` 411,419 B (356,523 B without the specialised verifier, STATUS.md "Auditor-off transfer").
- Every SV p99 ≥ 4× under the 60 ms limit on every build.

</details>

### 5.2 PQZH Ligero, proven preset (runs `l15-tx0`, 2026-10-14, gate-B method: 1,000 verifies)

| Relation | Proof size, 5 seeds (bytes) | Exact max (bytes) | Prove, native / wasm32 (ms) | Verify p99, native / wasm32 (ms) |
|---|---|---|---|---|
| `R_REG` | 186,232–187,674 | 190,458 | 366 / 769 | 7.83 / 14.89 |
| `R_TX` | 230,584–232,302 | 235,470 | 652 / 1,309 | 10.49 / 19.44 |
| `R_TX0` | 229,672–231,800 | 234,744 | 637 / 1,333 | 11.36 / 20.88 |
| `R_BURN` | 231,256–232,632 | 234,744 | 629 / 1,286 | 10.63 / 20.76 |
| `R_DS` | 187,354–187,802 | 190,458 | 376 / 748 | 8.16 / 13.71 |
| `R_DR` | 185,462–187,226 | 190,458 | 358 / 758 | 8.33 / 14.31 |

<details>
<summary>All PQZH columns (m, memory, p50, adversarial) and sources</summary>

Sources: `pqzh/ligero/runs/l15-tx0-proven.jsonl` (+ `-time.txt`; native, 5 proofs, **1,000** honest verifies,
12 × 80 mutations per form) and `pqzh/ligero/runs/l15-tx0-proven-wasm.jsonl` (+ `-time.txt`; wasm32, 2 proofs made in
wasm32, **1,000** honest verifies, 12 × 4 mutations, `fails` 0). The gate-B round that introduced the wasm32 21-bit
multiply is `l9` (five relations, `pqzh/ligero/runs/l9-proven-wasm.jsonl`, `R_TX` p99 18.7 ms); the exact-length limits
are `l11` / `l12` ([pqzh-ligero.md](../docs/research/pqzh-ligero.md), "exact length bounds"). Prove: p50 native / mean wasm32.

| Relation | m (rows) | Proof size, 5 seeds (bytes) | Exact max (bytes) | Prove p50 native / mean wasm32 (ms) | Peak heap prove / verify, native (MB) | Verify p50 / p99, native (ms) | Verify p50 / p99, wasm32 (ms) | Adversarial p99, native / wasm32 (ms) |
|---|---|---|---|---|---|---|---|---|
| `R_REG` | 63 | 186,232–187,674 | 190,458 | 366 / 769 | 25.9 / 0.8 | 7.00 / 7.83 | 11.32 / 14.89 | 0.91 / 1.04 |
| `R_TX` | 125 | 230,584–232,302 | 235,470 | 652 / 1,309 | 43.2 / 1.2 | 9.75 / 10.49 | 17.14 / 19.44 | 1.53 / 1.50 |
| `R_TX0` | 124 | 229,672–231,800 | 234,744 | 637 / 1,333 | 42.9 / 1.2 | 9.38 / 11.36 | 16.60 / 20.88 | 1.25 / 1.56 |
| `R_BURN` | 124 | 231,256–232,632 | 234,744 | 629 / 1,286 | 42.9 / 1.1 | 9.23 / 10.63 | 16.25 / 20.76 | 1.23 / 1.42 |
| `R_DS` | 63 | 187,354–187,802 | 190,458 | 376 / 748 | 25.9 / 0.8 | 7.34 / 8.16 | 12.04 / 13.71 | 0.96 / 1.09 |
| `R_DR` | 63 | 185,462–187,226 | 190,458 | 358 / 758 | 25.9 / 0.8 | 7.18 / 8.33 | 11.53 / 14.31 | 0.98 / 1.14 |

- Process max RSS 47 MB native (six forms); wasm32 linear memory 48.1 MiB (all six forms in one module, module
  276,406 B).
- 6 × 960 mutated inputs native, 0 accepted, 0 panics.
- Every proof ≤ 262,144 B and every p99 ≤ 20.9 ms against the 60 ms limit.
- Without the precompile an EVM verifier is not viable: proven `R_TX` costs ≈ 530 M gas
  (`pqzh/ligero/runs/l11-forge.txt`, [pqzh-ligero.md](../docs/research/pqzh-ligero.md), "EVM verifier").

</details>

### 5.3 The `PQZ` precompile path (`pqz-ffi`, run `layout`, 2026-10-17)

Through `pqz-ffi` as the node calls it, with the verify-only arena of 512 MiB (ops 1–5: the C ABI `pqz_precompile`;
op 7: the Rust entry point `precompile`, the same call without the C wrapper):

| Form (op) | PQZL verify p50 / p99 (ms) | PQZH verify p50 / p99 (ms) |
|---|---|---|
| TRANSFER (1) | 7.90 / 8.62 | 9.56 / 9.71 |
| TRANSFER0 (1) | 7.65 / 8.61 | 9.33 / 9.42 |
| BURN (2) | 7.50 / 10.04 | 9.12 / 10.02 |
| REFRESH (2) | 7.49 / 9.57 | 9.12 / 9.39 |
| REGISTER (3) | 3.99 / 6.58 | 6.91 / 7.04 |
| DISCLOSE-SENDER (4) | 4.16 / 4.46 | 7.22 / 7.40 |
| DISCLOSE-RECEIVER (5) | 4.38 / 4.80 | 7.07 / 7.26 |
| DISCLOSE-AUDITOR (5) | 4.38 / 4.77 | 7.06 / 7.54 |
| TRANSFER-MULTI (7), M = 1, auditor on | 7.98 / 8.76 | 9.60 / 9.77 |
| TRANSFER-MULTI (7), M = 1, auditor off | 8.27 / 10.41 | 9.28 / 9.62 |
| TRANSFER-MULTI (7), M = 2, auditor on | 8.45 / 10.81 | 9.91 / 10.72 |
| TRANSFER-MULTI (7), M = 2, auditor off | 8.52 / 10.16 | 9.58 / 9.83 |
| TRANSFER-MULTI (7), M = 4, auditor on | 9.27 / 10.52 | 10.64 / 11.02 |
| TRANSFER-MULTI (7), M = 4, auditor off | 9.06 / 13.24 | 9.87 / 10.01 |
| TRANSFER-MULTI (7), M = 8, auditor on | 13.58 / 14.48 | not built |
| TRANSFER-MULTI (7), M = 8, auditor off | 12.93 / 20.05 | not built |


<details>
<summary>Proof sizes, the Rust entry point, adversarial inputs, op 7 sizes and source</summary>

Source: `ffi/runs/layout-bench.jsonl` (native, n = 200 per cell, one proof per form, verify-only arena 512 MiB; the
verification run of the layout move). Adversarial = one flipped proof bit.

| Form (op) | PQZL proof (bytes) | PQZL `precompile` p50 / p99 (ms) | PQZL adversarial p99 (ms) | PQZH proof (bytes) | PQZH `precompile` p50 / p99 (ms) | PQZH adversarial p99 (ms) |
|---|---|---|---|---|---|---|
| TRANSFER (1) | 42,759 | 7.88 / 8.07 | 8.04 | 231,022 | 9.58 / 10.23 | 1.26 |
| TRANSFER0 (1) | 42,387 | 7.61 / 7.93 | 9.97 | 231,064 | 9.27 / 9.56 | 1.28 |
| BURN (2) | 41,914 | 7.51 / 9.52 | 8.77 | 231,320 | 9.11 / 9.41 | 0.57 |
| REFRESH (2) | 41,902 | 7.49 / 8.33 | 10.18 | 231,928 | 9.11 / 9.25 | 1.19 |
| REGISTER (3) | 28,068 | 3.92 / 5.94 | 5.49 | 187,738 | 6.91 / 7.49 | 0.38 |
| DISCLOSE-SENDER (4) | 28,964 | 4.15 / 4.83 | 4.39 | 186,842 | 7.22 / 7.34 | 0.42 |
| DISCLOSE-RECEIVER (5) | 28,990 | 4.39 / 4.72 | 4.61 | 187,098 | 7.06 / 7.18 | 0.43 |
| DISCLOSE-AUDITOR (5) | 28,995 | 4.40 / 4.89 | 4.60 | 186,778 | 7.06 / 7.24 | 0.43 |


op 7 (statement, proof and prove time of the bench's proof; largest input = 5 + statement + the proof bound):

| M, auditor | statement (bytes) | PQZL proof (bytes) | PQZL prove (ms) | PQZL largest input (bytes) | PQZH proof (bytes) | PQZH prove (ms) | PQZH largest input (bytes) |
|---|---|---|---|---|---|---|---|
| 1, on | 83,072 | 42,766 | 810 | 181,381 | 232,174 | 627 | 318,547 |
| 1, off | 66,560 | 42,409 | 920 | 164,869 | 230,968 | 638 | 301,309 |
| 2, on | 99,712 | 43,603 | 1,100 | 198,021 | 232,174 | 646 | 335,187 |
| 2, off | 83,072 | 42,951 | 1,703 | 181,381 | 231,918 | 630 | 318,547 |
| 4, on | 132,992 | 45,274 | 1,958 | 231,301 | 232,708 | 634 | 369,193 |
| 4, off | 116,096 | 43,922 | 854 | 214,405 | 230,904 | 632 | 351,571 |
| 8, on | 215,936 | 61,802 | 2,517 | 314,245 | not built | — | — |
| 8, off | 198,528 | 58,998 | 1,948 | 296,837 | not built | — | — |


- Decode ≤ 0.04 ms; the C wrapper adds ≤ 0.1 ms at p50.
- Self-test cold 83.5 ms; verify-only arena peak 268,113,792 B with every form's and every op 7 shape's keys and tables
  kept (×2.0 margin to 512 MiB); prove with every relation loaded peaks at 853,679,872 B (1 GiB arena).
- Every op ≤ 20.1 ms p99 against the 60 ms limit. The earlier run `ffi1f2` (144 MiB arena, ops 1–5) is in
  `ffi/runs/`.

</details>

### 5.4 op 7 `R_TXM`, multi-recipient transfer

Built shapes, auditor on (auditor off is a little smaller and faster). Run: the package's `--multi-bench` in Docker
(P6-ANON S6, 2026-10-17, `artifact/runs/s6-docker-multi/`; full table with auditor off and the oversize shapes in
[artifact/README.md](artifact/README.md)). Parameters: `pqzl/params/estimator-e-s1-txm.txt` (MSIS β 452–459, MLWE β
470, knowledge error ≤ 2^−127); PQZH: [pqzh-ligero.md §15](../docs/research/pqzh-ligero.md).

| M | PQZL proof max (bytes) | PQZL prove native / wasm32 (ms) | PQZL SV verify p99 portable / wasm32 (ms) | PQZH proof max (bytes) | PQZH prove native / wasm32 (ms) | PQZH verify p99 native / wasm32 (ms) |
|---|---|---|---|---|---|---|
| 1 | 42,784 | 914 / 1,296 | 7.8 / 13.2 | 233,102 | 631 / 1,340 | 9.86 / 18.54 |
| 2 | 43,616 | 978 / 1,371 | 8.6 / 14.2 | 232,526 | 635 / 1,346 | 10.12 / 19.01 |
| 4 | 45,295 | 1,354 / 1,827 | 9.1 / 15.0 | 233,604 | 626 / 1,297 | 10.90 / 20.36 |
| 8 | 61,822 | 2,398 / 2,931 (wasm32: bench build only) | 13.6 / 23.1 | not built | — | — |

- Memory: PQZL wasm32 prove peak 221–256 MiB for M ≤ 4 and 495 MiB for M = 8 (hence browser wallets offer M ≤ 4, M = 8
  is for native / desktop clients); native prove arena 343 MiB at M = 4, 664 MiB at M = 8 (P6-ANON L3). PQZH prove heap
  ≤ 44 MB native, ≤ 49 MiB wasm32.
- The node's verify arena (512 MiB, S3) holds every op 7 shape's keys and tables with a 2× margin (§5.3).
- One (4, on) transfer vs 4 op 1 transfers: ≈ 3.5× fewer bytes and verify time (PQZH, pqzh-ligero.md §15.3).

### 5.5 Comparisons

**vs upstream LaZer.** Same statement, witness and relation source; upstream built from source by
`artifact/reproduce.sh --upstream` (`artifact/runs/docker-upstream/upstream-bench.txt`, N = 3 medians).

| | upstream LaZer `3330e48` (x86-64-v3 = AVX2 build) | this fork, portable (no AVX2 / AVX-512 needed) | fork faster by |
|---|---|---|---|
| `R_TX` prove / verify | 6,581 / 6,403 ms | 1,012 / 613 ms | 6.5× / 10.4× |
| `R_REG` prove / verify | 548 / 513 ms | 247 / 178 ms | 2.2× / 2.9× |
| `R_TX` verify, specialised verifier | — | ≈ 8 ms | ≈ 800× |

- **The fork needs no AVX-512** (and no AVX2): every number in this README comes from the portable build on a CPU
  without AVX-512; x86-64-v3 (AVX2 + AES-NI) is an optional, faster build of the specialised verifier only.
- Upstream LaZer's fastest path needs AVX-512 IFMA (its HEXL backend). That variant builds here but cannot run on the
  reference CPU, so the comparison uses upstream's AVX2 build; running the AVX-512 variant on an AVX-512 machine is an
  owner step. Method and the earlier cross-check: [research/upstream/RESULTS.md](research/upstream/RESULTS.md).

**vs the PQZH backends that were tried and rejected.** Same statement (`R_TX`), zero knowledge, 128 bits, proven
security, measured on the reference machine (details: [pqzh-backend-comparison.md](../docs/research/pqzh-backend-comparison.md)).

| Backend | Proof | Prove | Prover memory | Verify p99 native | Outcome |
|---|---|---|---|---|---|
| **Ligero over F_q** (this directory) | **≈ 231 KB** | **0.65 s** | **43 MB** | 10.5 ms | **chosen** |
| STARK (Plonky3, FRI + ZK, Goldilocks⁵) | 622 KB | 20.4 s | 2.8 GB | 19.1 ms | rejected: 2.7× larger, 30× slower to prove, 65× more memory |
| ZK WHIR (Plonky3 WHIR with hiding) | 1.95 MB | 43 s | 2.4 GB | 46.5 ms | rejected: 8× larger, reaches only ≈ 124 bits |

The rejected backends' code and runs are kept in `pqzh/stark-backup/` as the record.

## 6. Build, test, run

**Requirements:** clang / lld 18 (`wasm-ld-18`), node ≥ 26 for wasm32, Rust 1.97.1 (pinned per crate by
`rust-toolchain.toml`), Python 3 (stdlib only, run with `-I`).

> **Run every heavy step under `scripts/capped`** — the machine-wide lock, at most two heavy jobs at a time. Paths are relative to
> `pqz-core/` unless they start with `pqz-core/` (repository root).

**The usual checks in one place:**

| Want to… | Run |
|---|---|
| build PQZL (native + wasm) | `pqzl/build.sh all` |
| check the PQZL arithmetic against upstream | `pqzl/build/native/kat_dump > pqzl/build/native/kat-pqz.json` then `python3 -I pqzl/kat/check.py pqzl/kat/lazer-3330e48.json pqzl/build/native/kat-pqz.json` (19/19) |
| test PQZH | `(cd pqzh/ligero && cargo test --release --offline)` |
| test the precompile boundary | `scripts/capped pqz-core/ffi/run.sh <label>` |
| check every vector file | `scripts/capped pqz-core/ffi/vectors/run.sh <label>` |
| reproduce the published numbers | `OUT=<dir> scripts/capped pqz-core/artifact/reproduce.sh [--full]` |
| build / test the node plugin and image | `scripts/capped pqz-core/nethermind/run-tests.sh`, `scripts/capped pqz-core/nethermind/build-image.sh pqz<n>` ([nethermind/README.md](nethermind/README.md)) |

<details>
<summary><b>PQZL core (C)</b> — builds, bench, KAT, fix checks, keys</summary>

```sh
pqzl/build.sh native            # pqzl/build/native: libpqz.a, libpqz.so, pqz_bench, kat_dump
pqzl/build.sh native-x86v3      # optional: pqz_sv.c (pqz_verify_fast) for x86-64-v3 + AES-NI, pqzl/build/native-x86v3
pqzl/build.sh wasm              # pqzl/build/wasm/pqz.wasm (clang 18, wasm-ld-18, freestanding)
SV=0 B=build/wasm-nosv pqzl/build.sh wasm        # (B relative to pqzl/) without the specialised verifier (no pqz_sv.c, no pqz_verify_fast): a
                                         #   wallet's prover build; SV=0 works for native too
pqzl/build.sh all
```

Every build runs `pqzl/check_symbols.sh` on the library objects: outside themselves they may reference only `memcpy`,
`memset`, `__stack_chk_fail` (and wasm's `__stack_pointer`). The build fails on anything else (`malloc`, stdio, libm,
GMP, MPFR, `getentropy`).

```sh
pqzl/build/native/pqz_bench 7 7                                  # 7 proves, 7 + 7 honest verifies per relation (JSON lines)
pqzl/build/native/pqz_bench 1 0 2                                # R_TX only (3rd argument, bit mask: 1 R_REG, 2 R_TX,
                                                            #   4 R_BURN, 8 R_DS, 16 R_DR, 32 R_TX0; default 63 = all)
research/opt/bench.sh <label>                                        # pqz_bench 5 5 + run_wasm.mjs 3 1 -> research/opt/runs/<label>-*.jsonl
node pqzl/test/run_wasm.mjs 3 1                                  # the same under node
PQZ_VERIFY=fast pqzl/build/native/pqz_bench 2 200                # time pqz_verify_fast (wasm: PQZ_VERIFY=fast|both node ...)
pqzl/build/native/pqz_sv_diff 10 5 2 1 10                        # both verifiers on honest + mutated proofs, must agree
pqzl/build/native/kat_dump > pqzl/build/native/kat-pqz.json
python3 -I pqzl/kat/check.py pqzl/kat/lazer-3330e48.json pqzl/build/native/kat-pqz.json   # must print 19/19
pqzl/check_tbox_fixes.sh                                       # after pqzl/build.sh native: the tbox fixes and the z21 check are in place
pqzl/sv/review/review.sh zdiff 1                                 # z21-inflated proofs, all five relations: both verifiers agree
pqzl/sv/check_sv_fixes.sh                                        # after pqzl/build.sh native: pqz_verify_fast follows both fixes
pqzl/build/native/pqz_keys_kat 1000 > k.jsonl                    # keys KAT + 1,000-seed Dec(Enc(m)) = m round trip
python3 -I ../smartcontracts/vectors/pqz/pqz_kat.py --c-keys k.jsonl   # the independent Python check: pqz_kat: ok
python3 -I ../smartcontracts/vectors/pqz/pqz_kat.py --check            # its self-test + every PQZ vector file
```

- `R_TX` needs about 0.30 GB of arena alone (0.31 GB after an `R_REG` in the same process: a relation's keys are built
  at its first use and kept; the bench allocates 768 MiB).
- Same seeds must give the same `proofs_fnv` (native and wasm) across pure implementation changes.
- Run the bench under `scripts/capped`.
- Debug build with the libc heap instead of the arena (for ASan/LSan only): `-DPQZ_DEBUG_MALLOC`.

Full measurement rounds (each one capped job; outputs `<dir>/runs/<label>-*`; the tables above):

```sh
NP=10 NV=30 NPW=5 NVW=10 scripts/capped pqz-core/research/pqzl-measure/relfix.sh <label>   # build, KAT, tbox fixes, proofs_fnv, arena per
                                                                          #   op, ASan + UBSan, generic timings, six relations
scripts/capped pqz-core/pqzl/sv/rel3.sh <label>     # SV: differential (portable, x86-64-v3, wasm), bench, fuzz, KAT, fix checks
scripts/capped pqz-core/pqzl/sv/diff.sh <label>     # differential test only; pqzl/sv/bench.sh, pqzl/sv/fuzz.sh (ASan + libFuzzer) likewise
```

</details>

<details>
<summary><b>Regenerate</b> — PQZL parameters and the golden KAT</summary>

```sh
pqzl/params/codegen/run.sh <LaZer 3330e48 checkout> pqzl/params/tx_params.sage > pqzl/params/pqz_tx_params.h   # also reg
pqzl/params/regen.sh <LaZer 3330e48 checkout> <out dir> > pqzl/params/codegen-<label>.txt   # every spec, diffed against git
pqzl/params/run_e_s1.sh <LaZer 3330e48 checkout> <lattice-estimator 53da598 checkout> > pqzl/params/estimator-e-s1.txt
pqzl/kat/build-lazer-dump.sh <work dir> v4      # upstream golden dump (v3 = AVX2 build); needs docker and network
```

All three refuse other LaZer / estimator commits and run pinned images. The codegen takes minutes; headers are checked
in and regenerated only on purpose. The v4 golden dump needs an AVX-512 CPU or Intel SDE
(`sde64 -spr -- ./lazer_dump-v4 > pqzl/kat/lazer-3330e48.json`). Sizing details: [pqzl/params/README.md](pqzl/params/README.md).

</details>

<details>
<summary><b>PQZH Ligero (Rust)</b> — tests, gate-B round, cross-checks</summary>

```sh
(cd pqzh/ligero && cargo test --release --offline)                        # unit + integration tests (mutations, negative witnesses)
(cd pqzh/ligero && cargo test --release --offline --no-default-features)  # the production build (no `bench`, no floats)
scripts/capped pqz-core/pqzh/ligero/runs/tx0.sh <tag>      # fixtures, tests, native + wasm32 bench (1,000 verifies), xcheck, forge
scripts/capped pqz-core/pqzh/ligero/runs/gateb.sh <tag>    # gate-B round: tests, production build, native FNV, wasm32 1,000 verifies
scripts/capped pqz-core/pqzh/ligero/runs/stmt.sh <tag>     # tests, clippy float lint, dependency / float-instruction scan
scripts/capped pqz-core/pqzh/ligero/runs/limits.sh <tag>   # exact length bounds, xcheck, forge
scripts/capped pqz-core/pqzh/xcheck/ligero.sh              # statement / witness bytes = pqz_bench.c's, all six forms
```

</details>

<details>
<summary><b>Shared</b> — <code>pqz-stmt</code>, <code>pqz-ffi</code>, vectors, package, licences</summary>

```sh
scripts/capped pqz-core/stmt/xcheck.sh <label>       # unit tests, C statements + pqz_kat.py cross-check, wasm32 build
scripts/capped pqz-core/ffi/run.sh <label>           # tests, symbol scans, C smoke test, wasm32 digest diff, bench
scripts/capped pqz-core/ffi/vectors/run.sh <label>   # pqz-vectors --check (byte for byte), pqz_kat.py --check,
                                                     #   tamper.py, wasm32 replay; add `write` to regenerate the vectors
OUT=<dir> scripts/capped pqz-core/artifact/reproduce.sh [--full | --serve | --upstream]   # the reproducibility package
scripts/capped pqz-core/glic/absence.sh > pqz-core/glic/runs/absence-<date>.txt 2>&1     # GMP / MPFR / HEXL absence
```

The package (`artifact/`, [artifact/README.md](artifact/README.md)) is source only: a pinned `Dockerfile`, quick and
`--full` modes, `--serve` (local browser demo), `--upstream` (upstream LaZer built from source); `results.py` compares a
run with `expected-results.json` (frozen 2026-10-17).

</details>

## 7. Directory map

**Kind:** **core** = shipped code · **tool** = build / test / check scripts the core relies on · **measurement** = spike
or benchmark harness kept with its runs (experiment code stays in the repository) · **backup** = superseded, kept, never
built by the core. Layout (applied 2026-10-17, [plan](../docs/superpowers/plans/2026-10-15-pqz-core-layout.md)):
`pqzl/` = the PQZL C core and its tools, `pqzh/` = PQZH (`ligero/` the backend, `stark-backup/` the rejected STARK
crate), `research/` = measurement harnesses with their runs, shared crates and tools at the top. Run files keep the
paths of their day.

| Path | System | Kind | In one line |
|---|---|---|---|
| `pqzl/build.sh`, `pqzl/check_symbols.sh` | PQZL | tool | builds (native / x86-64-v3 / wasm); symbol scan of every library build |
| `pqzl/check_tbox_fixes.sh` | PQZL | tool | fails if a LaZer fix (lazer#24, #25) or the z21 check (#26) is gone |
| `pqzl/lazer/` | PQZL | core | the LaZer `3330e48` subset, changes marked `PQZ:` |
| `pqzl/src/` | PQZL | core | the rewritten layers, relations, keys, specialised verifier, C ABI `pqz.h` |
| `pqzl/params/` | PQZL | core + tool | relation specs, generated headers, codegen and sizing |
| `pqzl/kat/` | PQZL | tool | arithmetic-layer KAT against upstream |
| `pqzl/test/` | PQZL | tool | bench, wasm runner, keys KAT, SV differential and fuzz targets |
| `pqzl/sv/` | PQZL | tool + measurement | specialised-verifier checks, bench, review reproducers |
| `pqzl/sz/`, `pqzl/l2dom/` | PQZL | tool (spike origin) | the two LaZer tbox findings' reproducers |
| `research/pqzl-measure/` | PQZL | measurement | the PQZL measurement round (`relfix.sh`) and its runs (was `rel3/`) |
| `research/opt/` | PQZL | measurement | optimisation round: bench, profiling, microbenches |
| `research/floor/` | PQZL | measurement | verifier-floor microbenchmarks and cost model |
| `research/upstream/` | PQZL | measurement | upstream LaZer vs the fork on the same statements |
| `pqzh/ligero/` | PQZH | core | crate `pqzh-ligero`, THE PQZH backend |
| `pqzh/xcheck/` | PQZH | tool | C ↔ Rust statement / witness cross-check |
| `pqzh/stark-backup/` | PQZH | backup | the Plonky3 STARK crate and the rejected backends' records |
| `stmt/` | both | core | `pqz-stmt`, the statement codec |
| `ffi/` | both | core | `pqz-ffi`, the precompile boundary; vector generator |
| `artifact/` | both | tool | reproducibility package, source only |
| `glic/` | both | tool | licence step 1: GMP / MPFR / HEXL absence scans |
| `fuzz/` | both | tool | continuous fuzzing: targets `precompile`, `mutate`, `codec` (ASan + UBSan, libFuzzer) |
| `nethermind/` | both | core + tool | `Nethermind.Pqz` plugin (PQZ + ML-DSA precompiles), tests, P/Invoke harness, calibration, image build, chain runbook and runs |
| `NOTICE`, `STATUS.md` | — | — | third-party notices; the detailed status log |

<details>
<summary>What each directory contains in detail</summary>

| Path | Content |
|---|---|
| `pqzl/build.sh`, `pqzl/check_symbols.sh` | native / x86-64-v3 / wasm builds; symbol scan of every library build |
| `pqzl/check_tbox_fixes.sh` | fails if either LaZer tbox fix (lazer#24, #25) or the z21 norm check (lazer#26, `docs/research/pqz-z21-norm.md`, verifier only) is gone; runs `pqzl/sz/`, `pqzl/l2dom/`, `pqzl/sv/review/review.sh norm` |
| `pqzl/lazer/` | LaZer `3330e48` subset. The pristine copy is commit `c91b3ab`; changes are in place, marked `PQZ:`; SHAKE256 added to `shake128.c`. Licence `pqzl/lazer/LICENSE` |
| `pqzl/src/` | the rewritten layers and the C ABI (`pqz.h`): `pqz_mpn.h`, `pqz_ntt.c`, `pqz_fixexp.h`, `pqz_arena.c`, `pqz_rt.h`, `pqz_aes_gen.h` (from `gen_aes.py`); relations `R_REG`, `R_TX`, `R_TX0` (op 1 by statement length), `R_BURN`, `R_DS`, `R_DR` (`pqz_rel.c`); KeyGen / Enc / Dec from seeds (`pqz_keys.c`, deterministic); the specialised verifier (`pqz_sv.c`); wasm runtime (`pqz_wasm_rt.c`), `freestanding/` headers |
| `pqzl/params/` | LaZer codegen (`codegen/`), relation specs `{reg,tx,tx0,burn,ds,dr}_params.sage`, generated headers `pqz_*_params.h`, `regen.sh`, parameter sizing (`e_s0.py`, `e_s1_proof.sage`, `estimator*.txt`), `anon/` (multi-recipient transfer sizing); [pqzl/params/README.md](pqzl/params/README.md) |
| `pqzl/kat/` | arithmetic-layer KAT: `lazer_dump.c` (one source, upstream or pqz-core backend), golden `lazer-3330e48.json`, `check.py`, `build-lazer-dump.sh` |
| `pqzl/test/` | `pqz_bench.c` (prove, verify, tamper checks, the hedging check, timings, a hash of the proofs), `run_wasm.mjs` (the same under node), `pqz_keys_kat.c` (SHAKE256 / KeyGen / Enc / Dec KAT and round trip, checked by `pqz_kat.py --c-keys`), `pqz_sv_diff.c`, `pqz_sv_fuzz.c`, runs `runs/` |
| `pqzl/sv/` | specialised verifier checks (`docs/research/pqz-specialised-verifier.md`): `diff.sh` (differential test against `pqz_verify`), `bench.sh` (portable, x86-64-v3, wasm), `fuzz.sh` (ASan + UBSan, libFuzzer), `research/pqzl-measure.sh` (all relations in one capped job: diff, bench, wasm both, ASan, KAT, both fix checks, memory per op), `check_sv_fixes.sh` (fails unless the differential test catches either tbox fix reverted in `pqz_sv.c`), runs `runs/`; `review/` the independent review's reproducers (`review.sh dom | norm | zdiff | fuzz`: cheating provers past the final hash, the z21 differential `z21diff.c`; never compiled by `pqzl/build.sh`) |
| `research/pqzl-measure/` | the PQZL measurement round: `bench.sh` (build, KAT, `R_REG` / `R_TX` proof hashes, timings), `relfix.sh` (after the owner's fix-ups of 2026-10-13: build, KAT, tbox fixes, proof hashes, arena peak per relation, ASan + UBSan, timings of all six), raw runs `runs/` (latest `tx0c-*`) |
| `research/opt/` | optimisation round: `bench.sh` (native + wasm bench), `prof.sh` (gprof), `asan.sh` (ASan + UBSan, malloc path), microbenches `micro_basemul.c` / `micro_aes.c`, raw results `runs/` (STATUS.md, optimisation section) |
| `pqzl/sz/`, `pqzl/l2dom/` | the two LaZer tbox soundness findings behind `proofSystemId` v2 ([lazer#24](https://github.com/lazer-crypto/lazer/issues/24), [#25](https://github.com/lazer-crypto/lazer/issues/25)): challenge-row trace and the pooled-slack cheating prover; run by `pqzl/check_tbox_fixes.sh` ([pqzl/sz/README.md](pqzl/sz/README.md)) |
| `research/floor/` | verifier-floor microbenchmarks and cost model (`docs/research/pqz-verifier-floor.md`): unit costs, prototypes, operation counts of the generic verifier; `research/floor/build.sh run` under `scripts/capped` |
| `research/upstream/` | upstream LaZer vs the fork on the same statements ([research/upstream/README.md](research/upstream/README.md), [RESULTS.md](research/upstream/RESULTS.md)); `shim/` is also used by `artifact/reproduce.sh --upstream`; `static/` a local benchmark bundle (never published) |
| `pqzh/ligero/` | crate `pqzh-ligero` (`docs/research/pqzh-ligero.md`): field, FFT, constraint systems of the six forms, protocol, Merkle, transcript; `wasm/` module; `ligero_params.py` and `evm_model.py` models; run scripts and raw runs `runs/` |
| `pqzh/xcheck/` | C ↔ Rust statement / witness cross-check: `ligero.sh` (Ligero, six forms, plus `kat_stmt.py`), `run.sh` (the STARK crate), `dump_setup.c` |
| `pqzh/stark-backup/` (`Cargo.toml`, `src/`, `tests/`, `examples/`, `wasm/`, `runs/`, `sol/`, `pqzh_count.py`, `counts.txt`) | the Plonky3 STARK crate `pqzh` (FRI + ZK, Goldilocks⁵, the ZK WHIR adapter `pqzl/src/whirpcs.rs`), its runs, the Solidity / StarkEx cost models (`sol/`), the design-study counts; kept as the record of the rejected backends, never linked by `pqz-ffi` |
| `stmt/` | `pqz-stmt`, the statement codec; `xcheck.sh` (unit tests, the six C statements and `pqz_kat.py`'s statements and rejections, the wasm build), runs `runs/` |
| `ffi/` | `pqz-ffi`, the precompile boundary ([ffi/README.md](ffi/README.md)); `src/bin/pqz-vectors.rs` (feature `prove`) with `vectors/` (`run.sh`, `tamper.py`, `replay_wasm.mjs`, runs); `wasm/` prove harness; `run.sh`, runs `runs/` |
| `artifact/` | reproducibility package, source only ([artifact/README.md](artifact/README.md)); Docker test logs `runs/`; PQZL runs today (PQZH stages on branch `pqz-artifact2`) |
| `glic/` | licence check, step 1 (`docs/research/pqz-licence-inventory.md`): `absence.sh` (builds every artifact into `pqzl/build/glic` and scans symbols, `DT_NEEDED`, wasm imports and strings for GMP / MPFR / HEXL), raw outputs and licence tables `runs/` |
| `fuzz/` | continuous fuzzing ([fuzz/README.md](fuzz/README.md)): Rust oracles behind C shims (`src/lib.rs`, `targets/*.c`), `build.sh` (stable Rust with sancov + clang 18 libFuzzer, ASan + UBSan, `pqz-ffi` feature `fuzz`), `run.sh <target> <seconds>` under `scripts/capped`, `seeds.py` (seeds from the frozen vectors); targets `precompile` (raw bytes into `pqz_precompile`), `mutate` (edit scripts over honest inputs; any accepted change is a finding; specialised vs generic verifier), `codec` (accepted ⇒ re-encoding equals the input); first campaigns 2026-10-15: ≈ 3.2 M inputs, no finding, arena peak 95,169,680 B; corpora `corpus/`, logs `runs/` |

</details>

## 8. Licences

- **Notices:** third-party notices for a source or binary distribution are in [`NOTICE`](NOTICE); inventory and gaps:
  `docs/research/pqz-licence-inventory.md`.
- **LaZer:** MIT, (c) 2022-2026 IBM, `pqzl/lazer/LICENSE`; no patent grant — a licence / patent review is
  required before production use (not before publication).
- **No GMP, MPFR, HEXL or libstdc++** in the library objects (`glic/runs/absence-2026-10-14.txt`).
- **Rust dependencies:** `pqz-ffi` depends on the in-tree crates and `sha3`, plus `hkdf` / `sha2` with feature `prove` (the op 7 memo; `cc` at build time), the Ligero crate on
  `sha3` and `pqz-stmt`, `pqz-stmt` on nothing; the backup STARK crate's licence table is
  `glic/runs/pqzh-cargo-licences.tsv`.
- **Local-only builds:** `pqzl/kat/build-lazer-dump.sh` links upstream LaZer statically with GMP / MPFR (LGPL), HEXL and
  libstdc++. That binary is a local build output, never committed or distributed (distributing it would carry LGPL
  relinking duties). Intel SDE 9.48.0 was used once, locally, to run the AVX-512 golden dump on a CPU without AVX-512;
  it is not vendored and not needed to build or test pqz-core.
- **Nothing built is published** (no release assets, hosted wasm or pushed images); `artifact/` rebuilds from source.

## 9. Status and what's next

**Done so far:** the first spike (`R_REG`, a first `R_TX`, native and freestanding wasm32), an optimisation round, then
`R_BURN` (also REFRESH), `R_DS` and `R_DR` (also the auditor) (`docs/research/pqz-relations-burn-disclose.md`), the
tbox fixes (v2) and z21, the specialised verifier, then the relations round: hedged provers, keys from seeds, `R_TX0`, `pqz-stmt`,
PQZH on Ligero with all six forms, `pqz-ffi`, the frozen vectors (`smartcontracts/vectors/pqz/`) and serialization v1.

Then (2026-10-15 / 17): the precompile **live on chain 7622** for ops 1–6 (P6f, §3) and the PQZ contracts deployed there
(P6g: `PqzSafety`, `UAPqzVerifier`, the PQZ token kinds; end-to-end with real PQZL proofs); op 7 `R_TXM` in both systems,
`pqz-stmt` and `pqz-ffi` with its vectors, fuzzing and package stage (P6-ANON L, H, S1–S6, S9); the directory layout
(`pqzl/`, `pqzh/`, `research/`, 2026-10-17).

**Next, in order:**

1. ~~S7 and the op 7 entry points in the PQZ tokens~~ — done 2026-10-17 (op 7 live in the tokens on 7622).
2. ~~**Gate A (PQZL)** and **gate B (PQZH)**~~ — **passed 2026-10-17** (`gate.sh`, runs `runs/gate/2026-10-17-*`; both ids
   frozen; decisions.md CTR-PQZ-09) ([relations plan](../docs/superpowers/plans/2026-10-14-p6e-relations.md)): KAT 19/19, fix checks, differential 0 disagreements,
   `pqz-vectors --check` and `pqz_kat.py --check`, wasm32 replay byte-equal, `pqz-ffi` tests, fuzzing clean;
   gate B also every PQZH op ≤ 262,144 B and ≤ 60 ms p99 native and wasm32 and the review of the modified Ligero ZK
   construction. Both ids freeze there.
3. ~~**The freeze**~~ — done 2026-10-17: `artifact/runs/freeze-2026-10-17/`, PASS (233 ok), `expected-results.json` frozen.
4. **PQZL in Rust** (after the freeze; [plan](../docs/superpowers/plans/2026-10-17-pqzl-rust-port.md)): crate `pqzl` in
   `pqzl/rust/`, byte-for-byte equal to the C core; which one is the production core is decided later (owner).

**Possible extension (research only, not planned): zero knowledge for arbitrary circuits on Ligero.** Today each
operation has its own hand-written relation. Ligero can prove any arithmetic circuit, so PQZ could become
general-purpose:

- a **circuit front-end** (R1CS, Plonkish or Noir's ACIR) compiles a circuit into Ligero's constraints over F_q;
- circuits are **data, not node code**: each is registered once on chain under an id (the hash of its constraint
  system), and **the same `PQZ` precompile** verifies a proof for any registered circuit — no node update per circuit;
- gas is priced by circuit size, and a maximum circuit size keeps verification under 60 ms;
- estimate: ≈ 1–2 months; proofs grow roughly with √(circuit size) (231 KB for `R_TX` → ≈ 0.6–1 MB at 10^6
  constraints); still post-quantum and zero-knowledge.

Uses: private voting, auctions, credential checks, confidential matching. Details, and why a zkVM or zkEVM is out of
scope: [pqz-general-purpose.md](../docs/research/pqz-general-purpose.md).

Open items (arena exhaustion, global state, secret zeroing, `pqzl/check_symbols.sh` on missing files, …):
[STATUS.md "Open"](STATUS.md#open).

## 10. Further reading

| Topic | Read |
|---|---|
| Spec | [pq-zero-knowledge.md](../docs/contracts/pq-zero-knowledge.md) — [encryption](../docs/contracts/pq-zero-knowledge.md#encryption), [protocol](../docs/contracts/pq-zero-knowledge.md#protocol), [proof engine](../docs/contracts/pq-zero-knowledge.md#proof-engine), [serialization](../docs/contracts/pq-zero-knowledge.md#serialization) |
| PQZL | `docs/research/pqz-core-e-s1.md` (the spike write-up), `pqz-specialised-verifier.md`, `pqz-verifier-floor.md`, `pqz-relations-burn-disclose.md`, `pqz-tbox-soundness.md`, `pqz-l2-domain.md`, `pqz-z21-norm.md`, `pqz-parameters-e-s0.md` |
| PQZH | `docs/research/pqzh-ligero.md`, `pqzh-backend-comparison.md`, `pqzh-design.md`, `pqzh-prototype.md`, `pqzh-zk-ext5.md`, `pqzh-zk-whir.md`, `pqzh-solidity-verifier.md`, `pqzh-starkex-verifier.md` |
| Node | [nethermind/README.md](nethermind/README.md) (plugin, image, gas), [nethermind/chain/RUNBOOK.md](nethermind/chain/RUNBOOK.md) (copy gate, live roll-out, rollback) |
| Plans | [relations and serialization](../docs/superpowers/plans/2026-10-14-p6e-relations.md), [multi-recipient transfer](../docs/superpowers/plans/2026-10-14-p6-anon.md), [precompiles on chain 7622](../docs/superpowers/plans/2026-10-14-p6f-precompiles.md), [pqz-core layout](../docs/superpowers/plans/2026-10-15-pqz-core-layout.md), [PQZL in Rust](../docs/superpowers/plans/2026-10-17-pqzl-rust-port.md) |
| Other | anonymity research `docs/research/pqz-anonymity.md`; general-purpose circuits `docs/research/pqz-general-purpose.md`; licences `docs/research/pqz-licence-inventory.md` |

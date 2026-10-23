# pqz-core/params/sets — PQZ parameter sets

Owner 2026-10-21: **parameter sets are per-directory, selected at compile time; one set per library build** (a
runtime choice between sets is deferred). Each directory `<set>/` holds every parameter-dependent input of the PQZL C
and Rust cores; the algorithm code uses only the named constants. Sets are named by n and `K_MAX`. PQZH has its own
generated file per set (`pqzh_set.rs`, from `set.toml`'s `[pqzh_preset]`; plan 5h Task 8c part 2) for every set whose
`set.toml` says `pqzh = true`, and `pqz-ffi` / `pqz-vectors` / the gate build it there. Adding a set: write
`<set>/set.toml`, then `make.sh <set> all`; a new set with PQZH also needs, by hand (a missing one fails loudly):
pqzh-ligero's `set-<set>` feature and `src/set.rs` branch, the ligero wasm feature, `pqz_kat.py` `_LIGERO_MAX` and the
`limits_exact` tables (`pqzh/ligero/src/ligero.rs`).

| Set | n, k | q | `K_MAX` | Status | `SET.md` |
|---|---|---|---|---|---|
| `n2048-kmax1024` | 2048, 32 | 2^42 − 215 | 1,024 | the frozen v3 set: main's build, the committed vectors, the contracts until 8d | [SET.md](n2048-kmax1024/SET.md) |
| `n2304-kmax4096` | 2304, 36 | 61,275,424,977,257 (2^45.80) | 4,096 | owner 2026-10-21: the default of the `pqzl` crate and `gate.sh` | [SET.md](n2304-kmax4096/SET.md) |
| `n2560-kmax16384` | 2560, 40 | 2^50 − 42,310,535 | 16,384 | approved 2026-10-20 as the Task 8 set, superseded as the default by `n2304-kmax4096` 2026-10-21: shippable for customer chains; full vectors + gate | [SET.md](n2560-kmax16384/SET.md) |
| `n2816-kmax65536` | 2816, 44 | 2^54 − 327 | 65,536 | research record `pqzl/params/aprime/`, owner 2026-10-21: **core only** (`core_only = true`: C + Rust cores, KATs; no pqz-stmt / precompile / vectors / contracts) | [SET.md](n2816-kmax65536/SET.md) |

Older notes and plans use short names for three of these sets: "set (a)" = `n2304-kmax4096`, "16k" = `n2560-kmax16384`,
"A′" = `n2816-kmax65536`; new text uses the directory names only.

## What a set fixes: cryptography first, cost follows (owner question 2026-10-23)

A parameter set is not a gas or storage setting: it is the cryptographic instance itself. Every value below decides
security or correctness; gas, state and calldata only follow from the sizes they produce.

| Parameter | Cryptographic role |
|---|---|
| n (= k · 64), q | the ring and modulus of the lattice encryption (MLWE): the root of its security |
| `K_MAX` | how many credits (homomorphic additions of encrypted amounts) an account may receive between refreshes and still decrypt correctly: the summed noise of `K_MAX` fresh ciphertexts must stay below the noise ceiling E (`n2816-kmax65536`: 65,535 · B_FRESH = 1,044,627,900 < E = 2^30) |
| Δ, β_s / β_e, CBD widths | plaintext scale and noise distributions: correct decryption and encryption security |
| proof MLWE rank `kmlwe` | security of the zero-knowledge proofs (MSIS / MLWE); `n2816-kmax65536` needs 42, at 41 dual_hybrid gives β 447 / 448 < 450 |
| norm-proof exactness, Fiat–Shamir rounds (`e-s0.txt`) | soundness of the proofs, checked again for every set |

What is the same across sets: the target security bar — every set must reach β ≥ 450 (MSIS, hiding MLWE uSVP and
dual_hybrid, `e-s1.txt`). One recorded exception: `n2048-kmax1024`, encryption with 80 worst-case hints, DDGR20 β 446.0
(owner-accepted, CTR-PQZ-03, 2026-10-15); the larger sets clear 450 there without an exception.

What differs: the capacity `K_MAX`. A larger `K_MAX` needs a larger q (more noise room), and a larger q needs a larger n
to keep the same security; larger n and q make keys, ciphertexts and proofs larger, and that is where the cost comes
from (state gas per stored ciphertext, calldata, prover and verifier time).

| Set | `K_MAX` | q | proof rank `kmlwe` | encryption uSVP β (no hints) | pk / ciphertext (B) |
|---|---|---|---|---|---|
| `n2048-kmax1024` | 1,024 | 2^42 − 215 | 33 | 476 | 16,384 / 16,512 |
| `n2304-kmax4096` | 4,096 | 61,275,424,977,257 (2^45.80) | 36 | 496 | 18,432 / 18,560 |
| `n2560-kmax16384` | 16,384 | 2^50 − 42,310,535 | 39 | 508 | 20,480 / 20,608 |
| `n2816-kmax65536` | 65,536 | 2^54 − 327 | 42 | 520 | 22,528 / 22,656 |

Each set is a separate cryptographic instance: a proof made at one set does not verify at another, a deployment needs
its own `proofSystemId` (plan 5h Task 8d), and a cryptographic audit covers one set at a time. Choosing a set trades
capacity (`K_MAX`) against cost at the same target security; it never changes the cryptography's bar, only its instance.
Numbers: each set's `SET.md`.

## PQZL and PQZH in one set: what is shared, what is not (owner question 2026-10-23)

**Shared.** PQZL (lattice proofs, LaZer) and PQZH (hash-based backup, Ligero over F_q) prove the same statements over
the same ciphertexts mod q, so a set's q, n, `K_MAX`, Δ and the statement / object layout are one source for both; both
live in the same directory `params/sets/<set>/` and are built for one set per library build.

**Not shared.** The proof parameters are each system's own:

| | PQZL | PQZH |
|---|---|---|
| file in `<set>/` | `pqz_set.h`, `rust/set.rs`, `<rel>_params.sage`, `pqz_<rel>_params.h`, `rust/<rel>.rs` | `pqzh_set.rs` (generated from `set.toml` `[pqzh_preset]`) |
| proof parameters | proof MLWE rank `kmlwe`, norm bounds, codegen shapes per relation | the Ligero preset: domain radices, code length n, message length k, query count t |
| security measure | lattice estimator β ≥ 450 (MSIS, MLWE uSVP / dual_hybrid, `e-s1.txt`), norm-proof exactness and Fiat–Shamir rounds (`e-s0.txt`) | soundness bits of the preset (query and total soundness, `PQZH.md`; `n2304-kmax4096` preset B: 127.40 bits total) |
| size limit | `MAX_PROOF` 98,304 B | `MAX_PROOF_PQZH` per set (`set.toml` `[pqzh_preset] max_proof`, in `rust/set.rs` for pqz-stmt): 262,144 B; `n2560-kmax16384` only: 327,680 B (owner 2026-10-23) |

**Not every set has PQZH.** Ligero's evaluation domains need q − 1 to be divisible by small radices, so whether PQZH
exists at a set depends on q:

| Set | PQZH |
|---|---|
| `n2048-kmax1024` | built and running (`pqz-ffi`, vectors, gate): THE preset (D3 id) |
| `n2304-kmax4096` | built (plan 5h Task 8c part 2; owner 2026-10-22): the **radix-7/17 preset** (radices 2 / 7 / 17 / 19 / 43 / 431, n 45,752, k 952, t 120), debit proofs 251,608–253,048 B (9–10 KB under 262,144), soundness 127.40 bits; the two other options below stay as fallbacks (re-prove under the limit: Cargo feature `fallback-retry`, never in production builds; per-set limit raise: documented only) |
| `n2560-kmax16384` | built (plan 5h Task 8c part 2): debit proofs above 262,144 and no set-specific preset (q − 1 = 2^3 · 19 · 43 · 431 · 5,659 · 70,627 has no other small radix; re-proving cannot close a ≈ 40 KB gap) → **owner 2026-10-23: `MAX_PROOF_PQZH` = 327,680 B (320 KiB) for this set only** (per-set limit raise; decisions CTR-PQZ-10) and t = 122 on THE preset's n / k (soundness 127.55 bits, above the other sets'): debit bounds 303,412–305,120 B |
| `n2816-kmax65536` | none: q − 1 = 2^3 · 3 · 1,789 · 419,563,967,521 has none of the radices 19 / 43 / 431 of PQZH's domains; PQZH here would need other domains |

Details per set: `<set>/PQZH.md`.

### What the sizes and limits below mean (both tables)

Every number in the two tables below is a **size in bytes (B)** — not gas (1 KiB = 1,024 B). Gas is elsewhere and not yet
measured for every set: `n2560-kmax16384` in its `SET.md` ("Conditions for this set to work on a chain") and
[`pqzl/params/p16k/results-16k.md`](../../pqzl/params/p16k/results-16k.md) §8 (plan 5h Task 7b, Amsterdam);
`n2304-kmax4096` estimates in [`docs/research/pqz-pack.md`](../../../docs/research/pqz-pack.md) (spike PACK), measured in
plan 5h Task 8d part 2; the PQZH calldata floor gas per relation in each set's `PQZH.md`.

- **proof**: the bytes of one zero-knowledge proof, as the client sends it.
- **statement**: the public data the proof is about (public keys, ciphertexts, amounts' commitments), built by the token
  contract from its own state.
- **precompile input**: what the token passes to the `PQZ` precompile for one check = 5-byte header + statement + proof.
- **`MAX_PROOF_PQZL`, `MAX_PROOF_PQZH`**: the largest proof (B) the `PQZ` precompile accepts for that proof system; a
  longer proof is rejected before any verification (a revert, not a wrong answer). Set in `pqz-stmt` from the set's
  `rust/set.rs`.
- **`MAX_INPUT`**: the largest precompile input (B) the precompile accepts, whatever the proof system.
- **bound** (PQZH): the longest proof the PQZH prover can produce for that relation (computed by the crate, exact); a set
  is only usable if every bound is ≤ its `MAX_PROOF_PQZH`.
- **arena peak** (PQZL): the prover's memory use on the client, in MB — not a chain limit.

Gas limits the sizes are judged against (spec §12 item 2: Ethereum-like limits, never the testnet's): **per transaction
16,777,216 regular gas (2^24, EIP-7825)** — so at most ≈ 261,909 B of calldata under the EIP-7976 floor
(15,000 + 64 gas per byte); **per block 60 M gas** on Ethereum mainnet today (≈ 200 M expected with Glamsterdam; the
SCaaS testnet's genesis has 200 M). New contract state is paid separately as state gas (EIP-8037): it counts towards the
block, not towards the 2^24 regular-gas cap of the transaction.

### PQZL per set: proof sizes and size limits (bytes)

PQZL proof size per relation, the largest of two proofs from the C prover bench of each set's gate
(`pqz-core/runs/gate/<set>-fnv-c.jsonl`, `proof_bytes_max`; C = Rust = wasm32 byte for byte), and the C prover's arena
peak. Op 7 (`R_TXM`) M legs with the auditor; `M = …, no auditor` without. The limit for every set is `MAX_PROOF_PQZL` =
98,304 B (96 KiB), the same for all four sets.

| Relation | `n2048-kmax1024` | `n2304-kmax4096` | `n2560-kmax16384` | `n2816-kmax65536` |
|---|---|---|---|---|
| R_REG (op 9, register) | 28,080 | 30,273 | 32,433 | 35,420 |
| R_DS (disclose to the sender) | 28,984 | 30,800 | 32,979 | 35,925 |
| R_DR (disclose to the receiver) | 29,002 | 31,451 | 33,780 | 36,753 |
| R_TX (op 1, transfer) | 42,768 | 46,706 | 50,407 | 54,857 |
| R_TX0 (transfer from a fresh account) | 42,423 | 46,322 | 50,060 | 54,508 |
| R_BURN | 41,925 | 45,836 | 49,551 | 54,031 |
| op 7 M = 1 | 42,755 | 46,673 | 50,385 | 54,882 |
| op 7 M = 2 | 43,614 | 47,509 | 51,226 | 57,762 |
| op 7 M = 4 | 45,278 | 50,749 | 54,850 | 59,529 |
| op 7 M = 8 (two randomness groups) | 61,831 | 67,604 | 72,724 | 79,195 |
| op 7 M = 1, no auditor | 42,434 | 46,364 | 50,066 | 54,501 |
| op 7 M = 2, no auditor | 42,938 | 46,844 | 50,538 | 55,018 |
| op 7 M = 4, no auditor | 43,918 | 47,862 | 51,576 | 58,125 |
| op 7 M = 8, no auditor | 58,981 | 64,632 | 69,904 | 76,364 |
| largest / `MAX_PROOF_PQZL` | 61,831 / 98,304 | 67,604 / 98,304 | 72,724 / 98,304 | 79,195 / 98,304 |
| pk / ciphertext (B) | 16,384 / 16,512 | 18,432 / 18,560 | 20,480 / 20,608 | 22,528 / 22,656 |
| op 1 statement, auditor on (B) | 83,072 | 93,312 | 103,552 | 113,792 |
| C prover arena peak: R_TX / op 7 M = 8 | 312 / 794 MB | 380 / 937 MB | 457 / 1,094 MB | 538 / 1,259 MB |

op 7 M = 8 needs `PQZ_ARENA_MB=2048` in the C bench at every set (above its default 768 MiB). `n2816-kmax65536` is core
only: no pqz-stmt / precompile build, so its limits are the other sets' for comparison, not a deployed limit.

### PQZH per set: preset, proof sizes and size limits (bytes; plan 5h Task 8c part 2)

`set.toml` holds the preset and the limits; `gen_set.py` writes `pqzh_set.rs` (radices, n, k, t; q − 1's factors,
generator and non-square computed and checked), `MAX_PROOF_PQZH` / `MAX_INPUT` into `rust/set.rs` (pqz-stmt) and all
of them into `set.json` (`pqz_kat.py`, `ligero_params.py`). Bounds and soundness: the crate (`ligero_kat sizes`).

| Set | radices | n / k / t | largest bound (B) | soundness (bits) | `MAX_PROOF_PQZH` (B) | `MAX_INPUT` (B) | largest precompile input (B): proof at the bound / at `MAX_PROOF_PQZH` |
|---|---|---|---|---|---|---|---|
| `n2048-kmax1024` | 2/19/43/431 | 32,756 / 817 / 121 | 236,196 (op 7 M = 4, auditor) | 127.23 | 262,144 | 393,216 | 369,193 / 395,141 (above: a proof over 260,219 B there is an Input revert) |
| `n2304-kmax4096` | 2/7/17/19/43/431 | 45,752 / 952 / 120 | 253,048 | 127.40 | 262,144 | 524,288 | 402,429 / 411,525 |
| `n2560-kmax16384` | 2/19/43/431 | 32,756 / 817 / 122 | 305,120 | 127.55 | 327,680 | 524,288 | 470,885 / 493,445 |

Per relation: the proof bound from the crate (`ligero_kat sizes`; `pqzh/ligero/runs/c8-v3-sizes.jsonl`,
`c8b-a-sizes.jsonl`, `c8c-n2560-sizes.jsonl`), in brackets the honest proofs measured (`c8c-<set>-kat.jsonl`, seeds 0
and 1, all verify), then the largest precompile input (5 + statement + bound), all in bytes. `n2816-kmax65536`: no PQZH.

| Relation | `n2048-kmax1024` | `n2304-kmax4096` | `n2560-kmax16384` |
|---|---|---|---|
| R_REG (op 9, register) | 190,458 (186,904–187,098) / 206,943 | 207,688 (204,358–204,936) / 226,221 | 234,238 (230,526–231,006) / 254,819 |
| R_DS (disclose to the sender) | 190,458 (187,482–187,546) / 223,647 | 207,688 (204,616–205,416) / 244,973 | 234,238 (230,366–231,774) / 275,619 |
| R_DR (disclose to the receiver) | 190,458 (185,462–185,462) / 223,647 | 207,688 (204,552–204,936) / 244,973 | 234,238 (231,422–231,678) / 275,619 |
| R_TX (op 1, transfer) | 235,470 (231,256–231,416) / 318,547 | 251,608 (248,312–248,952) / 344,925 | 304,266 (299,850–300,490) / 407,823 |
| R_TX0 (transfer from a fresh account) | 234,744 (229,672–231,320) / 301,309 | 251,608 (247,544–248,376) / 326,365 | 304,266 (300,682–301,194) / 387,215 |
| R_BURN | 234,744 (231,256–232,344) / 284,797 | 251,608 (247,176–248,440) / 307,805 | 303,412 (300,148–301,204) / 365,753 |
| op 7 M = 1 | 235,470 (230,242–231,598) / 318,547 | 251,608 (247,304–248,344) / 344,925 | 304,266 (299,923–301,226) / 407,823 |
| op 7 M = 2 | 235,470 (231,128–232,462) / 335,187 | 252,328 (248,424–248,434) / 364,333 | 304,266 (300,170–300,586) / 428,559 |
| op 7 M = 4 | 236,196 (231,944–233,604) / 369,193 | 253,048 (249,752–249,880) / 402,429 | 305,120 (301,824–302,112) / 470,885 |
| op 7 M = 1, no auditor | 234,744 (231,304–232,024) / 301,309 | 251,608 (247,304–248,440) / 326,365 | 304,266 (301,450–301,610) / 387,215 |
| op 7 M = 2, no auditor | 235,470 (231,438–232,366) / 318,547 | 251,608 (246,792–248,088) / 344,925 | 304,266 (300,019–300,682) / 407,823 |
| op 7 M = 4, no auditor | 235,470 (230,872–232,526) / 351,571 | 252,328 (249,160–249,384) / 382,765 | 304,266 (299,219–301,098) / 449,039 |
| op 7 M = 8 (not a PQZH shape: over the limit) | 281,208 / 497,149 | 296,968 / 539,533 | 375,148 / 644,337 |
| op 7 M = 8, no auditor (same) | 279,756 / 478,289 | 296,248 / 519,357 | 374,294 / 621,979 |
| `MAX_PROOF_PQZH` / `MAX_INPUT` (pqz-stmt) | 262,144 / 393,216 | 262,144 / 524,288 | 327,680 / 524,288 |
| soundness (bits) | 127.23 | 127.40 | 127.55 |

op 7 M = 8 is measured for the record only: its bound is over every set's `MAX_PROOF_PQZH`, so PQZH does not offer it
(PQZL does; table above).

#### Calldata floor gas of one transaction (EIP-7976) [model]

The precompile input is built in memory by the token / registry, so only the call's calldata counts (payload + proof +
UA authorisation); its floor = 15,000 + 64 gas × calldata bytes is a **lower bound** of the transaction's regular gas
(execution and the `PQZ` precompile's own price come on top: plan 5h Task 8d part 2 and Task 9; state gas is separate).
Calldata = the proof (PQZL: the table above; PQZH: its bound) + the call path's overhead taken from each set's `PQZH.md`
calldata table. ✗ = above 16,777,216: cannot be one transaction on an Ethereum-like chain. "—": that `PQZH.md` has no row
for the path (≈ the R_TX row).

| Relation — call path | `n2048-kmax1024` PQZL / PQZH | `n2304-kmax4096` PQZL / PQZH | `n2560-kmax16384` PQZL / PQZH |
|---|---|---|---|
| R_REG — `UARegistry.register` | 3.22 M / 13.61 M | 3.49 M / 14.84 M | 3.76 M / 16.67 M |
| R_DS / R_DR — `verifyTransferAmount` (`eth_call`) | 1.88 M / 12.22 M | 2.00 M / 13.32 M | 2.14 M / 15.02 M |
| R_TX — relayed `mtxExecute` (op 1) | 4.12 M / 16.45 M | 4.50 M / 17.61 M ✗ | 4.87 M / 21.11 M ✗ |
| R_TX0 — relayed `mtxExecute` (op 1) | 4.08 M / 16.39 M | 4.47 M / 17.60 M ✗ | — / — |
| R_BURN — relayed `mtxExecute` (op 2) | 4.04 M / 16.38 M | 4.43 M / 17.60 M ✗ | 4.79 M / 21.04 M ✗ |
| op 7 M = 1, auditor — relayed `mtxExecute` | 4.12 M / 16.45 M | 4.50 M / 17.62 M ✗ | — / — |
| op 7 M = 2, auditor | 4.19 M / 16.47 M | 4.57 M / 17.68 M ✗ | — / — |
| op 7 M = 4, auditor | 4.34 M / 16.55 M | 4.82 M / 17.76 M ✗ | 5.21 M / 21.23 M ✗ |

PQZL fits every path at every set with ≥ 11.5 M of the 2^24 cap left for execution and the precompile; PQZH debits fit
only at `n2048-kmax1024` (≈ 0.2–0.4 M margin) — at `n2304-kmax4096` and `n2560-kmax16384` they need a per-transaction cap
≥ 17.8 M / 21.3 M (PQZH is a backup, spec §12 item 4).

`MAX_INPUT` 524,288 (512 KiB, decisions 2026-10-20 O8 / 2026-10-21 (7)) is pqz-stmt's at the non-frozen sets; the node's
precompile input limit (`pqz_ffi.h` `PQZ_FFI_MAX_INPUT`, Nethermind plugin) stays 393,216 until plan 5h Task 8d, so the
inputs above it at the bound (n2304-kmax4096: op 7 M = 4 with the auditor; n2560-kmax16384: R_TX and op 7 M = 1 with
the auditor, M = 2, M = 4 — R_TX0, R_BURN and op 7 M = 1 without the auditor fit) need 8d.

### When a PQZH proof exceeds `MAX_PROOF_PQZH`: three options

Found at `n2304-kmax4096` (plan 5h Task 8c, 2026-10-22): with the Ligero layout every other set uses, its debit proofs
were 263,784–265,236 B, 1.6–3 KB above 262,144. Three ways out, usable for any set that hits the same limit (research
note `docs/research/pqzh-set-a-proof-limit.md`; 8c notes call them A, B, C — the letters say nothing, the names below
are used here):

| Option (8c letter) | What it does | Cost / limits | Where used |
|---|---|---|---|
| **re-prove under the limit** (A) | keep the preset; when a proof comes out over the limit, prove again with fresh randomness until it fits. The proof length depends only on the query indices (public), so dropping a long proof reveals nothing about the witness (ZK argument in the research note) | extra prover runs: at `n2304-kmax4096` 0.9 % of runs for most forms, 27.6 % for op 7 M = 4 with the auditor (average 1.38 runs, at most 7 in 200); useless when the gap is larger than the spread of honest proof lengths (a few KB) | `n2304-kmax4096` fallback: Cargo feature `fallback-retry`, never in default or production builds; tag `pqzh-set-a-fallback-A` |
| **set-specific preset** (B; at `n2304-kmax4096` the radix-7/17 preset) | a new Ligero preset whose evaluation domain uses extra small radices of q − 1 (there 7 and 17, through the existing generic FFT stage), so the code length / message length / query count fit under the limit | needs q − 1 to have such radices; soundness must stay at or above the old preset's | **`n2304-kmax4096` production** (owner 2026-10-22): debits 251,608–253,048 B, soundness 127.40 bits, prover 4–5 % fewer products |
| **per-set limit raise** (C) | keep the preset; raise `MAX_PROOF_PQZH` for that set only (one constant per set in `pqz-stmt` and the prover) | larger precompile inputs (`MAX_INPUT` must cover 5 + largest statement + limit) and calldata; every chain running the set must accept the larger limit | **`n2560-kmax16384`** (owner 2026-10-23): 327,680 B (320 KiB), largest bound 305,120 B at t = 122 (22,560 B headroom), largest input 493,445 B ≤ `MAX_INPUT` 512 KiB; `n2304-kmax4096` fallback (≥ 265,236 B, documented only) |

Picking an option for a new set: try a set-specific preset first (no limit change, no extra prover runs); re-proving
fits only a gap of a few KB; the per-set raise always works but changes the chain-facing limits. Whatever is chosen is
an owner decision recorded in `docs/decisions.md` (CTR-PQZ-10) and in the set's `PQZH.md`; it is written into
the set's `set.toml` `[pqzh_preset]` (preset, `max_proof`).

## Selecting a set

| Build | How |
|---|---|
| C core (`pqzl/build.sh`, `sz/build.sh`, harnesses) | `PQZ_SET=<set>` (default `n2304-kmax4096`); `pqzl/set.sh` copies the set's headers into `build/include` |
| Rust `pqzl` | cargo feature `set-<set>` (default `set-n2304-kmax4096`; another set: `--no-default-features --features sv,set-<set>`) |
| `pqz-stmt` | cargo feature `set-<set>` (none = `n2048-kmax1024`, the contracts' set until 8d) |
| `pqzh-ligero` | cargo feature `set-<set>` for a set with PQZH (none = `n2048-kmax1024`), forwarded to `pqz-stmt` |
| `pqz-ffi` (precompile, prover API, `pqz-vectors`) | cargo feature `set-<set>` (default `set-n2048-kmax1024`, forwarded to `pqz-stmt`, `pqzl` and, for a set with PQZH, `pqzh-ligero` with feature `pqzh`) |
| gate | `PQZ_SET=<set> scripts/capped pqz-core/gate.sh <label>`; the gates of different sets may run at the same time from one worktree, one `scripts/capped` slot each (every build / output path per set: `pqzl/build/<set>/`, `…/target/<set>/`, `build/fuzz-<set>/`; owner 2026-10-23) |

Each build checks that exactly one set is chosen (C: `pqz_set.h` from one directory; Rust: a compile error otherwise).

## Files of a set

| File | What | Made by |
|---|---|---|
| `set.toml` | the set's only input: n, `K_MAX`, q, `pqz_delta`, `kmlwe_min`, description, approval, `core_only` / `pqzh` / `frozen`, `max_input` (sets with pqz-stmt), `[pqzh_preset]` (description, radices, n, k, t, `max_proof`; sets with PQZH) | by hand |
| `pqz_set.h`, `rust/set.rs` | n, k, q, log2 q, Δ, `K_MAX`, digit / carry / noise widths, norm bounds, NTT roots, Barrett constants, the specialised verifier's CRT prime count | [`gen_set.py`](gen_set.py) (`--check` in the gate) |
| `set.json` | every derived constant the Python tools read (`pqz_kat.py`, `e_s0_set.py`, `ligero_params.py`, the tests' `core_only`; the limits and the PQZH preset) | `gen_set.py` |
| `pqzh_set.rs` | a set with PQZH: q − 1's factors, generator, F_q^4 non-residue, radices, the Ligero preset (n, k, t) | `gen_set.py` |
| `pqzh_set_fallback.rs`, `pqzh_set_spike_b.rs` | `n2304-kmax4096` only, hand-written research files kept as they are (plan 5h Task 8c part 1b): THE preset for fallback A (pqzh-ligero feature `fallback-retry`, never in production) and the superseded t = 119 spike (not compiled) | by hand |
| `PqzSet.sol` | the set's Solidity constants; `PQZ_SOL_INSTALL=1 make.sh <set> sol` copies it to `smartcontracts/evm/src/pqz/` (the `n2048-kmax1024` one until 8d) | `gen_set.py` |
| `<rel>_params.sage` | LaZer codegen specs of the 14 relations (reg, tx, tx0, burn, ds, dr, txm2 / 20 / 4 / 40 / 8 / 80, bench-only txm16 / 160) | `gen_set.py` (`n2048-kmax1024`'s have the shapes of `pqzl/params/*.sage`, the record) |
| `pqz_<rel>_params.h`, `codegen.txt` | LaZer codegen headers and the codegen log (`codegen-check.txt` for the frozen `n2048-kmax1024`: the regenerated headers byte-identical) | `make.sh <set> codegen` (LaZer 3330e48, pinned Sage image) |
| `rust/<rel>.rs`, `rust/mod.rs` | the headers' Rust form | `pqzl/params/to_rust.py` (`make.sh <set> rust`) |
| `e-s1.txt` | lattice-estimator check of every spec (MSIS β, hiding MLWE uSVP and dual_hybrid ≥ 450) | `pqzl/params/n-study/e_s1_n.sage` |
| `e-s0.txt` | set budget checks, exactness of the norm proofs per relation, per-round Fiat–Shamir soundness | [`e_s0_set.py`](e_s0_set.py) (`SET=<set> scripts/capped …/run_e_s0_set.sh`) |
| `lazer-3330e48-kat.json` | upstream LaZer golden arithmetic KAT at the set's q (the gate's `kat` step: pqz-core = upstream) | `pqzl/kat/build-lazer-dump.sh` |
| `SET.md`, `PQZH.md` | the set's numbers, approval, conditions; PQZH's preset, sizes and the conditions for a chain to run it | by hand |

`gen_set.py --all --check` (the gate's `rust` step) fails on a file in a set directory that is not in this table.

Vectors: `smartcontracts/vectors/pqz/` for `n2048-kmax1024` (read by the contracts until 8d),
`smartcontracts/vectors/pqz/<set>/` for every other set (`pqz-ffi/vectors/run.sh`, `PQZ_SET=<set>`).

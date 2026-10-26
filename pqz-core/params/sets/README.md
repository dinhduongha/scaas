# pqz-core/params/sets — PQZ parameter sets

Owner 2026-10-21: **parameter sets are per-directory, selected at compile time; one set per library build** (a
runtime choice between sets is deferred). Each directory `<set>/` holds every parameter-dependent input of the PQZL C
and Rust cores; the algorithm code uses only the named constants. Sets are named by n and `K_MAX`. PQZH has its own
generated file per set (`pqzh_set.rs`, from `set.toml`'s `[pqzh_preset]`; plan 5h Task 8c part 2) for every set whose
`set.toml` says `pqzh = true`, and `pqz-ffi` / `pqz-vectors` / the gate build it there. Adding a set: write
`<set>/set.toml` (with its own `proofSystemId` labels, see "proofSystemIds per set"), then `make.sh <set> all`; a new set with PQZH also needs, by hand (a missing one fails loudly):
pqzh-ligero's `set-<set>` feature and `src/set.rs` branch, the ligero wasm feature, `pqz_kat.py` `_LIGERO_MAX` and the
`limits_exact` tables (`pqzh/ligero/src/ligero.rs`).

| Set | n, k | q | `K_MAX` | Status | `SET.md` |
|---|---|---|---|---|---|
| `n2048-kmax1024` | 2048, 32 | 2^42 − 215 | 1,024 | the v3 parameters, frozen until the R0 review fix (2026-10-25: `frozen = false`, its reg / dr / audited txm headers regenerated): the committed vectors at `smartcontracts/vectors/pqz/`; the contracts' set until 8d part 2 (since then `n2304-kmax4096`; every set builds with `at-set.sh`) | [SET.md](n2048-kmax1024/SET.md) |
| `n2304-kmax4096` | 2304, 36 | 61,275,424,977,257 (2^45.80) | 4,096 | owner 2026-10-21: the default set on chain; the default of the `pqzl` crate, `gate.sh` and (since 8d part 1) `pqz-ffi` | [SET.md](n2304-kmax4096/SET.md) |
| `n2560-kmax16384` | 2560, 40 | 2^50 − 42,310,535 | 16,384 | approved 2026-10-20 as the Task 8 set, superseded as the default by `n2304-kmax4096` 2026-10-21: shippable for customer chains; full vectors + gate | [SET.md](n2560-kmax16384/SET.md) |
| `n2816-kmax65536` | 2816, 44 | 2^54 − 327 | 65,536 | research record `pqzl/params/aprime/`, owner 2026-10-21 core only; **owner 2026-10-24: a full PQZL set for customers** (pqz-stmt, precompile, vectors, gate since plan 5h Task 8d part 1b; contracts in 8d part 2); **no PQZH** (none of the current Ligero radices divides q − 1; a radix-1,789 preset is unexplored, not in scope) | [SET.md](n2816-kmax65536/SET.md) |

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
| size limit | `MAX_PROOF` 98,304 B | `MAX_PROOF_PQZH` per set (`set.toml` `[pqzh_preset] max_proof`, in `rust/set.rs` for pqz-stmt): 327,680 B at every PQZH set (owner 2026-10-23 for `n2560-kmax16384`, 2026-10-25 for `n2048-kmax1024` / `n2304-kmax4096`: the audited R_TXM M = 4 with the R0-1 groups; it was 262,144 B there) |

**Not every set has PQZH.** Ligero's evaluation domains need q − 1 to be divisible by small radices, so whether PQZH
exists at a set depends on q:

| Set | PQZH |
|---|---|
| `n2048-kmax1024` | built and running (`pqz-ffi`, vectors, gate): THE preset (D3 id) |
| `n2304-kmax4096` | built (plan 5h Task 8c part 2; owner 2026-10-22): the **radix-7/17 preset** (radices 2 / 7 / 17 / 19 / 43 / 431, n 45,752, k 952, t 120), debit proofs 251,608–253,048 B (9–10 KB under 262,144), soundness 127.40 bits; the two other options below stay as fallbacks (re-prove under the limit: Cargo feature `fallback-retry`, never in production builds; per-set limit raise: documented only) |
| `n2560-kmax16384` | built (plan 5h Task 8c part 2): debit proofs above 262,144 and no set-specific preset (q − 1 = 2^3 · 19 · 43 · 431 · 5,659 · 70,627 has no other small radix; re-proving cannot close a ≈ 40 KB gap) → **owner 2026-10-23: `MAX_PROOF_PQZH` = 327,680 B (320 KiB) for this set only** (per-set limit raise; decisions CTR-PQZ-10) and t = 122 on THE preset's n / k (soundness 127.55 bits, above the other sets'): debit bounds 303,412–305,120 B |
| `n2816-kmax65536` | none (owner ruling 2026-10-24): q − 1 = 2^3 · 3 · 1,789 · 419,563,967,521 has no power-of-two part beyond 2^3 and a smooth part of only 24, none of the radices the current Ligero presets use (19 / 43 / 431; 7 / 17 at `n2304-kmax4096`). F_q^* does have subgroups of order 1,789 and 42,936 (= 24 · 1,789), so PQZH here would need a radix-1,789 FFT step and a new preset at a different rate (k = 1,789, n = 42,936: rate 1/24 against ≈ 1/40 today, more column queries, a fresh soundness and size analysis) — unexplored work, not in scope — or another q, i.e. another set. **Not pursued (owner ruling 2026-10-25: no spike, write the reason down).** Controller estimate from the cost model of `pqz-core/pqzh/ligero/ligero_params.py` (`fft_cost(n) = n · Σ (r + 1)` over the radices of n; computed by hand, not run): (1) a radix-r stage costs ≈ r + 1 products per point, so the largest FFT at n = 42,936 = 2^3 · 3 · 1,789 is ≈ 77.4 M products against ≈ 3.7 M at `n2304-kmax4096`'s n = 45,752 (≈ 21×); k = 1,789 about halves the row count, so the prover's work is ≈ 10× `n2304-kmax4096`'s, most likely over the prover budget (`PMAX` 4e9 base products), and the prover runs on the client (wasm32 in the browser). (2) A fast 1,789-point DFT (Rader) needs a cyclic convolution of length 1,788 = 2^2 · 3 · 149, which has no NTT in F_q (149 does not divide q − 1); an extension field does not help (q + 1 = 2 · 31 · 109 · 409 · 6,517,458,439 is not smooth either); only nested Winograd-style convolutions remain — several days of work with an uncertain result. (3) The verifier (the precompile) would not be the problem: it evaluates at the t opened columns (Lagrange), with no size-n FFT. A chain that needs PQZH with `K_MAX` 65,536 needs another parameter set whose q − 1 is smooth like the other sets' (2^3 · 19 · 43 · 431 divides q − 1), with a full parameter and estimator run. The set is PQZL only (`set.toml` `pqzh = false`): pqz-stmt knows no PQZH id there, pqz-ffi has no PQZH build, the gate skips Ligero and the cross-checks |

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

Relations (the statements a proof is about; names as in `pqz-stmt` and the vectors):

| Relation | What it proves | Used by |
|---|---|---|
| R_REG | the owner of a new PQZ public key knows its secret key (registration) | `UARegistry.register` |
| R_DS / R_DR | a ciphertext's amount, disclosed to the sender / to the receiver or the auditor | `verifyTransferAmount` (read-only `eth_call`) |
| R_TX | a confidential transfer to one recipient, with the auditor's ciphertext | the token's transfer (relayed `mtxExecute`) |
| R_TX0 | the same transfer on a token without an auditor | the token's transfer |
| R_BURN | a confidential debit with no recipient (burn, refresh) | the token's unshield / refresh |
| R_TXM M = k | one confidential transfer to k recipients at once, with the auditor (M = 8: the legs in two randomness groups of four) | the token's multi-transfer |
| R_TXM M = k, no auditor | the same on a token without an auditor | the token's multi-transfer |

Gas limits the sizes are judged against (spec §12 item 2: Ethereum-like limits, never the testnet's), as Glamsterdam
defines them. A transaction has **two gas dimensions, regular and state**; the calldata floor is not a third budget but
a minimum on the regular one. The block limit is a separate, larger limit.

| Item | Dimension | Rule and value | Source |
|---|---|---|---|
| intrinsic gas, a call with no ETH value (every PQZ call) | regular | 15,000 (was 21,000) | [EIP-2780](https://eips.ethereum.org/EIPS/eip-2780) / [EIP-8007](https://eips.ethereum.org/EIPS/eip-8007) |
| calldata, standard cost | regular | 4 gas per zero byte, 16 per non-zero byte | [EIP-7976](https://eips.ethereum.org/EIPS/eip-7976) |
| calldata floor | regular | the transaction pays at least 15,000 + 64 gas × calldata bytes (zero or not): regular gas charged = max(intrinsic + standard calldata + execution, floor) | EIP-7976 |
| execution (EVM, the `PQZ` precompile's price) | regular | shares the cap below with intrinsic + calldata | [EIP-7825](https://eips.ethereum.org/EIPS/eip-7825) |
| **regular gas per transaction** | regular | **≤ 16,777,216 (2^24, `TX_MAX_GAS_LIMIT`)**; Glamsterdam keeps it; so the floor allows at most (2^24 − 15,000) / 64 = **261,909 B of calldata** | EIP-7825, [EIP-8037](https://eips.ethereum.org/EIPS/eip-8037) |
| new state (storage slots, SSTORE2 blobs) | state | ≈ 1,530 gas per stored byte of an SSTORE2 blob (measured, plan 5h Task 7b); a cold storage-word rewrite ≈ 12,100 ([EIP-8038](https://eips.ethereum.org/EIPS/eip-8038)); paid first from the reservoir = `tx.gas` − 2^24, then from regular gas | EIP-8037 |
| **`tx.gas` per transaction** | both | **≤ 4,294,967,295 (2^32 − 1)**: state gas may take a transaction far above 2^24 | EIP-8037 |
| **gas used per block** | both | **max(Σ execution gas, Σ state gas) ≤ block gas limit** — the two dimensions are not added | EIP-8037 |
| **block gas limit** | — | **60,000,000 on Ethereum mainnet** (October 2026); ≈ 200,000,000 planned with Glamsterdam; SCaaS testnet genesis 200,000,000. 60 M is a block limit, not a transaction limit | [ethereum.org](https://ethereum.org/latest/building-on-ethereum-in-2026/) |

Example, a PQZL transfer (R_TX) at `n2304-kmax4096`: calldata ≈ 70 KB → standard calldata ≈ 1.1 M (16 gas per
non-zero byte), so ≈ 15.6 M of the 2^24 cap is left for execution and the precompile; the floor (≈ 4.50 M, table below)
only binds if execution costs less than ≈ 3.4 M. Its stored ciphertexts cost ≈ 29.6 M state gas
before the P46 packing and ≈ 21.5 M with it [spike PACK estimate, `docs/research/pqz-pack.md`; measured in plan 5h Task
8d part 2] — state gas, so it does not count against the 2^24 cap, only against the block (60 M) in the state dimension.

- **Regular gas per transaction ≤ 16,777,216 (2^24, `TX_MAX_GAS_LIMIT`)** — intrinsic gas, the EIP-7976 calldata floor
  (15,000 + 64 gas per byte, so at most ≈ 261,909 B of calldata) and execution gas. Glamsterdam keeps this cap.
- **State gas** (EIP-8037: new storage, SSTORE2 blobs) may go above it: the part of `tx.gas` over 2^24 is a reservoir
  usable only for state gas; `tx.gas` ≤ 4,294,967,295 (2^32 − 1).
- **Per block:** gas used = max(execution gas, state gas) — the two are not added — and must stay ≤ the block gas
  limit: 60 M on Ethereum mainnet today (October 2026), ≈ 200 M planned with Glamsterdam; the SCaaS testnet's genesis
  has 200 M. 60 M is a block limit, not a transaction limit.

### PQZL per set: proof sizes and size limits (bytes)

PQZL proof size per relation, the largest of two proofs from the C prover bench of each set's gate
(`pqz-core/runs/gate/<set>-fnv-c.jsonl`, `proof_bytes_max`; C = Rust = wasm32 byte for byte), and the C prover's arena
peak. R_TXM rows: M recipients, with the auditor unless the row says "no auditor". The limit for every set is `MAX_PROOF_PQZL` =
98,304 B (96 KiB), the same for all four sets.

| Relation | `n2048-kmax1024` | `n2304-kmax4096` | `n2560-kmax16384` | `n2816-kmax65536` |
|---|---|---|---|---|
| R_REG | 28,080 | 30,273 | 32,433 | 35,420 |
| R_DS | 28,984 | 30,800 | 32,979 | 35,925 |
| R_DR | 29,002 | 31,451 | 33,780 | 36,753 |
| R_TX | 42,768 | 46,706 | 50,407 | 54,857 |
| R_TX0 | 42,423 | 46,322 | 50,060 | 54,508 |
| R_BURN | 41,925 | 45,836 | 49,551 | 54,031 |
| R_TXM M = 1 | 42,755 | 46,673 | 50,385 | 54,882 |
| R_TXM M = 2 | 43,614 | 47,509 | 51,226 | 57,762 |
| R_TXM M = 4 | 45,278 | 50,749 | 54,850 | 59,529 |
| R_TXM M = 8 | 61,831 | 67,604 | 72,724 | 79,195 |
| R_TXM M = 1, no auditor | 42,434 | 46,364 | 50,066 | 54,501 |
| R_TXM M = 2, no auditor | 42,938 | 46,844 | 50,538 | 55,018 |
| R_TXM M = 4, no auditor | 43,918 | 47,862 | 51,576 | 58,125 |
| R_TXM M = 8, no auditor | 58,981 | 64,632 | 69,904 | 76,364 |
| largest / `MAX_PROOF_PQZL` | 61,831 / 98,304 | 67,604 / 98,304 | 72,724 / 98,304 | 79,195 / 98,304 |
| pk / ciphertext (B) | 16,384 / 16,512 | 18,432 / 18,560 | 20,480 / 20,608 | 22,528 / 22,656 |
| R_TX statement (B) | 83,072 | 93,312 | 103,552 | 113,792 |
| C prover arena peak: R_TX / R_TXM M = 8 | 312 / 794 MB | 380 / 937 MB | 457 / 1,094 MB | 538 / 1,259 MB |

R_TXM M = 8 needs `PQZ_ARENA_MB=2048` in the C bench at every set (above its default 768 MiB). The C backend's wasm32 leg limit (`set.toml`
`[pqzl_c] wasm_max_legs`, one 512 MiB arena) is measured only at `n2816-kmax65536` (1); the other sets' 2 are estimates
from the native peaks ([`ffi/README.md`](../../ffi/README.md) Arenas). `n2816-kmax65536` (a
full PQZL set since plan 5h Task 8d part 1b): its vectors' largest proof is 79,208 B (R_TXM M = 8 with the auditor,
`smartcontracts/vectors/pqz/n2816-kmax65536/proof_pqzl.json`), 19,096 B under `MAX_PROOF_PQZL`; its `MAX_INPUT` is
524,288 like the other non-frozen sets' (largest input at the limit 5 + 295,808 + 98,304 = 394,117 B, R_TXM M = 8 with
the auditor: above the frozen set's 393,216).

### PQZH per set: preset, proof sizes and size limits (bytes; plan 5h Task 8c part 2)

`set.toml` holds the preset and the limits; `gen_set.py` writes `pqzh_set.rs` (radices, n, k, t; q − 1's factors,
generator and non-square computed and checked), `MAX_PROOF_PQZH` / `MAX_INPUT` into `rust/set.rs` (pqz-stmt) and all
of them into `set.json` (`pqz_kat.py`, `ligero_params.py`). Bounds and soundness: the crate (`ligero_kat sizes`).

| Set | radices | n / k / t | largest bound (B) | soundness (bits) | `MAX_PROOF_PQZH` (B) | `MAX_INPUT` (B) | largest precompile input (B): proof at the bound / at `MAX_PROOF_PQZH` |
|---|---|---|---|---|---|---|---|
| `n2048-kmax1024` | 2/19/43/431 | 32,756 / 817 / 121 | 279,756 (R_TXM M = 4, G = 2: R0-1) | 127.23 | 327,680 | 524,288 | 429,137 / 477,061 |
| `n2304-kmax4096` | 2/7/17/19/43/431 | 45,752 / 952 / 120 | 296,248 (R_TXM M = 4, G = 2: R0-1) | 127.40 | 327,680 | 524,288 | 464,061 / 495,493 |
| `n2560-kmax16384` | 2/19/43/431 | 32,756 / 817 / 122 | 305,120 | 127.55 | 327,680 | 524,288 | 470,885 / 493,445 |

Per relation: the proof bound from the crate (`ligero_kat sizes`; `pqzh/ligero/runs/c8-v3-sizes.jsonl`,
`c8b-a-sizes.jsonl`, `c8c-n2560-sizes.jsonl`), in brackets the honest proofs measured (`c8c-<set>-kat.jsonl`, seeds 0
and 1, all verify), then the largest precompile input (5 + statement + bound), all in bytes. `n2816-kmax65536`: no PQZH.

| Relation | `n2048-kmax1024` | `n2304-kmax4096` | `n2560-kmax16384` |
|---|---|---|---|
| R_REG | 190,458 (186,904–187,098) / 206,943 | 207,688 (204,358–204,936) / 226,221 | 234,238 (230,526–231,006) / 254,819 |
| R_DS | 190,458 (187,482–187,546) / 223,647 | 207,688 (204,616–205,416) / 244,973 | 234,238 (230,366–231,774) / 275,619 |
| R_DR | 190,458 (185,462–185,462) / 223,647 | 207,688 (204,552–204,936) / 244,973 | 234,238 (231,422–231,678) / 275,619 |
| R_TX | 235,470 (231,256–231,416) / 318,547 | 251,608 (248,312–248,952) / 344,925 | 304,266 (299,850–300,490) / 407,823 |
| R_TX0 | 234,744 (229,672–231,320) / 301,309 | 251,608 (247,544–248,376) / 326,365 | 304,266 (300,682–301,194) / 387,215 |
| R_BURN | 234,744 (231,256–232,344) / 284,797 | 251,608 (247,176–248,440) / 307,805 | 303,412 (300,148–301,204) / 365,753 |
| R_TXM M = 1 | 235,470 (230,242–231,598) / 318,547 | 251,608 (247,304–248,344) / 344,925 | 304,266 (299,923–301,226) / 407,823 |
| R_TXM M = 2 | 235,470 (231,128–232,462) / 335,187 | 252,328 (248,424–248,434) / 364,333 | 304,266 (300,170–300,586) / 428,559 |
| R_TXM M = 4 (G = 2 at n2048 / n2304 since the R0 review fix; the vectors' proof in brackets) | 279,756 (277,036) / 429,137 | 296,248 (293,112) / 464,061 | 305,120 (301,824–302,112) / 470,885 |
| R_TXM M = 1, no auditor | 234,744 (231,304–232,024) / 301,309 | 251,608 (247,304–248,440) / 326,365 | 304,266 (301,450–301,610) / 387,215 |
| R_TXM M = 2, no auditor | 235,470 (231,438–232,366) / 318,547 | 251,608 (246,792–248,088) / 344,925 | 304,266 (300,019–300,682) / 407,823 |
| R_TXM M = 4, no auditor | 235,470 (230,872–232,526) / 351,571 | 252,328 (249,160–249,384) / 382,765 | 304,266 (299,219–301,098) / 449,039 |
| R_TXM M = 8 (bound over the limit: not offered; G = 4 / 3 / 2) | 368,328 / 617,037 | 340,168 / 601,165 | 375,148 / 644,337 |
| R_TXM M = 8, no auditor (not offered either) | 279,756 / 478,289 | 296,248 / 519,357 | 374,294 / 621,979 |
| `MAX_PROOF_PQZH` / `MAX_INPUT` (pqz-stmt) | 327,680 / 524,288 (R0 fix; were 262,144 / 393,216) | 327,680 / 524,288 (R0 fix; was 262,144) | 327,680 / 524,288 |
| soundness (bits) | 127.23 | 127.40 | 127.55 |

R_TXM M = 8 is measured for the record only: PQZH does not offer it (built legs {1, 2, 4}; the audited M = 8 bounds are
over every set's `MAX_PROOF_PQZH`); PQZL does (table above). A PQZH proof above ≈ 261,909 B does not fit one
transaction's calldata under the 2^24 regular-gas cap (EIP-7825 / EIP-7976): the 2026-10-25 limit raise (decisions
CTR-PQZ-10) changes nothing there, PQZH stays the backup system.

#### Calldata floor gas of one transaction (EIP-7976) [model]

The precompile input is built in memory by the token / registry, so only the call's calldata counts (payload + proof +
UA authorisation); its floor = 15,000 + 64 gas × calldata bytes is a **lower bound** of the transaction's regular gas
(execution and the `PQZ` precompile's own price come on top: plan 5h Task 8d part 2 and Task 9; state gas is separate).
Calldata = the proof (PQZL: the table above; PQZH: its bound) + the call path's overhead taken from each set's `PQZH.md`
calldata table. ✗ = above 16,777,216: cannot be one transaction on an Ethereum-like chain. "≈": the path's overhead is
not in that `PQZH.md` and is estimated from the ABI layout (R_TX0 = R_TX − 128 B, R_TXM M = 1 = R_TX + 64 B, + 288 B per
extra recipient; the per-recipient step reproduces Task 7's measured R_TXM M = 8 calldata at the old 16k parameters,
`pqzl/params/p16k/results-16k.md` §8). "not offered": PQZH cannot prove R_TXM M = 8 under its limit. `n2816-kmax65536`
(PQZL only, no `PQZH.md`): every value ≈, its proof (table above) + `n2560-kmax16384`'s overhead of the same path + 2,048 B
(one pk more per path that carries a pk; none for the `eth_call` path).

| Relation — call path | `n2048-kmax1024` PQZL / PQZH | `n2304-kmax4096` PQZL / PQZH | `n2560-kmax16384` PQZL / PQZH | `n2816-kmax65536` PQZL |
|---|---|---|---|---|
| R_REG — `UARegistry.register` | 3.22 M / 13.61 M | 3.49 M / 14.84 M | 3.76 M / 16.67 M | ≈ 4.08 M |
| R_DS / R_DR — `verifyTransferAmount` (`eth_call`) | 1.88 M / 12.22 M | 2.00 M / 13.32 M | 2.14 M / 15.02 M | ≈ 2.33 M |
| R_TX — relayed `mtxExecute` | 4.12 M / 16.45 M | 4.50 M / 17.61 M ✗ | 4.87 M / 21.11 M ✗ | ≈ 5.29 M |
| R_TX0 — relayed `mtxExecute` | 4.08 M / 16.39 M | 4.47 M / 17.60 M ✗ | ≈ 4.84 M / ≈ 21.11 M ✗ | ≈ 5.26 M |
| R_BURN — relayed `mtxExecute` | 4.04 M / 16.38 M | 4.43 M / 17.60 M ✗ | 4.79 M / 21.04 M ✗ | ≈ 5.21 M |
| R_TXM M = 1 — relayed `mtxExecute` | 4.12 M / 16.45 M | 4.50 M / 17.62 M ✗ | ≈ 4.87 M / ≈ 21.12 M ✗ | ≈ 5.29 M |
| R_TXM M = 2 | 4.19 M / 16.47 M | 4.57 M / 17.68 M ✗ | ≈ 4.94 M / ≈ 21.14 M ✗ | ≈ 5.49 M |
| R_TXM M = 4 | 4.34 M / 16.55 M | 4.82 M / 17.76 M ✗ | 5.21 M / 21.23 M ✗ | ≈ 5.64 M |
| R_TXM M = 8 | ≈ 5.47 M / not offered | ≈ 5.97 M / not offered | ≈ 6.43 M / not offered | ≈ 6.98 M |

PQZL fits every path at every set, R_TXM M = 8 included, with ≥ 10.3 M of the 2^24 cap left for execution and the
precompile (≈ 9.8 M at `n2816-kmax65536`); PQZH debits fit
only at `n2048-kmax1024` (≈ 0.2–0.4 M margin) — at `n2304-kmax4096` and `n2560-kmax16384` they need a per-transaction cap
≥ 17.8 M / 21.3 M (PQZH is a backup, spec §12 item 4).

`MAX_INPUT` 524,288 (512 KiB, decisions 2026-10-20 O8 / 2026-10-21 (7)) is pqz-stmt's at the non-frozen sets. Since
plan 5h Task 8d part 1 the node takes its precompile input limit from the library it loads (`pqz-ffi`'s
`pqz_max_input()` = the set's `MAX_INPUT`; `pqz_ffi.h`, the Nethermind plugin's `PqzNative.MaxInput`), so every input
in the table fits; the former node literal 393,216 did not fit the largest inputs of `n2304-kmax4096` (R_TXM M = 4) and
`n2560-kmax16384` (R_TX, R_TXM M = 1, 2, 4).

### proofSystemIds per set (plan 5h Task 8d part 1; bumped by the R0 review fix 2026-10-25)

The one `proofSystemId` bump of plan 5h Task 8 (B-1, A-2, `R_REG` and the new parameters; decisions CTR-PQZ-09 / D23)
gave every set its own ids, so a proof of one set never verifies under another set's id. The R0 review fix
(2026-10-25, `pqz-core/research/code-review-2026-10-25/`: R0-1 the auditor copies' windows and the `s_aud` groups,
R0-C2 `Bprime` 8, R0-C3 the eta-filtered final challenge) bumped every set once more: PQZL `…/v5`, PQZH `…/v3`; the
Task 8d ids (PQZL v4, PQZH v2) are retired. `set.toml` holds the labels
(`pqzl_id`, `pqzh_id`; a controller proposal, the owner may override), `gen_set.py` writes keccak256 of each into
`pqz_set.h` (`PQZ_PROOF_SYSTEM_ID`, `PQZ_PQZH_ID`), `rust/set.rs` (`PQZL_ID` / `PQZH_ID` and the labels, read by
`pqz-stmt` and the `pqzl` crate), `set.json` (`pqz_kat.py`) and `PqzSet.sol` (`PQZL_ID` / `PQZH_ID`). It checks that a
label names its set (PQZL `d64k<k>-q<log2q>`, PQZH `fq<log2q>-n<n>k<k>t<t>` of `[pqzh_preset]`), that all ids of all
sets differ and that none is retired (`gen_set.py` RETIRED: PQZL v2 `0x2e07e6ed…798c2f`, v3 `0x8079d65b…16baef`, the
four v4 of the table below's previous version, PQZH v1 `0x0a47a768…2fead4`, the three v2, the STARK backup's
`0xaa1f92dd…284304`; `pqz-stmt` refuses them, test `retired_ids_refused` reads `stmt/src/sets.rs`' generated
`RETIRED_IDS`, and every vector set has a negative row per retired id of its own: PQZL v2 / v3 / v4, PQZH v1 / v2).

| Set | PQZL label → id | PQZH label → id |
|---|---|---|
| `n2048-kmax1024` | `scaas/pqz/lnp22/mlwe-d64k32-q42l4/v5` → `0xc752e7f5…c6cdfe` (v4 `0x19fad50a…9a326d` retired) | `scaas/pqz/pqzh/ligero-fq42-n32756k817t121-keccak256-zk-proven/v3` → `0x56293621…a7df5d` (v2 `0x9d945089…a7dca4` retired) |
| `n2304-kmax4096` | `scaas/pqz/lnp22/mlwe-d64k36-q46l4/v5` → `0xef1ffbcb…90336e` (v4 `0x15d16d77…cb608a` retired) | `scaas/pqz/pqzh/ligero-fq46-n45752k952t120-keccak256-zk-proven/v3` → `0x046859a8…944ead` (v2 `0xe4bc6d17…885730` retired) |
| `n2560-kmax16384` | `scaas/pqz/lnp22/mlwe-d64k40-q50l4/v5` → `0xeacf34a3…276882` (v4 `0xa3db21fc…70262d` retired) | `scaas/pqz/pqzh/ligero-fq50-n32756k817t122-keccak256-zk-proven/v3` → `0xc93f3bdd…3f3662` (v2 `0xe83ad1da…109851` retired) |
| `n2816-kmax65536` | `scaas/pqz/lnp22/mlwe-d64k44-q54l4/v5` → `0xa801f5c4…8e8aa9` (v4 `0x9d23a0de…bd53a3` retired) | — (no PQZH: pqz-stmt's `HAS_PQZH` false, its `PQZH_ID` the zero word, refused; plan 5h Task 8d part 1b) |

**Changing a label (an owner override, or a later bump).** Edit the set's `pqzl_id` / `pqzh_id` in `set.toml`, then:
`python3 -I pqz-core/params/sets/gen_set.py --all` (the generated files, `stmt/src/sets.rs`' `ALL_IDS`; at
`n2048-kmax1024` also `PQZ_SOL_INSTALL=1 make.sh n2048-kmax1024 sol`, the contracts' `PqzSet.sol`), regenerate the
set's vectors (`PQZ_SET=<set> scripts/capped pqz-core/ffi/vectors/run.sh <label> write`) and the pinned
`negative_rows_reject` counts in `pqzl/rust/tests/vectors.rs` if the coder-padding rows move, and run the set's gate.
Copies that are not generated: at `n2048-kmax1024` the PQZL id literal in `pqzh/stark-backup/src/rel.rs`
(`PQZL_PROOF_SYSTEM_ID`; the STARK cross-check fails loudly otherwise) and the fuzz input
`fuzz/regress/valid/fixture-disclose-receiver-rnd33` (re-prove it under the new id, as
`fuzz/runs/2026-10-23-t8d1-regress-valid.txt`); in the docs the id tables of decisions CTR-PQZ-09, `pq-zero-knowledge.md`
(versioning, serialization), `pqz-core/README.md` §4, this section, the set's `SET.md` / `PQZH.md` and the vectors
READMEs.

### When a PQZH proof exceeds `MAX_PROOF_PQZH`: three options

Found at `n2304-kmax4096` (plan 5h Task 8c, 2026-10-22): with the Ligero layout every other set uses, its debit proofs
were 263,784–265,236 B, 1.6–3 KB above 262,144. Three ways out, usable for any set that hits the same limit (research
note `docs/research/pqzh-set-a-proof-limit.md`; 8c notes call them A, B, C — the letters say nothing, the names below
are used here):

| Option (8c letter) | What it does | Cost / limits | Where used |
|---|---|---|---|
| **re-prove under the limit** (A) | keep the preset; when a proof comes out over the limit, prove again with fresh randomness until it fits. The proof length depends only on the query indices (public), so dropping a long proof reveals nothing about the witness (ZK argument in the research note) | extra prover runs: at `n2304-kmax4096` 0.9 % of runs for most forms, 27.6 % for R_TXM M = 4 (average 1.38 runs, at most 7 in 200); useless when the gap is larger than the spread of honest proof lengths (a few KB) | `n2304-kmax4096` fallback: Cargo feature `fallback-retry`, never in default or production builds; tag `pqzh-set-a-fallback-A` |
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
| `pqz-stmt` | cargo feature `set-<set>` (none = `n2048-kmax1024`, the frozen set) |
| `pqzh-ligero` | cargo feature `set-<set>` for a set with PQZH (none = `n2048-kmax1024`), forwarded to `pqz-stmt` |
| contracts (`smartcontracts/evm`) | the generated `src/pqz/PqzSet.sol` (committed: `n2304-kmax4096`, which `gen_set.py --check` wants); another set: `scripts/capped smartcontracts/evm/script/pqz/at-set.sh <set> [forge args]` installs that set's `PqzSet.sol`, runs forge (default: the PQZ suites) in `out/at-set-<set>` and restores the committed file (plan 5h Task 8d part 2) |
| `pqz-ffi` (precompile, prover API, `pqz-vectors`) | cargo feature `set-<set>` (default `set-n2304-kmax4096` since plan 5h Task 8d part 1, forwarded to `pqz-stmt`, `pqzl` and, for a set with PQZH, `pqzh-ligero` with feature `pqzh`) |
| gate | `PQZ_SET=<set> scripts/capped pqz-core/gate.sh <label>`; the gates of different sets may run at the same time from one worktree, one `scripts/capped` slot each (every build / output path per set: `pqzl/build/<set>/`, `…/target/<set>/`, `build/fuzz-<set>/`; owner 2026-10-23) |

Each build checks that exactly one set is chosen (C: `pqz_set.h` from one directory; Rust: a compile error otherwise).

## Files of a set

| File | What | Made by |
|---|---|---|
| `set.toml` | the set's only input: n, `K_MAX`, q, `pqz_delta`, `kmlwe_min`, description, approval, `core_only` / `pqzh` / `frozen`, `max_input` (sets with pqz-stmt), the `proofSystemId` labels `pqzl_id` (every set) / `pqzh_id` (sets with PQZH), `[pqzh_preset]` (description, radices, n, k, t, `max_proof`; sets with PQZH) | by hand |
| `pqz_set.h`, `rust/set.rs` | n, k, q, log2 q, Δ, `K_MAX`, digit / carry / noise widths, norm bounds, NTT roots, Barrett constants, the specialised verifier's CRT prime count, the `proofSystemId`s (keccak256 of the labels) | [`gen_set.py`](gen_set.py) (`--check` in the gate) |
| `set.json` | every derived constant the Python tools read (`pqz_kat.py`, `e_s0_set.py`, `ligero_params.py`, the tests' `core_only`; the limits and the PQZH preset) | `gen_set.py` |
| `pqzh_set.rs` | a set with PQZH: q − 1's factors, generator, F_q^4 non-residue, radices, the Ligero preset (n, k, t) | `gen_set.py` |
| `pqzh_set_fallback.rs`, `pqzh_set_spike_b.rs` | `n2304-kmax4096` only, hand-written research files kept as they are (plan 5h Task 8c part 1b): THE preset for fallback A (pqzh-ligero feature `fallback-retry`, never in production) and the superseded t = 119 spike (not compiled) | by hand |
| `PqzSet.sol` | the set's Solidity constants, **read by every PQZ contract since plan 5h Task 8d part 2** (`PqzCt`, `PqzCore`, `PqzSafety`, `UAPqzVerifier`): sizes, q, Δ, `K_MAX`, `PACK_BITS` (P46), `PQZL_ID`, `HAS_PQZH` / `PQZH_ID` (the zero word without PQZH), `ZERO_HASH` (the packed `Trivial(0)`), from the set's vectors (zero words until the set has them) the precompile's `SELFTEST` hash and `UAPqzVerifier`'s `PROBE_PQZL` / `PROBE_PQZH`, and the file-level `PQZ_ACC_WORDS` (the packed `acc` slots; Solidity takes no library member as an array length); `PQZ_SOL_INSTALL=1 make.sh <set> sol` copies it to `smartcontracts/evm/src/pqz/` (committed: `n2304-kmax4096`) | `gen_set.py` (reads the set's `selftest.json`, `statement_register.json`, `proof_*.json`) |
| `<rel>_params.sage` | LaZer codegen specs of the 14 relations (reg, tx, tx0, burn, ds, dr, txm2 / 20 / 4 / 40 / 8 / 80, bench-only txm16 / 160) | `gen_set.py` (`n2048-kmax1024`'s have the shapes of `pqzl/params/*.sage`, the record) |
| `pqz_<rel>_params.h`, `codegen.txt` | LaZer codegen headers and the codegen log (`codegen-check.txt` for the frozen `n2048-kmax1024`: the regenerated headers byte-identical) | `make.sh <set> codegen` (LaZer 3330e48, pinned Sage image) |
| `rust/<rel>.rs`, `rust/mod.rs` | the headers' Rust form | `pqzl/params/to_rust.py` (`make.sh <set> rust`) |
| `e-s1.txt` | lattice-estimator check of every spec (MSIS β, hiding MLWE uSVP and dual_hybrid ≥ 450) | `pqzl/params/n-study/e_s1_n.sage` |
| `e-s0.txt` | set budget checks, exactness of the norm proofs per relation, per-round Fiat–Shamir soundness | [`e_s0_set.py`](e_s0_set.py) (`SET=<set> scripts/capped …/run_e_s0_set.sh`) |
| `lazer-3330e48-kat.json` | upstream LaZer golden arithmetic KAT at the set's q (the gate's `kat` step: pqz-core = upstream) | `pqzl/kat/build-lazer-dump.sh` |
| `SET.md`, `PQZH.md` | the set's numbers, approval, conditions; PQZH's preset, sizes and the conditions for a chain to run it | by hand |

`gen_set.py --all --check` (the gate's `rust` step) fails on a file in a set directory that is not in this table.

Vectors: `smartcontracts/vectors/pqz/` for `n2048-kmax1024`,
`smartcontracts/vectors/pqz/<set>/` for every other set (`pqz-ffi/vectors/run.sh`, `PQZ_SET=<set>`).

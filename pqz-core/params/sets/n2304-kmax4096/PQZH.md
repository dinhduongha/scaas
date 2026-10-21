# Conditions for a chain to run PQZH — set `n2304-kmax4096` (set (a))

PQZH (Ligero over F_q, `pqz-core/pqzh/ligero`) is the **backup** proof system (owner 2026-10-21); PQZL is the one on
chain. This file says what a chain needs before it can accept PQZH proofs at this parameter set. Plan 5h Task 8c
part 1; the PQZH `proofSystemId` of this set comes with Task 8d's bump. `SET.md` (Task 8b) is this set's main
description.

Sources: `[crate]` = the Rust crate built with `--features set-n2304-kmax4096` (`pqz-core/pqzh/ligero/runs/c8-a-*`);
`[model]` = `python3 -I pqz-core/pqzh/ligero/ligero_params.py --set n2304-kmax4096`
(`runs/c8-params-n2304-kmax4096.txt`, equal to the crate on all 14 relations it checks); `[measured]` = an earlier
measurement named in place; `[estimate]` = scaled or assumed, not measured.

## Field and domains [crate]

| item | value |
|---|---|
| q | 61,275,424,977,257 (2^45.80), q ≡ 9 mod 16; q − 1 = 2^3 · 7 · 17 · 19 · 43 · 431 · 182,789 |
| F_q element in a proof | 46 bits in 6 bytes, big-endian, canonical (as v3) |
| extension | F_q^4 = F_q[X]/(X^4 − 3), 3 a non-square, \|F_q^4\| = 2^183.2 |
| generator | 3 (generates F_q^*) |
| domains | THE preset of v3 kept: n = 32,756 = 4·19·431 (code on the coset 3·H_n), k = 817 = 19·43 (messages on H_k), t = 121, l = 695, products on H_1634; FFT radices 2 / 19 / 43 / 431 |
| arithmetic | native: Barrett, u128 products; wasm32: three 16-bit limbs in u64 (no 64 × 64 → 128 multiply) |
| constants | `pqzh_set.rs` (this directory) + `rust/set.rs` (PQZL's) |

## Soundness [crate]

Every relation: 127.23 bits in total (query 128.50 = 121 columns × 0.9298 + 16 grinding; Keccak 128;
proximity ≥ 159.8, linear ≥ 169.2, quadratic 183.2). The same total as v3: the query term depends on n and k only,
the field terms grow with q (v3: 145.0 / 154.3 / 168.0).

## Sizes per form

The bound is the verifier's exact maximum (`Params::max_len_exact`): the length gate before anything is parsed.
Honest proofs: seeds 0 and 1 of the crate's test inputs (`runs/c8-a-kat.jsonl`).

| relation | rows m | proof bound B [crate] | honest proofs B [crate] | statement B | input 5 + stmt + bound B |
|---|---|---|---|---|---|
| R_REG (op 3) | 83 | 204,978 | 200,376–201,746 | 18,528 | 223,511 |
| R_DS (op 4) | 83 | 204,978 | 201,458–201,650 | 37,280 | 242,263 |
| R_DR / R_DA (op 5) | 83 | 204,978 | 201,714–202,162 | 37,280 | 242,263 |
| R_TX (op 1, auditor) | 165 | 264,510 | 260,702–261,086 | 93,312 | 357,827 |
| R_TX0 (op 1, no auditor) | 164 | 263,784 | 260,168–260,616 | 74,752 | 338,541 |
| R_BURN / refresh (op 2) | 164 | 263,784 | 260,328–261,096 | 56,192 | 319,981 |
| R_TXM op 7 M = 1 / 2 / 4, auditor | 165 / 165 / 166 | 264,510 / 264,510 / 265,236 | 260,862–261,972 | 93,312 / 112,000 / 149,376 | 357,827 / 376,515 / 414,617 |
| R_TXM op 7 M = 1 / 2 / 4, no auditor | 164 / 165 / 165 | 263,784 / 264,510 / 264,510 | 259,432–262,014 | 74,752 / 93,312 / 130,432 | 338,541 / 357,827 / 394,947 |
| R_TXM op 7 M = 8 (G = 2; not a PQZH shape) | 248 / 247 | 324,768 / 324,042 [model] | — | 242,560 / 223,104 | 567,333 / 547,151 |

- `MAX_PROOF_PQZH` = 262,144 (owner 2026-10-21: stays): R_REG / R_DS / R_DR fit; **every debit bound is above it**
  (by 1,640–3,092 B), and the honest debit proofs measured are 130–2,712 B below it. A chain at this set either accepts
  that a debit proof above 262,144 is refused (the prover can re-prove with fresh randomness until it is below:
  `prove_inner`'s retry with the precompile's limit, Task 8c part 2), or uses a preset with the extra radices 7 / 17 of
  this q (n 45,752, k 952, t 119: R_TX bound 250,512, op 7 M = 4 251,940 [model]; not built), or raises the limit.
- `MAX_INPUT`: 393,216 today, 512 KiB from Task 8d: every built form fits 512 KiB (op 7 M = 4 auditor 414,617 does not
  fit today's 393,216).

## One transaction's calldata (EIP-7976) [model]

A transaction pays at least 15,000 + 64 gas per calldata byte (EIP-7976 floor, Task 7b's formula [measured on
Foundry 1.8.5 Amsterdam]); with Ethereum's per-transaction regular-gas cap 2^24 (EIP-7825) that is at most
**261,909 B**. Through the token or the registry the precompile input is built in memory, so only the call's calldata
(payload + proof + UA auth) counts; the proof at its bound:

| relation | path | calldata B | floor gas | fits 2^24 | smallest per-tx cap (floor) |
|---|---|---|---|---|---|
| R_REG | `UARegistry.register` | 228,996 | 14,670,744 | yes | 14.67 M |
| R_DS / R_DR | `verifyTransferAmount` (`eth_call`) | 205,188 | 13,147,032 | yes | 13.15 M |
| R_TX / R_TX0 | relayed `mtxExecute` (op 1) | 287,844 / 287,012 | 18,437,016 / 18,383,768 | **no** | 18.44 / 18.38 M |
| R_BURN / refresh | relayed `mtxExecute` (op 2) | 286,884 | 18,375,576 | **no** | 18.38 M |
| R_TXM op 7 M = 1 / 2 / 4, auditor | relayed `mtxExecute` | 287,908 / 288,196 / 289,508 | 18.44 / 18.46 / 18.54 M | **no** | 18.44 / 18.46 / 18.54 M |

The largest proof one 2^24 transaction can carry on the debit paths is ≈ 237.6–238.8 KB. **A PQZH debit needs a
per-transaction regular-gas cap of at least ≈ 18.6 M** (e.g. 2^25); with 2^24 only registration and the disclosure
`eth_call`s work. A direct call to the precompile carries the whole input as calldata: R_REG / R_DS / R_DR fit 2^24
(223,511 / 242,263 B), the debit forms do not.

## Gas per operation [estimate]

| item | value |
|---|---|
| PQZH precompile row (`G_op`) | **not calibrated at this set.** v3 rows [measured, P6f 2026-10-15]: transfer 4,225,000, transfer0 4,021,000, burn 3,738,000, register 3,322,000, disclose 3,283,000 / 2,881,000 (p99 valid 8.0–11.8 ms native). Scaled by rows (m + 12: 177 / 137, 95 / 75) ≈ 5.5 M transfer, ≈ 4.2 M register [estimate] |
| regular gas of a debit | floor-bound: ≈ 18.4–18.5 M (the floor above; the execution part, ≈ 2 M token work + the precompile row + 16 gas / byte standard calldata ≈ 4.6 M, stays below it [estimate]) |
| state gas of a debit (EIP-8037) | as PQZL's, independent of the proof system: op 1 29.63 M with 64-bit lanes, 21.54 M with the P46 layout of Task 8d; op 7 M = 4 31.64 / 23.21 M [measured at set (a), spike PACK `55d38e61`, precompile burnt] |
| total of a debit | ≈ 48 M (64-bit lanes) / ≈ 40 M (P46) [estimate] |
| R_REG | regular ≈ max(14.67 M floor, execution) ≤ 2^24 [estimate]; state: the stored key as PQZL's registration |

## Block gas limit

One PQZH debit needs ≈ 40 M (P46) to ≈ 48 M (64-bit lanes) of block gas [estimate]: a 60 M block holds one (two PQZL
op 1 debits fit the same block with P46). The block must also allow the per-transaction cap above (≥ 18.6 M regular).

## Verify time

Target: p99 ≤ 60 ms in wasm32 (and native on the chain host). **Not measured at this set** (no timing in Task 8c). For
reference, v3 wasm32 p99 honest verify was 15–24 ms (`runs/rev2-proven-wasm.jsonl`, before the set-generic field,
which also changed the wasm32 reduction); this set has 1.3× the rows. Calibrate before any chain uses it.

## Summary: what a chain needs for PQZH at this set

1. A PQZH `proofSystemId` for this set in the precompile build and the chainspec's schedule rows (Task 8d), with
   `G_op` calibrated at this set (not done).
2. Debits (op 1 / 2 / 7): a per-transaction regular-gas cap ≥ ≈ 18.6 M (2^24 is not enough), and a debit proof
   ≤ `MAX_PROOF_PQZH` 262,144 (re-prove when above, or one of the alternatives in "Sizes per form").
3. Registration and disclosures: work under 2^24.
4. A block gas limit ≥ ≈ 48 M (≈ 40 M with P46) per PQZH debit.
5. Verify time measured ≤ 60 ms p99 (not yet).

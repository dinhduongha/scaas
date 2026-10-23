# Conditions for a chain to run PQZH — set `n2560-kmax16384` (the 16k set)

PQZH (Ligero over F_q, `pqz-core/pqzh/ligero`) is the **backup** proof system (owner 2026-10-21). The 16k set is a
shippable set (owner 2026-10-21: customer chains may choose it). **Every number here is a model estimate**: the
crate is not built at this set yet (Task 8b creates this directory's `rust/set.rs`; the crate's `pqzh_set.rs` and
build are Task 8c part 2). Source: `python3 -I pqz-core/pqzh/ligero/ligero_params.py --set n2560-kmax16384`
(`pqz-core/pqzh/ligero/runs/c8-params-n2560-kmax16384.txt`; constants from n-study `budget(2560, 16384, q)` as
`gen_set.py` derives them; its sizes and calldata equal Task 7's `ligero-16k.txt` and Task 7b's
`inputs-amsterdam-16k.txt`). `SET.md` (Task 8b) is this set's main description.

## Field and domains [model]

q = 2^50 − 42,310,535 = 1,125,899,864,532,089, q − 1 = 2^3 · 19 · 43 · 431 · 5,659 · 70,627; F_q element 50 bits in
**7 bytes**; F_q^4 = F_q[X]/(X^4 − 3) (3 a non-square), |F_q^4| = 2^200; generator 3; THE preset kept (n = 32,756 on
3·H_n, k = 817, t = 121, l = 695; radices 2 / 19 / 43 / 431; q − 1 has no other small prime); wasm32: three 17-bit
limbs. Query soundness 128.50 bits as v3 (field terms larger).

## Sizes per form [model]

| relation | rows m | proof bound B | statement B | input 5 + stmt + bound B |
|---|---|---|---|---|
| R_REG / R_DS / R_DR | 83 | 233,289 | 20,576 / 41,376 / 41,376 | 253,870 / 274,670 / 274,670 |
| R_TX / R_TX0 / R_BURN | 165 / 165 / 164 | 302,743 / 302,743 / 301,896 | 103,552 / 82,944 / 62,336 | 406,300 / 385,692 / 364,237 |
| R_TXM op 7 M = 4, auditor / no auditor | 166 / 165 | 303,590 / 302,743 | 165,760 / 144,768 | 469,355 / 447,516 |

Every debit bound is above `MAX_PROOF_PQZH` 262,144 by ≈ 40 KB. Every built form fits `MAX_INPUT` 512 KiB (Task 8d).

### Decision (owner 2026-10-23): `MAX_PROOF_PQZH` = 327,680 B (320 KiB) for this set only

The debit bounds (≈ 301.9–303.6 KB [model]) exceed the 262,144 B every other set keeps. Of the three options for a
proof over the limit (`pqz-core/params/sets/README.md`, "When a PQZH proof exceeds `MAX_PROOF_PQZH`"), only the per-set
limit raise works here [model, `runs/c8-params-n2560-kmax16384.txt`]:

- **set-specific preset:** not available. q − 1 = 2^3·19·43·431·5,659·70,627 has no other small radix, and the preset
  search over the crate's radices (prover cost modelling the crate's FFT, n up to 148,264) finds no proven preset below
  ≈ 299.6 KB for R_TX (≈ 300.4 KB for op 7 M = 4 with the auditor).
- **re-prove under the limit:** a ≈ 37–41 KB gap; at `n2304-kmax4096` honest debit proofs sat ≈ 2–7 KB under their
  bound [measured], so rejection on length would essentially never succeed here.
- **per-set limit raise (chosen):** `MAX_PROOF_PQZH` = **327,680 B** at `n2560-kmax16384` only (decisions CTR-PQZ-10).
  Headroom over the largest bound (op 7 M = 4 with the auditor, 303,590 B): 24,090 B. Largest precompile input
  5 + 165,760 + 327,680 = 493,445 B ≤ `MAX_INPUT` 512 KiB. Built in Task 8c part 2 (the prover limit in this set's
  `pqzh_set.rs`) and Task 8d (per-set `pqz-stmt` `max_proof(PQZH_ID)` and `MAX_INPUT`).

For anyone running PQZH at this set: a chain must accept PQZH proofs up to 327,680 B and precompile inputs up to
493,445 B, and the calldata conditions below still apply (debits need a per-transaction cap ≥ ≈ 21.2 M).

## One transaction's calldata (EIP-7976: 15,000 + 64 gas / byte ≤ the cap; 261,909 B at 2^24) [model]

| relation | path | calldata B | floor gas | fits 2^24 |
|---|---|---|---|---|
| R_REG | `UARegistry.register` | 259,364 | 16.61 M | yes (by 2,545 B) |
| R_DS / R_DR | `verifyTransferAmount` (`eth_call`) | 233,508 | 14.96 M | yes |
| R_TX / R_BURN | relayed `mtxExecute` | 328,132 / 327,044 | 21.02 / 20.95 M | **no** |
| R_TXM op 7 M = 4, auditor | relayed `mtxExecute` | 329,924 | 21.13 M | **no** |

A PQZH debit needs a per-transaction regular-gas cap ≥ ≈ 21.2 M; under 2^24 only registration and the disclosure
`eth_call`s work (a direct precompile call: R_REG only).

## Gas, block, verify time [estimate]

- PQZH precompile rows: not calibrated (v3 rows 2.9–4.2 M [measured]; ≈ 1.3× the rows here).
- Regular gas of a debit: floor-bound, ≈ 21.0–21.2 M. State gas as PQZL's debit at 16k: ≈ 32.8–34.8 M per op with
  64-bit lanes (Task 7b [measured], precompile burnt). Total ≈ 54–56 M per PQZH debit: one per 60 M block.
- Verify p99 ≤ 60 ms wasm32: not measured.

## Summary

PQZH at 16k needs: a 16k PQZH `proofSystemId` (8d), `MAX_PROOF_PQZH` = 327,680 B for this set (owner 2026-10-23, built in 8c part 2 /
8d), a
per-transaction cap ≥ ≈ 21.2 M for debits, a block ≥ ≈ 56 M per debit, calibrated `G_op`, and measured verify time.
